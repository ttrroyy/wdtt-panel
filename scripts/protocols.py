#!/usr/bin/env python3
"""Linux runtime for the panel's isolated VPN inbounds. No third party Python modules."""
import base64
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(os.environ.get('WDTT_PROTOCOL_DIR', '/etc/wdtt/protocols'))
BIN = Path('/usr/local/lib/wdtt/protocols')
PROFILES = {
    'wdtt': {'name': 'WDTT', 'port': 56000, 'pool': 66, 'index': 0, 'ifaces': ['wdtt0', 'wdtt-raw']},
    'qwdtt': {'name': 'qWDTT', 'port': 56100, 'pool': 67, 'index': 1, 'ifaces': ['wdtt0', 'wdttraw0']},
    'wdtt-plus': {'name': 'WDTT Plus', 'port': 56200, 'pool': 68, 'index': 2, 'ifaces': ['wdtt0']},
    'csqtt-2.1.9': {'name': 'CSQTT 2.1.9', 'port': 56300, 'pool': 69, 'index': 3, 'ifaces': ['csqtt1']},
    'csqtt-2.5.0': {'name': 'CSQTT 2.5.0', 'port': 56400, 'pool': 71, 'index': 4, 'ifaces': ['csqtt1']},
    'freeturn': {'name': 'FreeTurn', 'port': 56500, 'pool': 72, 'index': 5, 'ifaces': ['ftwg0']},
}


def run(*args, check=True, input=None):
    p = subprocess.run([str(x) for x in args], input=input, text=True, capture_output=True, timeout=45)
    if check and p.returncode:
        raise RuntimeError(f'{args[0]} failed: {p.stderr.strip() or p.stdout.strip()}')
    return p.stdout.strip()


def atomic(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd,filename=tempfile.mkstemp(prefix=path.name+'.',dir=path.parent)
    temp=Path(filename)
    os.fchmod(fd,mode)
    with os.fdopen(fd, 'w') as f:
        f.write(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2))
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


@contextlib.contextmanager
def locked():
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (ROOT/'lock').open('a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


def state():
    path = ROOT/'state.json'
    return json.loads(path.read_text()) if path.exists() else {'profiles': {}, 'users': {}, 'next_port': 22000}


def save(s):
    atomic(ROOT/'state.json', s)


def spec(name):
    if name not in PROFILES:
        raise ValueError('Неизвестный протокол')
    return PROFILES[name]


def directory(name):
    spec(name)
    return ROOT/name


def settings(name):
    return json.loads((directory(name)/'settings.json').read_text())


def unit(name):
    spec(name)
    return 'wdtt-protocol@'+name+'.service'


def namespace(name):
    return 'wdtt-'+str(spec(name)['index'])


def nsrun(name, *args, **kwargs):
    return run('ip', 'netns', 'exec', namespace(name), *args, **kwargs)


def ipt(table, chain, *args, ns=None):
    prefix = ['ip', 'netns', 'exec', namespace(ns)] if ns else []
    base = prefix + ['iptables', '-w', '3', '-t', table]
    if subprocess.run(base+['-C', chain]+list(args), capture_output=True).returncode:
        run(*(base+['-I', chain,'1']+list(args)))


def net_up(name):
    p = spec(name); index=p['index']; host=f'wp{index}h'; peer=f'wp{index}n'
    host_ip=f'10.253.{index}.1'; ns_ip=f'10.253.{index}.2'; ns=namespace(name)
    if not Path('/run/netns', ns).exists():
        run('ip','netns','add',ns)
    if not Path('/sys/class/net',host).exists():
        run('ip','link','add',host,'type','veth','peer','name',peer)
        run('ip','link','set',peer,'netns',ns)
    run('ip','addr','replace',host_ip+'/30','dev',host)
    run('ip','link','set',host,'up')
    nsrun(name,'ip','addr','replace',ns_ip+'/30','dev',peer)
    nsrun(name,'ip','link','set',peer,'up')
    nsrun(name,'ip','link','set','lo','up')
    nsrun(name,'ip','route','replace','default','via',host_ip)
    nsrun(name,'sysctl','-qw','net.ipv4.ip_forward=1','net.ipv4.conf.all.rp_filter=0','net.ipv4.conf.default.rp_filter=0')
    atomic(Path('/etc/netns')/ns/'resolv.conf','nameserver 1.1.1.1\n',0o644)
    pools=[f'10.{p["pool"]}.0.0/16'] + (['10.73.0.0/16'] if name=='qwdtt' else [])
    for pool in pools:
        run('ip','route','replace',pool,'via',ns_ip,'dev',host)
        # Preserve client identity across the namespace boundary for Xray and quotas.
        if subprocess.run(['ip','netns','exec',ns,'iptables','-t','nat','-C','POSTROUTING','-s',pool,'-j','ACCEPT'],capture_output=True).returncode:
            nsrun(name,'iptables','-t','nat','-I','POSTROUTING','1','-s',pool,'-j','ACCEPT')
        ipt('nat','POSTROUTING','-s',pool,'!','-o',host,'-j','MASQUERADE')
    ipt('nat','POSTROUTING','-s',ns_ip+'/32','!','-o',host,'-j','MASQUERADE')
    ipt('filter','FORWARD','-i',host,'-j','ACCEPT')
    ipt('filter','FORWARD','-o',host,'-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
    ports=[p['port']] + ([p['port']+2,p['port']+3] if name=='qwdtt' else [])
    for port in ports:
        ipt('nat','PREROUTING','-m','addrtype','--dst-type','LOCAL','-p','udp','--dport',str(port),'-j','DNAT','--to-destination',f'{ns_ip}:{port}')
        ipt('filter','FORWARD','-o',host,'-p','udp','-d',ns_ip,'--dport',str(port),'-j','ACCEPT')


def net_down(name):
    index=spec(name)['index']; host=f'wp{index}h'; ns_ip=f'10.253.{index}.2'
    # Remove only rules owned by this namespace, leaving other software untouched.
    for table in ('nat','filter'):
        lines=run('iptables','-w','3','-t',table,'-S').splitlines()
        import shlex
        for line in lines:
            if line.startswith('-A ') and (host in line.split() or ns_ip in line):
                args=shlex.split(line); args[0]='-D'
                run('iptables','-w','3','-t',table,*args,check=False)
    run('ip','link','del',host,check=False)
    run('ip','netns','del',namespace(name),check=False)


def setup(name, public_host):
    d=directory(name); d.mkdir(parents=True,exist_ok=True,mode=0o700)
    if (d/'settings.json').exists():
        return
    cfg={'host':public_host,'secret':secrets.token_hex(24),'admin_token':secrets.token_hex(32),'obf_key':secrets.token_hex(32)}
    atomic(d/'settings.json',cfg)
    atomic(d/'owner-password',cfg['secret']+'\n')
    atomic(d/'admin-token',cfg['admin_token']+'\n')
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','3650','-subj','/CN=localhost',
        '-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',d/'web_key.pem','-out',d/'web_cert.pem')
    os.chmod(d/'web_key.pem',0o600)
    if name=='freeturn':
        private=run('wg','genkey'); public=run('wg','pubkey',input=private+'\n')
        atomic(d/'wg-private',private+'\n'); atomic(d/'wg-public',public+'\n')
        atomic(d/'clients.json',{'clients':{}})


def serve(name):
    p=spec(name); d=directory(name); cfg=settings(name); port=p['port']
    net_up(name)
    (d/'bandwidth.signature').unlink(missing_ok=True)
    env=dict(os.environ)
    if name=='qwdtt':
        args=[BIN/name,'-listen',f'0.0.0.0:{port}','-wg-port',str(port+1),'-listen-direct',f'0.0.0.0:{port+2}',
              '-listen-raw',f'0.0.0.0:{port+3}','-config-dir',d,'-password-file',d/'owner-password',
              '-admin-listen',f'0.0.0.0:{port+4}','-admin-token-file',d/'admin-token','-admin-cert',d/'web_cert.pem','-admin-key',d/'web_key.pem']
    elif name=='wdtt-plus':
        args=[BIN/name,'-listen',f'0.0.0.0:{port}','-wg-port',str(port+1),'-config-dir',d,
              '-max-passwords','65023','-max-client-mbps','0','-wg-backend','userspace']
        if not (d/'passwords.json').exists():
            atomic(d/'passwords.json',{'main_password':cfg['secret'],'dns':'1.1.1.1','max_passwords':65023,
                                     'default_ports':f'{port},{port+1},9000','public_ip':cfg['host'],'passwords':{},'devices':{}})
    elif name.startswith('csqtt'):
        args=[BIN/name,'--listen',f'0.0.0.0:{port}','--web-port',str(port+2),'--config-dir',d]
        env.update(CSQTT_MAIN_PASSWORD=cfg['secret'],CSQTT_WEB_USER='admin',CSQTT_WEB_PASS=cfg['admin_token'],
                   CSQTT_PUBLIC_IP=cfg['host'],CSQTT_WEB_SECRET_PATH='')
    elif name=='freeturn':
        nsrun(name,'ip','link','add','ftwg0','type','wireguard',check=False)
        nsrun(name,'ip','addr','replace','10.72.66.1/16','dev','ftwg0')
        nsrun(name,'wg','set','ftwg0','private-key',d/'wg-private','listen-port',str(port+1))
        nsrun(name,'ip','link','set','ftwg0','mtu','1280','up')
        ipt('filter','FORWARD','-i','ftwg0','-j','ACCEPT',ns=name)
        ipt('filter','FORWARD','-o','ftwg0','-j','ACCEPT',ns=name)
        args=[BIN/name,'-listen',f'0.0.0.0:{port}','-connect',f'127.0.0.1:{port+1}',
              '-obf-profile','rtpopus3','-obf-key',cfg['obf_key'],'-clients-file',d/'clients.json']
    else:
        raise ValueError('WDTT runs in the unified panel process')
    child=subprocess.Popen(['ip','netns','exec',namespace(name),*[str(a) for a in args]],env=env)
    def stop(*_):
        child.terminate()
    signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
    try:
        rc=child.wait()
    finally:
        net_down(name)
    return rc


def request(name, path, data=None, method=None):
    p=spec(name); cfg=settings(name); host=f'10.253.{p["index"]}.2'
    headers={'Host':cfg['host']}
    if name=='qwdtt':
        # Trust only this instance's generated certificate; the API is namespace-local.
        context=ssl.create_default_context(cafile=str(directory(name)/'web_cert.pem'))
        context.check_hostname=False
        url=f'https://{host}:{p["port"]+4}'
        headers['Authorization']='Bearer '+cfg['admin_token']
        if data is not None:
            data=urllib.parse.urlencode(data).encode(); headers['Content-Type']='application/x-www-form-urlencoded'
    else:
        context=ssl.create_default_context(cafile=str(directory(name)/'web_cert.pem'))
        context.check_hostname=False
        url=f'https://{host}:{p["port"]+2}'
        if name=='csqtt-2.1.9':
            cache=directory(name)/'api-cookie.json'
            saved=json.loads(cache.read_text()) if cache.exists() else {}
            if saved.get('expires',0)>time.time():
                headers['Cookie']=saved['cookie']
            else:
                login=urllib.request.Request(url+'/api/login',data=json.dumps({'user':'admin','pass':cfg['admin_token']}).encode(),headers={'Content-Type':'application/json'})
                with urllib.request.urlopen(login,timeout=4,context=context) as response:
                    headers['Cookie']=response.headers['Set-Cookie'].split(';')[0]
                atomic(cache,{'cookie':headers['Cookie'],'expires':time.time()+600})
        else:
            headers['Authorization']='Bearer '+cfg['admin_token']
        if data is not None:
            data=json.dumps(data).encode(); headers['Content-Type']='application/json'
    req=urllib.request.Request(url+path,data=data,headers=headers,method=method)
    try:
        with urllib.request.urlopen(req,timeout=5,context=context) as response:
            body=response.read()
            if not body: return {}
            try: return json.loads(body)
            except ValueError: return {'message':body.decode()}
    except urllib.error.HTTPError as error:
        if error.code==401 and name=='csqtt-2.1.9' and cache.exists():
            cache.unlink(missing_ok=True)
            # A restarted server invalidates sessions; retry once with fresh credentials.
            if not getattr(request,'refreshing',False):
                request.refreshing=True
                try:
                    original=json.loads(data.decode()) if data else None
                    return request(name,path,original,method)
                finally: request.refreshing=False
        raise ValueError(f'{p["name"]}: {error.read().decode()[:300]}') from None


def plus(*args):
    cfg=settings('wdtt-plus')
    result=json.loads(run(BIN/'wdtt-plus','admin','--config-dir',directory('wdtt-plus'),'--request-stdin',
                          input=json.dumps({'main_password':cfg['secret'],'args':list(args)})))
    if not result.get('ok'):
        raise ValueError(result.get('message','WDTT Plus admin error'))
    return result


def users(name):
    if name=='wdtt':
        with sqlite3.connect('/etc/wdtt/panel.db',timeout=5) as db:
            db.row_factory=sqlite3.Row
            rows=[dict(row) for row in db.execute('SELECT * FROM wdtt_users')]
            devices=dict(db.execute('SELECT device_id,ip FROM wdtt_devices'))
            links={}
            for password,device in db.execute('SELECT password,device_id FROM wdtt_user_devices'):
                links.setdefault(password,[]).append(device)
        for row in rows:
            row['ips']=[devices[x] for x in set(links.get(row['password'],[])+[row.get('device_id','')]) if x in devices]
        stats=Path('/etc/wdtt/server.log')
        if stats.exists():
            try:
                addresses=json.loads(stats.read_text()).get('user_ips',{})
                for row in rows: row['ips']=list(set(row['ips']+addresses.get(user_id(name,row['password']),[])))
            except ValueError: pass
        return rows
    if name=='wdtt-plus':
        rows=plus('list').get('passwords',[])
        for row in rows:
            row['ips']=[row['device_ip']] if row.get('device_ip') else []
        return rows
    if name=='qwdtt':
        rows=request(name,'/admin/passwords').get('passwords',[])
        dbpath=directory(name)/'passwords.json'
        devices=json.loads(dbpath.read_text()).get('devices',{}) if dbpath.exists() else {}
        for row in rows:
            row['ips']=[devices[x][key] for x in (row.get('device_ids') or []) if x in devices for key in ('ip','raw_ip') if devices[x].get(key)]
        return rows
    if name.startswith('csqtt'):
        rows=request(name,'/api/clients')
        if isinstance(rows,dict):
            rows=rows.get('clients',[])
        for row in rows:
            row['ips']=[row['ip']] if row.get('ip') else []
            row['down_bytes']=row.get('down',0); row['up_bytes']=row.get('up',0)
            row['expires_at']=row.get('expires',0)
        return rows
    with locked():
        entries=state()['users'].get(name,{})
    rows=[]
    counters=nsrun(name,'wg','show','ftwg0','dump').splitlines()[1:]
    traffic={parts[0]:(int(parts[5]),int(parts[6])) for line in counters if len(parts:=line.split())>=8}
    for password,entry in entries.items():
        up,down=traffic.get(entry['public_key'],(0,0))
        with locked():
            s=state(); stored=s['users'][name][password]
            for key,raw in [('up',up),('down',down)]:
                previous=stored.get('last_'+key,0)
                stored[key+'_bytes']=stored.get(key+'_bytes',0)+(raw-previous if raw>=previous else raw)
                stored['last_'+key]=raw
            entry=dict(stored); save(s)
        rows.append(dict(entry,password=password,ips=[entry['ip']]))
    return rows


def user_id(name, password):
    return hashlib.sha256((name+'\0'+password).encode()).hexdigest()[:20]


def display_users(name):
    rows=users(name)
    with locked():
        saved=state()['users'].get(name,{})
    cfg=settings(name) if name!='wdtt' else {}
    if name!='wdtt': rows=[row for row in rows if row['password']!=cfg['secret']]
    port=spec(name)['port']
    for row in rows:
        password=row['password']; meta=saved.get(password,{})
        row['id']=user_id(name,password)
        row['tag']='vpn-'+name+'-user-'+row['id']
        row['name']=row.get('name') or row.get('label') or row.get('comment') or 'Пользователь'
        row['expires_at']=row.get('expires_at',0)
        row['up_bytes']=row.get('up_bytes',0)
        row['down_bytes']=row.get('down_bytes',0)
        row['total_bytes']=meta.get('total_bytes',row.get('total_bytes',0))
        row['max_mbps']=meta.get('max_mbps',0)
        row['enabled']=not row.get('is_deactivated',False) and row.get('active',True) and row.get('status','active')=='active' and not (row.get('expires_at',0) and row['expires_at']<=time.time())
        if name=='qwdtt':
            row['link']='qwdtt://config?'+urllib.parse.urlencode({'name':row['name'],'peer':f'{cfg["host"]}:{port}','pass':password,
                                                              'hashes':row.get('vk_hash',''),'workers':9,'port':9000})
        elif name=='wdtt-plus':
            row['link']=f'wdtt://{cfg["host"]}:{port}:{port+1}:9000:{password}:{row.get("vk_hash","")}'
        elif name=='csqtt-2.5.0':
            # Use the original server's encrypted URI, including its original hash encoding.
            if not row.get('link','').startswith('csqtt://'): raise ValueError('Сервер CSQTT не вернул ссылку')
        elif name=='csqtt-2.1.9':
            row['link']='csqtt://connect?'+urllib.parse.urlencode({'v':2,'host':cfg['host'],'peer':port,'password':password},quote_via=urllib.parse.quote)
            hashes=[value.strip() for value in (row.get('vk_hashes') or row.get('vk_hash','')).split(',') if value.strip()]
            if hashes: row['link']+='&hashes='+'+'.join(urllib.parse.quote(value,safe='') for value in hashes)
        elif name=='freeturn':
            payload={'v':1,'provider':'vk','peer':f'{cfg["host"]}:{port}','obf':'rtpopus3','key':cfg['obf_key'],'cid':password,'name':row['name']}
            row['wg_config']=f'[Interface]\nPrivateKey = {meta["private_key"]}\nAddress = {meta["ip"]}/32\nDNS = 1.1.1.1\nMTU = 1280\n\n[Peer]\nPublicKey = {(directory(name)/"wg-public").read_text().strip()}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9000\nPersistentKeepalive = 25\n'
            payload['wg']=row['wg_config'];payload['listen']='127.0.0.1:9000'
            hashes=[value.strip() for value in meta.get('vk_hash','').split(',') if value.strip()]
            if hashes: payload['vk']=','.join(value if '://' in value else 'https://vk.com/call/join/'+value for value in hashes)
            row['link']='freeturn://'+base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':'),ensure_ascii=False).encode()).decode().rstrip('=')
    return rows


def create_user(name, data):
    p=spec(name); days=int(data.get('days',0)); total=int(data.get('total_bytes',0)); speed=float(data.get('max_mbps',0))
    if not 0<=days<=365 or total<0 or speed<0 or speed>100000:
        raise ValueError('Некорректный срок, трафик или скорость; 0 означает безлимит')
    label=str(data.get('name','')).strip(); vk=str(data.get('vk_hash','')).strip()
    if not label or len(label)>128 or len(vk)>4096:
        raise ValueError('Укажите имя пользователя (до 128 символов)')
    if name=='wdtt':
        raise ValueError('Пользователи WDTT редактируются в разделе «Пользователи»')
    if name=='wdtt-plus':
        row=plus('create','--days',str(days),'--label',label,'--vk-hash',vk,'--ports',f'{p["port"]},{p["port"]+1},9000')['password']
    elif name=='qwdtt':
        row=request(name,'/admin/passwords',{'label':label,'days':days,'vk_hash':vk,'max_devices':int(data.get('max_devices',1)),
                                            'ports':f'{p["port"]},{p["port"]+1},9000'})
    elif name.startswith('csqtt'):
        payload={'name':label,'days':days,'hash':vk,'local_port':9000}
        payload['dtls_port' if name=='csqtt-2.1.9' else 'peer_port']=p['port']
        row=request(name,'/api/clients',payload)
    else:
        private=run('wg','genkey'); public=run('wg','pubkey',input=private+'\n')
        with locked():
            existing=state()['users'].get(name,{})
        used={x['ip'] for x in existing.values()}
        address=next((str(ip) for ip in ipaddress.ip_network('10.72.0.0/16').hosts() if str(ip) not in used and str(ip)!='10.72.66.1'),None)
        if address is None:
            raise ValueError('Адресный пул исчерпан')
        row={'password':secrets.token_hex(16),'name':label,'ip':address,'public_key':public,'private_key':private,
             'expires_at':int(time.time())+days*86400 if days else 0}
        nsrun(name,'wg','set','ftwg0','peer',public,'allowed-ips',address+'/32')
    password=row['password']
    with locked():
        s=state(); entry=s['users'].setdefault(name,{}).setdefault(password,{})
        entry.update(row if name=='freeturn' else {})
        entry.update(name=label,total_bytes=total,max_mbps=speed,vk_hash=vk)
        save(s)
    if name=='freeturn':
        sync_freeturn()
    return row


def enabled_user(name,password,enabled):
    if name=='qwdtt':
        request(name,'/admin/passwords/'+('activate' if enabled else 'deactivate'),{'password':password})
    elif name=='wdtt-plus':
        plus('activate' if enabled else 'deactivate','--password',password)
    elif name.startswith('csqtt'):
        current=next(x for x in users(name) if x['password']==password)
        if bool(current.get('active',True))!=enabled:
            request(name,'/api/clients/'+urllib.parse.quote(password,safe='')+'/toggle',{},'POST')
    elif name=='freeturn':
        with locked():
            s=state(); s['users'][name][password]['is_deactivated']=not enabled; save(s)
        sync_freeturn()


def sync_freeturn():
    with locked():
        entries=state()['users'].get('freeturn',{})
    active={key:{'comment':row['name']} for key,row in entries.items() if not row.get('is_deactivated',False) and not (row.get('expires_at',0) and row['expires_at']<=time.time())}
    atomic(directory('freeturn')/'clients.json',{'clients':active})
    for password,row in entries.items():
        args=['peer',row['public_key']]
        args+=['allowed-ips',row['ip']+'/32'] if password in active else ['remove']
        nsrun('freeturn','wg','set','ftwg0',*args)


def mutate_user(name, data, delete=False):
    password=str(data.get('password',''))
    current=next((r for r in display_users(name) if r['password']==password),None)
    if current is None:
        raise ValueError('Пользователь не найден')
    if delete:
        if name=='qwdtt': request(name,'/admin/passwords/delete',{'password':password})
        elif name=='wdtt-plus': plus('delete','--password',password)
        elif name.startswith('csqtt'): request(name,'/api/clients/'+urllib.parse.quote(password,safe=''),method='DELETE')
        elif name=='freeturn': nsrun(name,'wg','set','ftwg0','peer',current['public_key'],'remove')
        with locked():
            s=state(); s['users'].get(name,{}).pop(password,None); save(s)
        if name=='freeturn': sync_freeturn()
        return {}
    total=int(data.get('total_bytes',current['total_bytes'])); speed=float(data.get('max_mbps',current['max_mbps']))
    if total<0 or speed<0 or speed>100000:
        raise ValueError('Лимиты должны быть неотрицательными; 0 — безлимит')
    if 'name' in data or 'days' in data or 'vk_hash' in data:
        label=str(data.get('name',current['name'])).strip()
        vk=str(data.get('vk_hash',current.get('vk_hashes') or current.get('vk_hash',''))).strip()
        days=int(data.get('days',max(1,int((current.get('expires_at',0)-time.time())/86400)+1) if current.get('expires_at',0) else 0))
        if not label or len(label)>128 or not 0<=days<=365:
            raise ValueError('Некорректное имя или срок')
        if name=='qwdtt':
            payload={'password':password,'label':label,'days':days,'max_devices':int(data.get('max_devices',current.get('max_devices',1)))}
            payload['vk_hash']=vk
            request(name,'/admin/passwords/update',payload)
        elif name=='wdtt-plus':
            port=spec(name)['port']
            plus('update-client','--password',password,'--label',label,'--vk-hash',vk,'--ports',f'{port},{port+1},9000')
            if 'days' in data: plus('set-expiry','--password',password,'--days',str(days))
        elif name.startswith('csqtt'):
            payload={'name':label,'hash':vk,'days':days,'local_port':9000}
            payload['dtls_port' if name=='csqtt-2.1.9' else 'peer_port']=spec(name)['port']
            request(name,'/api/clients/'+urllib.parse.quote(password,safe=''),payload,'POST')
        elif name=='freeturn':
            with locked():
                s=state(); entry=s['users'][name][password]; entry['name']=label; entry['vk_hash']=vk
                if 'days' in data: entry['expires_at']=int(time.time())+days*86400 if days else 0
                save(s)
    if 'enabled' in data:
        enabled_user(name,password,bool(data['enabled']))
    with locked():
        s=state(); entry=s['users'].setdefault(name,{}).setdefault(password,{})
        was_quota_blocked=entry.get('quota_blocked',False)
        entry.update(total_bytes=total,max_mbps=speed)
        if 'enabled' in data:
            entry.pop('quota_blocked',None)
        save(s)
    if was_quota_blocked and (total==0 or total>current.get('down_bytes',0)+current.get('up_bytes',0)):
        enabled_user(name,password,True)
        with locked():
            s=state(); s['users'][name][password].pop('quota_blocked',None); save(s)
    return {}


def profile_list():
    with locked(): s=state()
    native=None
    db_path=ROOT.parent/'panel.db'
    if db_path.exists():
        with sqlite3.connect(db_path,timeout=5) as db:
            native=db.execute('SELECT dtls_port,enable,wg_port,raw_enable,raw_direct_port,remark FROM wdtt_inbound WHERE id=1').fetchone()
        if native and s['profiles'].get('wdtt') and s.get('disabled',{}).get('wdtt',False)==bool(native[1]):
            with locked():
                current=state();current.setdefault('disabled',{})['wdtt']=not bool(native[1]);save(current)
            s.setdefault('disabled',{})['wdtt']=not bool(native[1])
    counts={name:0 for name in PROFILES}
    if db_path.exists():
        with sqlite3.connect(db_path,timeout=5) as db:
            for (sub_id,) in db.execute('SELECT sub_id FROM wdtt_users'):
                selected=db.execute('SELECT protocols FROM vpn_user_inbounds WHERE sub_id=?',(sub_id,)).fetchone()
                for name in json.loads(selected[0]) if selected else ['wdtt']:
                    if name in counts: counts[name]+=1
    rows=[]
    for name,p in PROFILES.items():
        row=dict(p,id=name,tag='vpn-'+name,subnet=f'10.{p["pool"]}.0.0/16',present=bool(s['profiles'].get(name)))
        if name=='wdtt' and native: row['port']=native[0]
        row['display_id']=p['index']+1
        row['enabled']=not s.get('disabled',{}).get(name,False)
        cache=directory(name)/'last-users.json'
        cached=json.loads(cache.read_text()) if cache.exists() else []
        row['users']=counts[name]
        row['traffic_bytes']=sum(x.get('up_bytes',0)+x.get('down_bytes',0) for x in cached)
        ports=[row['port']]
        if name in ('wdtt','qwdtt','wdtt-plus','freeturn'): ports.append(native[2] if name=='wdtt' and native else row['port']+1)
        if name=='qwdtt': ports.extend([row['port']+2,row['port']+3])
        if name=='wdtt' and (not native or native[3]): ports.append((native[4] or row['port']+3) if native else row['port']+3)
        row['ports']=ports
        row['protocol_labels']=[p['name']]+(['DTLS','WG','RAW'] if name in ('wdtt','qwdtt') else ['DTLS','WG'] if name in ('wdtt-plus','freeturn') else ['RTP','TUN'])
        row['subnets']=[row['subnet']]
        if name=='wdtt' and native:
            row['name']=native[5] or 'WDTT'
            if not native[3]:row['protocol_labels'].remove('RAW')
        if name=='qwdtt':row['subnets'].append('10.73.0.0/16')
        if name=='wdtt' and (not native or native[3]):row['subnets'].append('10.70.0.0/16')
        row['active']=run('systemctl','is-active','wdtt.service' if name=='wdtt' else unit(name),check=False)=='active'
        rows.append(row)
    return rows


def profile_create(name,host):
    spec(name)
    with locked():
        s=state()
        if s['profiles'].get(name):
            raise ValueError('На VPS уже есть этот протокол')
        s['profiles'][name]=True
        s.setdefault('disabled',{})[name]=False;save(s)
    try:
        if name!='wdtt':
            if not (BIN/name).exists():
                raise ValueError('Серверный бинарник не установлен')
            setup(name,host)
            run('systemctl','enable','--now',unit(name))
        else:
            pass  # The panel applies the managed WDTT runtime configuration itself.
    except Exception:
        with locked():
            s=state(); s['profiles'][name]=False; save(s)
        raise


def profile_delete(name):
    spec(name)
    if name!='wdtt':
        run('systemctl','disable','--now',unit(name))
    with locked():
        s=state(); s['profiles'][name]=False; save(s)


def profile_toggle(name, enabled):
    spec(name)
    with locked():
        s=state()
        if not s['profiles'].get(name): raise ValueError('Сначала создайте инбаунд')
    if name!='wdtt':
        run('systemctl','enable' if enabled else 'disable','--now',unit(name))
    with locked():
        s=state();s.setdefault('disabled',{})[name]=not enabled;save(s)


def native_users():
    with sqlite3.connect(ROOT.parent/'panel.db',timeout=5) as db:
        db.row_factory=sqlite3.Row
        return [dict(row) for row in db.execute('SELECT * FROM wdtt_users')]


def selected_protocols(master,bundle):
    with sqlite3.connect(ROOT.parent/'panel.db',timeout=5) as db:
        row=db.execute('SELECT protocols FROM vpn_user_inbounds WHERE sub_id=?',(master['sub_id'],)).fetchone()
        if row: return json.loads(row[0])
        # Preserve memberships of subscriptions created by the previous release.
        selected=['wdtt']+list(bundle.get('members',{}))
        db.execute('INSERT INTO vpn_user_inbounds(sub_id,protocols) VALUES(?,?)',(master['sub_id'],json.dumps(selected)))
        return selected


def seed_default_subscription():
    with sqlite3.connect(ROOT.parent/'panel.db',timeout=5) as db:
        row=db.execute('SELECT u.sub_id FROM wdtt_users u JOIN wdtt_global g ON u.password=g.main_password WHERE g.id=1').fetchone()
    if not row or not row[0]: raise ValueError('Главный пользователь ещё не инициализирован')
    atomic(ROOT/'default-subscription-id',row[0]+'\n')
    return {'sub_id':row[0]}


def adopt_legacy_users(rows_by_profile):
    with locked():
        s=state()
        linked={(name,password) for bundle in s.get('bundles',{}).values() for name,password in bundle.get('members',{}).items()}
        for name,rows in rows_by_profile.items():
            if name=='wdtt': continue
            for row in rows:
                if (name,row['password']) in linked: continue
                identity=secrets.token_hex(16);sub_id=secrets.token_hex(8)
                with sqlite3.connect(ROOT.parent/'panel.db',timeout=5) as db:
                    db.execute('INSERT INTO wdtt_users(password,sub_id,comment,expires_at,is_deactivated,total_bytes) VALUES(?,?,?,?,?,?)',
                               (identity,sub_id,row['name'],row.get('expires_at',0),int(not row['enabled']),row.get('total_bytes',0)))
                    db.execute('INSERT INTO vpn_user_inbounds(sub_id,protocols) VALUES(?,?)',(sub_id,json.dumps([name])))
                    db.execute("UPDATE wdtt_global SET users_rev=users_rev+1 WHERE id=1")
                s.setdefault('bundles',{})[sub_id]={'wdtt_password':identity,'members':{name:row['password']}}
                save(s)


def sync_subscription_bundles(rows_by_profile):
    with locked():
        current=state();bundles=dict(current.get('bundles',{}))
        active_profiles={name:present and not current.get('disabled',{}).get(name,False) for name,present in current['profiles'].items()}
    result={};aliases={};options=[];errors=[]
    native={master['sub_id']:master for master in native_users() if master['sub_id']}
    # Deleted identities lose all backend access, even when their old credentials remain on disk.
    for sub_id,bundle in list(bundles.items()):
        if sub_id in native: continue
        for name,password in bundle.get('members',{}).items():
            row=next((x for x in rows_by_profile.get(name,[]) if x['password']==password),None)
            if row and row['enabled']: enabled_user(name,password,False)
    for sub_id,master in native.items():
        bundle=bundles.setdefault(sub_id,{'members':{}})
        bundle['wdtt_password']=master['password']
        selected=selected_protocols(master,bundle)
        if any(name not in PROFILES for name in selected): raise ValueError('Неизвестный инбаунд подписки')
        connections=[];up=down=0;tags=[]
        if 'wdtt' in selected: tags.append('vpn-wdtt-user-'+user_id('wdtt',master['password']))
        master_active=not master['is_deactivated'] and not (master['expires_at'] and master['expires_at']<=time.time())
        signature=json.dumps([master['comment'],master['vk_hash'],master['expires_at'],master['total_bytes'],master['max_down_mbps'],master['max_up_mbps'],master['max_devices']])
        for name in PROFILES:
            if name=='wdtt': continue
            password=bundle['members'].get(name)
            row=next((item for item in rows_by_profile.get(name,[]) if item['password']==password),None) if password else None
            try:
                if name in selected and active_profiles.get(name) and not password:
                    created=create_user(name,{'name':master['comment'] or 'Пользователь','vk_hash':master['vk_hash'],'days':0,'max_devices':master['max_devices'] or 1})
                    password=created['password'];bundle['members'][name]=password
                    # Save immediately: a failed following backend must not duplicate this credential.
                    with locked():
                        state_now=state();state_now.setdefault('bundles',{})[sub_id]=bundle;save(state_now)
                    row=next(x for x in display_users(name) if x['password']==password)
                    rows_by_profile.setdefault(name,[]).append(row)
                if row is None: continue
                if name in selected: tags.append('vpn-'+name+'-user-'+user_id(name,password))
                if active_profiles.get(name) and signature!=bundle.get('signatures',{}).get(name):
                    days=min(365,max(1,int((master['expires_at']-time.time())/86400)+1)) if master['expires_at'] else 0
                    # Identity controls expiry and quota across all of its member protocols.
                    speeds=[v*8 for v in (master['max_down_mbps'],master['max_up_mbps']) if v>0]
                    mutate_user(name,{'password':password,'name':master['comment'] or 'Пользователь','vk_hash':master['vk_hash'],'days':days,'max_devices':master['max_devices'] or 1,'total_bytes':0,'max_mbps':min(speeds) if speeds else 0})
                    bundle.setdefault('signatures',{})[name]=signature
                up+=row.get('up_bytes',0);down+=row.get('down_bytes',0)
                allowed=master_active and name in selected
                if active_profiles.get(name) and row['enabled']!=allowed:
                    enabled_user(name,password,allowed);row['enabled']=allowed
                if allowed and active_profiles.get(name):
                    connections.append({'protocol':name,'title':spec(name)['name'],'link':row['link'],'wg_config':row.get('wg_config','')})
            except Exception as error: errors.append(sub_id+'/'+name+': '+str(error))
        raw_up,raw_down=up,down
        offsets=bundle.get('traffic_offsets',{})
        up=max(0,up-offsets.get('up_bytes',0));down=max(0,down-offsets.get('down_bytes',0))
        used=up+down+master['up_bytes']+master['down_bytes']
        if master['total_bytes'] and used>=master['total_bytes']:
            # Native suspension also triggers its normal live peer revocation.
            with sqlite3.connect(ROOT.parent/'panel.db',timeout=5) as db:
                db.execute('UPDATE wdtt_users SET is_deactivated=1 WHERE sub_id=?',(sub_id,))
                db.execute("UPDATE wdtt_global SET users_rev=users_rev+1 WHERE id=1")
            for name,password in bundle['members'].items():
                if active_profiles.get(name): enabled_user(name,password,False)
            connections=[]
        with locked():
            state_now=state();state_now.setdefault('bundles',{})[sub_id]=bundle;save(state_now)
        tag='vpn-user-'+sub_id;aliases[tag]=tags
        options.append({'tag':tag,'label':master['comment'] or 'Пользователь'})
        result[sub_id]={'connections':connections,'up_bytes':up,'down_bytes':down,'raw_up_bytes':raw_up,'raw_down_bytes':raw_down}
    atomic(ROOT.parent/'protocol-subscriptions.json',result)
    atomic(ROOT/'user-route-aliases.json',aliases)
    return options,errors


def transparent_inbound(tag,port):
    return {'tag':tag,'listen':'127.0.0.1','port':port,'protocol':'tunnel',
            'settings':{'allowedNetwork':'tcp,udp','followRedirect':True},
            'sniffing':{'enabled':True,'destOverride':['http','tls','quic'],'routeOnly':True},
            'streamSettings':{'sockopt':{'tproxy':'tproxy','mark':255}}}


def protocol_ingress(name):
    p=spec(name);iface='wdtt0' if name=='wdtt' else f'wp{p["index"]}h';port=21000+p['index']
    rows=[(iface,f'10.{p["pool"]}.0.0/16',port)]
    if name=='qwdtt':rows.append((iface,'10.73.0.0/16',port))
    if name=='wdtt':rows.append(('wdtt-raw','10.70.0.0/16',port))
    return rows


def routing_snapshot(rows_by_profile):
    generated=[]; ingress=[]
    with locked():
        s=state()
        for name,rows in rows_by_profile.items():
            p=spec(name); port=21000+p['index']; tag='vpn-'+name
            generated.append(transparent_inbound(tag,port))
            iface=f'wp{p["index"]}h' if name!='wdtt' else 'wdtt0'
            for row in rows:
                # Allocate a listener only for users explicitly selected in a routing rule.
                row['id']=user_id(name,row['password']); row['tag']=tag+'-user-'+row['id']
            ingress.extend(protocol_ingress(name))
        raw_path=Path('/etc/wdtt-xray/config.json')
        raw=json.loads(raw_path.read_text()) if raw_path.exists() else {}
        db_path=ROOT.parent/'panel.db'
        if db_path.exists():
            with sqlite3.connect(db_path,timeout=5) as db:
                row=db.execute('SELECT raw_json FROM xray_config WHERE id=1').fetchone()
                if row and row[0]: raw=json.loads(row[0])
        wanted={tag for rule in raw.get('routing',{}).get('rules',[]) for tag in rule.get('inboundTag',[]) if '-user-' in tag}
        aliases=ROOT/'user-route-aliases.json'
        if aliases.exists():
            for tag,children in json.loads(aliases.read_text()).items():
                if tag in wanted: wanted.update(children)
        for name,rows in rows_by_profile.items():
            for row in rows:
                if row['tag'] not in wanted: continue
                key=row['password']; entry=s['users'].setdefault(name,{}).setdefault(key,{})
                if 'route_port' not in entry:
                    if s['next_port']>=55000: raise ValueError('Исчерпаны локальные порты маршрутизации')
                    entry['route_port']=s['next_port']; s['next_port']+=1
                port=entry['route_port']; generated.append(transparent_inbound(row['tag'],port))
                iface='wdtt0' if name=='wdtt' else f'wp{spec(name)["index"]}h'
                for address in row.get('ips',[]):
                    target_iface='wdtt-raw' if name=='wdtt' and address.startswith('10.70.') else iface
                    ingress.insert(0,(target_iface,address,port))
        save(s)
    return generated,ingress


def apply_routes(ingress):
    run('iptables','-w','3','-t','mangle','-N','WDTT_PANEL',check=False)
    ipt('mangle','PREROUTING','-j','WDTT_PANEL')
    if not any('fwmark 0x77/0xff' in line and 'lookup 10990' in line for line in run('ip','rule','show').splitlines()):
        run('ip','rule','add','priority','10990','fwmark','0x77/0xff','lookup','10990')
    run('ip','route','replace','local','0.0.0.0/0','dev','lo','table','10990')
    run('sysctl','-qw','net.ipv4.conf.all.rp_filter=0')
    ipt('filter','INPUT','-m','mark','--mark','0x77/0xff','-j','ACCEPT')
    lines=['*mangle',':WDTT_PANEL - [0:0]','-F WDTT_PANEL']
    for iface,address,port in ingress:
        for proto in ('tcp','udp'):
            parts=['-A','WDTT_PANEL','-i',iface,'-p',proto]
            if address: parts+=['-s',str(ipaddress.ip_network(address,strict=False))]
            parts+=['-j','TPROXY','--on-ip','127.0.0.1','--on-port',str(port),'--tproxy-mark','0x77/0xff']
            lines.append(' '.join(parts))
    lines.append('COMMIT')
    run('iptables-restore','--noflush',input='\n'.join(lines)+'\n')


def bandwidth(name, rows):
    if name=='wdtt': return
    # Configure only changed limits; zero removes filters instead of throttling traffic.
    signature=hashlib.sha256(json.dumps([(r['password'],r.get('ips',[]),r.get('max_mbps',0)) for r in rows],sort_keys=True).encode()).hexdigest()
    path=directory(name)/'bandwidth.signature'
    if path.exists() and path.read_text()==signature: return
    for iface in spec(name)['ifaces']:
        nsrun(name,'tc','qdisc','del','dev',iface,'root',check=False)
        nsrun(name,'tc','qdisc','del','dev',iface,'ingress',check=False)
        limited=[r for r in rows if r.get('max_mbps',0)>0]
        if limited:
            nsrun(name,'tc','qdisc','add','dev',iface,'root','handle','1:','htb','default','fffe')
            nsrun(name,'tc','class','add','dev',iface,'parent','1:','classid','1:1','htb','rate','100gbit')
            nsrun(name,'tc','class','add','dev',iface,'parent','1:1','classid','1:fffe','htb','rate','100gbit','ceil','100gbit')
            nsrun(name,'tc','qdisc','add','dev',iface,'handle','ffff:','ingress')
            for index,row in enumerate(limited,2):
                rate=f'{int(row["max_mbps"]*1000)}kbit'; cls=f'1:{index:x}'
                nsrun(name,'tc','class','add','dev',iface,'parent','1:1','classid',cls,'htb','rate',rate,'ceil',rate)
                for address in row.get('ips',[]):
                    nsrun(name,'tc','filter','add','dev',iface,'parent','1:','protocol','ip','u32','match','ip','dst',address+'/32','flowid',cls)
                    nsrun(name,'tc','filter','add','dev',iface,'parent','ffff:','protocol','ip','u32','match','ip','src',address+'/32','police','rate',rate,'burst','64kb','drop')
    atomic(path,signature)


def reconcile():
    rows_by_profile={}; errors=[]
    with locked():
        current=state();enabled=dict(current['profiles']);disabled=dict(current.get('disabled',{}))
    for name,present in enabled.items():
        if not present: continue
        if disabled.get(name):
            cache=directory(name)/'last-users.json'
            rows_by_profile[name]=json.loads(cache.read_text()) if cache.exists() else []
            continue
        try:
            rows=display_users(name); rows_by_profile[name]=rows
            atomic(directory(name)/'last-users.json', rows)
            if name!='wdtt':
                pools=[f'10.{spec(name)["pool"]}.0.0/16']+(['10.73.0.0/16'] if name=='qwdtt' else [])
                # Upstreams insert their NAT rule during startup; keep the identity exemption first.
                nat=nsrun(name,'iptables','-t','nat','-S','POSTROUTING')
                first=next((line for line in nat.splitlines() if line.startswith('-A ')), '')
                if pools[0] not in first or '-j ACCEPT' not in first:
                    for pool in reversed(pools):
                        nsrun(name,'iptables','-t','nat','-D','POSTROUTING','-s',pool,'-j','ACCEPT',check=False)
                        nsrun(name,'iptables','-t','nat','-I','POSTROUTING','1','-s',pool,'-j','ACCEPT')
            for row in rows:
                if row['total_bytes'] and row.get('down_bytes',0)+row.get('up_bytes',0)>=row['total_bytes'] and row['enabled']:
                    if name!='wdtt': enabled_user(name,row['password'],False)
                    with locked():
                        s=state(); s['users'].setdefault(name,{}).setdefault(row['password'],{})['quota_blocked']=True; save(s)
            bandwidth(name,rows)
            if name=='freeturn': sync_freeturn()
        except Exception as error:
            errors.append(name+': '+str(error))
            cache=directory(name)/'last-users.json'
            rows_by_profile.setdefault(name,json.loads(cache.read_text()) if cache.exists() else [])
    adopt_legacy_users(rows_by_profile)
    user_options,user_errors=sync_subscription_bundles(rows_by_profile)
    errors.extend(user_errors)
    options=[{'tag':'vpn-'+name,'label':spec(name)['name']} for name in rows_by_profile]
    atomic(ROOT/'route-options.json',options+user_options)
    generated,ingress=routing_snapshot(rows_by_profile)
    path=ROOT/'routing.signature'; signature=hashlib.sha256(json.dumps(ingress).encode()).hexdigest()
    if not path.exists() or path.read_text()!=signature:
        apply_routes(ingress); atomic(path,signature)
    atomic(ROOT.parent/'protocol-inbounds.json',generated)
    atomic(ROOT/'health.json',{'updated_at':int(time.time()),'errors':errors})


def api(data):
    operation=data.get('op','list'); name=data.get('protocol','')
    if operation=='list': return profile_list()
    if operation=='seed-default': return seed_default_subscription()
    if operation=='reset-user-traffic':
        sub_id=str(data.get('sub_id',''))
        with locked():
            s=state();bundle=s.get('bundles',{}).get(sub_id)
            if not bundle: return {}
            snapshot=ROOT.parent/'protocol-subscriptions.json'
            totals=json.loads(snapshot.read_text()).get(sub_id,{}) if snapshot.exists() else {}
            offsets=bundle.setdefault('traffic_offsets',{})
            for key in ('up_bytes','down_bytes'):offsets[key]=totals.get('raw_'+key,totals.get(key,0))
            save(s)
        return {}
    spec(name)
    if operation=='create': profile_create(name,str(data.get('host','')))
    elif operation=='delete': profile_delete(name)
    elif operation in ('enable','disable'): profile_toggle(name,operation=='enable')
    elif operation=='users': return display_users(name)
    elif operation=='user-add': return create_user(name,data)
    elif operation=='user-update': return mutate_user(name,data)
    elif operation=='user-delete': return mutate_user(name,data,True)
    else: raise ValueError('Неизвестная операция')
    return {}


if __name__=='__main__':
    try:
        if len(sys.argv)>1 and sys.argv[1]=='run':
            sys.exit(serve(sys.argv[2]))
        elif len(sys.argv)>1 and sys.argv[1]=='watch':
            (ROOT/'routing.signature').unlink(missing_ok=True)
            while True:
                try: reconcile()
                except Exception as error: print(str(error),file=sys.stderr,flush=True)
                time.sleep(3)
        else:
            print(json.dumps({'success':True,'obj':api(json.load(sys.stdin))},ensure_ascii=False))
    except Exception as error:
        print(json.dumps({'success':False,'msg':str(error)},ensure_ascii=False))
        sys.exit(1)
