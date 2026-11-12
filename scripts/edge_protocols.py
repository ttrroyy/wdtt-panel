"""Original DNS engines and OpenFlux, isolated per panel identity."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import sqlite3
import subprocess
import time

TYPES = {'dnstt':'DNSTT','vaydns':'VayDNS','slipstream':'Slipstream','masterdns':'MasterDNS / StormDNS','cottendns':'CottenDNS','soar':'Soar','openflux':'OpenFlux'}
R = None


def configure(runtime):
    global R
    R=runtime


def catalog(root):
    path=root/'catalog.json'
    return json.loads(path.read_text()) if path.exists() else {}


def is_edge(name):
    return name.startswith('edge-')


def config(name):
    if not re.fullmatch(r'edge-[a-z]+-[a-f0-9]{8}',name):raise ValueError('Некорректный ID инбаунда')
    return json.loads((R['ROOT']/name/'settings.json').read_text())


def members(name):
    path=R['ROOT']/name/'members.json'
    return json.loads(path.read_text()) if path.exists() else {}


def store_members(name, values):
    R['atomic'](R['ROOT']/name/'members.json',values)


def sections(cfg):
    def f(key,label,kind='text',**kw):return dict(key=key,label=label,type=kind,value=cfg.get(key,''),**kw)
    fixed='Закреплено для изоляции пользователей и сохранения маршрутизации.'
    fields=[f('enabled','Включить','switch'),f('remark','Примечание'),f('engine','Оригинальный движок',readonly=True,help=fixed)]
    if cfg['engine']!='openflux':
        fields += [f('zone','Базовая DNS-зона',readonly=True,help='Делегированная NS-зона. Пользователи получают отдельные поддомены.'),f('ns','Авторитетный NS',readonly=True),f('resolvers','DNS-резолверы',help='Через запятую. Пусто — DNS клиента.'),f('user_zone','Поддомен пользователя',readonly=True,help=fixed)]
        if cfg['engine'] in ('dnstt','vaydns'):fields += [f('mtu','Максимальный DNS-ответ','number',min=512,max=4096)]
        if cfg['engine']=='vaydns':fields += [f('record_type','Тип DNS-записи','select',options=['txt','null','cname','a','aaaa','mx','ns','srv','caa']),f('clientid_size','Размер ClientID','number',min=2,max=16),f('dnstt_compat','DNSTT wire compatibility','switch')]
        if cfg['engine'] in ('masterdns','cottendns'):fields += [f('encryption','Шифрование','select',options=['0','1','2','3','4','5'],help='0: NONE; 1: XOR; 2: ChaCha20; 3/4/5: AES-128/192/256-GCM.'),f('server_options','Оригинальные параметры сервера (JSON)',help='Только параметры производительности из server_config.toml; адреса, ключи и upstream управляются панелью.')]
        if cfg['engine']=='slipstream':fields += [f('max_connections','Максимум QUIC-подключений','number',min=1,max=4096),f('idle_timeout','Тайм-аут QUIC, сек','number',min=10,max=3600)]
        if cfg['engine']=='soar':fields += [f('allow_ports','Разрешённые порты назначения',help='По умолчанию 80,443; any — все. Локальные адреса блокирует Xray.')]
    else:
        fields += [f('host','Адрес в ссылке'),f('transport','Транспорт',default='direct',readonly=True,help='Direct с оригинальным шифрованием и согласованием сессии.'),f('port','Первый TCP-порт пользователей','number',min=1024,max=65000,readonly=True),f('codec','Кодек','select',options=['batched','legacy']),f('negotiate','Согласование сессии','switch',readonly=True,help=fixed)]
    return [{'title':'Основное','fields':fields}]


def validate(data, old=None):
    engine=data.get('engine')
    if engine not in TYPES:raise ValueError('Неизвестный движок')
    result=dict(engine=engine,remark=TYPES[engine],enabled=True,resolvers='1.1.1.1,8.8.8.8',mtu=1232,record_type='txt',clientid_size=2,dnstt_compat=False,encryption='5',server_options='{}',max_connections=256,idle_timeout=60,allow_ports='80,443',codec='batched',transport='direct',negotiate=True,port=56600,host='')
    if old:result.update(old)
    editable={f['key'] for s in sections(result) for f in s['fields'] if not f.get('readonly')}
    if not old:editable|={'zone','ns','host','port'}
    for key in editable:
        if key in data:result[key]=data[key]
    if not isinstance(result['enabled'],bool):raise ValueError('Некорректный статус')
    if not isinstance(result['remark'],str) or len(result['remark'])>128:raise ValueError('Слишком длинное примечание')
    if engine!='openflux':
        for key in ('zone','ns'):
            value=str(result.get(key,'')).lower().strip().rstrip('.')
            if len(value)>220 or '.' not in value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in value.split('.')):raise ValueError('Нужны корректные DNS-зона и NS-имя')
            result[key]=value
        if engine=='soar' and len(result['zone'])+19>45:raise ValueError('Для Soar нужна более короткая зона (не более 26 символов)')
        if engine=='slipstream' and len(result['zone'])>18:raise ValueError('Для Slipstream нужна короткая DNS-зона (не более 18 символов): длинные имена не проходят QUIC handshake оригинального движка')
        for address in str(result['resolvers']).split(','):
            if address.strip():ipaddress.ip_address(address.strip())
        if engine=='vaydns':
            if result['record_type'] not in ['txt','null','cname','a','aaaa','mx','ns','srv','caa']:raise ValueError('Некорректный DNS record type')
            if not isinstance(result['dnstt_compat'],bool):raise ValueError('Некорректный compatibility mode')
        if engine in ('dnstt','vaydns','slipstream'):
            for key,lo,hi in [('mtu',512,4096),('clientid_size',2,16),('max_connections',1,4096),('idle_timeout',10,3600)]:
                if not isinstance(result[key],int) or not lo<=result[key]<=hi:raise ValueError('Некорректный '+key)
        if engine in ('masterdns','cottendns'):
            if str(result['encryption']) not in list('012345'):raise ValueError('Некорректное шифрование')
            result['encryption']=str(result['encryption'])
            options=json.loads(result['server_options'])
            if not isinstance(options,dict):raise ValueError('Параметры сервера должны быть JSON-объектом')
            blocked=('DOMAIN','FORWARD','SOCKS','HOST','PORT','KEY','PROTOCOL','LISTEN','FALLBACK','TLS','DOH','DOT','TUNNEL','COTTENMAX')
            if len(options)>80 or any(not re.fullmatch('[A-Z][A-Z0-9_]*',k) or any(x in k for x in blocked) or not isinstance(v,(int,float,bool)) for k,v in options.items()):raise ValueError('Можно изменять только числовые параметры производительности; адреса, ключи и маршруты закреплены')
        if engine=='soar' and result['allow_ports']!='any':
            if not all(p.isdigit() and 1<=int(p)<=65535 for p in str(result['allow_ports']).split(',')):raise ValueError('Некорректный список портов')
    else:
        if not result['host'] or len(result['host'])>253 or any(ch in result['host'] for ch in '/\r\n\t '):raise ValueError('Некорректный адрес в ссылке')
        if not isinstance(result['port'],int) or not 1024<=result['port']<=65000:raise ValueError('Некорректный порт OpenFlux')
    if result['codec'] not in ('batched','legacy'):raise ValueError('Некорректный кодек')
    return result


def create(data):
    cfg=validate(data)
    if not (R['BIN']/cfg['engine']).is_file():raise ValueError('Ядро не найдено. Повторите установку панели.')
    if cfg['engine']!='openflux' and R['run']('systemctl','is-active','wdtt-dns.service',check=False)!='active':
        sockets=[]
        try:
            for kind in (socket.SOCK_DGRAM,socket.SOCK_STREAM):
                sock=socket.socket(socket.AF_INET,kind);sockets.append(sock);sock.bind(('0.0.0.0',53))
                if socket.has_ipv6:
                    sock=socket.socket(socket.AF_INET6,kind);sockets.append(sock);sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);sock.bind(('::',53))
        except OSError:raise ValueError('Порт 53 занят другим DNS-сервером. Его служба не изменена; освободите TCP/UDP 53 перед созданием инбаунда') from None
        finally:
            for sock in sockets:sock.close()
    name='edge-'+cfg['engine']+'-'+secrets.token_hex(4)
    cfg['user_zone']=name.rsplit('-',1)[1]
    with R['locked']():
        values=catalog(R['ROOT']);values[name]={'name':cfg['remark'],'engine':cfg['engine'],'port':53 if cfg['engine']!='openflux' else cfg['port'],'pool':0,'index':len(values)+100,'ifaces':[]}
        R['atomic'](R['ROOT']/name/'settings.json',cfg)
        R['atomic'](R['ROOT']/'catalog.json',values)
        s=R['state']();s['profiles'][name]=True;s.setdefault('disabled',{})[name]=False;R['save'](s)
    return {'id':name}


def update(name,data):
    previous=config(name);cfg=validate(dict(data,engine=previous['engine']),previous)
    snapshot={file:file.read_text() for file in (R['ROOT']/name).rglob('*') if file.is_file() and file.name in ('settings.json','runtime.json','server.toml','encrypt_key.txt','soar.json')}
    try:
        with R['locked']():R['atomic'](R['ROOT']/name/'settings.json',cfg)
        for password,row in members(name).items():prepare(name,password,row,cfg);R['run']('systemctl','try-restart',service(name,password))
        toggle(name,cfg['enabled'])
    except Exception:
        for file,value in snapshot.items():R['atomic'](file,value)
        for password in members(name):R['run']('systemctl','try-restart',service(name,password),check=False)
        raise
    return {}


def service(name,password):return 'wdtt-edge@'+name+'-'+R['user_id'](name,password)+'.service'


def toggle(name,enabled,present=True):
    with R['locked']():
        s=R['state']();s['profiles'][name]=present;s.setdefault('disabled',{})[name]=not enabled;R['save'](s)
    for password,row in members(name).items():
        R['run']('systemctl','enable' if enabled and row['enabled'] and present else 'disable','--now',service(name,password))


def allocate(s):
    port=s.setdefault('next_port',22000)
    while port<55000:
        sock=socket.socket();udp=socket.socket(type=socket.SOCK_DGRAM)
        try:sock.bind(('127.0.0.1',port));udp.bind(('127.0.0.1',port));return port
        except OSError:port+=1
        finally:sock.close();udp.close();s['next_port']=port+1
    raise ValueError('Исчерпаны внутренние порты')


def create_user(name,data):
    cfg=config(name);password=secrets.token_hex(16)
    with R['locked']():
        s=R['state']();rows=members(name)
        if cfg['engine']=='slipstream':
            used={zone_name(n,p,config(n)) for n in catalog(R['ROOT']) if config(n)['engine']=='slipstream' for p in members(n)}
            while zone_name(name,password,cfg) in used:password=secrets.token_hex(16)
        row=dict(password=password,name=data.get('name','Пользователь'),enabled=True,total_bytes=0,expires_at=0,max_mbps=0,up_bytes=0,down_bytes=0,socks_port=allocate(s))
        if cfg['engine']=='openflux':
            index=s.setdefault('next_edge_net',1)
            if index>=16384:raise ValueError('Исчерпаны подсети OpenFlux')
            s['next_edge_net']=index+1;row['net_index']=index
            used={r['public_port'] for n in catalog(R['ROOT']) for r in members(n).values() if 'public_port' in r}
            port=cfg['port']
            while port<65535:
                sock=socket.socket()
                try:
                    if port not in used:sock.bind(('0.0.0.0',port));break
                except OSError:pass
                finally:sock.close()
                port+=1
            if port>=65535:raise ValueError('Исчерпаны TCP-порты OpenFlux')
            row['public_port']=port
        else:row['dns_port']=allocate(s)
        rows[password]=row;store_members(name,rows);R['save'](s)
    try:
        prepare(name,password,row,cfg)
        R['run']('systemctl','enable','--now',service(name,password))
    except Exception:
        with R['locked']():rows=members(name);rows.pop(password,None);store_members(name,rows)
        raise
    return row


def mutate_user(name,data,delete=False):
    password=data['password']
    with R['locked']():
        rows=members(name)
        if password not in rows:raise ValueError('Пользователь не найден')
        row=rows[password]
        for key in ('name','total_bytes','max_mbps'):
            if key in data:row[key]=data[key]
        if 'days' in data:row['expires_at']=int(time.time())+int(data['days'])*86400 if data['days'] else 0
        if delete:row['enabled']=False
        store_members(name,rows)
    if delete:enabled_user(name,password,False)
    return row


def enabled_user(name,password,enabled):
    with R['locked']():
        rows=members(name);rows[password]['enabled']=enabled;store_members(name,rows)
    R['run']('systemctl','enable' if enabled else 'disable','--now',service(name,password))


def member_dir(name,password):return R['ROOT']/name/'members'/R['user_id'](name,password)


def zone_name(name,password,cfg):
    if cfg['engine']=='slipstream':
        token=base64.b32encode(hashlib.sha256((name+'\0'+password).encode()).digest()).decode().lower()[:8]
        return token+'.'+cfg['zone']
    return 'u'+R['user_id'](name,password)[:8]+'.'+cfg['user_zone']+'.'+cfg.get('zone','')


def prepare(name,password,row,cfg):
    d=member_dir(name,password);d.mkdir(parents=True,exist_ok=True,mode=0o700)
    engine=cfg['engine'];binary=R['BIN']/engine
    ident=R['user_id'](name,password)
    zone=zone_name(name,password,cfg)
    upstream='127.0.0.1:'+str(row['socks_port'])
    if engine in ('dnstt','vaydns') and not (d/'server.key').exists():R['run'](binary,'-gen-key','-privkey-file',d/'server.key','-pubkey-file',d/'server.pub')
    if engine=='dnstt':args=[binary,'-udp',f'127.0.0.1:{row["dns_port"]}','-privkey-file',d/'server.key','-mtu',str(cfg['mtu']),zone,upstream]
    elif engine=='vaydns':
        args=[binary,'-udp',f'127.0.0.1:{row["dns_port"]}','-privkey-file',d/'server.key','-domain',zone,'-upstream',upstream,'-mtu',str(cfg['mtu']),'-record-type',cfg['record_type'],'-clientid-size',str(cfg['clientid_size'])]
        if cfg['dnstt_compat']:args+=['-dnstt-compat']
    elif engine=='slipstream':
        if not (d/'server.crt').exists():
            R['run']('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','3650','-subj','/CN=slipstream','-keyout',d/'server.key','-out',d/'server.crt')
        args=[binary,'--dns-listen-host','127.0.0.1','--dns-listen-port',str(row['dns_port']),'--domain',zone,'--target-address',upstream,'--cert',d/'server.crt','--key',d/'server.key','--reset-seed',d/'reset-seed','--max-connections',str(cfg['max_connections']),'--idle-timeout-seconds',str(cfg['idle_timeout'])]
    elif engine in ('masterdns','cottendns'):
        length={'3':16,'4':24}.get(cfg['encryption'],32)
        key=d/'encrypt_key.txt'
        if not key.exists() or len(key.read_text().strip())!=length:R['atomic'](key,secrets.token_hex(16)[:length])
        options=json.loads(cfg['server_options'])
        options.update(PROTOCOL_TYPE='SOCKS5',UDP_HOST='127.0.0.1',UDP_PORT=row['dns_port'],DOMAIN=[zone],USE_EXTERNAL_SOCKS5=True,SOCKS5_AUTH=True,SOCKS5_USER=ident,SOCKS5_PASS=password,FORWARD_IP='127.0.0.1',FORWARD_PORT=row['socks_port'],DATA_ENCRYPTION_METHOD=int(cfg['encryption']),ENCRYPTION_KEY_FILE=str(key),LOG_LEVEL='ERROR')
        if engine=='cottendns':options.update(TCP_LISTENER_ENABLED=False,UDP_IPV6_ENABLED=False,TCP_IPV6_ENABLED=False,DOT_LISTENER_ENABLED=False,DOH_LISTENER_ENABLED=False,ACME_ENABLED=False)
        R['atomic'](d/'server.toml','\n'.join(k+' = '+json.dumps(v) for k,v in options.items())+'\n')
        args=[binary,'-config',d/'server.toml']+(['-nowait'] if engine=='masterdns' else [])
    elif engine=='soar':
        if not (d/'server.key').exists():
            # Use the upstream CLI for key generation, built beside the SDK adapter.
            output=R['run'](str(binary)+'-native','keygen')
            keys={line.split()[0]:line.split()[1] for line in output.splitlines() if len(line.split())==2}
            R['atomic'](d/'server.key',keys['private']);R['atomic'](d/'server.pub',keys['public'])
        R['atomic'](d/'soar.json',dict(zone=zone,listen=f'127.0.0.1:{row["dns_port"]}',key_file=str(d/'server.key'),socks=upstream,user=ident,password=password,allow_ports=cfg['allow_ports'].split(',')))
        args=[binary,'-config',d/'soar.json']
    else:
        if not (d/'secret').exists():R['atomic'](d/'secret',secrets.token_hex(32))
        args=[binary,'--role=exit','--mode=l4','--negotiate','--transport=direct','--direct-listen=0.0.0.0:'+str(row['public_port']),'--encryption-key-file='+str(d/'secret'),'--codec='+cfg['codec']]
    R['atomic'](d/'runtime.json',dict(args=list(map(str,args)),engine=engine,zone=zone,name=name,password=password,row=row,cwd=str(d)))


def display_users(name):
    cfg=config(name);result=[]
    for password,row in members(name).items():
        d=member_dir(name,password);runtime=json.loads((d/'runtime.json').read_text());engine=cfg['engine'];ident=R['user_id'](name,password)
        item=dict(row,ips=[],id=ident,tag='vpn-'+name+'-user-'+ident)
        if engine=='openflux':
            value=dict(name=row['name'],negotiate=True,codec=cfg['codec'],secret=(d/'secret').read_text().strip(),context='http://#',transports=[dict(type='direct',dial=cfg['host']+':'+str(row['public_port']))])
            item['link']=json.loads(R['run'](R['BIN']/engine,'--make-link','-',input=json.dumps(value)))['link']
        else:
            transport=dict(type=engine,domain=runtime['zone'])
            if engine in ('dnstt','vaydns','soar'):transport['pubkey']=(d/'server.pub').read_text().strip()
            if engine=='vaydns':transport.update(record_type=cfg['record_type'],clientid_size=cfg['clientid_size'],dnstt_compat=cfg['dnstt_compat'])
            if engine=='slipstream':transport['cert']=base64.urlsafe_b64encode(ssl.PEM_cert_to_DER_cert((d/'server.crt').read_text())).decode().rstrip('=')
            if engine in ('masterdns','cottendns'):transport.update(mkey=(d/'encrypt_key.txt').read_text().strip(),encryption=int(cfg['encryption']))
            if engine=='cottendns':transport['options']={'MIN_UPLOAD_MTU':32,'MIN_DOWNLOAD_MTU':128}
            value=dict(tag=row['name'],transport=transport,resolvers=[v.strip() for v in cfg['resolvers'].split(',') if v.strip()])
            if engine in ('dnstt','vaydns','slipstream'):value['backend']=dict(type='socks',user=ident,password=password)
            item['link']='dnst://'+base64.urlsafe_b64encode(json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()).decode().rstrip('=')
        result.append(item)
    return result


def profile_rows():
    s=R['state']();rows=[]
    for name,p in catalog(R['ROOT']).items():
        cfg=config(name);users=members(name);present=s['profiles'].get(name,False);enabled=not s.get('disabled',{}).get(name,False)
        fields=sections(cfg)
        rows.append(dict(p,id=name,tag='vpn-'+name,name=cfg['remark'],present=present,enabled=enabled,display_id=1+sum(not is_edge(n) for n in R['PROFILES'])+len(rows),ports=published_ports(name),subnet='—',subnets=['—' if cfg['engine']=='openflux' else cfg['zone']],users=sum(r['enabled'] for r in users.values()),traffic_bytes=sum(r['up_bytes']+r['down_bytes'] for r in users.values()),protocol_labels=[TYPES[cfg['engine']],'TCP' if cfg['engine']=='openflux' else 'DNS'],active=enabled and all(R['run']('systemctl','is-active',service(name,pwd),check=False)=='active' for pwd,r in users.items() if r['enabled']),settings_sections=fields,multiple=True,engine=cfg['engine']))
        if cfg['engine']!='openflux' and R['run']('systemctl','is-active','wdtt-dns.service',check=False)!='active':rows[-1]['active']=False
    for engine,title in TYPES.items():rows.append(dict(id=engine,name=title,present=False,multiple=True,template=True,installed=(R['BIN']/engine).is_file(),engine=engine))
    return rows


def published_ports(name):
    return [53] if config(name)['engine']!='openflux' else [r['public_port'] for r in members(name).values() if r['enabled']]


def routing(rows_by_profile):
    generated=[];ingress=[];routes=[];zones={}
    s=R['state']()
    for name,rows in rows_by_profile.items():
        if not is_edge(name):continue
        cfg=config(name)
        if cfg['engine']!='openflux':zones[cfg['zone']]=cfg['ns']
        for row in rows:
            if not row['enabled'] or s.get('disabled',{}).get(name):continue
            tag='vpn-'+name+'-user-'+R['user_id'](name,row['password']);row['tag']=tag
            if cfg['engine']=='openflux':
                generated.append(R['transparent_inbound'](tag,row['socks_port']))
                address=ipaddress.IPv4Address(int(ipaddress.IPv4Address('10.254.0.0'))+row['net_index']*4+2)
                ingress.append(('we'+str(row['net_index'])+'h',str(address),row['socks_port']))
            else:
                ident=R['user_id'](name,row['password'])
                generated.append(dict(tag=tag,listen='127.0.0.1',port=row['socks_port'],protocol='socks',settings=dict(auth='password',accounts=[dict(user=ident,**{'pass':row['password']})],udp=False),sniffing=dict(enabled=True,destOverride=['http','tls'],routeOnly=True)))
                runtime=json.loads((member_dir(name,row['password'])/'runtime.json').read_text())
                routes.append(dict(domain=runtime['zone'],target='127.0.0.1:'+str(row['dns_port'])))
    for name in catalog(R['ROOT']):
        if s['profiles'].get(name) and config(name)['engine']!='openflux':
            cfg=config(name);zones[cfg['zone']]=cfg['ns']
    R['atomic'](R['ROOT'].parent/'dns-router.json',dict(zones=[dict(domain=z,ns=ns) for z,ns in zones.items()],routes=routes))
    if zones and R['run']('systemctl','is-active','wdtt-dns.service',check=False)!='active':R['run']('systemctl','enable','--now','wdtt-dns.service')
    return generated,ingress


def counters():
    output=R['run']('/usr/local/wdtt-xray/bin/xray-linux-amd64','api','statsquery','--server=127.0.0.1:62889',check=False)
    if not output:return
    stats={r['name']:int(r.get('value',0)) for r in json.loads(output).get('stat',[])}
    pid=R['run']('systemctl','show','--property=MainPID','--value','wdtt-xray.service',check=False)
    with R['locked']():
        for name in catalog(R['ROOT']):
            values=members(name)
            for password,row in values.items():
                tag='inbound>>>vpn-'+name+'-user-'+R['user_id'](name,password)+'>>>traffic>>>'
                for key,direction in [('up_bytes','uplink'),('down_bytes','downlink')]:
                    count=stats.get(tag+direction)
                    if count is None:continue
                    previous=row.get('last_'+key,0) if row.get('stats_pid')==pid else 0
                    row[key]+=count-previous if count>=previous else count;row['last_'+key]=count
                row['stats_pid']=pid
            store_members(name,values)


def bypass_rules():
    result=[]
    for name in catalog(R['ROOT']):
        if config(name)['engine']!='openflux':continue
        for row in members(name).values():
            result.append(f'-A WDTT_PANEL -i we{row["net_index"]}h -p tcp --sport {row["public_port"]} -j RETURN')
    return result


def serve(instance):
    match=re.fullmatch(r'(edge-[a-z]+-[a-f0-9]{8})-([a-f0-9]{20})',instance)
    if not match:raise ValueError('Некорректный экземпляр')
    name,ident=match.groups();runtime=json.loads((R['ROOT']/name/'members'/ident/'runtime.json').read_text());row=runtime['row']
    if runtime['engine']=='openflux':
        i=row['net_index'];ns='wdtt-edge-'+str(i);host=f'we{i}h';peer=f'we{i}n';base=int(ipaddress.IPv4Address('10.254.0.0'))+i*4;host_ip=str(ipaddress.IPv4Address(base+1));ns_ip=str(ipaddress.IPv4Address(base+2))
        run=R['run']
        if not Path('/run/netns',ns).exists():run('ip','netns','add',ns)
        if not Path('/sys/class/net',host).exists():run('ip','link','add',host,'type','veth','peer','name',peer);run('ip','link','set',peer,'netns',ns)
        run('ip','addr','replace',host_ip+'/30','dev',host);run('ip','link','set',host,'up')
        prefix=['ip','netns','exec',ns]
        run(*prefix,'ip','addr','replace',ns_ip+'/30','dev',peer);run(*prefix,'ip','link','set',peer,'up');run(*prefix,'ip','link','set','lo','up');run(*prefix,'ip','route','replace','default','via',host_ip)
        R['atomic'](Path('/etc/netns')/ns/'resolv.conf','nameserver 1.1.1.1\n',0o644)
        R['ipt']('nat','POSTROUTING','-s',ns_ip+'/32','!','-o',host,'-j','MASQUERADE')
        R['ipt']('filter','FORWARD','-i',host,'-j','DROP')
        R['ipt']('filter','FORWARD','-i',host,'-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
        R['ipt']('filter','FORWARD','-o',host,'-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
        port=str(row['public_port'])
        R['ipt']('nat','PREROUTING','-m','addrtype','--dst-type','LOCAL','-p','tcp','--dport',port,'-j','DNAT','--to-destination',ns_ip+':'+port)
        R['ipt']('filter','FORWARD','-o',host,'-p','tcp','-d',ns_ip,'--dport',port,'-j','ACCEPT')
        # Bind the bypass to this namespace's transport listener, not its user traffic.
        args=prefix+runtime['args']
    else:args=runtime['args']
    os.chdir(runtime['cwd']);os.execvp(args[0],args)
