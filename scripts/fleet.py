#!/usr/bin/env python3
"""Private SSH control plane; node traffic uses authenticated Xray channels."""
import base64
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request
import urllib.parse

BASE=Path('/etc/wdtt')
ROOT=BASE/'fleet'
CONTROLLER=Path('/usr/local/lib/wdtt')
ID=re.compile(r'^[a-z][a-z0-9-]{0,31}$')

def read(path,default=None):
    return json.loads(path.read_text()) if path.exists() else default

def atomic(path,value):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    temporary=path.with_name('.'+path.name+'.'+secrets.token_hex(8))
    try:
        with open(temporary,'x',encoding='utf-8') as stream:
            os.chmod(temporary,0o600);json.dump(value,stream,ensure_ascii=False);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:temporary.unlink(missing_ok=True)

@contextlib.contextmanager
def locked():
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with open(ROOT/'lock','a') as stream:
        fcntl.flock(stream,fcntl.LOCK_EX);yield

def state():return read(ROOT/'state.json',{'nodes':[]})
def command(args,**kwargs):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=60,**kwargs).stdout
def role():return (BASE/'role').read_text().strip() if (BASE/'role').exists() else 'combined'

def ensure_local():
    if role()=='panel':return
    with locked():
        s=state()
        if any(n['id']=='local' for n in s['nodes']):return
        installation=read(BASE/'installation.json',{})
        address=installation.get('public_ip') or os.environ.get('WDTT_PUBLIC_IP','')
        if not address:
            import runpy
            native=runpy.run_path(str(CONTROLLER/'protocols.py'))
            address=native['settings']('wdtt').get('host','')
        if not address:raise ValueError('Не задан внешний адрес локальной ноды')
        s['nodes'].insert(0,dict(id='local',name='Эта VPS',address=address,ssh_port=22,machine_id=Path('/etc/machine-id').read_text().strip(),fingerprint='',status='ready'))
        atomic(ROOT/'state.json',s)

def node_directory(node):
    if not ID.fullmatch(node['id']):raise ValueError('Некорректный ID ноды')
    return ROOT/node['id']

def ssh_args(node):
    directory=node_directory(node)
    return ['ssh','-T','-o','BatchMode=yes','-o','ConnectTimeout=12','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2','-o','StrictHostKeyChecking=yes','-o','IdentitiesOnly=yes','-o','UserKnownHostsFile='+str(directory/'known_hosts'),'-i',str(directory/'key'),'-p',str(node['ssh_port']),'root@'+node['address']]

def remote(node,payload,timeout=55):
    if node.get('api_url'):
        request=urllib.request.Request(node['api_url']+'/rpc',data=json.dumps(payload).encode(),headers={'Authorization':'Bearer '+node['api_key'],'Content-Type':'application/json'})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        with urllib.request.build_opener(NoRedirect()).open(request,timeout=timeout) as response:
            data=response.read(8*1024*1024+1)
        if len(data)>8*1024*1024:raise ValueError('Ответ ноды слишком велик')
        result=json.loads(data)
        if not result.get('success'):raise ValueError(result.get('msg','Ошибка ноды'))
        return result['obj']
    result=subprocess.run(ssh_args(node)+['python3 /usr/local/lib/wdtt/fleet.py rpc'],input=json.dumps(payload),capture_output=True,text=True,timeout=timeout)
    if result.returncode and not result.stdout.strip():raise ValueError('SSH ноды недоступен или агент не установлен')
    try:response=json.loads(result.stdout)
    except ValueError:raise ValueError('Некорректный ответ агента ноды') from None
    if not response.get('success'):raise ValueError(response.get('msg','Ошибка ноды'))
    return response['obj']

def local_api(payload):
    result=subprocess.run(['python3',str(CONTROLLER/'protocols.py')],input=json.dumps(payload),capture_output=True,text=True,timeout=55)
    response=json.loads(result.stdout)
    if not response.get('success'):raise ValueError(response.get('msg','Ошибка протокола'))
    return response['obj']

def snapshot():
    return dict(machine_id=Path('/etc/machine-id').read_text().strip(),role=role(),profiles=local_api({'op':'list'}),
                subscriptions=read(BASE/'protocol-subscriptions.json',{}),users=export_users(),
                native_links=agent('links',{}),dns=read(BASE/'dns-router.json',{}),updated_at=int(time.time()))

def export_users():
    with sqlite3.connect(BASE/'panel.db',timeout=10) as db:
        db.row_factory=sqlite3.Row
        rows=[dict(row) for row in db.execute('SELECT * FROM wdtt_users')]
        memberships={row[0]:json.loads(row[1]) for row in db.execute('SELECT sub_id,protocols FROM vpn_user_inbounds')}
        main=db.execute('SELECT main_password FROM wdtt_global WHERE id=1').fetchone()[0]
    return dict(rows=rows,memberships=memberships,main=main)

def sync_users(payload):
    incoming=payload['users'];node_id=payload['node_id'];prefix=node_id+'--'
    if not ID.fullmatch(node_id):raise ValueError('Некорректный ID ноды')
    if not isinstance(incoming,dict) or len(incoming.get('rows',[]))>100000:raise ValueError('Некорректный список пользователей')
    with sqlite3.connect(BASE/'panel.db',timeout=15) as db:
        db.row_factory=sqlite3.Row
        columns={r[1] for r in db.execute('PRAGMA table_info(wdtt_users)')}
        existing={r['sub_id']:dict(r) for r in db.execute('SELECT * FROM wdtt_users')}
        desired=[]
        for user in incoming['rows']:
            user={k:v for k,v in user.items() if k in columns};sub=user.get('sub_id')
            if not sub or not user.get('password'):raise ValueError('Нет идентификатора пользователя')
            desired.append(sub)
            # Central accounting owns the quota; node counters remain local and survive sync.
            previous=existing.get(sub,{})
            if previous.get('password') and previous['password']!=user['password']:
                db.execute('UPDATE wdtt_user_devices SET password=? WHERE password=?',(user['password'],previous['password']))
                db.execute('UPDATE wdtt_users SET password=? WHERE sub_id=?',(user['password'],sub))
            for field in ('up_bytes','down_bytes','last_seen_at'):user[field]=previous.get(field,0)
            user['total_bytes']=0
            names=list(user);values=[user[k] for k in names]
            updates=','.join('"'+k+'"=excluded."'+k+'"' for k in names if k!='password')
            db.execute('INSERT INTO wdtt_users('+','.join('"'+k+'"' for k in names)+') VALUES('+','.join('?' for _ in names)+') ON CONFLICT(password) DO UPDATE SET '+updates,values)
            selected=[p[len(prefix):] for p in incoming['memberships'].get(sub,[]) if p.startswith(prefix)]
            db.execute('INSERT INTO vpn_user_inbounds VALUES(?,?) ON CONFLICT(sub_id) DO UPDATE SET protocols=excluded.protocols',(sub,json.dumps(selected)))
        for sub in existing:
            if sub not in desired:
                db.execute('DELETE FROM wdtt_user_devices WHERE password IN (SELECT password FROM wdtt_users WHERE sub_id=?)',(sub,))
                db.execute('DELETE FROM wdtt_users WHERE sub_id=?',(sub,));db.execute('DELETE FROM vpn_user_inbounds WHERE sub_id=?',(sub,))
        db.execute('UPDATE wdtt_global SET main_password=?,users_rev=users_rev+1 WHERE id=1',(incoming['main'],))
        token=db.execute('SELECT session_key FROM panel_config WHERE id=1').fetchone()[0]
    request=urllib.request.Request('http://127.0.0.1:2861/admin/reload',data=b'{}',headers={'X-WDTT-Admin-Token':token,'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=15) as response:response.read()
    return {}

def rpc(payload):
    op=payload.get('op')
    if op=='state':return snapshot()
    if op=='protocols':
        request=payload['request']
        if request.get('op')=='create':request['host']=read(BASE/'installation.json',{}).get('public_ip','')
        result=local_api(request)
        if request.get('protocol')=='wdtt' and request.get('op') in ('create','enable','disable','delete'):
            cfg=agent('inbound',{});cfg['enable']=request['op'] in ('create','enable');agent('inbound-save',cfg)
        return result
    if op=='sync-users':return sync_users(payload)
    if op=='routing':return agent('routing',payload['config'])
    if op in ('inbound','inbound-save'):return agent(op,payload.get('request',{}))
    raise ValueError('Неизвестная операция агента')

def agent(op,payload):
    token=(BASE/'node-token').read_text().strip()
    address=read(BASE/'node-agent.json')['address']
    if not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}',address):raise ValueError('Некорректный адрес агента')
    request=urllib.request.Request('http://'+address+'/'+op,data=json.dumps(payload).encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=50) as response:result=json.load(response)
    if not result.get('success'):raise ValueError(result.get('msg','Ошибка агента'))
    return result.get('obj',{})

def safe_host(value):
    if not isinstance(value,str) or len(value)>253:raise ValueError('Некорректный адрес VPS')
    try:return str(ipaddress.ip_address(value))
    except ValueError:
        if not all(re.fullmatch(r'(?!-)[a-zA-Z0-9-]{1,63}(?<!-)',part) for part in value.split('.')):raise ValueError('Укажите IP или домен без порта и пути') from None
        return value.lower()

def add_node(payload):
    if payload.get('transport')=='api':return add_api_node(payload)
    address=safe_host(payload.get('address'));port=payload.get('ssh_port',22);name=str(payload.get('name','')).strip()
    if not name or len(name)>128 or isinstance(port,bool) or not isinstance(port,int) or not 1<=port<=65535:raise ValueError('Укажите имя и SSH-порт ноды')
    password=payload.get('password','')
    if not isinstance(password,str) or not password:raise ValueError('Для первого подключения нужен пароль root')
    with locked():
        s=state()
        if any(n['address']==address and n['ssh_port']==port for n in s['nodes']):raise ValueError('Эта VPS уже добавлена')
        node=dict(id='n-'+secrets.token_hex(8),name=name,address=address,ssh_port=port,status='connecting',fingerprint='',machine_id='')
        folder=node_directory(node);folder.mkdir(mode=0o700,parents=True)
        command(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(folder/'key')])
        hostkeys=command(['ssh-keyscan','-T','10','-t','ed25519','-p',str(port),address])
        if not hostkeys.strip():raise ValueError('SSH-сервер не вернул ключ')
        (folder/'known_hosts').write_text(hostkeys);os.chmod(folder/'known_hosts',0o600)
        fingerprint=command(['ssh-keygen','-lf',str(folder/'known_hosts')]).split()[1];node['fingerprint']=fingerprint
        # Password goes through an inherited pipe, never argv, logs, state or environment.
        readfd,writefd=os.pipe()
        try:
            os.write(writefd,password.encode()+b'\n');os.close(writefd);writefd=-1
            args=ssh_args(node);args[args.index('BatchMode=yes')]='BatchMode=no'
            bootstrap="python3 -c 'import json,os,pathlib; p=pathlib.Path(\"/root/.ssh\");p.mkdir(mode=448,exist_ok=True);f=p/\"authorized_keys\";k=json.loads(input())[\"key\"];s=f.read_text() if f.exists() else \"\";f.write_text(s+(k+\"\\n\" if k not in s else \"\"));os.chmod(f,384);print(pathlib.Path(\"/etc/machine-id\").read_text().strip())'"
            result=subprocess.run(['sshpass','-d',str(readfd)]+args+[bootstrap],input=json.dumps({'key':(folder/'key.pub').read_text().strip()}),pass_fds=(readfd,),capture_output=True,text=True,timeout=40)
            if result.returncode:raise ValueError('Не удалось подключиться по SSH: проверьте пароль root и порт')
            machine=result.stdout.strip()
        finally:
            os.close(readfd)
            if writefd!=-1:os.close(writefd)
        if not re.fullmatch('[a-f0-9]{32}',machine):raise ValueError('VPS не вернула корректный machine-id')
        if machine==Path('/etc/machine-id').read_text().strip() or any(n['machine_id']==machine for n in s['nodes']):raise ValueError('Нельзя привязать эту же VPS повторно')
        node['machine_id']=machine
        if payload.get('deploy'):
            # The web action has exactly one role: node. Shell text contains no user fields.
            bundle=CONTROLLER/'node-source.tar.gz'
            if not bundle.is_file():raise ValueError('Нет пакета исходников ноды: переустановите основную панель')
            with open(bundle,'rb') as source:
                transfer=subprocess.run(ssh_args(node)+['umask 077; cat > /root/.wdtt-node-source.tar.gz'],stdin=source,capture_output=True,timeout=60)
            if transfer.returncode:raise ValueError('Не удалось передать пакет установки')
            script="set -eu; if test -f /etc/wdtt/panel.db; then test \"$(cat /etc/wdtt/role 2>/dev/null)\" = node; fi; export WDTT_PROTOCOLS='' WDTT_FRONTEND=local; install -d -m 700 /opt/wdtt-panel/node-source; tar -xzf /root/.wdtt-node-source.tar.gz -C /opt/wdtt-panel/node-source; exec bash /opt/wdtt-panel/node-source/install.sh node"
            remote_script=folder/'deploy.sh';remote_script.write_text(script)
            result=subprocess.run(ssh_args(node)+['umask 077; cat > /root/.wdtt-node-deploy.sh; nohup sh /root/.wdtt-node-deploy.sh > /root/.wdtt-node-deploy.log 2>&1 < /dev/null &'],input=script,capture_output=True,text=True,timeout=30)
            if result.returncode:raise ValueError('Не удалось запустить установщик ноды')
            node['status']='installing'
        else:
            snap=remote(node,{'op':'state'})
            if snap['role']!='node':raise ValueError('Подключается только установка в режиме node')
            adopt_users(node,snap)
            node['status']='ready'
        s['nodes'].append(node);atomic(ROOT/'state.json',s)
    return public_node(node)

def add_api_node(payload):
    if payload.get('deploy'):raise ValueError('По API можно привязать уже установленную ноду; для установки нужен SSH')
    url=urllib.parse.urlsplit(str(payload.get('api_url','')))
    if url.scheme!='https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('','/'):raise ValueError('Укажите HTTPS-адрес ноды без пути, логина и параметров')
    name=str(payload.get('name','')).strip();token=payload.get('api_key','')
    if not name or len(name)>128 or not re.fullmatch(r'wdtt_api_[A-Za-z0-9_-]{43}',token):raise ValueError('Укажите имя и API-ключ ноды')
    node=dict(id='n-'+secrets.token_hex(8),name=name,address=safe_host(url.hostname),api_url='https://'+url.netloc,api_key=token,ssh_port=0,status='ready',fingerprint='',machine_id='')
    snap=remote(node,{'op':'state'})
    if snap.get('role')!='node':raise ValueError('Подключается только установка в режиме node')
    machine=snap.get('machine_id','')
    with locked():
        s=state()
        if machine==Path('/etc/machine-id').read_text().strip() or any(n['machine_id']==machine for n in s['nodes']):raise ValueError('Эта VPS уже привязана')
        if not re.fullmatch('[a-f0-9]{32}',machine):raise ValueError('Некорректный machine-id ноды')
        node['machine_id']=machine;node_directory(node).mkdir(mode=0o700,parents=True);adopt_users(node,snap);s['nodes'].append(node);atomic(ROOT/'state.json',s)
    return public_node(node)

def public_node(node):return {k:v for k,v in node.items() if k not in ('server_key','client_key','api_key')}


def adopt_users(node,snapshot):
    registry=read(ROOT/'inbounds.json',{})
    for p in snapshot.get('profiles',[]):
        if not p.get('template'):registry[node['id']+'--'+p['id']]=dict(node_id=node['id'],local_id=p['id'],name=node['name']+' · '+p['name'],present=bool(p.get('present')))
    incoming=snapshot['users'];memberships=incoming['memberships']
    with sqlite3.connect(BASE/'panel.db',timeout=15) as db:
        db.row_factory=sqlite3.Row;columns={r[1] for r in db.execute('PRAGMA table_info(wdtt_users)')}
        for user in incoming['rows']:
            selected=[node['id']+'--'+name for name in memberships.get(user['sub_id'],[]) if node['id']+'--'+name in registry]
            if not selected:continue
            existing=db.execute('SELECT password,sub_id FROM wdtt_users WHERE password=? OR sub_id=?',(user['password'],user['sub_id'])).fetchall()
            if existing and any(r['password']!=user['password'] or r['sub_id']!=user['sub_id'] for r in existing):raise ValueError('Конфликт идентификаторов пользователей ноды; данные не изменены')
            if not existing:
                row={k:v for k,v in user.items() if k in columns};row.update(up_bytes=0,down_bytes=0,last_seen_at=0,comment=(node['name']+' · '+(row.get('comment') or 'User'))[:128])
                names=list(row);db.execute('INSERT INTO wdtt_users('+','.join('"'+k+'"' for k in names)+') VALUES('+','.join('?' for _ in names)+')',[row[k] for k in names])
            old=db.execute('SELECT protocols FROM vpn_user_inbounds WHERE sub_id=?',(user['sub_id'],)).fetchone();values=json.loads(old[0]) if old else []
            values+=[name for name in selected if name not in values]
            db.execute('INSERT INTO vpn_user_inbounds VALUES(?,?) ON CONFLICT(sub_id) DO UPDATE SET protocols=excluded.protocols',(user['sub_id'],json.dumps(values)))
        main=db.execute('SELECT u.sub_id FROM wdtt_users u JOIN wdtt_global g ON u.password=g.main_password WHERE g.id=1').fetchone()
        if main:
            old=db.execute('SELECT protocols FROM vpn_user_inbounds WHERE sub_id=?',(main[0],)).fetchone();values=json.loads(old[0]) if old else []
            values+=[name for name,p in registry.items() if p['node_id']==node['id'] and p['present'] and name not in values]
            db.execute('INSERT INTO vpn_user_inbounds VALUES(?,?) ON CONFLICT(sub_id) DO UPDATE SET protocols=excluded.protocols',(main[0],json.dumps(values)))
        atomic(ROOT/'inbounds.json',registry)
        db.execute('UPDATE wdtt_global SET users_rev=users_rev+1 WHERE id=1')

def api(payload):
    ensure_local();op=payload.get('op','list')
    if op=='add':return add_node(payload)
    s=state()
    if op=='list':
        sources=[]
        users=export_users()
        for row in users['rows']:sources.append(dict(node_id='',tag='vpn-user-'+row['sub_id'],label=row['comment'] or 'Пользователь'))
        snapshots=read(ROOT/'snapshots.json',{})
        for n in s['nodes']:
            profiles=local_api({'op':'list'}) if n['id']=='local' else snapshots.get(n['id'],{}).get('profiles',[])
            for p in profiles:
                if p.get('present'):sources.append(dict(node_id=n['id'],tag='vpn-'+p['id'],label=n['name']+' · '+p['name']))
        return dict(nodes=[public_node(n) for n in s['nodes']],role=role(),sources=sources)
    node=next((n for n in s['nodes'] if n['id']==payload.get('node_id')),None)
    if not node:raise ValueError('Нода не найдена')
    if op in ('inbound','inbound-save'):return remote(node,dict(op=op,request=payload.get('request',{})))
    if op=='protocols':return local_api(payload['request']) if node['id']=='local' else remote(node,{'op':'protocols','request':payload['request']})
    if op=='delete':
        if node['id']=='local':raise ValueError('Локальная нода удаляется через CLI смены роли')
        with locked():
            s=state()
            s['nodes']=[n for n in s['nodes'] if n['id']!=node['id']];atomic(ROOT/'state.json',s)
        return {}
    raise ValueError('Неизвестная операция')

def watch():
    ensure_local()
    while True:
        try:reconcile()
        except Exception as error:print('fleet: '+str(error),file=sys.stderr,flush=True)
        time.sleep(5)

def node_routing(config,node_id):
    result={key:config[key] for key in ('outbounds','routing','dns','policy') if key in config}
    routing=dict(result.get('routing',{}));rules=[];prefix='vpn-node-'+node_id+'--'
    for original in routing.get('rules',[]):
        rule=dict(original)
        if 'inboundTag' in rule:
            tags=[]
            for tag in rule['inboundTag']:
                if tag.startswith(prefix):tags.append('vpn-'+tag[len(prefix):])
                elif tag.startswith('vpn-user-') or not tag.startswith('vpn-'):tags.append(tag)
            if not tags:continue
            rule['inboundTag']=tags
        rules.append(rule)
    routing['rules']=rules;result['routing']=routing
    return result

def sync_routing(node):
    with sqlite3.connect(BASE/'panel.db',timeout=10) as db:row=db.execute('SELECT raw_json FROM xray_config WHERE id=1').fetchone()
    if not row:return
    config=node_routing(json.loads(row[0]),node['id']);path=node_directory(node)/'routing.json'
    if read(path)!=config:remote(node,dict(op='routing',config=config));atomic(path,config)

def reconcile():
    s=state();users=export_users();snapshots=read(ROOT/'snapshots.json',{})
    for node in s['nodes']:
        if node.get('retry_after',0)>time.time():continue
        if node['id']=='local':continue
        try:
            if node['status']=='installing':
                snap=remote(node,{'op':'state'})
                if snap['role']!='node':raise ValueError('Установлена неверная роль')
                with locked():adopt_users(node,snap)
                node['status']='ready'
            if node['status']!='ready':continue
            control=dict(users,rows=[{k:v for k,v in u.items() if k not in ('up_bytes','down_bytes','last_seen_at')} for u in users['rows']])
            signature=hashlib.sha256(json.dumps(control,sort_keys=True).encode()).hexdigest()
            signature_path=node_directory(node)/'users.signature'
            if not signature_path.exists() or signature_path.read_text()!=signature:
                remote(node,dict(op='sync-users',users=users,node_id=node['id']));signature_path.write_text(signature)
            sync_routing(node)
            snapshots[node['id']]=remote(node,{'op':'state'});node.pop('error',None)
        except Exception as error:node['error']=str(error);node['retry_after']=int(time.time())+30
        with locked():
            current=state()
            for row in current['nodes']:
                if row['id']==node['id']:row['status']=node['status'];row['error']=node.get('error','');row['retry_after']=node.get('retry_after',0)
            atomic(ROOT/'state.json',current)
    atomic(ROOT/'snapshots.json',snapshots)
    registry={}
    for n in s['nodes']:
        if n['id']=='local':continue
        for p in snapshots.get(n['id'],{}).get('profiles',[]):
            if p.get('present'):registry[n['id']+'--'+p['id']]=dict(node_id=n['id'],local_id=p['id'],name=n['name']+' · '+p['name'],present=True)
    previous=read(ROOT/'inbounds.json',{})
    new=[name for name in registry if name not in previous]
    registry={**{name:dict(row,present=False) for name,row in previous.items()},**registry}
    atomic(ROOT/'inbounds.json',registry)
    if new:
        with sqlite3.connect(BASE/'panel.db',timeout=10) as db:
            row=db.execute('SELECT u.sub_id FROM wdtt_users u JOIN wdtt_global g ON g.main_password=u.password WHERE g.id=1').fetchone()
            if row:
                old=db.execute('SELECT protocols FROM vpn_user_inbounds WHERE sub_id=?',row).fetchone()
                selected=json.loads(old[0]) if old else []
                selected+= [name for name in new if name not in selected]
                db.execute('INSERT INTO vpn_user_inbounds VALUES(?,?) ON CONFLICT(sub_id) DO UPDATE SET protocols=excluded.protocols',(row[0],json.dumps(selected)))
                db.execute('UPDATE wdtt_global SET users_rev=users_rev+1 WHERE id=1')

if __name__=='__main__':
    try:
        mode=sys.argv[1] if len(sys.argv)>1 else 'api'
        if mode=='watch':watch()
        else:print(json.dumps(dict(success=True,obj=(rpc if mode=='rpc' else api)(json.load(sys.stdin))),ensure_ascii=False))
    except Exception as error:
        print(json.dumps(dict(success=False,msg=str(error)),ensure_ascii=False));sys.exit(1)
