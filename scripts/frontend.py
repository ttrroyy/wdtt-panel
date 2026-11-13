#!/usr/bin/env python3
"""Certbot owns certificate renewal; the selected proxy owns public HTTP(S)."""
import grp
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

BASE=Path('/etc/wdtt')
STATE=BASE/'frontend.json'
WEBROOT=Path('/var/lib/wdtt-panel/acme')
TLS=Path('/var/lib/wdtt-panel/tls')
NGINX=Path('/etc/nginx/conf.d/wdtt-panel.conf')
CADDY=Path('/etc/caddy/wdtt-panel/panel.caddy')
IMPORT='import /etc/caddy/wdtt-panel/*.caddy'
HOOK=Path('/etc/letsencrypt/renewal-hooks/deploy/wdtt-panel')

def run(*args):
    result=subprocess.run(args,capture_output=True,text=True)
    if result.returncode:raise RuntimeError(args[0]+': '+(result.stderr or result.stdout)[-2000:])
    return result.stdout
def read_state():return json.loads(STATE.read_text()) if STATE.exists() else {}
def ask(label,default=''):
    with open('/dev/tty','r+') as tty:
        tty.write(label+(' ['+default+']' if default else '')+': ');tty.flush();return tty.readline().strip() or default
def domain(value):
    value=value.strip().lower().rstrip('.')
    if len(value)>253 or '.' not in value or not all(re.fullmatch(r'(?!-)[a-z0-9-]{1,63}(?<!-)',v) for v in value.split('.')):raise ValueError('Укажите домен без схемы, порта и пути')
    return value

def choose():
    previous=read_state()
    mode=os.environ.get('WDTT_FRONTEND')
    if mode is None:
        mode=ask('Доступ: 1 — HTTPS через Nginx, 2 — HTTPS через Caddy, 3 — только локально',{'nginx':'1','caddy':'2','local':'3'}.get(previous.get('mode'),'1'))
    mode={'1':'nginx','2':'caddy','3':'local'}.get(mode,mode)
    if mode not in ('nginx','caddy','local'):raise ValueError('Выберите nginx, caddy или local')
    result=dict(mode=mode)
    if mode!='local':
        result['domain']=domain(os.environ.get('WDTT_DOMAIN') or ask('Домен, A/AAAA которого указывают на эту VPS',previous.get('domain','')))
        email=os.environ.get('WDTT_CERT_EMAIL')
        if email is None:email=ask('Email для Certbot (можно оставить пустым)',previous.get('email',''))
        if email and (len(email)>254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email)):raise ValueError('Некорректный email')
        result.update(email=email,cert_name='wdtt-panel-'+result['domain'])
    BASE.mkdir(mode=0o700,parents=True,exist_ok=True)
    (BASE/'frontend-selection.json').write_text(json.dumps(result))

def nginx_config(s,secure):
    host=s['domain'];http=f'''server {{
 listen 80;
 listen [::]:80;
 server_name {host};
 location ^~ /.well-known/acme-challenge/ {{ root {WEBROOT}; default_type text/plain; }}
 location / {{ return 301 https://{host}$request_uri; }}
}}
'''
    if not secure:return http
    return http+f'''server {{
 listen 443 ssl;
 listen [::]:443 ssl;
 server_name {host};
 ssl_certificate {TLS}/fullchain.pem;
 ssl_certificate_key {TLS}/privkey.pem;
 ssl_protocols TLSv1.2 TLSv1.3;
 client_max_body_size 16m;
 location / {{
  proxy_pass http://{s['upstream']};
  proxy_http_version 1.1;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto https;
  proxy_read_timeout 120s;
 }}
}}
'''

def caddy_config(s,secure):
    host=s['domain'];http=f'''http://{host} {{
 handle /.well-known/acme-challenge/* {{
  root * {WEBROOT}
  file_server
 }}
 handle {{ redir https://{host}{{uri}} permanent }}
}}
'''
    if not secure:return http
    return http+f'''https://{host} {{
 tls {TLS}/fullchain.pem {TLS}/privkey.pem
 reverse_proxy {s['upstream']}
}}
'''

def proxy_reload(mode):
    if mode=='nginx':run('nginx','-t')
    else:run('caddy','validate','--config','/etc/caddy/Caddyfile','--adapter','caddyfile')
    run('systemctl','reload-or-restart',mode)

def write_proxy(s,secure):
    target=NGINX if s['mode']=='nginx' else CADDY
    target.parent.mkdir(parents=True,exist_ok=True)
    previous=target.read_bytes() if target.exists() else None
    target.write_text((nginx_config if s['mode']=='nginx' else caddy_config)(s,secure))
    try:proxy_reload(s['mode'])
    except Exception:
        if previous is None:target.unlink(missing_ok=True)
        else:target.write_bytes(previous)
        raise

def install_cert(s,lineage):
    expected=Path('/etc/letsencrypt/live')/s['cert_name']
    if Path(lineage)!=expected:raise ValueError('Сертификат не принадлежит этой установке')
    certificate=expected/'fullchain.pem';private=expected/'privkey.pem'
    checked=run('openssl','x509','-in',str(certificate),'-noout','-checkhost',s['domain'])
    if 'does match certificate' not in checked:raise ValueError('Сертификат не соответствует домену')
    run('openssl','pkey','-in',str(private),'-noout')
    cert_pub=run('openssl','x509','-in',str(certificate),'-pubkey','-noout')
    key_pub=run('openssl','pkey','-in',str(private),'-pubout')
    if cert_pub!=key_pub:raise ValueError('Ключ не соответствует сертификату')
    TLS.mkdir(parents=True,exist_ok=True);os.chmod(TLS,0o750)
    group=grp.getgrnam('caddy').gr_gid if s['mode']=='caddy' else 0
    os.chown(TLS,0,group)
    for source,name in ((certificate,'fullchain.pem'),(private,'privkey.pem')):
        temporary=TLS/(name+'.new');shutil.copyfile(source,temporary);os.chown(temporary,0,group);os.chmod(temporary,0o640);os.replace(temporary,TLS/name)

def renew():
    s=read_state()
    if s.get('mode') not in ('nginx','caddy'):return
    expected='/etc/letsencrypt/live/'+s['cert_name']
    if os.environ.get('RENEWED_LINEAGE')!=expected:return
    install_cert(s,expected);proxy_reload(s['mode'])

def info():
    s=read_state();role=(BASE/'role').read_text().strip()
    if role=='node':
        print('Нода установлена без веб-панели. Для связи по API: wdtt-node-key; для SSH — вкладка «Ноды» основной панели.')
        if s.get('mode') in ('nginx','caddy'):print('HTTPS-адрес ноды: https://'+s['domain'])
        return
    import sqlite3
    with sqlite3.connect(BASE/'panel.db') as db:port,path,sub=db.execute('SELECT port,web_base_path,sub_path FROM panel_config WHERE id=1').fetchone()
    if s.get('mode') in ('nginx','caddy'):print('Панель: https://'+s['domain']+path+'\nПодписки: HTTPS на 443, отдельный случайный путь.')
    else:print('Панель: http://127.0.0.1:'+str(port)+path+'\nSSH-туннель: ssh -L '+str(port)+':127.0.0.1:'+str(port)+' root@<IP-VPS>\nЛокальный режим: конфиги копируются вручную; подписка доступна через SSH.')
    print('Логин и пароль: /etc/wdtt/install-credentials. Пути сохраняются при переустановке.')

def configure():
    s=json.loads((BASE/'frontend-selection.json').read_text());old=read_state()
    if s['mode']=='local':
        for p in (NGINX,CADDY):
            if p.exists():p.unlink()
        if old.get('mode') in ('nginx','caddy'):
            # Keep HTTP-01 reachable for retained certificates, without publishing the panel.
            acme=nginx_config(old,False).replace('return 301 https://'+old['domain']+'$request_uri','return 404') if old['mode']=='nginx' else caddy_config(old,False).replace('redir https://'+old['domain']+'{uri} permanent','respond 404')
            (NGINX if old['mode']=='nginx' else CADDY).write_text(acme)
            proxy_reload(old['mode'])
        STATE.write_text(json.dumps(s));(BASE/'public-scheme').write_text('http');HOOK.unlink(missing_ok=True);return
    # A different TLS server on 443 must be resolved before installing another proxy.
    listeners=run('ss','-H','-lntp','sport = :443')
    if listeners and any('"'+s['mode']+'"' not in line for line in listeners.splitlines()):raise ValueError('Порт 443 занят другим сервером. Выберите уже используемый Nginx/Caddy либо локальный режим; сторонние службы не изменены')
    run('apt-get','install','-y','-qq','certbot',s['mode'])
    run('systemctl','enable',s['mode'])
    if s['mode']=='caddy':
        conf=Path('/etc/caddy/Caddyfile');text=conf.read_text() if conf.exists() else ''
        if IMPORT not in text:conf.write_text(text.rstrip()+'\n'+IMPORT+'\n')
    if old.get('mode') in ('nginx','caddy') and old['mode']!=s['mode']:raise ValueError('Для смены прокси сначала освободите 443 или выберите текущий прокси')
    WEBROOT.mkdir(mode=0o755,parents=True,exist_ok=True)
    os.chmod(WEBROOT.parent,0o755);os.chmod(WEBROOT,0o755)
    node=(BASE/'role').exists() and (BASE/'role').read_text().strip()=='node'
    if node:s['upstream']=json.loads((BASE/'node-agent.json').read_text())['address']
    else:
        import sqlite3
        with sqlite3.connect(BASE/'panel.db') as db:port=db.execute('SELECT port FROM panel_config WHERE id=1').fetchone()[0]
        s['upstream']='127.0.0.1:'+str(port)
    if not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}',s['upstream']):raise ValueError('Некорректный внутренний адрес')
    cert=Path('/etc/letsencrypt/live')/s['cert_name']/'fullchain.pem'
    if cert.exists():install_cert(s,str(cert.parent))
    write_proxy(s,cert.exists())
    args=['certbot','certonly','--non-interactive','--agree-tos','--webroot','-w',str(WEBROOT),'--preferred-challenges','http','--cert-name',s['cert_name'],'-d',s['domain'],'--keep-until-expiring']
    args+=['--email',s['email']] if s['email'] else ['--register-unsafely-without-email']
    run(*args);install_cert(s,str(cert.parent));write_proxy(s,True)
    STATE.write_text(json.dumps(s))
    (BASE/'public-scheme').write_text('https')
    (BASE/'owned-acme-cert').write_text(s['cert_name'])
    HOOK.parent.mkdir(parents=True,exist_ok=True)
    HOOK.write_text('#!/bin/sh\nset -eu\nexec /usr/bin/python3 /usr/local/lib/wdtt/frontend.py renew\n');os.chmod(HOOK,0o755)
    run('systemctl','enable','--now','certbot.timer')

if __name__=='__main__':
    try:{'choose':choose,'configure':configure,'renew':renew,'info':info}[sys.argv[1]]()
    except Exception as error:print('HTTPS: '+str(error),file=sys.stderr);sys.exit(1)
