#!/usr/bin/env python3
"""Installer choices are JSON data; the panel never owns a public HTTP/TLS listener."""
import json
import os
from pathlib import Path
import runpy
import socket
import sqlite3
import subprocess
import sys

BASE=Path('/etc/wdtt')
SELECTION=Path(os.environ.get('WDTT_SELECTION_DIR') or BASE)
LEGACY=['wdtt','qwdtt','wdtt-plus','csqtt-2.1.9','csqtt-2.5.0','freeturn','csqtt-2.5.3-community']
EXTRA=['dnstt','vaydns','slipstream','masterdns','cottendns','soar','openflux']


def free_port(start=2860):
    for port in range(max(start,1024),65536):
        with socket.socket() as sock:
            try:sock.bind(('127.0.0.1',port));return port
            except OSError:continue
    raise ValueError('Нет свободного внутреннего TCP-порта')


def select_protocols(value):
    names=[v.strip().lower() for v in value.replace(' ', ',').split(',') if v.strip()]
    if names==['all']:return LEGACY+EXTRA
    result=[]
    for name in names:
        if name.isdigit() and 1<=int(name)<=len(LEGACY+EXTRA):name=(LEGACY+EXTRA)[int(name)-1]
        if name not in LEGACY+EXTRA:raise ValueError('Неизвестный протокол: '+name)
        if name not in result:result.append(name)
    return result


def ask(label,default=''):
    try:terminal=open('/dev/tty','r+')
    except OSError:raise ValueError('Нет терминала для вопроса «'+label+'»: задайте ответ переменной окружения') from None
    with terminal:
        terminal.write(label+(' ['+default+']' if default else '')+': ');terminal.flush()
        return terminal.readline().strip() or default


def choose():
    SELECTION.mkdir(mode=0o700,parents=True,exist_ok=True)
    settings=BASE/'installation.json'
    previous=json.loads(settings.read_text()) if settings.exists() else {}
    choice=os.environ.get('WDTT_PROTOCOLS')
    if choice is None:
        for i,name in enumerate(LEGACY+EXTRA,1):print(str(i)+') '+name,file=sys.stderr)
        choice=ask('Протоколы: номера или имена через запятую; all — все',','.join(previous.get('protocols',LEGACY)))
    selected=select_protocols(choice)
    zone=os.environ.get('WDTT_DNS_ZONE',previous.get('dns_zone',''))
    ns=os.environ.get('WDTT_DNS_NS',previous.get('dns_ns',''))
    if any(name in EXTRA[:-1] for name in selected):
        if not zone and 'WDTT_DNS_ZONE' not in os.environ:zone=ask('Делегированная DNS-зона (пусто — создать DNS-инбаунды позже)')
        if zone and not ns:ns=ask('NS-имя, A-запись которого указывает на VPS')
    result=dict(protocols=selected,dns_zone=zone,dns_ns=ns,fresh=not (BASE/'panel.db').exists())
    (SELECTION/'install-selection.json').write_text(json.dumps(result))


def cleanup_public_frontend():
    if (BASE/'frontend.json').exists():return
    # Migration removes only marked locations and this panel's vhost; shared proxies survive.
    uninstall=runpy.run_path(str(Path(__file__).with_name('uninstall.py')))
    seen=set();changed=False
    for folder in ('/etc/nginx/sites-enabled','/etc/nginx/conf.d'):
        for file in Path(folder).glob('*'):
            if not file.is_file():continue
            file=file.resolve()
            if file in seen:continue
            seen.add(file);text=file.read_text();updated=uninstall['remove_locations'](text)
            if updated!=text:file.write_text(updated);changed=True
    previous=BASE/'installation.json'
    previous=json.loads(previous.read_text()) if previous.exists() else {}
    mapping=Path('/etc/nginx/wdtt-panel-sni.map');host=previous.get('WDTT_PANEL_HOST')
    if mapping.exists() and host:
        import re
        updated=re.sub(r'(?m)^\s*'+re.escape(host)+r'\s+[^;]+;\s*$','',mapping.read_text())
        mapping.write_text(updated);changed=True
        if not updated.strip():
            stream=Path('/etc/nginx/stream-enabled/stream.conf')
            if stream.exists():stream.write_text(stream.read_text().replace('include /etc/nginx/wdtt-panel-sni.map;',''))
            mapping.unlink()
    for name in ('/etc/nginx/conf.d/wdtt-panel.conf','/etc/nginx/conf.d/wdtt-panel-acme.conf','/etc/letsencrypt/renewal-hooks/deploy/wdtt-panel','/etc/wdtt/nginx-managed','/etc/wdtt/public-scheme'):
        path=Path(name)
        if path.exists():path.unlink();changed=True
    if changed and Path('/usr/sbin/nginx').exists():
        subprocess.run(['nginx','-t'],check=True)
        subprocess.run(['systemctl','reload','nginx'],check=True)


def configure():
    selected=json.loads((BASE/'install-selection.json').read_text());runtime=runpy.run_path(str(Path(__file__).with_name('protocols.py')))
    created=[]
    for engine in selected['protocols']:
        if engine in LEGACY:
            if not runtime['state']()['profiles'].get(engine):runtime['profile_create'](engine,os.environ['WDTT_PUBLIC_IP']);created.append(engine)
        elif engine=='openflux' or selected['dns_zone']:
            found=any(p['engine']==engine for n,p in runtime['edge'].catalog(runtime['ROOT']).items() if runtime['state']()['profiles'].get(n))
            if not found:
                row=runtime['edge'].create(dict(engine=engine,zone=selected['dns_zone'],ns=selected['dns_ns'],host=os.environ['WDTT_PUBLIC_IP']))
                created.append(row['id'])
    for name in runtime['edge'].catalog(runtime['ROOT']):
        for password,row in runtime['edge'].members(name).items():
            runtime['edge'].prepare(name,password,row,runtime['edge'].config(name))
            runtime['run']('systemctl','try-restart',runtime['edge'].service(name,password))
    with sqlite3.connect(BASE/'panel.db') as db:
        sub_id=db.execute('SELECT u.sub_id FROM wdtt_users u JOIN wdtt_global g ON g.main_password=u.password WHERE g.id=1').fetchone()[0]
        old=db.execute('SELECT protocols FROM vpn_user_inbounds WHERE sub_id=?',(sub_id,)).fetchone()
        names=json.loads(old[0]) if old else []
        if selected['fresh']:names=[n for n,present in runtime['state']()['profiles'].items() if present]
        else:names+= [name for name in created if name not in names]
        db.execute('INSERT INTO vpn_user_inbounds(sub_id,protocols) VALUES(?,?) ON CONFLICT(sub_id) DO UPDATE SET protocols=excluded.protocols',(sub_id,json.dumps(names)))
        db.execute('UPDATE wdtt_inbound SET enable=? WHERE id=1',(int(runtime['state']()['profiles'].get('wdtt',False) and not runtime['state']().get('disabled',{}).get('wdtt')),))
        db.execute('UPDATE wdtt_global SET users_rev=users_rev+1 WHERE id=1')
    selected.update(backend_port=int(os.environ['WDTT_BACKEND_PORT']),public_ip=os.environ['WDTT_PUBLIC_IP'])
    selected.pop('fresh',None);runtime['atomic'](BASE/'installation.json',selected)


if __name__=='__main__':
    operation=sys.argv[1]
    if operation=='choose':
        try:choose()
        except ValueError as error:print(error,file=sys.stderr);sys.exit(1)
    elif operation=='port':print(free_port(int(sys.argv[2]) if len(sys.argv)>2 else 2860))
    elif operation=='migrate':cleanup_public_frontend()
    elif operation=='configure':configure()
    else:raise SystemExit('Unknown installer operation')
