#!/usr/bin/env python3
"""Read-only installation checks. Foreign listeners, routes and proxy sites are never stopped."""
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import sys

BASE=Path('/etc/wdtt')
SELECTION=Path(os.environ.get('WDTT_SELECTION_DIR') or BASE)
PUBLIC={'wdtt':[56000,56001,56003],'qwdtt':[56100,56102,56103],'wdtt-plus':[56200],'csqtt-2.1.9':[56300],'csqtt-2.5.0':[56400],'freeturn':[56500],'csqtt-2.5.3-community':[56700]}
POOLS={'wdtt':[66,70],'qwdtt':[67,73],'wdtt-plus':[68],'csqtt-2.1.9':[69],'csqtt-2.5.0':[71],'freeturn':[72],'csqtt-2.5.3-community':[74]}
DNS={'dnstt','vaydns','slipstream','masterdns','cottendns','soar'}

def command(*args):
    result=subprocess.run(args,capture_output=True,text=True,timeout=30)
    if result.returncode:raise ValueError(args[0]+': '+(result.stderr or result.stdout)[-600:])
    return result.stdout

def listeners():
    result=[]
    for line in command('ss','-H','-lntup').splitlines():
        parts=line.split()
        if len(parts)<6:continue
        match=re.search(r':([0-9]+)$',parts[4])
        if not match:continue
        pid=re.search(r'pid=([0-9]+)',line);executable=''
        if pid:
            try:executable=str(Path('/proc/'+pid[1]+'/exe').resolve(strict=True))
            except OSError:pass
        managed=executable in ('/usr/local/bin/wdtt-app','/usr/local/bin/wdtt-dns','/usr/local/wdtt-xray/bin/xray-linux-amd64')
        result.append(dict(protocol=parts[0],port=int(match[1]),address=parts[4],managed=managed,process=Path(executable).name or 'неизвестный процесс'))
    return result

def conflicts(rows,ports,proxy):
    errors=[]
    for row in rows:
        port=row['port'];proto=row['protocol']
        if row['managed']:continue
        if proto=='tcp' and port in (80,443) and proxy!='local':
            if row['process']!=proxy:errors.append(f"TCP {port} занят {row['process']}; выбран {proxy}. Используйте текущий прокси или локальный режим")
        elif port in ports.get(proto,set()):errors.append(f"{proto.upper()} {port} занят {row['process']} ({row['address']})")
    return errors

def route_conflicts(routes,pools):
    errors=[]
    for route in routes:
        dest=route.get('dst','default');device=route.get('dev','')
        if dest=='default' or device=='lo' or re.fullmatch(r'(wdtt0|wdtt-raw|wp[0-9]+[hn]|we[0-9]+[hn])',device):continue
        try:network=ipaddress.ip_network(dest,strict=False)
        except ValueError:continue
        for pool in pools:
            if network.overlaps(ipaddress.ip_network(pool)):errors.append(f"Подсеть {pool} пересекается с маршрутом {dest} через {device or 'другой VPN'}")
    return sorted(set(errors))

def required_ports(selection):
    udp=set();tcp=set()
    for name in selection['protocols']:
        ports=list(PUBLIC.get(name,[]));settings=BASE/'protocols'/name/'settings.json'
        if settings.exists():
            cfg=json.loads(settings.read_text());base=PUBLIC.get(name,[0])[0]
            port=int(cfg.get('port',base));ports=[port]
            if name=='qwdtt':
                if cfg.get('direct_enabled',True):ports.append(int(cfg.get('direct_port',port+2)))
                if cfg.get('raw_enabled',True):ports.append(int(cfg.get('raw_port',port+3)))
        if name=='wdtt' and (BASE/'panel.db').exists():
            with sqlite3.connect('file:'+str(BASE/'panel.db')+'?mode=ro',uri=True) as db:
                row=db.execute('SELECT dtls_port,wg_port,raw_enable,raw_direct_port FROM wdtt_inbound WHERE id=1').fetchone()
            if row:ports=[row[0],row[1]]+([row[3] or row[0]+3] if row[2] else [])
        udp.update(ports)
    if DNS.intersection(selection['protocols']) and selection.get('dns_zone'):udp.add(53);tcp.add(53)
    return dict(tcp=tcp,udp=udp)

def addresses(name):
    try:return sorted({row[4][0] for row in socket.getaddrinfo(name,None,socket.AF_INET)})
    except OSError:return []

def dns_errors(selection,frontend,public_ip,role):
    """Certbot and the DNS tunnels need records that already point here; checked before anything is installed."""
    errors=[]
    names=[('Домен панели',frontend['domain'])] if frontend['mode']!='local' else []
    tunnels=DNS.intersection(selection['protocols']) if role!='panel' else set()
    zone=selection.get('dns_zone','')
    if tunnels and zone:
        if not selection.get('dns_ns'):errors.append('Для DNS-туннелей укажите NS-имя с A-записью на эту VPS')
        else:names.append(('NS-имя DNS-зоны',selection['dns_ns']))
        if 'slipstream' in tunnels and len(zone)>18:errors.append('Для Slipstream зона '+zone+' длиннее 18 символов')
        if 'soar' in tunnels and len(zone)>26:errors.append('Для Soar зона '+zone+' длиннее 26 символов')
        if selection.get('dns_ns','').endswith('.'+zone):errors.append('NS-имя должно быть вне зоны '+zone+', например ns.'+zone.split('.',1)[-1])
    for label,name in names:
        found=addresses(name)
        if not found:errors.append(label+' '+name+': нет A-записи')
        elif public_ip and public_ip not in found:errors.append(label+' '+name+' указывает на '+', '.join(found)+', а IP этой VPS '+public_ip)
    return errors

def main(role):
    errors=[]
    if os.geteuid()!=0:errors.append('Нужны права root')
    if platform.machine() not in ('x86_64','aarch64'):errors.append('Поддерживаются только amd64 и arm64')
    if sys.version_info<(3,9):errors.append('Нужен Python 3.9 или новее')
    if not Path('/run/systemd/system').exists():errors.append('Требуется работающий systemd')
    if not shutil.which('ss'):errors.append('Для проверки портов установите iproute2 (команда ss)')
    # The first node build downloads Rust and Go toolchains and their caches.
    need=5 if role!='panel' and not Path('/root/.rustup').exists() else 2
    if shutil.disk_usage('/').free<need*1024**3:errors.append(f'Нужно не менее {need} ГиБ свободного места')
    previous=(BASE/'role').read_text().strip() if (BASE/'role').exists() else ''
    # install.sh only ever widens the role: a panel or node added to the other becomes combined.
    if previous and previous!=role and role!='combined':errors.append('На VPS уже установлено: '+previous+'. Добавить можно только недостающий компонент')
    selection=json.loads((SELECTION/'install-selection.json').read_text());frontend=json.loads((SELECTION/'frontend-selection.json').read_text())
    errors+=dns_errors(selection,frontend,os.environ.get('WDTT_PUBLIC_IP',''),role)
    if role!='panel':
        if not Path('/dev/net/tun').exists():errors.append('Нет /dev/net/tun: включите TUN/TAP у провайдера')
        status=Path('/proc/self/status').read_text();match=re.search(r'^CapEff:\s*([0-9a-f]+)',status,re.M)
        caps=int(match[1],16) if match else 0
        if any(not caps&(1<<bit) for bit in (12,13,21)):errors.append('Нужны CAP_NET_ADMIN, CAP_NET_RAW и CAP_SYS_ADMIN для изолированных сетей ноды')
    if shutil.which('ss'):errors+=conflicts(listeners(),required_ports(selection) if role!='panel' else {},frontend['mode'])
    if role!='panel' and shutil.which('ip'):
        pools=[f'10.{pool}.0.0/'+('24' if name=='csqtt-2.5.3-community' else '16') for name in selection['protocols'] for pool in POOLS.get(name,[])]+(['10.254.0.0/16'] if 'openflux' in selection['protocols'] else [])
        errors+=route_conflicts(json.loads(command('ip','-j','-4','route','show','table','all')),pools)
    mode=frontend['mode']
    current=json.loads((BASE/'frontend.json').read_text()).get('mode','') if (BASE/'frontend.json').exists() else ''
    if current in ('nginx','caddy') and mode in ('nginx','caddy') and current!=mode:errors.append('Панель уже опубликована через '+current+'; выберите его или локальный режим')
    if mode=='nginx' and shutil.which('nginx'):command('nginx','-t')
    if mode=='caddy' and shutil.which('caddy') and Path('/etc/caddy/Caddyfile').exists():command('caddy','validate','--config','/etc/caddy/Caddyfile','--adapter','caddyfile')
    if mode!='local':
        domain=frontend['domain']
        if mode=='nginx' and shutil.which('nginx'):
            files=[Path(p) for p in re.findall(r'^# configuration file ([^\n]+):$',command('nginx','-T'),re.M)]
        else:files=[Path('/etc/caddy/Caddyfile')]+list(Path('/etc/caddy').rglob('*.caddy')) if mode=='caddy' else []
        for path in files:
            if not path.is_file() or path in (Path('/etc/nginx/conf.d/wdtt-panel.conf'),Path('/etc/caddy/wdtt-panel/panel.caddy')):continue
            text=path.read_text(errors='replace')
            pattern=r'\bserver_name\s+[^;]*\b'+re.escape(domain)+r'(?=[\s;])' if mode=='nginx' else r'(?m)^\s*(?:https?://)?'+re.escape(domain)+r'\s*\{'
            if re.search(pattern,text):errors.append('Домен '+domain+' уже настроен в '+str(path)+'; чужой виртуальный хост не изменён')
    if errors:raise ValueError('\n'.join(sorted(set(errors))))
    print('Совместимость проверена: порты, сетевые права, подсети, действующий прокси и свободное место. Чужие службы не изменены.')

if __name__=='__main__':
    try:main(sys.argv[1])
    except Exception as error:print('Установка остановлена до изменения служб:\n'+str(error),file=sys.stderr);sys.exit(1)
