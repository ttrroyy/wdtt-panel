#!/usr/bin/env python3
"""Remove this panel and its data without removing Nginx or another panel."""
import os
import json
import hashlib
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sqlite3


def remaining_role(role,target):
    if target not in ('panel','node'):raise ValueError('Укажите panel, node или all')
    if role==target:return ''
    if role=='combined':return 'node' if target=='panel' else 'panel'
    raise ValueError('Компонент '+target+' на этой VPS не установлен')


def checked(*args):
    result=run(*args)
    if result.returncode:raise RuntimeError(result.stderr.strip() or 'Не выполнено: '+' '.join(args))
    return result


def remove_component(target):
    root=Path('/etc/wdtt');role_file=root/'role'
    role=role_file.read_text().strip() if role_file.exists() else 'combined'
    next_role=remaining_role(role,target)
    if not next_role:return False
    unit=Path('/etc/systemd/system/wdtt.service');text=unit.read_text()
    if '/usr/local/bin/wdtt-app' not in text:raise RuntimeError('wdtt.service не принадлежит этой установке')
    if target=='node':
        stop_node()
        with sqlite3.connect(root/'panel.db',timeout=15) as db:
            rows=db.execute('SELECT sub_id,protocols FROM vpn_user_inbounds').fetchall()
            backup=root/'removed-node-inbounds.json';backup.write_text(json.dumps(dict(rows)));os.chmod(backup,0o600)
            for sub,raw in rows:db.execute('UPDATE vpn_user_inbounds SET protocols=? WHERE sub_id=?',(json.dumps([name for name in json.loads(raw) if '--' in name]),sub))
            db.execute('UPDATE wdtt_inbound SET enable=0 WHERE id=1');db.execute('UPDATE wdtt_global SET users_rev=users_rev+1 WHERE id=1')
        state=root/'protocols/state.json'
        if state.exists():
            value=json.loads(state.read_text());value['profiles']={k:False for k in value.get('profiles',{})};state.write_text(json.dumps(value))
        for name in ('protocol-inbounds.json','protocol-subscriptions.json','protocols/route-options.json'):(root/name).unlink(missing_ok=True)
        inventory=root/'fleet/state.json'
        if inventory.exists():
            value=json.loads(inventory.read_text());value['nodes']=[n for n in value['nodes'] if n['id']!='local'];inventory.write_text(json.dumps(value))
        text=re.sub(r'(?m)^ExecStartPost=.*\n','',text)
    else:
        checked('systemctl','stop','wdtt');checked('systemctl','disable','--now','wdtt-fleet')
    text=re.sub(r'(/usr/local/bin/wdtt-app)(?: -(?:node|panel)-only)?',r'\1 -'+next_role+'-only',text)
    role_file.write_text(next_role+'\n');unit.write_text(text)
    checked('systemctl','daemon-reload');checked('systemctl','enable','--now','wdtt');checked('systemctl','restart','wdtt')
    if next_role=='panel':checked('systemctl','enable','--now','wdtt-fleet','wdtt-panel-firewall');checked('systemctl','restart','wdtt-panel-firewall')
    frontend=root/'frontend.json'
    if frontend.exists():
        (root/'frontend-selection.json').write_bytes(frontend.read_bytes())
        checked('python3','/usr/local/lib/wdtt/frontend.py','configure')
    print('Удалён компонент '+target+'. Сохранены '+next_role+', пользователи и настройки. Для полного удаления: wdtt-uninstall')
    return True


def run(*args):
    return subprocess.run(args, capture_output=True, text=True)


def remove_locations(text):
    text = re.sub(r'# wdtt-panel locations begin.*?# wdtt-panel locations end', '', text, flags=re.S)
    return re.sub(r'# wdtt-panel acme begin.*?# wdtt-panel acme end', '', text, flags=re.S)


def stop_node():
    units = ['wdtt', 'wdtt-xray', 'wdtt-protocol-watch', 'wdtt-panel-firewall','wdtt-dns','wdtt-fleet']
    units += ['wdtt-protocol@'+name for name in ('qwdtt','wdtt-plus','csqtt-2.1.9','csqtt-2.5.0','freeturn','csqtt-2.5.3-community')]
    edge_networks=set()
    registry=Path('/etc/wdtt/protocols/catalog.json')
    if registry.exists():
        for name in json.loads(registry.read_text()):
            if not re.fullmatch('edge-[a-z]+-[a-f0-9]{8}',name):continue
            file=Path('/etc/wdtt/protocols')/name/'members.json'
            for password,row in json.loads(file.read_text() if file.exists() else '{}').items():
                ident=hashlib.sha256((name+'\0'+password).encode()).hexdigest()[:20]
                units.append('wdtt-edge@'+name+'-'+ident)
                if isinstance(row.get('net_index'),int) and 1<=row['net_index']<16384:edge_networks.add(row['net_index'])
    for unit in units: run('systemctl', 'disable', '--now', unit)
    edge_ips=set()
    import ipaddress
    for index in edge_networks:
        edge_ips.add(str(ipaddress.IPv4Address(int(ipaddress.IPv4Address('10.254.0.0'))+index*4+2)))
        run('ip','link','del',f'we{index}h');run('ip','netns','del','wdtt-edge-'+str(index))
        shutil.rmtree('/etc/netns/wdtt-edge-'+str(index),ignore_errors=True)
    for index in range(1, 7):
        run('ip', 'link', 'del', f'wp{index}h'); run('ip', 'netns', 'del', f'wdtt-{index}')
        shutil.rmtree(f'/etc/netns/wdtt-{index}', ignore_errors=True)
    for iface in ('wdtt0', 'wdtt-raw'): run('ip', 'link', 'del', iface)
    for binary in ('iptables', 'ip6tables'):
        for table in ('filter', 'nat', 'mangle'):
            for line in run(binary, '-w', '3', '-t', table, '-S').stdout.splitlines():
                args = shlex.split(line)
                if not args or args[0] != '-A': continue
                owned = any(token.startswith('WDTT_PANEL') or token in ('wdtt0','wdtt-raw','WDTT_MANAGED','WDTT_RAW_DIRECT') or re.fullmatch(r'wp[1-6][hn]',token) or re.fullmatch(r'we[0-9]+[hn]',token) or token.split(':')[0].split('/')[0] in edge_ips for token in args)
                owned = owned or bool(re.search(r'10\.253\.[1-6]\.2(?:/32)?', line))
                owned = owned or ('0x77/0xff' in args)
                owned = owned or any(re.fullmatch(r'10\.(?:66|67|68|69|70|71|72|73|74)\.0\.0/(?:16|24)', token) for token in args)
                if owned:
                    args[0] = '-D'; run(binary, '-w', '3', '-t', table, *args)
            for chain in ('WDTT_PANEL', 'WDTT_PANEL_INPUT'):
                run(binary, '-w', '3', '-t', table, '-F', chain)
                run(binary, '-w', '3', '-t', table, '-X', chain)
    run('nft','delete','table','ip','wdtt')
    run('ip', 'rule', 'del', 'priority', '10990', 'fwmark', '0x77/0xff', 'lookup', '10990')
    run('ip', 'route', 'flush', 'table', '10990')

def main(target="all"):
    if os.geteuid() != 0: raise SystemExit('Запустите от root')
    if target != "all" and remove_component(target):return
    stop_node()
    seen = set()
    for folder in ('/etc/nginx/sites-enabled','/etc/nginx/conf.d'):
        for file in Path(folder).glob('*'):
            if not file.is_file(): continue
            file = file.resolve()
            if file in seen: continue
            seen.add(file)
            text = file.read_text(); updated = remove_locations(text)
            if text != updated: file.write_text(updated)
    settings = Path('/etc/wdtt/installation.json')
    host = json.loads(settings.read_text()).get('WDTT_PANEL_HOST','') if settings.exists() else ''
    mapping = Path('/etc/nginx/wdtt-panel-sni.map')
    if mapping.exists():
        updated = re.sub(r'(?m)^\s*'+re.escape(host)+r'\s+[^;]+;\s*$', '', mapping.read_text()) if host else ''
        mapping.write_text(updated)
    stream = Path('/etc/nginx/stream-enabled/stream.conf')
    if stream.exists() and (not mapping.exists() or not mapping.read_text().strip()):
        stream.write_text(stream.read_text().replace('include /etc/nginx/wdtt-panel-sni.map;', ''))
    for name in ('/etc/nginx/conf.d/wdtt-panel.conf','/etc/nginx/conf.d/wdtt-panel-acme.conf',
                 '/etc/sysctl.d/90-wdtt-panel.conf','/etc/letsencrypt/renewal-hooks/deploy/wdtt-panel',
                 '/usr/local/bin/wdtt-app','/usr/local/bin/wdtt-dns','/usr/local/bin/wdtt-panel-uninstall','/usr/local/bin/wdtt-node-uninstall','/usr/local/bin/wdtt-uninstall','/usr/local/bin/wdtt-node-key','/usr/local/bin/wdtt-mtu-rules.sh','/etc/caddy/wdtt-panel/panel.caddy'):
        Path(name).unlink(missing_ok=True)
    if mapping.exists() and not mapping.read_text().strip(): mapping.unlink()
    issued = Path('/etc/wdtt/owned-acme-cert')
    if issued.exists():
        cert_name = issued.read_text().strip()
        reference = '/etc/letsencrypt/live/'+cert_name+'/'
        used = any(reference in f.read_text(errors='replace') for f in Path('/etc/nginx').rglob('*') if f.is_file() and f.suffix in ('.conf','.map'))
        if not used: run('certbot','delete','--non-interactive','--cert-name',cert_name)
    for unit in ('wdtt','wdtt-xray','wdtt-protocol-watch','wdtt-panel-firewall','wdtt-protocol@','wdtt-edge@','wdtt-dns','wdtt-fleet'):
        Path('/etc/systemd/system/'+unit+'.service').unlink(missing_ok=True)
    for folder in ('/etc/wdtt','/etc/wdtt-xray','/usr/local/lib/wdtt','/usr/local/wdtt-xray','/opt/wdtt-panel','/var/lib/wdtt-panel'):
        shutil.rmtree(folder, ignore_errors=False) if Path(folder).exists() else None
    run('systemctl', 'daemon-reload')
    if Path('/usr/sbin/nginx').exists():
        if run('nginx','-t').returncode == 0: run('systemctl','reload','nginx')
        else: raise SystemExit('Панель удалена, но нужна проверка nginx -t')
    if Path('/usr/bin/caddy').exists() and Path('/etc/caddy/Caddyfile').exists():
        if run('caddy','validate','--config','/etc/caddy/Caddyfile','--adapter','caddyfile').returncode==0:run('systemctl','reload','caddy')
        else:raise SystemExit('Установка удалена, но нужна проверка Caddyfile')
    print('WDTT Panel, пользователи и её сертификаты удалены. Существующие сторонние сертификаты и панели сохранены.')


if __name__ == '__main__':
    import sys
    main(sys.argv[1] if len(sys.argv)>1 else "all")
