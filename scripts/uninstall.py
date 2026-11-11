#!/usr/bin/env python3
"""Remove this panel and its data without removing Nginx or another panel."""
import os
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess


def run(*args):
    return subprocess.run(args, capture_output=True, text=True)


def remove_locations(text):
    text = re.sub(r'# wdtt-panel locations begin.*?# wdtt-panel locations end', '', text, flags=re.S)
    return re.sub(r'# wdtt-panel acme begin.*?# wdtt-panel acme end', '', text, flags=re.S)


def main():
    if os.geteuid() != 0: raise SystemExit('Запустите от root')
    units = ['wdtt', 'wdtt-xray', 'wdtt-protocol-watch', 'wdtt-panel-firewall']
    units += ['wdtt-protocol@'+name for name in ('qwdtt','wdtt-plus','csqtt-2.1.9','csqtt-2.5.0','freeturn')]
    for unit in units: run('systemctl', 'disable', '--now', unit)
    for index in range(1, 6):
        run('ip', 'link', 'del', f'wp{index}h'); run('ip', 'netns', 'del', f'wdtt-{index}')
        shutil.rmtree(f'/etc/netns/wdtt-{index}', ignore_errors=True)
    for iface in ('wdtt0', 'wdtt-raw'): run('ip', 'link', 'del', iface)
    for binary in ('iptables', 'ip6tables'):
        for table in ('filter', 'nat', 'mangle'):
            for line in run(binary, '-w', '3', '-t', table, '-S').stdout.splitlines():
                args = shlex.split(line)
                if not args or args[0] != '-A': continue
                owned = any(token.startswith('WDTT_PANEL') or token in ('wdtt0','wdtt-raw','WDTT_MANAGED','WDTT_RAW_DIRECT') or re.fullmatch(r'wp[1-5][hn]',token) for token in args)
                owned = owned or bool(re.search(r'10\.253\.[1-5]\.2(?:/32)?', line))
                owned = owned or ('0x77/0xff' in args)
                owned = owned or any(re.fullmatch(r'10\.(?:66|67|68|69|70|71|72|73)\.0\.0/16', token) for token in args)
                if owned:
                    args[0] = '-D'; run(binary, '-w', '3', '-t', table, *args)
            for chain in ('WDTT_PANEL', 'WDTT_PANEL_INPUT'):
                run(binary, '-w', '3', '-t', table, '-F', chain)
                run(binary, '-w', '3', '-t', table, '-X', chain)
    run('nft','delete','table','ip','wdtt')
    run('ip', 'rule', 'del', 'priority', '10990', 'fwmark', '0x77/0xff', 'lookup', '10990')
    run('ip', 'route', 'flush', 'table', '10990')
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
                 '/usr/local/bin/wdtt-app','/usr/local/bin/wdtt-panel-uninstall','/usr/local/bin/wdtt-mtu-rules.sh'):
        Path(name).unlink(missing_ok=True)
    if mapping.exists() and not mapping.read_text().strip(): mapping.unlink()
    issued = Path('/etc/wdtt/owned-acme-cert')
    if issued.exists():
        cert_name = issued.read_text().strip()
        reference = '/etc/letsencrypt/live/'+cert_name+'/'
        used = any(reference in f.read_text(errors='replace') for f in Path('/etc/nginx').rglob('*') if f.is_file() and f.suffix in ('.conf','.map'))
        if not used: run('certbot','delete','--non-interactive','--cert-name',cert_name)
    for unit in ('wdtt','wdtt-xray','wdtt-protocol-watch','wdtt-panel-firewall','wdtt-protocol@'):
        Path('/etc/systemd/system/'+unit+'.service').unlink(missing_ok=True)
    for folder in ('/etc/wdtt','/etc/wdtt-xray','/usr/local/lib/wdtt','/usr/local/wdtt-xray','/opt/wdtt-panel'):
        shutil.rmtree(folder, ignore_errors=False) if Path(folder).exists() else None
    run('systemctl', 'daemon-reload')
    if run('nginx','-t').returncode == 0: run('systemctl','reload','nginx')
    else: raise SystemExit('Панель удалена, но нужна проверка nginx -t')
    print('WDTT Panel, пользователи и её сертификаты удалены. Существующие сторонние сертификаты и панели сохранены.')


if __name__ == '__main__':
    main()
