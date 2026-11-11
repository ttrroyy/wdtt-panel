#!/usr/bin/env python3
"""Expose only SSH, Nginx and the six VPN transports on the WAN interface."""
import json
import runpy
from pathlib import Path
import subprocess


def command(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check).stdout


def rules(chain, interface,ports=None):
    ports=[56000,56001,56003,56100,56102,56103,56200,56300,56400,56500] if ports is None else ports
    result = [f'-A {chain} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
              f'-A {chain} -p tcp -m multiport --dports 22,80,443 -j ACCEPT',
              f'-A {chain} -p icmp -j ACCEPT', f'-A {chain} -j DROP']
    if ports:result.insert(2,f'-A {chain} -p udp -m multiport --dports {",".join(map(str,ports))} -j ACCEPT')
    return result


def main():
    runtime=runpy.run_path('/usr/local/lib/wdtt/protocols.py')
    current=runtime['state']()
    transport_ports={name:runtime['published_ports'](name) for name in runtime['PROFILES'] if current['profiles'].get(name)}
    runtime['atomic'](runtime['ROOT']/'public-ports.json',transport_ports)
    ports=sorted({port for row in transport_ports.values() for port in row})
    for binary, family, icmp in [('iptables', '-4', 'icmp'), ('ip6tables', '-6', 'ipv6-icmp')]:
        routes = json.loads(command('ip', family, '-j', 'route', 'show', 'default'))
        for interface in sorted({route['dev'] for route in routes if 'dev' in route}):
            # Pass arguments directly; interface names never become shell code.
            chain = 'WDTT_PANEL_INPUT'
            command(binary, '-w', '3', '-N', chain, check=False)
            content = ['*filter', ':'+chain+' - [0:0]', '-F '+chain]
            content += [rule.replace('-p icmp ', '-p '+icmp+' ') for rule in rules(chain, interface,ports)]
            content += ['COMMIT', '']
            subprocess.run([binary+'-restore', '--noflush'], input='\n'.join(content), text=True, check=True)
            # Remove our previous jump before putting the filter first.
            while subprocess.run([binary, '-w', '3', '-C', 'INPUT', '-i', interface, '-j', chain], capture_output=True).returncode == 0:
                command(binary, '-w', '3', '-D', 'INPUT', '-i', interface, '-j', chain)
            command(binary, '-w', '3', '-I', 'INPUT', '1', '-i', interface, '-j', chain)


if __name__ == '__main__':
    main()
