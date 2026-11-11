#!/usr/bin/env python3
"""Expose only SSH, Nginx and the six VPN transports on the WAN interface."""
import json
import shlex
import subprocess


def command(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check).stdout


def rules(chain, interface):
    result = [f'-A {chain} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
              f'-A {chain} -p tcp -m multiport --dports 22,80,443 -j ACCEPT',
              f'-A {chain} -p udp -m multiport --dports 56000,56001,56003,56100,56102,56103,56200,56300,56400,56500 -j ACCEPT',
              f'-A {chain} -p icmp -j ACCEPT', f'-A {chain} -j DROP']
    return result


def main():
    for binary, family, icmp in [('iptables', '-4', 'icmp'), ('ip6tables', '-6', 'ipv6-icmp')]:
        routes = json.loads(command('ip', family, '-j', 'route', 'show', 'default'))
        for interface in sorted({route['dev'] for route in routes if 'dev' in route}):
            # Pass arguments directly; interface names never become shell code.
            chain = 'WDTT_PANEL_INPUT'
            command(binary, '-w', '3', '-N', chain, check=False)
            content = ['*filter', ':'+chain+' - [0:0]', '-F '+chain]
            content += [rule.replace('-p icmp ', '-p '+icmp+' ') for rule in rules(chain, interface)]
            content += ['COMMIT', '']
            subprocess.run([binary+'-restore', '--noflush'], input='\n'.join(content), text=True, check=True)
            # Remove our previous jump before putting the filter first.
            while subprocess.run([binary, '-w', '3', '-C', 'INPUT', '-i', interface, '-j', chain], capture_output=True).returncode == 0:
                command(binary, '-w', '3', '-D', 'INPUT', '-i', interface, '-j', chain)
            command(binary, '-w', '3', '-I', 'INPUT', '1', '-i', interface, '-j', chain)


if __name__ == '__main__':
    main()
