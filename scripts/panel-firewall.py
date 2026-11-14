#!/usr/bin/env python3
"""Keep control APIs private; expose selected VPN transports and authoritative DNS."""
import json
import runpy
from pathlib import Path
import subprocess


def command(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check).stdout


def rules(chain, interface,ports=None,tcp_ports=None):
    ports=[56000,56001,56003,56100,56102,56103,56200,56300,56400,56500] if ports is None else ports
    tcp_ports=[22,80,443] if tcp_ports is None else tcp_ports
    result = [f'-A {chain} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT']
    for protocol,values in [('tcp',tcp_ports),('udp',ports)]:
        for start in range(0,len(values),15):result.append(f'-A {chain} -p {protocol} -m multiport --dports {",".join(map(str,values[start:start+15]))} -j ACCEPT')
    result += [f'-A {chain} -p icmp -j ACCEPT',f'-A {chain} -j DROP']
    return result


def ssh_ports(sshd_config=None, listeners=None):
    """The ports SSH really answers on: sshd's own configuration and its listening sockets, and 22 always,
    so a server on another SSH port is never shut out of it."""
    if sshd_config is None:
        sshd_config = subprocess.run(['sshd', '-T'], capture_output=True, text=True).stdout
    if listeners is None:
        listeners = subprocess.run(['ss', '-Hltnp'], capture_output=True, text=True).stdout
    ports = {22}
    for line in sshd_config.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0].lower() == 'port' and fields[1].isdigit(): ports.add(int(fields[1]))
        if len(fields) == 2 and fields[0].lower() == 'listenaddress' and fields[1].rsplit(':', 1)[-1].isdigit() and ':' in fields[1]:
            ports.add(int(fields[1].rsplit(':', 1)[-1]))
    for line in listeners.splitlines():
        if 'sshd' not in line: continue
        fields = line.split()
        if len(fields) >= 4 and fields[3].rsplit(':', 1)[-1].isdigit(): ports.add(int(fields[3].rsplit(':', 1)[-1]))
    return {port for port in ports if 0 < port < 65536}


def main():
    runtime=runpy.run_path('/usr/local/lib/wdtt/protocols.py')
    current=runtime['state']()
    transport_ports={};tcp_ports={}
    for name in runtime['PROFILES']:
        if not current['profiles'].get(name):continue
        target=tcp_ports if runtime['edge'].is_edge(name) and runtime['edge'].config(name)['engine']=='openflux' else transport_ports
        target[name]=runtime['published_ports'](name)
    runtime['atomic'](runtime['ROOT']/'public-ports.json',transport_ports)
    ports=sorted({port for row in transport_ports.values() for port in row})
    tcp=sorted({80,443}|ssh_ports()|{port for row in tcp_ports.values() for port in row}|({53} if 53 in ports else set()))
    runtime['atomic'](runtime['ROOT']/'public-tcp-ports.json',tcp_ports)
    for binary, family, icmp in [('iptables', '-4', 'icmp'), ('ip6tables', '-6', 'ipv6-icmp')]:
        routes = json.loads(command('ip', family, '-j', 'route', 'show', 'default'))
        for interface in sorted({route['dev'] for route in routes if 'dev' in route}):
            # Pass arguments directly; interface names never become shell code.
            chain = 'WDTT_PANEL_INPUT'
            command(binary, '-w', '3', '-N', chain, check=False)
            content = ['*filter', ':'+chain+' - [0:0]', '-F '+chain]
            content += [rule.replace('-p icmp ', '-p '+icmp+' ') for rule in rules(chain, interface,ports,tcp)]
            content += ['COMMIT', '']
            subprocess.run([binary+'-restore', '--noflush'], input='\n'.join(content), text=True, check=True)
            # Remove our previous jump before putting the filter first.
            while subprocess.run([binary, '-w', '3', '-C', 'INPUT', '-i', interface, '-j', chain], capture_output=True).returncode == 0:
                command(binary, '-w', '3', '-D', 'INPUT', '-i', interface, '-j', chain)
            command(binary, '-w', '3', '-I', 'INPUT', '1', '-i', interface, '-j', chain)


if __name__ == '__main__':
    main()
