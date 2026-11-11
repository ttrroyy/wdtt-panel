#!/usr/bin/env python3
"""Install a panel vhost, or add one SNI route to lucx-ui-pro's existing frontend."""
import argparse
import ipaddress
from pathlib import Path
import re
import socket
import subprocess
import sys


def run(*args):
    result=subprocess.run(args,text=True,capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    return result.stdout+result.stderr


def free_port(start):
    for port in range(start,start+100):
        with socket.socket() as sock:
            try: sock.bind(('127.0.0.1',port)); return port
            except OSError: pass
    raise ValueError('Не найден свободный локальный порт')


def valid_host(host):
    try: return str(ipaddress.ip_address(host))
    except ValueError: pass
    if len(host)>253 or not all(re.fullmatch(r'(?!-)[a-zA-Z0-9-]{1,63}(?<!-)',label) for label in host.split('.')):
        raise ValueError('Некорректный домен')
    return host.lower()


def patch_stream(text, include_path):
    pattern=r'(map\s+\$ssl_preread_server_name\s+\$[a-zA-Z0-9_]+\s*\{)'
    if len(re.findall(pattern,text))!=1:
        raise ValueError('Неоднозначная SNI-конфигурация; выберите отдельный внешний порт')
    directive=f'include {include_path};'
    if directive in text: return text
    return re.sub(pattern,lambda m:m[0]+'\n    '+directive,text,count=1)


def server_blocks(text):
    for match in re.finditer(r'\bserver\s*\{',text):
        depth=1; end=match.end()
        while depth and end<len(text):
            depth+=(text[end]=='{')-(text[end]=='}'); end+=1
        if depth==0: yield match.start(),end,text[match.start():end]


def matching_vhost(host,port=None):
    hits=[]
    for folder in ('/etc/nginx/sites-enabled','/etc/nginx/conf.d'):
        for file in Path(folder).glob('*'):
            if not file.is_file() or file.name=='wdtt-panel.conf': continue
            file=file.resolve(); text=file.read_text()
            for start,end,block in server_blocks(text):
                names=re.findall(r'\bserver_name\s+([^;]+);',block)
                if any(host in row.split() for row in names) and re.search(r'\blisten\s+[^;]+\bssl\b',block):
                    if port is not None and not re.search(r'\blisten\s+(?:[^\s;]+:)?'+str(port)+r'(?:\s|;)',block): continue
                    hits.append((file,text,start,end))
    unique={str(file)+':'+str(start):(file,text,start,end) for file,text,start,end in hits}
    if len(unique)>1: raise ValueError('Несколько TLS vhost для этого домена; выберите другой домен или порт')
    return next(iter(unique.values()),None)


def locations(backend,subport):
    return f'''# wdtt-panel locations begin
    location ^~ /wdtt/sub/ {{
        proxy_pass http://127.0.0.1:{subport}/sub/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
    location /wdtt/ {{
        proxy_pass http://127.0.0.1:{backend};
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
        proxy_buffering off;
    }}
    # wdtt-panel locations end'''


def configure(args):
    host=valid_host(args.host)
    if not 1<=args.port<=65535: raise ValueError('Внешний порт должен быть 1..65535')
    listeners=run('ss','-H','-ltnp',f'sport = :{args.port}')
    occupied=bool(listeners.strip())
    owned=Path('/etc/nginx/conf.d/wdtt-panel.conf')
    own_listener=owned.exists() and re.search(r'\blisten\s+'+str(args.port)+r'(?:\s|;)',owned.read_text()) and f'server_name {host};' in owned.read_text()
    if occupied and 'nginx' not in listeners:
        raise ValueError(f'Порт {args.port} занят другим процессом. Выберите свободный внешний порт.')
    stream=Path('/etc/nginx/stream-enabled/stream.conf')
    own_sni=owned.exists() and f'server_name {host};' in owned.read_text() and '127.0.0.1:' in owned.read_text() and Path('/etc/nginx/wdtt-panel-sni.map').exists()
    if occupied and not own_listener and not own_sni and args.mode in ('http','selfsigned'):
        raise ValueError('Для общего порта нужен отдельный TLS-домен. Для HTTP или сертификата на IP выберите свободный порт.')
    stream=Path('/etc/nginx/stream-enabled/stream.conf')
    use_stream=occupied and args.port==443 and stream.exists() and 'ssl_preread' in stream.read_text()
    shared=matching_vhost(host,None if use_stream else args.port) if occupied and not own_listener else None
    if args.check:
        if use_stream and not shared:
            patch_stream(stream.read_text(),'/etc/nginx/wdtt-panel-sni.map')
        print('Порт доступен; '+('общий TLS vhost' if shared else 'SNI lucx-ui-pro' if use_stream else 'отдельный vhost'))
        return
    changes={}; backup={}
    snippet=locations(args.backend,args.subport)
    if shared:
        file,text,start,end=shared
        block=text[start:end]
        block=re.sub(r'# wdtt-panel locations begin.*?# wdtt-panel locations end','',block,flags=re.S)
        if re.search(r'location\s+(?:\^~\s+)?/wdtt/',block):
            raise ValueError('/wdtt/ уже используется в существующем vhost')
        changes[file]=text[:start]+block[:-1]+'\n'+snippet+'\n}'+text[end:]
    else:
        listen=f'{args.port}'
        proxy_protocol=False
        if use_stream:
            existing=re.search(r'listen\s+127\.0\.0\.1:(\d+)',owned.read_text()) if own_sni else None
            internal=int(existing[1]) if existing else free_port(29443); listen=f'127.0.0.1:{internal}'
            stream_text=stream.read_text()
            if re.search(r'(?m)^\s*'+re.escape(host)+r'\s+',stream_text):
                raise ValueError('Этот SNI-домен уже занят. Выберите отдельный поддомен или внешний порт.')
            changes[stream]=patch_stream(stream_text,'/etc/nginx/wdtt-panel-sni.map')
            map_file=Path('/etc/nginx/wdtt-panel-sni.map')
            mapping=map_file.read_text() if map_file.exists() else ''
            mapping=re.sub(r'(?m)^\s*'+re.escape(host)+r'\s+[^;]+;\s*$', '', mapping)
            changes[map_file]=mapping.rstrip()+'\n'+f'{host} 127.0.0.1:{internal};\n'
            proxy_protocol=bool(re.search(r'\bproxy_protocol\s+on;',stream_text))
        tls=''
        if args.mode!='http':
            for path in (args.cert,args.key):
                if not path or not Path(path).is_file() or not re.fullmatch(r'/[a-zA-Z0-9_./-]+',path):
                    raise ValueError('Укажите существующие абсолютные пути сертификата и ключа')
            listen+=' ssl'+(' proxy_protocol' if proxy_protocol else '')
            tls=f'ssl_certificate {args.cert};\n ssl_certificate_key {args.key};\n ssl_protocols TLSv1.2 TLSv1.3;'
        real_ip='set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol;' if proxy_protocol else ''
        ipv6='' if listen.startswith('127.0.0.1:') else f'\n listen [::]:{listen};'
        changes[Path('/etc/nginx/conf.d/wdtt-panel.conf')]=f'server {{\n listen {listen};{ipv6}\n server_name {host};\n {tls}\n {real_ip}\n {snippet}\n}}\n'
    try:
        for file,text in changes.items():
            backup[file]=file.read_bytes() if file.exists() else None
            file.write_text(text)
        run('nginx','-t')
        run('systemctl','reload','nginx')
    except Exception:
        for file,data in backup.items():
            if data is None: file.unlink(missing_ok=True)
            else: file.write_bytes(data)
        subprocess.run(['nginx','-t'],capture_output=True)
        raise
    print(f'{"http" if args.mode=="http" else "https"}://{host}:{args.port}/wdtt/')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--host',required=True)
    parser.add_argument('--port',required=True,type=int)
    parser.add_argument('--backend',type=int,default=2860)
    parser.add_argument('--subport',type=int,default=2096)
    parser.add_argument('--mode',choices=['http','selfsigned','existing','certbot'],required=True)
    parser.add_argument('--cert'); parser.add_argument('--key'); parser.add_argument('--check',action='store_true')
    try: configure(parser.parse_args())
    except Exception as error:
        print(str(error),file=sys.stderr); sys.exit(2)
