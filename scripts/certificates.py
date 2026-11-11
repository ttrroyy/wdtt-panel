#!/usr/bin/env python3
"""Validate and reuse TLS material; keep ACME changes out of other sites."""
import ipaddress
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile

nginx = runpy.run_path(str(Path(__file__).with_name('configure-nginx.py')))


def run(*args, input=None):
    result = subprocess.run(args, input=input, capture_output=True)
    if result.returncode:
        raise ValueError(result.stderr.decode(errors='replace') or result.stdout.decode(errors='replace'))
    return result.stdout


def validate(host, cert, key):
    for path in (cert, key):
        if not re.fullmatch(r'/[a-zA-Z0-9_./-]+', str(path)) or not Path(path).is_file():
            raise ValueError('Нужны существующие абсолютные пути сертификата и ключа')
    try:
        ipaddress.ip_address(host)
        check = '-checkip'
    except ValueError:
        check = '-checkhost'
    match = run('openssl', 'x509', '-in', str(cert), '-noout', check, host)
    if b'does NOT match' in match: raise ValueError('Сертификат не соответствует домену или IP')
    run('openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '0')
    public_cert = run('openssl', 'x509', '-in', str(cert), '-pubkey', '-noout')
    public_key = run('openssl', 'pkey', '-in', str(key), '-pubout')
    if public_cert != public_key:
        raise ValueError('Сертификат и закрытый ключ не соответствуют друг другу')


def find(host, port):
    hit = nginx['matching_vhost'](host, int(port)) or nginx['matching_vhost'](host)
    if not hit:
        return
    _, text, start, end = hit
    block = text[start:end]
    cert = re.search(r'\bssl_certificate\s+([^;\s]+);', block)
    key = re.search(r'\bssl_certificate_key\s+([^;\s]+);', block)
    if cert and key:
        print(cert[1]); print(key[1])


def selfsigned(host, cert, key):
    if Path(cert).exists() or Path(key).exists():
        validate(host, cert, key)
        return
    try:
        ipaddress.ip_address(host)
        san = 'IP:' + host
    except ValueError:
        san = 'DNS:' + host
    with tempfile.TemporaryDirectory(dir=Path(cert).parent) as folder:
        new_cert, new_key = Path(folder)/'cert.pem', Path(folder)/'key.pem'
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '365',
            '-subj', '/CN='+host, '-addext', 'subjectAltName='+san, '-keyout', str(new_key), '-out', str(new_cert))
        validate(host, new_cert, new_key)
        new_key.chmod(0o600); new_cert.chmod(0o600)
        os.replace(new_key, key); os.replace(new_cert, cert)


def certbot(host, cert, key):
    # Existing valid certificates are never replaced by a reinstall.
    if Path(cert).exists() or Path(key).exists():
        validate(host, cert, key)
    else:
        listeners = nginx['run']('ss', '-H', '-ltnp', 'sport = :80')
        if listeners.strip() and 'nginx' not in listeners:
            raise ValueError('Для Certbot нужен порт 80: он занят другим процессом')
        root = Path('/var/lib/wdtt-acme'); root.mkdir(parents=True, exist_ok=True)
        snippet = 'location ^~ /.well-known/acme-challenge/ { root /var/lib/wdtt-acme; }'
        candidates = {}
        for folder in ('/etc/nginx/sites-enabled', '/etc/nginx/conf.d'):
            for file in Path(folder).glob('*'):
                if not file.is_file(): continue
                file = file.resolve(); text = file.read_text()
                for start, end, block in nginx['server_blocks'](text):
                    if re.search(r'\blisten\s+(?:[^\s;]+:)?80(?:\s|;)', block) and any(host in names.split() for names in re.findall(r'\bserver_name\s+([^;]+);', block)):
                        candidates[(file, start)] = (text, start, end, block)
        if len(candidates)>1:
            raise ValueError('Неоднозначный HTTP vhost для ACME; устраните дубликаты server_name')
        if candidates:
            (file, _), (text, start, end, block) = next(iter(candidates.items()))
            if re.search(r'\breturn\s+30[1278]\s+', block):
                # A server-level redirect runs before locations and prevents webroot validation.
                raise ValueError('HTTP vhost перенаправляет все запросы: добавьте исключение ACME или используйте существующий сертификат')
            if '/.well-known/acme-challenge/' in block:
                if '/var/lib/wdtt-acme' not in block:
                    raise ValueError('У домена уже настроен другой ACME webroot; используйте его существующий сертификат')
                updated = text
            else:
                updated = text[:start]+block[:-1]+'\n# wdtt-panel acme begin\n'+snippet+'\n# wdtt-panel acme end\n}'+text[end:]
        else:
            file = Path('/etc/nginx/conf.d/wdtt-panel-acme.conf')
            updated = f'server {{ listen 80; listen [::]:80; server_name {host}; {snippet} }}\n'
        backup = file.read_bytes() if file.exists() else None
        try:
            file.write_text(updated)
            nginx['run']('nginx', '-t'); nginx['run']('systemctl', 'reload', 'nginx')
            run('certbot', 'certonly', '--non-interactive', '--agree-tos', '--register-unsafely-without-email',
                '--webroot', '-w', str(root), '--cert-name', host, '-d', host)
            validate(host, cert, key)
            Path('/etc/wdtt/owned-acme-cert').write_text(host)
        except Exception:
            if backup is None: file.unlink(missing_ok=True)
            else: file.write_bytes(backup)
            nginx['run']('nginx', '-t'); nginx['run']('systemctl', 'reload', 'nginx')
            raise
    hook = Path('/etc/letsencrypt/renewal-hooks/deploy/wdtt-panel')
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text('#!/bin/sh\nnginx -t && systemctl reload nginx\n'); hook.chmod(0o755)
    nginx['run']('systemctl', 'enable', '--now', 'certbot.timer')


if __name__ == '__main__':
    try:
        op, host, *args = sys.argv[1:]
        host = nginx['valid_host'](host)
        {'find': find, 'validate': validate, 'selfsigned': selfsigned, 'certbot': certbot}[op](host, *args)
    except Exception as error:
        print(str(error), file=sys.stderr); sys.exit(1)
