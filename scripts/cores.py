#!/usr/bin/env python3
"""Ready-built protocol cores: the Cores workflow builds them from these very sources and pins, a VPS downloads them.

The release tag is a fingerprint of everything that decides the binaries (sources, patches, build scripts), so a VPS
only ever takes cores built from what its own installer would build. Anything missing, older or not matching its
SHA-256 makes the installer build on the VPS as before.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tarfile
import tempfile
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REPO = 'ttrroyy/wdtt-panel'
INPUTS = ['scripts/protocol-sources.json', 'scripts/edge-sources.json', 'scripts/build-protocols.py', 'scripts/build-edges.py',
          '.github/workflows/cores.yml']
# Built on Ubuntu 22.04, the oldest system the installer supports: its glibc is the floor.
GLIBC = (2, 35)


def fingerprint(root=ROOT):
    digest = hashlib.sha256()
    files = [root / name for name in INPUTS] + sorted(p for p in (root / 'backends/soar').rglob('*') if p.is_file())
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode() + b'\0')
        digest.update(path.read_bytes().replace(b'\r\n', b'\n') + b'\0')
    return digest.hexdigest()[:16]


def expected(root=ROOT):
    """Every file a complete set holds: each protocol's binary, and SOAR's native server beside its adapter."""
    names = set(json.loads((root / 'scripts/protocol-sources.json').read_text())) | set(json.loads((root / 'scripts/edge-sources.json').read_text()))
    return sorted(names | {'soar-native'})


def asset(machine=None):
    return f'wdtt-cores-linux-{machine or platform.machine()}.tar.gz'


def url(name, tag):
    return f'https://github.com/{REPO}/releases/download/{tag}/{name}'


def glibc_ok(version=None):
    text = version if version is not None else os.confstr('CS_GNU_LIBC_VERSION') or ''
    try:
        return tuple(int(part) for part in text.split()[-1].split('.')[:2]) >= GLIBC
    except (ValueError, IndexError):
        return False


def unpack(archive, destination, required):
    """Every file into place only once the whole archive is safe and complete."""
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination) as folder:
        staging = Path(folder)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            members = tar.getmembers()
            for member in members:
                target = staging / member.name
                if member.issym() or member.islnk() or not (member.isfile() or member.isdir()) or not target.resolve().is_relative_to(staging.resolve()):
                    raise ValueError('Unsafe cores archive entry: ' + member.name)
            for member in members:
                target = staging / member.name
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as src, target.open('wb') as dst:
                    shutil.copyfileobj(src, dst)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
        missing = [name for name in required if not (staging / name).is_file()]
        if missing:
            raise ValueError('Cores archive lacks ' + ', '.join(missing))
        for path in sorted(p for p in staging.rglob('*') if p.is_file()):
            final = destination / path.relative_to(staging)
            final.parent.mkdir(parents=True, exist_ok=True)
            os.replace(path, final)


def fetch(destination, opener=urllib.request.urlopen, machine=None, glibc=None):
    if not glibc_ok(glibc):
        print('Готовые ядра не подходят этой системе (нужен glibc 2.35+), ядра соберутся на VPS', flush=True)
        return False
    tag, name = 'cores-' + fingerprint(), asset(machine)
    try:
        with opener(url(name, tag), timeout=600) as response:
            archive = response.read()
        with opener(url(name + '.sha256', tag), timeout=60) as response:
            digest = response.read().decode().split()[0]
    except Exception as error:
        print(f'Готовые ядра недоступны ({error}), ядра соберутся на VPS', flush=True)
        return False
    if hashlib.sha256(archive).hexdigest() != digest:
        print('Готовые ядра: SHA-256 не совпадает, ядра соберутся на VPS', flush=True)
        return False
    try:
        unpack(archive, destination, expected())
    except (ValueError, tarfile.TarError) as error:
        print(f'Готовые ядра не приняты ({error}), ядра соберутся на VPS', flush=True)
        return False
    print('Готовые ядра скачаны и проверены', flush=True)
    return True


def pack(source, out):
    missing = [name for name in expected() if not (source / name).is_file()]
    if missing:
        raise SystemExit('Not built: ' + ', '.join(missing))
    out.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out, 'w:gz') as tar:
        for path in sorted(source.rglob('*')):
            if path.is_file():
                tar.add(path, arcname=path.relative_to(source).as_posix(), recursive=False)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    Path(str(out) + '.sha256').write_text(f'{digest}  {out.name}\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('fingerprint')
    get = commands.add_parser('fetch')
    get.add_argument('--destination', type=Path, default=Path('/usr/local/lib/wdtt/protocols'))
    put = commands.add_parser('pack')
    put.add_argument('source', type=Path)
    put.add_argument('out', type=Path)
    args = parser.parse_args()
    if args.command == 'fingerprint':
        print(fingerprint())
    elif args.command == 'fetch':
        sys.exit(0 if fetch(args.destination) else 1)
    else:
        pack(args.source, args.out)
