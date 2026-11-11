#!/usr/bin/env python3
"""Build pinned upstream servers; keep their licenses next to the installed binaries."""
import argparse
import hashlib
import inspect
import tempfile
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
SOURCES = json.loads((HERE / 'protocol-sources.json').read_text())


def replace(path, old, new):
    text = path.read_text(encoding='utf-8')
    if old not in text:
        raise ValueError(f'Upstream changed: {path.name}: missing {old!r}')
    path.write_text(text.replace(old, new), encoding='utf-8')


def patch(root, name, pool):
    if name == 'freeturn':
        return
    folder = root / ('rust-server' if name.startswith('csqtt') else 'server' if name == 'qwdtt' else '.')
    suffix = '*.rs' if name.startswith('csqtt') else '*.go'
    for p in folder.glob(suffix):
        text = p.read_text(encoding='utf-8')
        text = text.replace('10.66.', f'10.{pool}.')
        if name == 'qwdtt':
            text = text.replace('10.70.', '10.73.')
        if name == 'wdtt-plus':
            text = text.replace('wgServerAddr + "/24"', 'wgServerAddr + "/16"')
            text = text.replace('> 500', '> 65023').replace('= 500', '= 65023')
        if name.startswith('csqtt'):
            text = text.replace('[10, 66,', f'[10, {pool},').replace('new(10, 66,', f'new(10, {pool},')
            text = text.replace('.netmask((255, 255, 255, 0))','.netmask((255, 255, 0, 0))')
            text = text.replace(f'10.{pool}.67.0/24', f'10.{pool}.0.0/16')
            text = text.replace('MAX_PASSWORDS: usize = 20', 'MAX_PASSWORDS: usize = 65023')
            text = re.sub(r'for i in ([23])\.\.=250u8 \{', 'for i in 0..=65023u32 {', text)
            text = text.replace(f'let _ = write!(buf, "10.{pool}.67.{{i}}");', f'let _ = write!(buf, "10.{pool}.{{}}.{{}}", i / 254, i % 254 + 1);\n        if buf == "10.{pool}.67.1" || buf == "10.{pool}.67.2" {{ continue; }}')
        p.write_text(text, encoding='utf-8')
    if name.startswith('csqtt'):
        p = folder/'tun_device.rs'
        text = p.read_text(encoding='utf-8')
        text = re.sub(r'const SUBNET_PREFIX: \[u8; 3\] = \[10, \d+, 67\];', f'const SUBNET_PREFIX: [u8; 2] = [10, {pool}];', text)
        text = re.sub(r'Box<\[Option<(RouteGroup|ClientRoute)>; 256\]>', r'Box<[Option<\1>]>', text)
        text = text.replace('Box::new(std::array::from_fn(|_| None))', '(0..65536).map(|_| None).collect::<Vec<_>>().into_boxed_slice()')
        text = text.replace('(ip[..3] == SUBNET_PREFIX).then_some(ip[3] as usize)', '(ip[..2] == SUBNET_PREFIX).then_some(ip[2] as usize * 256 + ip[3] as usize)')
        p.write_text(text, encoding='utf-8')
        if name == 'csqtt-2.1.9':
            p=folder/'dataplane.rs'; text=p.read_text(encoding='utf-8')
            text=text.replace('[None; 256]', 'vec![None; 65536]').replace('[Option<usize>; 256]', '[Option<usize>]')
            text=text.replace(f'ip[..3] == [10, {pool}, 67]', f'ip[..2] == [10, {pool}]')
            text=text.replace('ip[3] as usize', '(ip[2] as usize * 256 + ip[3] as usize)')
            p.write_text(text, encoding='utf-8')
            p=folder/'downlink_queue.rs'; text=p.read_text(encoding='utf-8')
            text=text.replace('Box<[ClientEgressLane; 256]>', 'Box<[ClientEgressLane]>')
            text=text.replace('Box::new(std::array::from_fn(|_| ClientEgressLane::default()))','(0..65536).map(|_| ClientEgressLane::default()).collect::<Vec<_>>().into_boxed_slice()')
            p.write_text(text, encoding='utf-8')
        else:
            p=folder/'tokio_io.rs'; text=p.read_text(encoding='utf-8')
            text=text.replace('owner_key: u8','owner_key: u16').replace('client_key.min(254)','client_key.min(65534)')
            text=text.replace('client_key.min(65534) as u8','client_key.min(65534) as u16')
            text=text.replace('let owner = if priority {\n            255','let owner = if priority {\n            65535')
            text=text.replace('owner_key != 255','owner_key != 65535').replace('if owner < 255','if owner < 65535')
            text=text.replace("&'a mut [u16; 256]", "&'a mut [u16]")
            text=text.replace('client_in_flight: [u16; 256]', 'client_in_flight: Box<[u16]>')
            text=text.replace('client_in_flight: [0; 256]', 'client_in_flight: vec![0; 65536].into_boxed_slice()')
            text=text.replace('[0u16; 256]', '[0u16; 65536]')
            p.write_text(text, encoding='utf-8')
    if name == 'wdtt-plus':
        p = root / 'server.go'
        replace(p, 'for i := 2; i <= 250; i++ {', 'for i := 0; i <= 65023; i++ {')
        replace(p, f'ip := fmt.Sprintf("10.{pool}.66.%d", i)', f'ip := fmt.Sprintf("10.{pool}.%d.%d", i/254, i%254+1)\n if ip == wgServerAddr {{ continue }}')
    if name == 'qwdtt':
        p = root / 'server/admin_api.go'
        replace(p, '\tvkHash := r.FormValue("vk_hash")\n\tif vkHash == "" {\n\t\twriteAdminError(w, http.StatusBadRequest, "vk_hash is required")\n\t\treturn\n\t}', '\tvkHash := r.FormValue("vk_hash")')
        replace(p, 'parsed < 1 || parsed > 365', 'parsed < 0 || parsed > 3650')
        replace(p, 'days, _ := strconv.Atoi', 'days, _ := strconv.Atoi') if 'days, _ := strconv.Atoi' in p.read_text() else None
        s = p.read_text(encoding='utf-8')
        s = s.replace('days := 30', 'days := 0')
        s = s.replace('\t\tif vkHash == "" {\n\t\t\tdbMutex.Unlock()\n\t\t\twriteAdminError(w, http.StatusBadRequest, "vk_hash cannot be empty")\n\t\t\treturn\n\t\t}', '')
        s = s.replace('ExpiresAt:  time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix(),', 'ExpiresAt:  protocolExpiry(days),')
        s = s.replace('entry.ExpiresAt = time.Now().Add(time.Duration(parsed) * 24 * time.Hour).Unix()', 'entry.ExpiresAt = protocolExpiry(parsed)')
        s += '\nfunc protocolExpiry(days int) int64 { if days == 0 { return 0 }; return time.Now().Add(time.Duration(days)*24*time.Hour).Unix() }\n'
        p.write_text(s, encoding='utf-8')
        for p in (root/'server').glob('*.go'):
            s=p.read_text(encoding='utf-8'); s=re.sub(r'(maxGeneratedPasswords\s*=\s*)10\b', r'\g<1>65023', s); p.write_text(s, encoding='utf-8')


def build(name, destination, cache):
    spec = SOURCES[name]
    patch_id = hashlib.sha256((spec['revision']+inspect.getsource(patch)).encode()).hexdigest()[:12]
    root = cache / (name+'-'+patch_id)
    if not root.exists():
        cache.mkdir(parents=True,exist_ok=True)
        final_root = root
        root = Path(tempfile.mkdtemp(prefix=name+"-extract-",dir=cache))
        archive = cache / (name + '.tar.gz')
        urllib.request.urlretrieve(f'https://codeload.github.com/{spec["repo"]}/tar.gz/{spec["revision"]}', archive)
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                parts = Path(member.name).parts[1:]
                if not parts:
                    continue
                target = root.joinpath(*parts)
                if not target.resolve().is_relative_to(root.resolve()) or member.issym() or member.islnk():
                    raise ValueError('Unsafe source archive entry')
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as src, target.open('wb') as dst:
                        shutil.copyfileobj(src, dst)
        patch(root, name, spec['pool'])
        os.replace(root,final_root)
        root=final_root
    destination.mkdir(parents=True, exist_ok=True)
    binary = destination / name
    fd, filename = tempfile.mkstemp(prefix=name+".", dir=destination)
    os.close(fd)
    staged = Path(filename)
    env = dict(os.environ, CGO_ENABLED='0', GOTOOLCHAIN='auto', CARGO_BUILD_JOBS='1')
    if name.startswith('csqtt'):
        target={'x86_64':'x86_64-unknown-linux-gnu','aarch64':'aarch64-unknown-linux-gnu'}[platform.machine()]
        subprocess.run(['cargo', '+1.97.1', 'build', '--release', '--locked', '--target', target, '--manifest-path', str(root/'rust-server/Cargo.toml')], cwd=root/'rust-server', env=env, check=True)
        shutil.copy2(root/f'rust-server/target/{target}/release/csqtt', staged)
    else:
        package = './server' if name == 'qwdtt' else './cmd/server' if name == 'freeturn' else '.'
        subprocess.run(['go', 'build', '-trimpath', '-o', str(staged.resolve()), package], cwd=root, env=env, check=True)
    staged.chmod(0o755)
    os.replace(staged, binary)
    license_dir = destination/'licenses'/name
    license_dir.mkdir(parents=True, exist_ok=True)
    for filename in ('LICENSE', 'README.md'):
        if (root/filename).exists():
            shutil.copy2(root/filename, license_dir/filename)
    (license_dir/'source.json').write_text(json.dumps(spec, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('protocol', nargs='?', choices=list(SOURCES))
    parser.add_argument('--destination', type=Path, default=Path('/usr/local/lib/wdtt/protocols'))
    parser.add_argument('--cache', type=Path, default=Path('/opt/wdtt-panel/sources'))
    args = parser.parse_args()
    for name in ([args.protocol] if args.protocol else SOURCES):
        print('Building', name, flush=True)
        build(name, args.destination, args.cache)
