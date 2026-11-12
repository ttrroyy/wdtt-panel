#!/usr/bin/env python3
"""Build original DNS/OpenFlux engines at the revisions supported by RawlineMobile."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

HERE = Path(__file__).resolve().parent
SOURCES = json.loads((HERE/'edge-sources.json').read_text())


def command(*args, **kw):
    subprocess.run([str(a) for a in args], check=True, **kw)


def source(name, cache):
    s=SOURCES[name];root=cache/(name+'-'+s['revision'])
    if root.exists():return root
    cache.mkdir(parents=True,exist_ok=True)
    if name=='slipstream':
        command('git','clone','--no-checkout','https://github.com/'+s['repo']+'.git',root)
        command('git','checkout','--detach',s['revision'],cwd=root)
        command('git','submodule','update','--init','--recursive',cwd=root)
        return root
    with tempfile.TemporaryDirectory(dir=cache) as folder:
        staging=Path(folder)/'source';staging.mkdir()
        archive=Path(folder)/'source.tar.gz'
        urllib.request.urlretrieve(f'https://codeload.github.com/{s["repo"]}/tar.gz/{s["revision"]}',archive)
        with tarfile.open(archive) as tar:
            for member in tar:
                parts=Path(member.name).parts[1:]
                if not parts:continue
                target=staging.joinpath(*parts)
                if member.issym() or member.islnk() or not target.resolve().is_relative_to(staging.resolve()):raise ValueError('Unsafe source archive')
                if member.isdir():target.mkdir(parents=True,exist_ok=True)
                elif member.isfile():
                    target.parent.mkdir(parents=True,exist_ok=True)
                    with tar.extractfile(member) as src,target.open('wb') as dst:shutil.copyfileobj(src,dst)
        os.replace(staging,root)
    return root


def build(name, destination, cache):
    s=SOURCES[name];destination.mkdir(parents=True,exist_ok=True)
    marker=destination/(name+'.source.json')
    adapter=HERE.parent/'backends/soar'
    fingerprint=dict(s)
    if name=='soar':
        import hashlib
        fingerprint['adapter']=hashlib.sha256((adapter/'main.go').read_bytes()+(adapter/'go.mod').read_bytes()).hexdigest()
    licensed=any(path.name.upper().startswith(('LICENSE','COPYING')) for path in (destination/'licenses'/name).glob('*'))
    if (destination/name).is_file() and marker.exists() and json.loads(marker.read_text())==fingerprint and licensed and (name!='soar' or (destination/'soar-native').is_file()):return
    env=dict(os.environ,GOWORK='off',CGO_ENABLED='0',GOTOOLCHAIN='auto',CARGO_BUILD_JOBS='1')
    env.setdefault('GOPATH',str(Path.home()/'go'))
    env.setdefault('GOCACHE',str(Path.home()/'.cache/go-build'))
    env.setdefault('RUSTUP_HOME',str(Path.home()/'.rustup'))
    env.setdefault('CARGO_HOME',str(Path.home()/'.cargo'))
    with tempfile.TemporaryDirectory(dir=destination) as folder:
        staged=Path(folder)/name
        if name=='dnstt':
            env['GOBIN']=str(Path(folder).resolve())
            command('go','install',s['module']+'/'+s['package']+'@'+s['version'],env=env)
            shutil.move(Path(folder)/'dnstt-server',staged)
        elif name=='soar':
            command('go','build','-mod=mod','-trimpath','-o',staged.resolve(),'.',cwd=adapter,env=env)
            root=source(name,cache)
            command('go','build','-mod=mod','-trimpath','-o',str(staged.resolve())+'-native','./cmd/soar-server',cwd=root,env=env)
            os.replace(str(staged)+'-native',destination/'soar-native')
        else:
            root=source(name,cache)
            if name=='slipstream':
                command('cargo','build','--release','--locked','-p',s['package'],cwd=root,env=dict(env,CGO_ENABLED='1'))
                shutil.copy2(root/'target/release'/s['package'],staged)
            else:command('go','build','-mod=mod','-trimpath','-o',staged.resolve(),s['package'],cwd=root,env=env)
        staged.chmod(0o755);os.replace(staged,destination/name)
    marker.write_text(json.dumps(fingerprint,indent=2))
    license_dir=destination/'licenses'/name;license_dir.mkdir(parents=True,exist_ok=True)
    root=Path(env['GOPATH'])/'pkg/mod'/(s['module']+'@'+s['version']) if name=='dnstt' else source(name,cache)
    for path in root.iterdir():
        if path.is_file() and (path.name.upper().startswith(('LICENSE','COPYING')) or path.name in ('README.md','README')):shutil.copy2(path,license_dir/path.name)
    (license_dir/'source.json').write_text(json.dumps(s,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('protocol',choices=list(SOURCES));p.add_argument('--destination',type=Path,default=Path('/usr/local/lib/wdtt/protocols'));p.add_argument('--cache',type=Path,default=Path('/opt/wdtt-panel/edge-sources'));a=p.parse_args()
    build(a.protocol,a.destination,a.cache)
