import hashlib
import io
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

import cores

ROOT = Path(__file__).resolve().parent.parent


class Response(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): self.close()


def opener(files):
    """Serves [files] by the last part of the URL, as the release does; anything else is not there."""
    def open_url(url, timeout=0):
        name = url.rsplit('/', 1)[-1]
        if name not in files: raise OSError('404 ' + name)
        return Response(files[name])
    return open_url


def complete(folder):
    for name in cores.expected():
        (folder / name).write_bytes(b'#!/bin/sh\necho ' + name.encode() + b'\n')
        (folder / name).chmod(0o755)
    (folder / 'licenses/qwdtt').mkdir(parents=True)
    (folder / 'licenses/qwdtt/LICENSE').write_text('GPL-3.0')


def archive(build):
    out = Path(tempfile.mkdtemp()) / cores.asset('x86_64')
    cores.pack(build, out)
    data = out.read_bytes()
    return {out.name: data, out.name + '.sha256': f'{hashlib.sha256(data).hexdigest()}  {out.name}\n'.encode()}


class CoresTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.build = self.folder / 'build'; self.build.mkdir()
        self.target = self.folder / 'protocols'

    def fetch(self, files, glibc='glibc 2.39'):
        return cores.fetch(self.target, opener=opener(files), machine='x86_64', glibc=glibc)

    def test_the_cores_of_a_release_are_put_in_place(self):
        complete(self.build)
        self.assertTrue(self.fetch(archive(self.build)))
        for name in cores.expected(): self.assertTrue((self.target / name).is_file(), name)
        self.assertEqual((self.target / 'licenses/qwdtt/LICENSE').read_text(), 'GPL-3.0')
        if os.name != 'nt': self.assertTrue(os.access(self.target / 'qwdtt', os.X_OK))
        self.assertEqual([p.name for p in self.target.iterdir() if p.name.startswith('tmp')], [])

    def test_a_wrong_checksum_builds_on_the_vps_and_changes_nothing(self):
        complete(self.build)
        files = archive(self.build)
        files[cores.asset('x86_64') + '.sha256'] = b'0' * 64
        self.assertFalse(self.fetch(files))
        self.assertFalse(self.target.exists() and any(self.target.iterdir()))

    def test_no_release_builds_on_the_vps(self):
        self.assertFalse(self.fetch({}))

    def test_an_older_system_builds_on_the_vps(self):
        complete(self.build)
        self.assertFalse(self.fetch(archive(self.build), glibc='glibc 2.31'))
        self.assertFalse(self.target.exists())

    def test_an_incomplete_set_is_not_taken(self):
        complete(self.build)
        files = archive(self.build)
        name = cores.asset('x86_64')
        with tarfile.open(fileobj=io.BytesIO(files[name])) as tar, io.BytesIO() as buffer:
            with tarfile.open(fileobj=buffer, mode='w:gz') as out:
                for member in tar.getmembers():
                    if member.name != 'slipstream': out.addfile(member, tar.extractfile(member))
            files[name] = buffer.getvalue()
        files[name + '.sha256'] = hashlib.sha256(files[name]).hexdigest().encode()
        self.assertFalse(self.fetch(files))
        self.assertFalse((self.target / 'qwdtt').exists())

    def test_an_entry_outside_the_folder_is_refused(self):
        name = cores.asset('x86_64')
        with io.BytesIO() as buffer:
            with tarfile.open(fileobj=buffer, mode='w:gz') as out:
                data = b'x'; info = tarfile.TarInfo('../escape'); info.size = 1
                out.addfile(info, io.BytesIO(data))
            payload = buffer.getvalue()
        self.assertFalse(self.fetch({name: payload, name + '.sha256': hashlib.sha256(payload).hexdigest().encode()}))
        self.assertFalse((self.folder / 'escape').exists())

    def test_pack_refuses_a_set_with_a_core_missing(self):
        complete(self.build); (self.build / 'dnstt').unlink()
        with self.assertRaises(SystemExit): cores.pack(self.build, self.folder / 'out.tar.gz')

    def test_glibc_floor(self):
        self.assertTrue(cores.glibc_ok('glibc 2.35'))
        self.assertTrue(cores.glibc_ok('glibc 2.41'))
        self.assertFalse(cores.glibc_ok('glibc 2.31'))
        self.assertFalse(cores.glibc_ok(''))

    def test_the_fingerprint_follows_what_decides_the_binaries(self):
        copy = self.folder / 'repo'
        for name in cores.INPUTS: (copy / name).parent.mkdir(parents=True, exist_ok=True); shutil.copy2(ROOT / name, copy / name)
        shutil.copytree(ROOT / 'backends/soar', copy / 'backends/soar')
        first = cores.fingerprint(copy)
        self.assertEqual(first, cores.fingerprint(copy))
        # Line endings of a Windows checkout do not change it.
        path = copy / 'scripts/edge-sources.json'
        path.write_bytes(path.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
        self.assertEqual(first, cores.fingerprint(copy))
        path.write_text(path.read_text().replace('0c5c52a5', '0c5c52a6'))
        self.assertNotEqual(first, cores.fingerprint(copy))

    def test_the_installer_takes_ready_cores_and_builds_only_without_them(self):
        script = (ROOT / 'install.sh').read_text(encoding='utf-8')
        fetch, rust, build = script.index('scripts/cores.py" fetch'), script.index('sh.rustup.rs'), script.index('build-protocols.py')
        self.assertLess(fetch, rust)
        self.assertLess(rust, build)
        self.assertIn('if ! python3 "$SOURCE_DIR/scripts/cores.py" fetch; then', script)


if __name__ == '__main__':
    unittest.main()
