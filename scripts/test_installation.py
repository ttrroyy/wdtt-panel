import argparse
import json
import types
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


uninstall = load('uninstall', 'uninstall.py')


def old_locations(*_):
    return '# wdtt-panel locations begin\nlocation /wdtt/ { proxy_pass http://127.0.0.1:2860; }\n# wdtt-panel locations end'


class InstallationTests(unittest.TestCase):
    def test_full_uninstall_preserves_other_panel_in_a_temporary_root(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            def path(value):
                assert str(value).startswith('/'),value
                return root/str(value).lstrip('/')
            def remove(value,**options):
                target=path(value)
                assert target.resolve().is_relative_to(root.resolve())
                shutil.rmtree(target,**options)
            for name in ('/etc/wdtt','/etc/wdtt-xray','/usr/local/lib/wdtt','/usr/local/wdtt-xray','/opt/wdtt-panel','/etc/nginx/conf.d','/etc/nginx/stream-enabled'):
                path(name).mkdir(parents=True)
            path('/etc/wdtt/installation.json').write_text(json.dumps({'WDTT_PANEL_HOST':'panel.example'}))
            shared=path('/etc/nginx/conf.d/other.conf')
            shared.write_text('server { location /lucx/ { proxy_pass http://127.0.0.1:8080; } '+old_locations(2860,2096)+' }')
            path('/etc/nginx/conf.d/wdtt-panel.conf').write_text('owned vhost')
            path('/etc/nginx/wdtt-panel-sni.map').write_text('panel.example 127.0.0.1:29443;\nother.example 127.0.0.1:30000;\n')
            stream=path('/etc/nginx/stream-enabled/stream.conf');stream.write_text('include /etc/nginx/wdtt-panel-sni.map;')
            calls=[]
            def command(*args):
                calls.append(args)
                rules='-A INPUT -i ens3 -j WDTT_PANEL_INPUT\n-A INPUT -p tcp --dport 443 -m comment --comment lucx-ui -j ACCEPT\n'
                return types.SimpleNamespace(returncode=0,stdout=rules if '-S' in args else '')
            with patch.object(uninstall,'Path',side_effect=path), patch.object(uninstall,'shutil',types.SimpleNamespace(rmtree=remove)), patch.object(uninstall,'run',side_effect=command), patch.object(uninstall.os,'geteuid',return_value=0,create=True):
                uninstall.main()
            self.assertFalse(path('/etc/wdtt').exists())
            self.assertFalse(path('/usr/local/lib/wdtt').exists())
            self.assertIn('location /lucx/',shared.read_text())
            self.assertNotIn('/wdtt/',shared.read_text())
            self.assertIn('other.example',path('/etc/nginx/wdtt-panel-sni.map').read_text())
            self.assertIn('include',stream.read_text())
            self.assertFalse(any('lucx-ui' in c and '-D' in c for c in calls))

    def test_uninstall_removes_only_panel_locations(self):
        text = 'server { location /other { proxy_pass http://127.0.0.1:8080; }\n'+old_locations(2860,2096)+'\n}'
        result = uninstall.remove_locations(text)
        self.assertIn('location /other',result)
        self.assertNotIn('/wdtt/',result)


if __name__ == '__main__': unittest.main()
