import argparse
import json
import types
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import sqlite3
from unittest.mock import patch


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


uninstall = load('uninstall', 'uninstall.py')


def old_locations(*_):
    return '# wdtt-panel locations begin\nlocation /wdtt/ { proxy_pass http://127.0.0.1:2860; }\n# wdtt-panel locations end'


class InstallationTests(unittest.TestCase):
    def test_remove_panel_keeps_local_node_and_user_database(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            def path(value):return root/str(value).lstrip('/')
            path('/etc/wdtt').mkdir(parents=True);path('/etc/systemd/system').mkdir(parents=True)
            path('/etc/wdtt/role').write_text('combined')
            path('/etc/wdtt/panel.db').write_bytes(b'keep user data')
            unit=path('/etc/systemd/system/wdtt.service');unit.write_text('[Service]\nExecStart=/usr/local/bin/wdtt-app -config-dir /etc/wdtt\n')
            with patch.object(uninstall,'Path',side_effect=path),patch.object(uninstall,'run',return_value=types.SimpleNamespace(returncode=0,stdout='',stderr='')),patch.object(uninstall,'stop_node') as stop,patch.object(uninstall.os,'geteuid',return_value=0,create=True):uninstall.main('panel')
            stop.assert_not_called();self.assertEqual(path('/etc/wdtt/panel.db').read_bytes(),b'keep user data');self.assertIn('-node-only',unit.read_text());self.assertEqual(path('/etc/wdtt/role').read_text().strip(),'node')

    def test_remove_node_keeps_panel_and_remote_memberships(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            def path(value):return root/str(value).lstrip('/')
            path('/etc/wdtt/protocols').mkdir(parents=True);path('/etc/wdtt/fleet').mkdir();path('/etc/systemd/system').mkdir(parents=True)
            path('/etc/wdtt/role').write_text('combined')
            path('/etc/wdtt/protocols/state.json').write_text(json.dumps({'profiles':{'wdtt':True}}))
            path('/etc/wdtt/fleet/state.json').write_text(json.dumps({'nodes':[{'id':'local'},{'id':'n-remote'}]}))
            with sqlite3.connect(path('/etc/wdtt/panel.db')) as db:
                db.executescript('CREATE TABLE vpn_user_inbounds(sub_id TEXT,protocols TEXT);CREATE TABLE wdtt_inbound(id INTEGER,enable INTEGER);CREATE TABLE wdtt_global(id INTEGER,users_rev INTEGER);INSERT INTO wdtt_inbound VALUES(1,1);INSERT INTO wdtt_global VALUES(1,0);')
                db.execute('INSERT INTO vpn_user_inbounds VALUES(?,?)',('owner',json.dumps(['wdtt','n-remote--qwdtt'])))
            unit=path('/etc/systemd/system/wdtt.service');unit.write_text('[Service]\nExecStart=/usr/local/bin/wdtt-app -config-dir /etc/wdtt\n')
            with patch.object(uninstall,'Path',side_effect=path),patch.object(uninstall,'run',return_value=types.SimpleNamespace(returncode=0,stdout='',stderr='')),patch.object(uninstall,'stop_node') as stop,patch.object(uninstall.os,'geteuid',return_value=0,create=True):uninstall.main('node')
            stop.assert_called_once();self.assertIn('-panel-only',unit.read_text());self.assertEqual(path('/etc/wdtt/role').read_text().strip(),'panel')
            with sqlite3.connect(path('/etc/wdtt/panel.db')) as db:self.assertEqual(json.loads(db.execute('SELECT protocols FROM vpn_user_inbounds').fetchone()[0]),['n-remote--qwdtt'])
            self.assertTrue(path('/etc/wdtt/removed-node-inbounds.json').exists())

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
