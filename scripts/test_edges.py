import base64
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import protocols as p
import edge_protocols as e


def load_installer():
    spec=importlib.util.spec_from_file_location('local_install',Path(__file__).with_name('local-install.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class EdgeTests(unittest.TestCase):
    def setUp(self):e.configure(vars(p))
    def test_original_keys_links_isolated_users_and_routing(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(p,'ROOT',Path(folder)/'protocols'),patch.object(p,'BIN',Path(folder)/'bin'),patch.object(p,'run',return_value='active'):
            p.BIN.mkdir();(p.BIN/'masterdns').touch()
            a=e.create(dict(engine='masterdns',zone='t.example.org',ns='ns.example.org'))['id']
            b=e.create(dict(engine='masterdns',zone='t.example.org',ns='ns.example.org'))['id']
            self.assertNotEqual(a,b)
            first=e.create_user(a,{'name':'One'});second=e.create_user(a,{'name':'Two'})
            p1,p2=first['password'],second['password']
            rows=e.display_users(a)
            payloads=[json.loads(base64.urlsafe_b64decode(r['link'][7:]+'='*(-len(r['link'][7:])%4))) for r in rows]
            self.assertEqual(payloads[0]['transport']['type'],'masterdns')
            self.assertNotEqual(payloads[0]['transport']['domain'],payloads[1]['transport']['domain'])
            self.assertNotEqual(payloads[0]['transport']['mkey'],payloads[1]['transport']['mkey'])
            self.assertEqual(payloads[0]['transport']['encryption'],5)
            generated,ingress=e.routing({a:rows})
            self.assertFalse(ingress)
            self.assertEqual(len(generated),2)
            self.assertEqual(generated[0]['settings']['accounts'][0]['pass'],p1)
            self.assertIn('-user-',generated[0]['tag'])
            self.assertEqual(generated[0]['listen'],'127.0.0.1')
            dns=json.loads((p.ROOT.parent/'dns-router.json').read_text())
            self.assertEqual(len(dns['routes']),2)
            e.enabled_user(a,p1,False)
            rows=e.display_users(a);generated,_=e.routing({a:rows})
            self.assertEqual(len(generated),1)
            self.assertEqual(generated[0]['settings']['accounts'][0]['pass'],p2)
            e.toggle(a,False,False)
            generated,_=e.routing({a:rows});self.assertEqual(generated,[])
            self.assertTrue((p.ROOT/a/'members.json').is_file())

    def test_settings_cannot_replace_backend_keys_or_upstream(self):
        cfg=e.validate(dict(engine='masterdns',zone='t.example.org',ns='ns.example.org'))
        changed=e.validate(dict(engine='masterdns',zone='attacker.example',user_zone='elsewhere'),cfg)
        self.assertEqual(changed['zone'],cfg['zone'])
        for options in [{'SOCKS5_PASS':'bypass'},{'UDP_PORT':53},{'FORWARD_PORT':22},{'LOG_FILE':'/etc/passwd'}]:
            with self.assertRaises(ValueError):e.validate(dict(engine='masterdns',server_options=json.dumps(options)),cfg)
        with self.assertRaises(ValueError):e.validate(dict(engine='soar',zone='a'*27+'.example.org',ns='ns.example.org'))
        for zone in ('bad;name.example','bad\n.example','bad..example'):
            with self.assertRaises(ValueError):e.validate(dict(engine='vaydns',zone=zone,ns='ns.example.org'))

    def test_installer_choices_and_busy_internal_port(self):
        installer=load_installer()
        self.assertEqual(installer.select_protocols('1, 8, dnSTT'),['wdtt','dnstt'])
        self.assertIn('soar',installer.select_protocols('all'))
        with self.assertRaises(ValueError):installer.select_protocols('http')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            if port<65535:self.assertNotEqual(installer.free_port(port),port)


if __name__=='__main__':unittest.main()
