import argparse
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


certs = load('certificates', 'certificates.py')
nginx = load('nginx', 'configure-nginx.py')
uninstall = load('uninstall', 'uninstall.py')


class InstallationTests(unittest.TestCase):
    def test_selfsigned_reinstall_preserves_key_and_checks_host_and_pair(self):
        with tempfile.TemporaryDirectory() as folder:
            cert, key = Path(folder)/'cert.pem', Path(folder)/'key.pem'
            certs.selfsigned('192.0.2.1', cert, key)
            before = (cert.read_bytes(), key.read_bytes())
            certs.selfsigned('192.0.2.1', cert, key)
            self.assertEqual(before, (cert.read_bytes(), key.read_bytes()))
            with self.assertRaises(ValueError): certs.validate('192.0.2.2', cert, key)
            other_cert, other_key = Path(folder)/'other.pem', Path(folder)/'other-key.pem'
            certs.selfsigned('192.0.2.1', other_cert, other_key)
            with self.assertRaises(ValueError): certs.validate('192.0.2.1', cert, other_key)

    def test_lucx_sni_reinstall_keeps_internal_port_and_other_routes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            def path(value):
                value = str(value)
                return root/value.lstrip('/') if value.startswith('/etc/') else Path(value)
            stream = path('/etc/nginx/stream-enabled/stream.conf')
            stream.parent.mkdir(parents=True)
            stream.write_text('map $ssl_preread_server_name $sni_name {\n old.example www;\n default xray;\n}\nserver { listen 443; proxy_protocol on; ssl_preread on; }')
            path('/etc/nginx/conf.d').mkdir(parents=True)
            mapping = path('/etc/nginx/wdtt-panel-sni.map'); mapping.write_text('other.example 127.0.0.1:30000;\n')
            cert, key = root/'cert.pem', root/'key.pem'; cert.touch(); key.touch()
            args = argparse.Namespace(host='panel.example',port=443,backend=2860,subport=2096,mode='existing',cert=str(cert),key=str(key),check=False)
            def command(*args): return 'nginx' if args[0]=='ss' else ''
            with patch.object(nginx,'Path',side_effect=path), patch.object(nginx,'run',side_effect=command), patch.object(nginx,'free_port',return_value=29443):
                nginx.configure(args)
                first = path('/etc/nginx/conf.d/wdtt-panel.conf').read_text()
                nginx.configure(args)
            self.assertEqual(first,path('/etc/nginx/conf.d/wdtt-panel.conf').read_text())
            self.assertIn('other.example 127.0.0.1:30000;',mapping.read_text())
            self.assertEqual(mapping.read_text().count('panel.example '),1)
            self.assertEqual(stream.read_text().count('include /etc/nginx/wdtt-panel-sni.map;'),1)
            self.assertIn('old.example www;',stream.read_text())

    def test_uninstall_removes_only_panel_locations(self):
        text = 'server { location /other { proxy_pass http://127.0.0.1:8080; }\n'+nginx.locations(2860,2096)+'\n}'
        result = uninstall.remove_locations(text)
        self.assertIn('location /other',result)
        self.assertNotIn('/wdtt/',result)


if __name__ == '__main__': unittest.main()
