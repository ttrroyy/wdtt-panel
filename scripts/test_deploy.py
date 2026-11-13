import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


preflight = load('preflight', 'preflight.py')
frontend = load('frontend', 'frontend.py')
local_install = load('local_install', 'local-install.py')
INSTALLER = Path(__file__).resolve().parent.parent/'install.sh'


class DnsChecks(unittest.TestCase):
    """Certbot and DNS tunnels fail late on wrong records; the check stops them before anything is installed."""
    def errors(self, records, selection, frontend_choice, role='combined', ip='203.0.113.7'):
        with patch.object(preflight, 'addresses', lambda name: records.get(name, [])):
            return preflight.dns_errors(selection, frontend_choice, ip, role)

    def test_panel_domain_must_point_here(self):
        nginx = dict(mode='nginx', domain='panel.example.org')
        none = dict(protocols=[], dns_zone='', dns_ns='')
        self.assertEqual(self.errors({'panel.example.org': ['203.0.113.7']}, none, nginx), [])
        self.assertEqual(self.errors({'panel.example.org': ['198.51.100.1', '203.0.113.7']}, none, nginx), [])
        wrong = self.errors({'panel.example.org': ['198.51.100.1']}, none, nginx)
        self.assertEqual(len(wrong), 1); self.assertIn('198.51.100.1', wrong[0]); self.assertIn('203.0.113.7', wrong[0])
        self.assertIn('нет A-записи', self.errors({}, none, nginx)[0])
        self.assertEqual(self.errors({}, none, dict(mode='local')), [])

    def test_dns_zone_records_and_limits(self):
        local = dict(mode='local')
        good = dict(protocols=['dnstt'], dns_zone='t.example.org', dns_ns='ns.example.org')
        self.assertEqual(self.errors({'ns.example.org': ['203.0.113.7']}, good, local), [])
        self.assertTrue(self.errors({'ns.example.org': ['198.51.100.1']}, good, local))
        self.assertTrue(self.errors({}, dict(good, dns_ns=''), local))
        inside = dict(good, dns_ns='ns.t.example.org')
        self.assertTrue(any('вне зоны' in e for e in self.errors({'ns.t.example.org': ['203.0.113.7']}, inside, local)))
        long_zone = dict(good, protocols=['slipstream', 'soar'], dns_zone='tunnel.long-example.org')
        found = self.errors({'ns.example.org': ['203.0.113.7']}, long_zone, local)
        self.assertTrue(any('Slipstream' in e for e in found)); self.assertFalse(any('Soar' in e for e in found))
        self.assertTrue(any('Soar' in e for e in self.errors({'ns.example.org': ['203.0.113.7']}, dict(long_zone, dns_zone='a'*20+'.example.org'), local)))
        # A zone left empty creates the DNS inbounds later; a panel alone has no tunnels to check.
        self.assertEqual(self.errors({}, dict(good, dns_zone='', dns_ns=''), local), [])
        self.assertEqual(self.errors({}, good, local, role='panel'), [])


class Status(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(); self.base = Path(self.folder.name)
        self.patches = [patch.object(frontend, 'BASE', self.base), patch.object(frontend, 'STATE', self.base/'frontend.json'),
                        patch.object(frontend.subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout='1.4.83\n')),
                        patch('urllib.request.urlopen', side_effect=OSError('offline'))]
        for p in self.patches: p.start()

    def tearDown(self):
        for p in self.patches: p.stop()
        self.folder.cleanup()

    def install(self, role, mode='local', domain=''):
        (self.base/'role').write_text(role+'\n')
        (self.base/'frontend.json').write_text(json.dumps(dict(mode=mode, domain=domain)))
        (self.base/'installation.json').write_text(json.dumps(dict(protocols=['wdtt', 'dnstt'], dns_zone='t.example.org', dns_ns='ns.example.org', public_ip='203.0.113.7')))
        (self.base/'install-credentials').write_text('admin\nsecret\n')
        with sqlite3.connect(self.base/'panel.db') as db:
            db.execute('CREATE TABLE panel_config(id INTEGER PRIMARY KEY, username TEXT, port INTEGER, web_base_path TEXT)')
            db.execute("INSERT INTO panel_config VALUES(1,'admin',2860,'/Abcdefghijklmnopq/')")
        Path('/usr/local/bin/wdtt-app')  # version comes from the patched subprocess

    def status(self):
        with patch('sys.stdout', new_callable=io.StringIO) as out:
            frontend.status()
        return json.loads(out.getvalue())

    def test_nothing_installed(self):
        s = self.status()
        self.assertEqual((s['role'], s['panel_url'], s['username'], s['password'], s['protocols']), ('', '', '', '', []))

    def test_local_panel_and_node(self):
        self.install('combined')
        s = self.status()
        self.assertEqual(s['panel_url'], 'http://127.0.0.1:2860/Abcdefghijklmnopq/')
        self.assertEqual((s['username'], s['password'], s['panel_port']), ('admin', 'secret', 2860))
        self.assertEqual(s['protocols'], ['wdtt', 'dnstt']); self.assertEqual(s['public_ip'], '203.0.113.7')

    def test_https_panel_alone_lists_no_protocols(self):
        self.install('panel', 'nginx', 'panel.example.org')
        s = self.status()
        self.assertEqual(s['panel_url'], 'https://panel.example.org/Abcdefghijklmnopq/')
        self.assertEqual(s['protocols'], [])

    def test_node_alone_has_no_panel_link(self):
        self.install('node')
        s = self.status()
        self.assertEqual(s['panel_url'], ''); self.assertEqual(s['protocols'], ['wdtt', 'dnstt'])


class Choices(unittest.TestCase):
    def test_check_writes_choices_outside_etc_wdtt(self):
        with tempfile.TemporaryDirectory() as folder:
            base, selection = Path(folder)/'etc', Path(folder)/'check'
            with patch.dict(os.environ, dict(WDTT_PROTOCOLS='wdtt,dnstt', WDTT_DNS_ZONE='t.example.org', WDTT_DNS_NS='ns.example.org',
                                             WDTT_FRONTEND='caddy', WDTT_DOMAIN='Panel.Example.org.', WDTT_CERT_EMAIL='')), \
                 patch.object(local_install, 'BASE', base), patch.object(local_install, 'SELECTION', selection), \
                 patch.object(frontend, 'BASE', base), patch.object(frontend, 'SELECTION', selection):
                local_install.choose(); frontend.choose()
            self.assertFalse(base.exists())
            chosen = json.loads((selection/'install-selection.json').read_text())
            self.assertEqual(chosen['protocols'], ['wdtt', 'dnstt']); self.assertEqual(chosen['dns_zone'], 't.example.org')
            access = json.loads((selection/'frontend-selection.json').read_text())
            self.assertEqual((access['mode'], access['domain']), ('caddy', 'panel.example.org'))

    def test_missing_answer_without_terminal_is_an_error_not_a_hang(self):
        with patch('builtins.open', side_effect=OSError('No such device')):
            with self.assertRaises(ValueError) as caught: frontend.ask('Домен')
            self.assertIn('переменной окружения', str(caught.exception))
            with self.assertRaises(ValueError): local_install.ask('Протоколы')

    def test_protocol_names_and_numbers(self):
        self.assertEqual(local_install.select_protocols('1, qwdtt,qwdtt'), ['wdtt', 'qwdtt'])
        self.assertEqual(local_install.select_protocols(''), [])
        with self.assertRaises(ValueError): local_install.select_protocols('wdtt;reboot')


class InstallerCommandLine(unittest.TestCase):
    """The shell entry: roles only widen, a removal keeps its target, and wrong usage says so."""
    text = INSTALLER.read_text(encoding='utf-8')

    def test_uninstall_passes_its_target(self):
        self.assertIn('exec python3 /usr/local/lib/wdtt/uninstall.py "${@:2}"', self.text)
        self.assertIn('uninstall) exec python3 "$SOURCE_DIR/scripts/uninstall.py" "${@:2}";;', self.text)

    def test_role_logic(self):
        script = self.text[self.text.index('PREVIOUS_ROLE='):self.text.index('if (( CHECK_ONLY )); then\n    WDTT_SELECTION_DIR')]
        def run(previous, requested, protocols=None):
            with tempfile.TemporaryDirectory() as root:
                code = script.replace('/etc/wdtt/', root+'/')
                if previous: Path(root, 'role').write_text(previous+'\n')
                Path(root, 'installation.json').write_text(json.dumps(dict(protocols=['wdtt', 'dnstt'])))
                env = dict(os.environ, ROOT=root, REQUESTED_ROLE=requested)
                env.pop('WDTT_PROTOCOLS', None)
                if protocols is not None: env['WDTT_PROTOCOLS'] = protocols
                out = subprocess.run(['bash', '-c', 'set -eu\n'+code+'\necho "$INSTALL_ROLE|${WDTT_PROTOCOLS-unset}"'], env=env, capture_output=True, text=True, check=True).stdout
                return out.strip()
        self.assertEqual(run('', 'panel'), 'panel|')
        self.assertEqual(run('', 'node'), 'node|unset')
        self.assertEqual(run('panel', 'node'), 'combined|unset')
        self.assertEqual(run('node', 'panel'), 'combined|wdtt,dnstt')
        self.assertEqual(run('node', 'panel', 'wdtt'), 'combined|wdtt')
        self.assertEqual(run('combined', 'panel'), 'combined|wdtt,dnstt')
        self.assertEqual(run('combined', 'node'), 'combined|unset')
        self.assertEqual(run('panel', 'panel'), 'panel|')

    def test_bad_usage_prints_help(self):
        self.assertIn('[[ $# -le 1 ]] || { echo "$USAGE" >&2; exit 1; }', self.text)


if __name__ == '__main__': unittest.main()
