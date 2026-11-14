import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('panel_firewall', Path(__file__).with_name('panel-firewall.py'))
firewall = importlib.util.module_from_spec(spec); spec.loader.exec_module(firewall)


class SshPortTests(unittest.TestCase):
    def test_another_ssh_port_stays_open(self):
        config = 'port 8904\nlistenaddress 0.0.0.0\nlistenaddress [::]:2222\n'
        listeners = 'LISTEN 0 128 0.0.0.0:8904 0.0.0.0:* users:(("sshd",pid=1,fd=3))\nLISTEN 0 4096 127.0.0.1:9090 0.0.0.0:* users:(("panel",pid=2,fd=5))\n'
        self.assertEqual(firewall.ssh_ports(config, listeners), {22, 8904, 2222})

    def test_without_sshd_answers_22_stays(self):
        self.assertEqual(firewall.ssh_ports('', ''), {22})

    def test_the_rules_accept_the_ssh_port(self):
        rules = firewall.rules('C', 'eth0', [56000], sorted({80, 443} | firewall.ssh_ports('port 8904\n', '')))
        self.assertTrue(any('--dports 22,80,443,8904' in rule for rule in rules))


if __name__ == '__main__':
    unittest.main()
