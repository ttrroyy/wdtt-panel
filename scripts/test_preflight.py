import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('preflight',Path(__file__).with_name('preflight.py'))
preflight=importlib.util.module_from_spec(spec);spec.loader.exec_module(preflight)

class PreflightTests(unittest.TestCase):
    def test_local_mode_does_not_require_public_web_ports(self):
        rows=[dict(protocol='tcp',port=443,address='0.0.0.0:443',managed=False,process='other-panel')]
        self.assertEqual(preflight.conflicts(rows,{},'local'),[])
        self.assertTrue(preflight.conflicts(rows,{},'nginx'))
        rows[0]['process']='nginx';self.assertEqual(preflight.conflicts(rows,{},'nginx'),[])
        self.assertTrue(preflight.conflicts(rows,{},'caddy'))

    def test_existing_foreign_dns_is_preserved_and_reported(self):
        rows=[dict(protocol='udp',port=53,address='127.0.0.53:53',managed=False,process='systemd-resolved')]
        self.assertTrue(preflight.conflicts(rows,dict(udp={53}),'local'))
        self.assertEqual(preflight.conflicts(rows,{},'local'),[])
        rows[0]['managed']=True;self.assertEqual(preflight.conflicts(rows,dict(udp={53}),'local'),[])

    def test_foreign_route_overlap_is_detected_without_touching_own_routes(self):
        pools=['10.66.0.0/16']
        self.assertTrue(preflight.route_conflicts([dict(dst='10.0.0.0/8',dev='another-vpn')],pools))
        self.assertEqual(preflight.route_conflicts([dict(dst='10.66.0.0/16',dev='wdtt0')],pools),[])
        self.assertEqual(preflight.route_conflicts([dict(dst='192.168.0.0/16',dev='eth0')],pools),[])

if __name__=='__main__':unittest.main()
