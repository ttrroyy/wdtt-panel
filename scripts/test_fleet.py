import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import fleet

class FleetTests(unittest.TestCase):
    def test_routing_scopes_inbounds_to_nodes_and_keeps_global_users(self):
        config=dict(outbounds=[dict(tag='direct',protocol='freedom')],routing=dict(rules=[
            dict(inboundTag=['vpn-wdtt'],outboundTag='local'),
            dict(inboundTag=['vpn-node-n-one--wdtt'],outboundTag='selected'),
            dict(inboundTag=['vpn-node-n-two--qwdtt'],outboundTag='another'),
            dict(inboundTag=['vpn-user-alice'],outboundTag='blocked'),
            dict(domain=['example.org'],outboundTag='direct')]))
        result=fleet.node_routing(config,'n-one')
        self.assertEqual([r['outboundTag'] for r in result['routing']['rules']],['selected','blocked','direct'])
        self.assertEqual(result['routing']['rules'][0]['inboundTag'],['vpn-wdtt'])
        self.assertEqual(config['routing']['rules'][1]['inboundTag'],['vpn-node-n-one--wdtt'])
        self.assertNotIn('inbounds',result)

    def test_node_api_keys_are_never_in_public_inventory(self):
        node=dict(id='n-one',api_key='secret',server_key='old-secret',client_key='old-secret',name='Node')
        public=fleet.public_node(node)
        self.assertNotIn('api_key',public)
        self.assertNotIn('server_key',public)
        self.assertNotIn('client_key',public)

    def test_loopback_and_plain_http_api_urls_are_rejected_before_connecting(self):
        with patch.object(fleet,'remote') as remote:
            for url in ('http://node.example','https://user:pass@node.example','https://node.example/path','https://node.example?token=abc'):
                with self.assertRaises(ValueError):fleet.add_api_node(dict(name='Node',api_url=url,api_key='wdtt_api_'+'A'*43))
            remote.assert_not_called()

if __name__=='__main__':unittest.main()
