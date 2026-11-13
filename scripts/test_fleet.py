import json
import tempfile
import sqlite3
import unittest
from pathlib import Path
from unittest.mock import patch
import fleet

class FleetTests(unittest.TestCase):
    def test_pairing_preserves_existing_node_users_and_adds_owner_membership(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with sqlite3.connect(root/'panel.db') as db:
                db.executescript("CREATE TABLE wdtt_users(password TEXT PRIMARY KEY,sub_id TEXT UNIQUE,comment TEXT,up_bytes INTEGER,down_bytes INTEGER,last_seen_at INTEGER);CREATE TABLE vpn_user_inbounds(sub_id TEXT PRIMARY KEY,protocols TEXT);CREATE TABLE wdtt_global(id INTEGER,main_password TEXT,users_rev INTEGER);INSERT INTO wdtt_users VALUES('owner-password','owner-sub','ADMIN',0,0,0);INSERT INTO wdtt_global VALUES(1,'owner-password',0);")
            snapshot=dict(profiles=[dict(id='wdtt',name='WDTT',present=True)],users=dict(rows=[dict(password='node-password',sub_id='node-sub',comment='ADMIN',up_bytes=100,down_bytes=200,last_seen_at=0)],memberships={'node-sub':['wdtt']}))
            with patch.object(fleet,'BASE',root),patch.object(fleet,'ROOT',root/'fleet'):fleet.adopt_users(dict(id='n-one',name='Amsterdam'),snapshot)
            with sqlite3.connect(root/'panel.db') as db:
                self.assertEqual(db.execute("SELECT password,up_bytes,down_bytes FROM wdtt_users WHERE sub_id='node-sub'").fetchone(),('node-password',0,0))
                self.assertEqual(json.loads(db.execute("SELECT protocols FROM vpn_user_inbounds WHERE sub_id='owner-sub'").fetchone()[0]),['n-one--wdtt'])
                self.assertEqual(json.loads(db.execute("SELECT protocols FROM vpn_user_inbounds WHERE sub_id='node-sub'").fetchone()[0]),['n-one--wdtt'])

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
