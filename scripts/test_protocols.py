import importlib.util
import ipaddress
import json
import sqlite3
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


p=load('protocols','protocols.py')
nginx=load('configure_nginx','configure-nginx.py')


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=patch.object(p,'ROOT',Path(self.temp.name)/'protocols');self.root.start()
    def tearDown(self):
        self.root.stop();self.temp.cleanup()

    def test_subnets_and_listeners_do_not_overlap(self):
        pools=[ipaddress.ip_network(f'10.{s["pool"]}.0.0/16') for s in p.PROFILES.values()]
        pools.extend(map(ipaddress.ip_network,['10.70.0.0/16','10.73.0.0/16','10.253.0.0/16']))
        self.assertTrue(all(not a.overlaps(b) for i,a in enumerate(pools) for b in pools[i+1:]))
        ports=[s['port'] for s in p.PROFILES.values()]
        self.assertEqual(len(ports),len(set(ports)))

    def test_unknown_protocol_cannot_reach_shell(self):
        with patch.object(p,'run') as command:
            with self.assertRaises(ValueError):p.api({'op':'create','protocol':'../../ssh'})
            command.assert_not_called()

    def test_only_one_instance_of_each_protocol(self):
        with p.locked():
            s=p.state();s['profiles']['qwdtt']=True;p.save(s)
        with patch.object(p,'run') as command:
            with self.assertRaisesRegex(ValueError,'уже есть'):p.profile_create('qwdtt','192.0.2.1')
            command.assert_not_called()

    def test_zero_days_and_zero_limits_are_unlimited(self):
        with patch.object(p,'request',return_value={'password':'test-password'}) as request:
            p.create_user('qwdtt',{'name':'Test','vk_hash':'hash','days':0,'total_bytes':0,'max_mbps':0})
            self.assertEqual(request.call_args.args[2]['days'],0)
        with p.locked():entry=p.state()['users']['qwdtt']['test-password']
        self.assertEqual(entry['total_bytes'],0)
        self.assertEqual(entry['max_mbps'],0)

    def test_transparent_proxy_never_captures_namespace_admin_replies(self):
        for name in p.PROFILES:
            for _,network,_ in p.protocol_ingress(name):
                self.assertNotIn(ipaddress.ip_address('10.253.1.2'),ipaddress.ip_network(network))

    def test_main_subscription_seed_is_read_only(self):
        with sqlite3.connect(Path(self.temp.name)/'panel.db') as db:
            db.execute('CREATE TABLE wdtt_global(id INTEGER, main_password TEXT)')
            db.execute('CREATE TABLE wdtt_users(password TEXT,sub_id TEXT)')
            db.execute("INSERT INTO wdtt_global VALUES(1,'owner')")
            db.execute("INSERT INTO wdtt_users VALUES('owner','owner-sub')")
        with patch.object(p,'create_user') as create:
            self.assertEqual(p.seed_default_subscription(),{'sub_id':'owner-sub'})
            self.assertEqual(p.seed_default_subscription(),{'sub_id':'owner-sub'})
            create.assert_not_called()


    def test_unified_user_has_one_route_choice_for_all_memberships(self):
        master=dict(sub_id='identity',password='native',comment='Person',vk_hash='',expires_at=0,is_deactivated=0,
                    total_bytes=0,up_bytes=0,down_bytes=0,max_down_mbps=0,max_up_mbps=0,max_devices=1)
        members={'qwdtt':'q-password','freeturn':'f-password'}
        with p.locked():
            state=p.state();state['profiles']={name:True for name in p.PROFILES}
            state['bundles']={'identity':{'members':members}};p.save(state)
        rows={name:[dict(password=password,enabled=True,name='Person',link='link',up_bytes=0,down_bytes=0)] for name,password in members.items()}
        with patch.object(p,'native_users',return_value=[master]), patch.object(p,'selected_protocols',return_value=list(members)), patch.object(p,'mutate_user'), patch.object(p,'enabled_user') as toggle:
            options,errors=p.sync_subscription_bundles(rows)
            self.assertEqual(errors,[])
            self.assertEqual(options,[{'tag':'vpn-user-identity','label':'Person'}])
            aliases=json.loads((p.ROOT/'user-route-aliases.json').read_text())
            self.assertEqual(set(aliases['vpn-user-identity']),{'vpn-'+n+'-user-'+p.user_id(n,pw) for n,pw in members.items()})
            toggle.assert_not_called()
        with patch.object(p,'native_users',return_value=[master]), patch.object(p,'selected_protocols',return_value=['freeturn']), patch.object(p,'mutate_user'), patch.object(p,'enabled_user') as toggle:
            p.sync_subscription_bundles(rows)
            toggle.assert_called_once_with('qwdtt','q-password',False)
            subscription=json.loads((p.ROOT.parent/'protocol-subscriptions.json').read_text())['identity']
            self.assertEqual([c['protocol'] for c in subscription['connections']],['freeturn'])

    def test_global_traffic_reset_is_idempotent(self):
        with p.locked():
            state=p.state();state['bundles']={'identity':{'members':{}}};p.save(state)
        p.atomic(p.ROOT.parent/'protocol-subscriptions.json',{'identity':{'raw_up_bytes':100,'raw_down_bytes':200,'up_bytes':40,'down_bytes':50}})
        for _ in range(2):
            p.api({'op':'reset-user-traffic','sub_id':'identity'})
            self.assertEqual(p.state()['bundles']['identity']['traffic_offsets'],{'up_bytes':100,'down_bytes':200})

    def test_csqtt_links_use_upstream_encoding(self):
        for name in ('csqtt-2.1.9','csqtt-2.5.0'):
            original='csqtt://original-encrypted-payload'
            with patch.object(p,'users',return_value=[dict(password='p@ss',vk_hash='abc+def,second/hash',link=original)]), patch.object(p,'settings',return_value={'secret':'owner','host':'vpn.example'}):
                row=p.display_users(name)[0]
            if name=='csqtt-2.5.0': self.assertEqual(row['link'],original)
            else: self.assertEqual(row['link'],'csqtt://connect?v=2&host=vpn.example&peer=56300&password=p%40ss&hashes=abc%2Bdef+second%2Fhash')

    def test_csqtt_does_not_send_duplicate_serde_aliases(self):
        for name,key,absent in [('csqtt-2.1.9','dtls_port','peer_port'),('csqtt-2.5.0','peer_port','dtls_port')]:
            with patch.object(p,'request',return_value={'password':'test-password'}) as request:
                p.create_user(name,{'name':'Test','days':0})
                self.assertIn(key,request.call_args.args[2]);self.assertNotIn(absent,request.call_args.args[2])

    def test_freeturn_traffic_survives_peer_counter_reset(self):
        with p.locked():
            s=p.state();s['users']['freeturn']={'test':{'name':'Test','ip':'10.72.0.1','public_key':'PUB'}};p.save(s)
        for raw,want in [(100,100),(100,100),(20,120)]:
            with patch.object(p,'nsrun',return_value=f'interface\nPUB\tpsk\tendpoint\tips\t0\t{raw}\t{raw}\t0'):
                rows=p.users('freeturn')
            self.assertEqual(rows[0]['up_bytes'],want)
            self.assertEqual(rows[0]['down_bytes'],want)

    def test_lucx_sni_map_is_preserved_and_patch_is_idempotent(self):
        source='map $ssl_preread_server_name $sni_name {\n old.example www;\n default xray;\n}\nupstream www { server 127.0.0.1:7443; }\n'
        updated=nginx.patch_stream(source,'/etc/nginx/wdtt-panel-sni.map')
        self.assertIn('old.example www;',updated)
        self.assertIn('default xray;',updated)
        self.assertEqual(nginx.patch_stream(updated,'/etc/nginx/wdtt-panel-sni.map'),updated)
        with self.assertRaises(ValueError):nginx.patch_stream('not a supported map','/tmp/include')

    def test_host_cannot_inject_nginx_directives(self):
        for host in ['good.example; listen 22','a\nserver{}','-bad.example','a/b']:
            with self.assertRaises(ValueError):nginx.valid_host(host)


if __name__=='__main__':unittest.main()
