import importlib.util
import base64
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
firewall=load('panel_firewall','panel-firewall.py')


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        p.edge.configure(vars(p))
        self.temp=tempfile.TemporaryDirectory()
        self.root=patch.object(p,'ROOT',Path(self.temp.name)/'protocols');self.root.start()
    def tearDown(self):
        self.root.stop();self.temp.cleanup()

    def test_subnets_and_listeners_do_not_overlap(self):
        profiles=[s for name,s in p.PROFILES.items() if not p.edge.is_edge(name)]
        pools=[ipaddress.ip_network(f'10.{s["pool"]}.0.0/16') for s in profiles]
        pools.extend(map(ipaddress.ip_network,['10.70.0.0/16','10.73.0.0/16','10.253.0.0/16']))
        self.assertTrue(all(not a.overlaps(b) for i,a in enumerate(pools) for b in pools[i+1:]))
        ports=[s['port'] for s in profiles]
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

    def test_freeturn_uri_fixes_mode_and_embeds_original_wg_field(self):
        folder=p.directory('freeturn');folder.mkdir(parents=True);(folder/'wg-public').write_text('server-public')
        meta={'private_key':'private','ip':'10.72.0.2','public_key':'public','name':'User'}
        with p.locked():
            state=p.state();state['users']['freeturn']={'client-id':meta};p.save(state)
        with patch.object(p,'users',return_value=[dict(meta,password='client-id')]), patch.object(p,'settings',return_value={'host':'vpn.example','secret':'owner','obf_key':'key','dns':'8.8.8.8'}):
            row=p.display_users('freeturn')[0]
        payload=json.loads(base64.urlsafe_b64decode(row['link'][len('freeturn://'):]+'==='))
        self.assertEqual(payload['mode'],'udp');self.assertEqual(payload['transport'],'tcp')
        self.assertEqual(payload['wg'],row['wg_config'])
        self.assertIn('DNS = 8.8.8.8',payload['wg'])
        self.assertEqual(payload['cid'],'client-id')

    def test_profile_settings_validate_before_write_and_keep_secrets(self):
        folder=p.directory('qwdtt');folder.mkdir(parents=True)
        original={'host':'old.example','secret':'keep-secret','admin_token':'keep-token'}
        p.atomic(folder/'settings.json',original)
        with p.locked():
            state=p.state();state['profiles']['qwdtt']=True;p.save(state)
        for invalid in ({'subnet':'10.0.0.0/8'},{'host':'host; evil'},{'dns':'8.8.8.8,broken'},{'enabled':'false'},{'port':443}):
            with self.assertRaises(ValueError):p.profile_update('qwdtt',invalid)
            self.assertEqual(p.settings('qwdtt'),original)
        with patch.object(p,'run') as run:
            p.profile_update('qwdtt',{'remark':'New qWDTT','host':'new.example','dns':'8.8.8.8, 1.1.1.1','enabled':True})
            run.assert_called_once_with('systemctl','restart',p.unit('qwdtt'))
        updated=p.settings('qwdtt')
        self.assertEqual(updated['secret'],original['secret']);self.assertEqual(updated['admin_token'],original['admin_token'])
        self.assertEqual(updated['dns'],'8.8.8.8,1.1.1.1')

    def test_firewall_tracks_configured_protocol_ports(self):
        rules=firewall.rules('CHAIN','ens3',[57500,58000])
        udp=[line for line in rules if '-p udp' in line]
        self.assertEqual(len(udp),1)
        self.assertIn('--dports 57500,58000',udp[0])
        self.assertFalse(any('-p udp' in line for line in firewall.rules('CHAIN','ens3',[])))
        self.assertTrue(any('22,80,443' in line for line in rules))

    def test_original_settings_catalog_and_protected_parameters(self):
        expected={'qwdtt':['direct_port','raw_port'],'wdtt-plus':['max_handshakes','handshake_rate','wg_backend'],'csqtt-2.1.9':['fec','secure_cookie'],'csqtt-2.5.0':['secure_cookie'],'freeturn':['obf_profile','obf_timing_ms','mtu','debug']}
        for name,keys in expected.items():
            fields={field['key']:field for section in p.settings_sections(name) for field in section['fields']}
            self.assertTrue(all(key in fields and not fields[key].get('readonly') for key in keys))
            self.assertTrue(fields['subnet']['readonly']);self.assertTrue(fields['tag']['readonly'])
        self.assertEqual(next(f['value'] for section in p.settings_sections('csqtt-2.5.0') for f in section['fields'] if f['key']=='mtu'),1500)

    def test_transport_ports_reject_overlap_and_remain_in_original_links(self):
        for name in ('qwdtt','freeturn'):
            folder=p.directory(name);folder.mkdir(parents=True);p.atomic(folder/'settings.json',{'host':'vpn.example'})
        with p.locked():
            state=p.state();state['profiles']={'qwdtt':True,'freeturn':True};p.save(state)
        with self.assertRaisesRegex(ValueError,'занят инбаундом'):
            p.profile_update('freeturn',{'port':56100})
        with self.assertRaisesRegex(ValueError,'должны отличаться'):
            p.profile_update('qwdtt',{'raw_port':56100})
        with patch.object(p,'run',return_value=''):
            p.profile_update('qwdtt',{'port':57100,'wg_port':57101,'raw_port':57103,'direct_port':57102,'client_port':9010})
        self.assertEqual(p.spec('qwdtt')['port'],57100)
        self.assertEqual(p.published_ports('qwdtt'),[57100,57102,57103])

    def test_profile_settings_roll_back_failed_restart(self):
        folder=p.directory('qwdtt');folder.mkdir(parents=True)
        original={'host':'old.example','secret':'keep-secret'}
        p.atomic(folder/'settings.json',original)
        with p.locked():
            state=p.state();state['profiles']['qwdtt']=True;p.save(state)
        with patch.object(p,'run',side_effect=[RuntimeError('restart failed'),'', '']):
            with self.assertRaisesRegex(RuntimeError,'restart failed'):p.profile_update('qwdtt',{'dns':'8.8.8.8'})
        self.assertEqual(p.settings('qwdtt'),original)

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



if __name__=='__main__':unittest.main()
