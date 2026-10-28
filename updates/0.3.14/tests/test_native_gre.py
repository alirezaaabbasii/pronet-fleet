"""Native GRE is an independent, owned, bidirectionally tested L3 carrier."""
import ipaddress
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

from pronet import engines, native_gre as gre, runtime
from pronet.common import PronetError, write_json
from pronet.controller import Controller, screen_batches
from pronet.model import DEFAULT_PROFILES, PROFILES, iface, ranking, validate_request
from pronet.report import blocked_patterns, describe, family


def plan(role='iran', subnet='10.244.0.0/30'):
    return dict(pair_id='a'*24, profile='gre', role=role, token='b'*64, subnet=subnet,
                iran_ip='192.0.2.1', foreign_ip='192.0.2.2', bind_ip='192.0.2.1' if role=='iran' else '192.0.2.2',
                control_port=24443, echo_port=24444, health_port=24445, data_port=24446, inbound_port=2053,
                bridge_health_port=24447, bridge_data_port=24448, probe_front_port=24449, direction='iran-dials')


class FakeKernel:
    def __init__(self, p):
        self.expected = gre.parameters(p)
        self.link = None
        self.routes = []
        self.calls = []
        self.fail_address = False
    def owned(self):
        e=self.expected
        return {'ifname':e['name'],'ifalias':e['owner'],'linkinfo':{'info_kind':'gre','info_data':{
            'local':e['local'],'remote':e['remote'],'ikey':str(ipaddress.IPv4Address(e['key'])),
            'okey':str(ipaddress.IPv4Address(e['key']))}}}
    def command(self, args, **kw):
        self.calls.append(args)
        if args == ['ip','-j','-d','link','show']:
            out=json.dumps([self.link] if self.link else [])
        elif args == ['ip','-j','-4','route','show','table','all']:
            out=json.dumps(self.routes)
        elif args[:3] == ['ip','link','add']:
            self.link=self.owned();out=''
        elif args[:3] == ['ip','link','delete']:
            self.link=None;out=''
        elif args[:4] == ['ip','-4','address','replace'] and self.fail_address:
            raise PronetError('address setup failed')
        else: out=''
        return subprocess.CompletedProcess(args,0,out,'')


class NativeGRETests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=pathlib.Path(self.tmp.name)
        self.kernel=FakeKernel(plan())
        self.root_patch=mock.patch.object(gre,'ROOT',self.root);self.root_patch.start()
        self.command_patch=mock.patch.object(gre,'command',side_effect=self.kernel.command);self.command_patch.start()
    def tearDown(self):
        self.command_patch.stop();self.root_patch.stop();self.tmp.cleanup()
    def test_native_gre_is_default_and_old_indices_do_not_move(self):
        self.assertIn('gre',DEFAULT_PROFILES)
        self.assertEqual(list(PROFILES).index('gre'),21)
        self.assertEqual(list(PROFILES).index('wstunnel-h2'),20)
        self.assertEqual(PROFILES['gre']['engine'],'native-gre')
        self.assertEqual(family('gre'),'GRE')
        self.assertIn('no BackPack',describe('gre'))
    def test_kernel_link_is_owned_at_creation_and_contains_no_shared_secret(self):
        gre.up(plan())
        add=next(c for c in self.kernel.calls if c[:3]==['ip','link','add'])
        self.assertIn('alias',add);self.assertIn('gre',add)
        self.assertEqual(add[add.index('key')+1],str(gre.parameters(plan())['key']))
        self.assertNotIn('b'*64,str(self.kernel.calls))
        self.assertFalse(any('default' in c or 'sysctl' in c for c in self.kernel.calls))
    def test_reuse_and_removal_are_idempotent(self):
        gre.up(plan());gre.up(plan());gre.down(plan());gre.down(plan())
        self.assertEqual(sum(c[:3]==['ip','link','add'] for c in self.kernel.calls),1)
        self.assertEqual(sum(c[:3]==['ip','link','delete'] for c in self.kernel.calls),1)
    def test_endpoints_and_key_are_symmetric_and_distinct_for_another_subnet(self):
        a,b=gre.parameters(plan()),gre.parameters(plan('foreign'))
        self.assertEqual((a['local'],a['remote']),(b['remote'],b['local']))
        self.assertEqual(a['key'],b['key'])
        self.assertNotEqual(a['key'],gre.parameters(plan(subnet='10.244.0.4/30'))['key'])
        self.assertLessEqual(len(a['name']),15)
    def test_matching_unowned_interface_is_never_adopted_or_deleted(self):
        self.kernel.link=self.kernel.owned();self.kernel.link.pop('ifalias')
        for action in (gre.up,gre.down):
            with self.assertRaisesRegex(PronetError,'ownership'):
                action(plan())
        self.assertFalse(any(c[:3] in (['ip','link','add'],['ip','link','delete']) for c in self.kernel.calls))
    def test_changed_remote_or_key_is_never_deleted_even_with_our_alias(self):
        for field in ('remote','ikey','okey'):
            self.kernel.link=self.kernel.owned()
            self.kernel.link['linkinfo']['info_data'][field]='192.0.2.99'
            with self.assertRaisesRegex(PronetError,'ownership'):
                gre.down(plan())
        self.assertFalse(any(c[:3]==['ip','link','delete'] for c in self.kernel.calls))
    def test_newly_owned_interface_is_removed_after_partial_start_failure(self):
        self.kernel.fail_address=True
        with self.assertRaisesRegex(PronetError,'address setup failed'):
            gre.up(plan())
        self.assertIsNone(self.kernel.link)
    def test_new_overlapping_route_aborts_without_changing_any_link(self):
        self.kernel.routes=[{'dst':'10.0.0.0/8','dev':'external-vpn'}]
        with self.assertRaisesRegex(PronetError,'overlaps'):
            gre.up(plan())
        self.assertFalse(any(c[:3]==['ip','link','add'] for c in self.kernel.calls))
    def test_native_gre_does_not_require_tun_or_an_engine_download(self):
        r=object.__new__(runtime.Runtime);r.root=self.root;r.identity={'role':'iran','bind_ip':'192.0.2.1',
                    'public_ip':'192.0.2.1','allowed_inbound_ports':[2053]}
        info={'ips':['192.0.2.1'],'systemd':True,'iptables':True,'ssh_ports':[22],'ports':[],
              'tun':False,'routes':[],'reserved_subnets':[]}
        with mock.patch.object(engines,'install_asset') as install:
            self.assertTrue(r.prepare(plan(),info)['prepared'])
            install.assert_not_called()
        pair={'id':'a'*24,'request':validate_request({'name':'gre','public_ip':'192.0.2.1','profiles':['gre']}),
              'iran_info':{'public_ip':'192.0.2.1'},'foreign_info':{'public_ip':'192.0.2.2'}}
        self.assertEqual(Controller(mock.Mock()).allocate(pair,{'iran':info,'foreign':info})[0]['profile'],'gre')
    def test_gre_does_not_consume_the_preferred_tcp_port_of_another_carrier(self):
        info={'ports':[],'ssh_ports':[22],'tun':True,'routes':[],'reserved_subnets':[]}
        pair={'id':'a'*24,'request':validate_request({'name':'gre','public_ip':'192.0.2.1','profiles':['gre','frp-tls']}),
              'iran_info':{'public_ip':'192.0.2.1'},'foreign_info':{'public_ip':'192.0.2.2'}}
        plans=Controller(mock.Mock()).allocate(pair,{'iran':info,'foreign':info})
        self.assertEqual(plans[1]['control_port'],443)

    def test_runtime_start_uses_native_helper_not_a_backpack_recipe(self):
        r=object.__new__(runtime.Runtime);r.root=self.root;r.validate=lambda p:p
        write_json(self.root/('a'*24)/'gre'/'plan.json',plan())
        r.write_services=mock.Mock()
        with mock.patch.object(engines,'install_asset') as install, mock.patch.object(runtime,'command'), \
             mock.patch.object(runtime,'service'), mock.patch.object(runtime,'is_active',return_value=False):
            self.assertTrue(r.start(plan())['started'])
            install.assert_not_called()
        self.assertEqual(engines.render(plan(),self.root,{})['native'],'gre')
    def test_firewall_uses_ip_protocol_47_with_exact_peer_and_no_fake_tcp_port(self):
        for role in ('iran','foreign'):
            p=plan(role);rules=runtime.firewall_rules(p,'engine')
            outer=[r for r in rules if '-p' in r and r[r.index('-p')+1]=='47']
            self.assertEqual(len(outer),2)
            self.assertTrue(all('--dport' not in r and '--sport' not in r for r in outer))
            self.assertTrue(all('192.0.2.1' in r and '192.0.2.2' in r for r in outer))
    def test_native_failure_does_not_count_as_evidence_that_tcp_is_blocked(self):
        rows=[{'profile':'gre','passed':False,'error':'unreachable'},
              {'profile':'bp-direct-stealth','passed':False,'error':'unreachable'},
              {'profile':'frp-tls','passed':True}]
        self.assertEqual(blocked_patterns(rows)[0],[])
    def test_gre_is_allocated_to_one_screening_group(self):
        plans=[{'profile':n,'direction':'iran-dials'} for n in DEFAULT_PROFILES]
        batches=screen_batches(plans)
        self.assertEqual(sum(p['profile']=='gre' for b in batches for p in b),1)
        self.assertTrue(all(len(b)<=8 for b in batches))


if __name__=='__main__': unittest.main()
