import base64
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

from pronet import carrier_engines, engines, model, spoof_wg
from pronet.common import PronetError, write_json
from test_extensions import ExtensionTests


class IndependentCarriers(unittest.TestCase):
    def plan(self, profile, role='iran'):
        return ExtensionTests().plan(profile, role)

    def test_existing_profile_indices_stay_unchanged(self):
        self.assertEqual(list(model.PROFILES).index('gre'), 21)
        self.assertEqual(list(model.PROFILES)[22:], ['paqet', 'backhaul-tcp', 'backhaul-tcpmux', 'parsa-spoof'])
        self.assertNotIn('gfk', model.DEFAULT_PROFILES)

    def test_spoof_never_invents_a_source_and_requires_both_addresses(self):
        for value in (None, [], {'iran': '192.0.2.3'}, {'iran':'192.0.2.3','foreign':None}):
            with self.assertRaises(PronetError): model.validate_spoof(value)
        with self.assertRaisesRegex(PronetError, 'not configured'):
            model.validate_profile(self.plan('parsa-spoof'))
        plan = dict(self.plan('parsa-spoof'), spoof={'iran':'192.0.2.1','foreign':'192.0.2.4'})
        with self.assertRaisesRegex(PronetError, 'differ'):
            model.validate_profile(plan)

    def test_backhaul_uses_only_owned_loopback_bridges_and_no_global_tuning(self):
        with tempfile.TemporaryDirectory() as folder:
            for profile in ('backhaul-tcp', 'backhaul-tcpmux'):
                for role in ('iran', 'foreign'):
                    path = pathlib.Path(folder)
                    recipe = engines.render(self.plan(profile,role), path, {'backhaul':'/managed/backhaul'})
                    self.assertEqual(recipe['command'][:2], ['/managed/backhaul','-c'])
                    text = (path/'engine.toml').read_text()
                    self.assertIn('skip_optz = true', text)
                    self.assertIn('web_port = 0', text)
                    self.assertNotIn('b'*64, str(recipe))
                    if role == 'iran': self.assertIn('127.0.0.1:24445=127.0.0.1:24447', text)

    def test_paqet_uses_real_route_and_pinned_port_on_both_nodes(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(carrier_engines,'route',return_value=('eth8','aa:bb:cc:dd:ee:ff')):
            for role in ('iran','foreign'):
                path = pathlib.Path(folder)
                recipe = engines.render(self.plan('paqet',role),path,{'paqet':'/managed/paqet'})
                data = json.loads((path/'engine.yaml').read_text())
                self.assertEqual(data['network']['interface'],'eth8')
                self.assertTrue(data['network']['ipv4']['addr'].endswith(':24443'))
                self.assertEqual(data['transport']['kcp']['block'],'aes')
                self.assertNotIn('b'*64,str(recipe))
                if role == 'iran': self.assertEqual(data['forward'][1]['target'],'127.0.0.1:24448')

    def test_raw_rules_are_pair_peer_and_port_scoped_and_never_flush(self):
        plan = self.plan('paqet')
        rules = carrier_engines.packet_rules(plan)
        self.assertEqual([row[0] for row in rules], ['raw','raw','mangle'])
        for table,chain,args in rules:
            self.assertIn('192.0.2.2',args)
            self.assertIn('24443',args)
            self.assertIn('pronetf:'+'a'*24+':paqet:engine',args)
            self.assertNotIn('FLUSH',args)

    def test_spoof_uses_only_tcp_and_one_wireguard_udp_endpoint(self):
        with tempfile.TemporaryDirectory() as folder:
            for role in ('iran','foreign'):
                plan = dict(self.plan('parsa-spoof',role),spoof={'iran':'192.0.2.3','foreign':'192.0.2.4'})
                path = pathlib.Path(folder)
                recipe = engines.render(plan,path,{'parsa-spoof':'/managed/spoof'})
                data=json.loads((path/'spoof.json').read_text())
                self.assertEqual(data['send_transport'],'tcp')
                self.assertEqual(data['recv_transport'],'tcp')
                self.assertEqual(data['spoof_ip'],plan['spoof'][role])
                self.assertNotIn('xdp_interface',data)
                self.assertEqual(recipe['command'][1:3],['run','-c'])

    def test_wireguard_refuses_unowned_and_replaced_interfaces(self):
        item={'name':'pnfixture','owner':'pronetf:test'}
        row={'ifname':'pnfixture','ifindex':4,'ifalias':item['owner'],'linkinfo':{'info_kind':'wireguard'}}
        record={'expected':item,'ifindex':4,'phase':'active'}
        with mock.patch.object(spoof_wg,'read_json',return_value=record):
            spoof_wg.owned(row,item)
            for altered in (dict(row,ifindex=5),dict(row,ifalias='outside'),dict(row,linkinfo={'info_kind':'dummy'})):
                with self.assertRaises(PronetError): spoof_wg.owned(altered,item)

    def test_wireguard_requires_exact_key_not_a_command_or_file_path(self):
        self.assertEqual(spoof_wg.checked_key(base64.b64encode(b'x'*32).decode()),base64.b64encode(b'x'*32).decode())
        for value in ('/etc/wireguard/key',None,'x',base64.b64encode(b'x'*31).decode()):
            with self.assertRaises(PronetError): spoof_wg.checked_key(value)


if __name__ == '__main__': unittest.main()
