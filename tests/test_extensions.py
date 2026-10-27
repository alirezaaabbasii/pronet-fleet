import base64
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

from pronet import engines, upgrades
from pronet.common import PronetError, write_json


class AccountingInterfaceTests(unittest.TestCase):
    def test_ubuntu_ipv4_json_without_link_type_keeps_all_public_addresses(self):
        from pronet.accounting import public_interfaces
        rows=[{'ifname':'eth0','flags':['UP','BROADCAST'], 'addr_info':[{'local':'45.67.89.10'},{'local':'45.67.89.11'},{'local':'10.0.0.1'}]}]
        with mock.patch('pronet.accounting.command',return_value=types.SimpleNamespace(stdout=json.dumps(rows))):
            self.assertEqual(public_interfaces(),[('eth0',['45.67.89.10','45.67.89.11'])])

    def test_loopback_and_private_tunnel_addresses_are_not_public_ip_inventory(self):
        from pronet.accounting import public_interfaces
        rows=[{'ifname':'lo','flags':['LOOPBACK'],'addr_info':[{'local':'127.0.0.1'}]},
              {'ifname':'pnfixture','flags':['UP'],'addr_info':[{'local':'10.244.1.1'}]},
              {'ifname':'ppp0','flags':['POINTOPOINT','UP'],'addr_info':[{'local':'45.67.89.12'}]}]
        with mock.patch('pronet.accounting.command',return_value=types.SimpleNamespace(stdout=json.dumps(rows))):
            self.assertEqual(public_interfaces(),[('ppp0',['45.67.89.12'])])


class ExtensionTests(unittest.TestCase):
    def test_private_ca_signs_a_non_ca_server_leaf(self):
        from pronet.common import command
        with tempfile.TemporaryDirectory() as temporary:
            directory=pathlib.Path(temporary)
            engines.wstunnel_certificate(directory,'test.invalid','192.0.2.1')
            text=command(['openssl','x509','-in',str(directory/'server.crt'),'-noout','-text']).stdout
            self.assertIn('CA:FALSE',text)
            command(['openssl','verify','-CAfile',str(directory/'ca.crt'),str(directory/'server.crt')])

    def plan(self, profile, role):
        return dict(pair_id='a'*24, profile=profile, role=role, token='b'*64, subnet='10.244.0.0/30',
                    iran_ip='192.0.2.1', foreign_ip='192.0.2.2', bind_ip='192.0.2.1' if role=='iran' else '192.0.2.2',
                    control_port=24443, echo_port=24444, health_port=24445, data_port=24446, inbound_port=2053,
                    bridge_health_port=24447, bridge_data_port=24448, probe_front_port=24449, direction='iran-dials')

    def test_websocket_and_h2_require_verified_ca_and_restrict_reverse_listeners(self):
        with tempfile.TemporaryDirectory() as temporary:
            for profile in ('wstunnel-wss', 'wstunnel-h2'):
                directory = pathlib.Path(temporary) / profile
                client = engines.render(self.plan(profile, 'foreign'), directory, {'wstunnel':'/test/wstunnel'})
                self.assertIn('--tls-verify-certificate', client['command'])
                self.assertTrue(client['environment']['SSL_CERT_FILE'].endswith('/peer.crt'))
                self.assertNotIn('b'*64, str(client['command']))
                server = engines.render(self.plan(profile, 'iran'), directory, {'wstunnel':'/test/wstunnel'})
                policy = (directory/'restrictions.yaml').read_text()
                self.assertIn('!ReverseTunnel', policy)
                self.assertNotIn('- !Tunnel', policy)
                self.assertIn('127.0.0.1/32', policy)
                self.assertIn('port: [24445, 24446]', policy)

    def test_noise_pins_the_generated_server_identity_and_never_exports_its_private_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            public = base64.b64encode(b'p'*32).decode()
            private = base64.b64encode(b'k'*32).decode()
            write_json(directory/'noise-key.json', {'private':private, 'public':public})
            server = engines.render(self.plan('rathole-noise','iran'), directory, {'rathole':'/test/rathole'})
            self.assertIn(private, (directory/'engine.toml').read_text())
            self.assertNotIn(private, str(server['command']))
            plan = dict(self.plan('rathole-noise','foreign'), server_noise_public_key=public)
            engines.render(plan, directory, {'rathole':'/test/rathole'})
            text = (directory/'engine.toml').read_text()
            self.assertIn(public, text)
            self.assertNotIn(private, text)
            self.assertIn('Noise_NK_25519_ChaChaPoly_BLAKE2s', text)


class UpgradeTests(unittest.TestCase):
    def test_only_owned_unit_version_references_are_migrated(self):
        text = '# Pronet Fleet owner=agent\n[Service]\nExecStart=/usr/bin/python3 /opt/pronet-fleet/0.1.0/main.py agent\n'
        migrated = upgrades.migrated_unit(text, '/opt/pronet-fleet/0.2.0/main.py')
        self.assertIn('/0.2.0/', migrated)
        with self.assertRaises(PronetError): upgrades.migrated_unit('[Service]\nExecStart=/other', '/new')

    def run_activation(self, fail=False):
        with tempfile.TemporaryDirectory() as temporary:
            root=pathlib.Path(temporary); units=root/'units'; units.mkdir(); config=root/'config'; config.mkdir()
            unit=units/'pronetf-agent.service'
            previous='# Pronet Fleet owner=agent\n[Service]\nExecStart=/usr/bin/python3 /opt/pronet-fleet/0.1.0/main.py agent\n'
            unit.write_text(previous)
            wrapper=root/'pronet'; wrapper.write_text('new-wrapper')
            def call(args, **kwargs):
                if fail and args[:2]==['systemctl','restart'] and '/0.2.0/' in unit.read_text(): raise PronetError('fault injected')
                return types.SimpleNamespace(stdout='active\n', returncode=0)
            with mock.patch.multiple(upgrades, ROOT=root/'state', CONFIG=config, UNIT_DIRECTORY=units), mock.patch.object(upgrades,'command',side_effect=call), mock.patch.object(upgrades.time,'sleep'):
                if fail:
                    with self.assertRaises(PronetError): upgrades.activate('/opt/pronet-fleet/0.2.0/main.py',b'old-wrapper',wrapper)
                    self.assertEqual(unit.read_text(),previous)
                    self.assertEqual(wrapper.read_text(),'old-wrapper')
                else:
                    report=upgrades.activate('/opt/pronet-fleet/0.2.0/main.py',b'old-wrapper',wrapper)
                    self.assertEqual(report['updated_units'],1)
                    self.assertIn('/0.2.0/',unit.read_text())
    def test_activation_changes_owned_units_and_retains_a_backup(self): self.run_activation()
    def test_failed_activation_restores_the_units_and_wrapper(self): self.run_activation(True)


if __name__=='__main__': unittest.main()
