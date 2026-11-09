import copy
import json
import unittest
from unittest.mock import MagicMock, patch

from pronet import cli
from pronet.common import APP, PronetError
from pronet.spoof_scan import load_targets, probe


class ScanTargetsTests(unittest.TestCase):
    def setUp(self):
        self.catalog = json.loads((APP / 'data' / 'iran-scan-seeds.json').read_text())

    def test_bundled_catalog_uses_only_recorded_iranian_https_endpoints(self):
        targets = load_targets(self.catalog)
        self.assertEqual(len(targets), 84)
        self.assertEqual(len({address for _, address in targets}), 54)

    def test_targets_outside_iran_or_invalid_hostnames_are_rejected(self):
        catalog = copy.deepcopy(self.catalog)
        catalog['public_web_domains'][0]['iran_ipv4'] = [{'ipv4': '1.1.1.1'}]
        with self.assertRaises(PronetError):
            load_targets(catalog)
        catalog = copy.deepcopy(self.catalog)
        catalog['public_web_domains'][0]['hostname'] = 'example.ir\r\nX-Fake: 1'
        with self.assertRaises(PronetError):
            load_targets(catalog)

    def test_probe_distinguishes_tcp_failure(self):
        with patch('pronet.spoof_scan.socket.create_connection', side_effect=TimeoutError):
            self.assertEqual(probe('example.ir', '185.143.232.2')['stage'], 'tcp')

    def test_probe_pins_address_and_uses_hostname_for_tls_and_http(self):
        raw = MagicMock()
        tls = MagicMock()
        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = tls
        tls.recv.return_value = b'HTTP/1.1 403 Forbidden\r\n'
        with patch('pronet.spoof_scan.socket.create_connection') as connect:
            connect.return_value.__enter__.return_value = raw
            result = probe('example.ir', '185.143.232.2', context)
        self.assertEqual(connect.call_args.args[0], ('185.143.232.2', 443))
        context.wrap_socket.assert_called_once_with(raw, server_hostname='example.ir')
        self.assertIn(b'Host: example.ir\r\n', tls.sendall.call_args.args[0])
        self.assertEqual(result['http_status'], 403)

    def test_spoof_menu_scan_does_not_request_pairing(self):
        with patch.object(cli, 'root_linux'), patch.object(cli, 'node_config', return_value={'role': 'iran'}), \
             patch.object(cli, 'ask', return_value='3'), patch.object(cli, 'spoof_scan') as scan, \
             patch.object(cli, 'new_tunnel') as tunnel:
            cli.emergency_menu()
        scan.assert_called_once_with()
        tunnel.assert_not_called()
