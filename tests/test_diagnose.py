import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock
from pronet.common import write_json

spec = importlib.util.spec_from_file_location('pronet_diagnostic', pathlib.Path(__file__).resolve().parents[1] / 'tools' / 'diagnose.py')
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


class DiagnosticTests(unittest.TestCase):
    def test_output_omits_secrets_and_preserves_useful_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            pair = 'a' * 24
            directory = root / 'pairs' / pair
            write_json(root / 'node.json', {'role': 'iran', 'node_secret': 'SECRET_NODE', 'hub_url': 'SECRET_URL'})
            write_json(directory / 'selection.json', {'active': 'frp-tls', 'profiles': ['frp-tls'],
                'token': 'SECRET_SELECTION', 'standby_health': {'bp-stealth': {'state': 'OK', 'token': 'SECRET_HEALTH'}}})
            write_json(directory / 'gateway.json', {'mode': 'framed', 'active_backend': ['127.0.0.1', 24443], 'frame_key': 'SECRET_FRAME'})
            write_json(directory / 'traffic.json', {'connection_failures': 12, 'rx_bytes': 1234, 'token': 'SECRET_STATS'})
            with mock.patch.object(diag, 'services', return_value={}), mock.patch.object(diag, 'host_metrics', return_value={}), mock.patch.object(diag, 'source_path', return_value=None):
                result = diag.snapshot(pair, root, root)
            self.assertNotIn('SECRET_', json.dumps(result))
            self.assertEqual(result['selection']['active'], 'frp-tls')
            self.assertEqual(result['traffic']['connection_failures'], 12)
            self.assertEqual(result['gateway']['active_backend'], ['127.0.0.1', 24443])

    def test_service_arguments_are_never_exported(self):
        result = mock.Mock(stdout='ActiveState=active\nNRestarts=3\nExecStart=/usr/bin/python3 /opt/pronet-fleet/0.2.4/main.py token=SECRET_ARGS\n')
        with mock.patch.object(diag.subprocess, 'run', return_value=result):
            rows = diag.services('a' * 24)
        self.assertNotIn('SECRET_ARGS', json.dumps(rows))
        self.assertEqual(rows['pronetf-agent.service']['unit_code_version'], '0.2.4')

    def test_foreign_never_initiates_transfer_test(self):
        with mock.patch.object(diag, 'read', return_value={'role': 'foreign'}), mock.patch.object(diag, 'source_path') as source:
            self.assertIn('skipped', diag.probe_paths('a' * 24))
            source.assert_not_called()

    def test_running_process_version_is_distinct_from_rewritten_unit(self):
        result = mock.Mock(stdout='ActiveState=active\nExecMainPID=123\nExecStart=/opt/pronet-fleet/0.3.4/main.py\n')
        with mock.patch.object(diag.subprocess, 'run', return_value=result), mock.patch.object(pathlib.Path, 'read_bytes', return_value=b'/usr/bin/python3\0/opt/pronet-fleet/0.2.4/main.py\0SECRET_PROCESS'):
            rows = diag.services('a' * 24)
        row = rows['pronetf-agent.service']
        self.assertEqual(row['unit_code_version'], '0.3.4')
        self.assertEqual(row['running_code_version'], '0.2.4')
        self.assertNotIn('SECRET_PROCESS', json.dumps(rows))
