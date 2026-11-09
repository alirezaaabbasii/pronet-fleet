"""Operator choices are scoped to the owning Iran node and passed tests."""
import tempfile
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from pronet.common import PronetError, secret
from pronet.store import Store
from pronet.model import validate_request
from pronet.controller import Controller


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.enrollment = secret()
        self.store = Store(Path(self.temp.name)/'state.db', self.enrollment, secret())
        def node(role, ip):
            enrolled = self.store.enroll(self.enrollment, {'name': role, 'role': role, 'public_ip': ip, 'bind_ip': ip})
            return self.store.authenticate(enrolled['node_id']+':'+enrolled['node_secret'])
        self.iran = node('iran', '192.0.2.1')
        self.foreign = node('foreign', '192.0.2.2')
        request = {'name': 'Selection', 'public_ip': '192.0.2.1', 'interactive_selection': True}
        self.pair = self.store.create_pair(self.iran, request)
        self.id = self.pair['pair_id']
        self.store.join_pair(self.foreign, self.pair['code'])
        self.result = {'phase': 'awaiting-selection', 'selection_prompt': {
            'token': 'choice-1', 'profiles': ['frp-tls', 'bp-stealth', 'gre'], 'limit': 3}}
        self.store.update_pair(self.id, 'TRIAL', self.result)

    def tearDown(self):
        self.temp.cleanup()

    def choose(self, profiles, node=None, token='choice-1'):
        return self.store.choose_carriers(node or self.iran, self.id, token, profiles)

    def test_owner_can_choose_order_and_repeat_identical_submission(self):
        selected = ['gre', 'frp-tls', 'bp-stealth']
        self.choose(selected); self.choose(selected)
        self.assertEqual(self.store.pair(self.id)['result']['selection_choice'], selected)
        with self.assertRaises(PronetError): self.choose(['frp-tls'])

    def test_foreign_stale_failed_unknown_duplicate_and_oversized_choices_refused(self):
        for names, node, token in [(['gre'], self.foreign, 'choice-1'),
                (['gre'], self.iran, 'old'), (['chisel'], self.iran, 'choice-1'),
                (['gre', 'gre'], self.iran, 'choice-1'),
                (['gre', 'frp-tls', 'bp-stealth', 'chisel'], self.iran, 'choice-1')]:
            with self.assertRaises(PronetError): self.choose(names, node, token)
        self.store.update_pair(self.id, 'FAILED', self.result)
        with self.assertRaises(PronetError): self.choose(['gre'])

    def test_auto_choice_is_explicit_and_stop_cancels_prompt(self):
        self.choose([])
        self.assertEqual(self.store.pair(self.id)['result']['selection_choice'], [])
        self.store.request_stop(self.iran, self.id)
        with self.assertRaises(PronetError): self.choose([])

    def test_manual_menu_keeps_order_and_never_repeats_carriers(self):
        from pronet.cli import choose_carriers
        rows = [{'profile': p, 'echo_ms': [10, 12]} for p in ('frp-tls', 'gre', 'bp-stealth')]
        with patch('builtins.input', side_effect=['2', '2', '2', '1']), patch('pronet.cli.say'):
            self.assertEqual(choose_carriers(rows, 3), ['gre', 'bp-stealth', 'frp-tls'])
        with patch('builtins.input', return_value='1'), patch('pronet.cli.say'):
            self.assertEqual(choose_carriers(rows, 3), [])

    def test_pending_choice_is_visible_only_in_owner_authenticated_overview(self):
        owner = self.store.overview(self.iran)['pairs'][0]['result']
        self.assertEqual(owner['selection_prompt']['token'], 'choice-1')
        self.assertNotIn('selection_prompt', self.store.overview(self.foreign)['pairs'][0]['result'])
        self.assertNotIn('selection_prompt', self.store.overview()['pairs'][0]['result'])

    def test_controller_waits_for_explicit_selection_and_honors_timeout(self):
        controller = Controller(self.store)
        pair = self.store.pair(self.id)
        result = {'live': {}, 'results': []}
        chosen = {}
        def run():
            chosen['value'] = controller.operator_selection(pair, result,
                [{'profile': 'gre'}, {'profile': 'frp-tls'}], 2, timeout=3)
        worker = threading.Thread(target=run); worker.start()
        import time
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            current = self.store.pair(self.id)['result']
            if current.get('selection_prompt', {}).get('token') != 'choice-1': break
            time.sleep(.01)
        self.choose(['gre', 'frp-tls'], token=current['selection_prompt']['token'])
        worker.join(4)
        self.assertEqual(chosen['value'], ['gre', 'frp-tls'])
        with self.assertRaisesRegex(PronetError, 'timed out'):
            controller.operator_selection(pair, result, [{'profile': 'gre'}], 1, timeout=0)

    def test_new_join_command_does_not_expire_but_is_single_use_and_revocable(self):
        store = self.store
        enroll = self.enrollment
        # A new server pair stays joinable months later, without a four-digit secret.
        created = store.create_pair(self.iran, {'name': 'durable', 'public_ip': '192.0.2.10'})
        self.assertEqual(len(created['code']), 32)
        self.assertIsNone(created['expires_in'])
        from pronet.cli import make_token, parse_token
        bootstrap = {'hub_url': 'https://192.0.2.1:9443', 'enrollment_key': enroll}
        self.assertEqual(parse_token(make_token(bootstrap, 2053, created['code']))['c'], created['code'])
        enrolled = store.enroll(enroll, {'name': 'later', 'role': 'foreign', 'public_ip': '192.0.2.20', 'bind_ip': '192.0.2.20'})
        foreign = store.authenticate(enrolled['node_id']+':'+enrolled['node_secret'])
        with patch.object(store, 'clock', return_value=store.clock()+365*86400):
            store.join_pair(foreign, created['code'])
            with self.assertRaises(PronetError): store.join_pair(foreign, created['code'])
        revoked = store.create_pair(self.iran, {'name': 'revoked', 'public_ip': '192.0.2.11'})
        store.request_stop(self.iran, revoked['pair_id'])
        with self.assertRaises(PronetError): store.join_pair(foreign, revoked['code'])

    def test_waiting_retires_old_trials_before_prompt_to_reset_service_lifetime(self):
        controller = Controller(self.store)
        running = {'gre', 'frp-tls'}
        with patch.object(controller, 'both') as operation:
            with self.assertRaisesRegex(PronetError, 'timed out'):
                controller.operator_selection(self.store.pair(self.id), {'live': {}},
                    [{'profile': 'gre'}], 1, timeout=0, running=running)
        self.assertEqual(running, set())
        self.assertEqual(operation.call_args.args[1], 'retire_batch')
        self.assertEqual(operation.call_args.args[2]['iran']['profiles'], ['frp-tls', 'gre'])

    def test_balanced_gaming_uses_two_long_runs_and_thorough_keeps_three(self):
        from pronet.controller import qualification_runs
        self.assertEqual(qualification_runs({'gaming': True, 'quality': 'balanced'}), 2)
        self.assertEqual(qualification_runs({'gaming': True, 'quality': 'thorough'}), 3)
        self.assertEqual(qualification_runs({'gaming': False, 'quality': 'balanced'}), 1)


if __name__ == '__main__': unittest.main()
