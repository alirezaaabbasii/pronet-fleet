"""Persistent switch budgets and operator-controlled carrier exploration."""
import pathlib
import tempfile
import time
import unittest
from unittest import mock
from pronet.common import read_json, write_json, PronetError
from pronet.controller import Controller
from pronet.runtime import Runtime
from pronet import runtime as runtime_module, cli

PAIR = 'a' * 24

class CommitPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.r = object.__new__(Runtime)
        self.r.root = pathlib.Path(self.tmp.name)
        self.r.identity = {'role': 'iran'}
        self.r.validate = lambda p: p
        self.r.write_services = mock.Mock()
        self.r.remove_profile = mock.Mock()
        self.d = self.r.root / PAIR
        self.d.mkdir()
        self.primary, self.backup, self.third = 'bp-stealth', 'frp-tls', 'wstunnel-wss'
        for name in (self.primary, self.backup, self.third):
            write_json(self.d / name / 'plan.json', {'profile': name, 'role': 'iran'})
        self.now = time.time()
        self.history = [self.now - 10, self.now - 20, self.now - 30]
        write_json(self.d / 'selection.json', {'profiles': [self.primary, self.backup],
                    'active': self.primary, 'switches': self.history})
    def tearDown(self): self.tmp.cleanup()
    def commit(self, profiles, alive=True):
        with mock.patch('pronet.runtime.command'), mock.patch('pronet.runtime.service') as service, mock.patch('pronet.runtime.is_active', return_value=alive):
            self.r.commit(PAIR, profiles)
        return service.call_args_list
    def test_recommit_preserves_recent_global_switch_budget(self):
        self.commit([self.primary, self.backup])
        self.assertEqual(read_json(self.d / 'selection.json')['switches'], self.history)
    def test_controller_primary_change_also_spends_switch_budget(self):
        self.commit([self.backup, self.primary])
        switches = read_json(self.d / 'selection.json')['switches']
        self.assertEqual(switches[:-1], self.history)
        self.assertGreaterEqual(switches[-1], self.now)
    def test_agent_rejects_automatic_switch_even_if_hub_telemetry_is_stale(self):
        with self.assertRaises(PronetError):
            self.r.commit(PAIR, [self.backup, self.primary], automatic=True)
        self.r.write_services.assert_not_called()
        self.r.remove_profile.assert_not_called()
        self.assertEqual(read_json(self.d / 'selection.json')['active'], self.primary)
    def test_only_expired_switch_history_is_pruned(self):
        old = read_json(self.d / 'selection.json')
        old['switches'] += [self.now - 1900, self.now + 100, True, 'bad']
        write_json(self.d / 'selection.json', old)
        self.commit([self.primary, self.backup])
        self.assertEqual(read_json(self.d / 'selection.json')['switches'], self.history)
    def test_retained_live_services_are_not_restarted(self):
        calls = self.commit([self.backup, self.primary])
        self.assertFalse(any(c.args[1] == 'restart' for c in calls))
        self.assertEqual(sum(c.args[1] == 'enable' for c in calls), 4)
    def test_new_or_inactive_services_are_still_started(self):
        calls = self.commit([self.third, self.primary])
        restarts = [c for c in calls if c.args[1] == 'restart']
        self.assertEqual(len(restarts), 2)
        self.assertTrue(all('-19-' in c.args[0] for c in restarts))
        calls = self.commit([self.third, self.primary], alive=False)
        self.assertEqual(sum(c.args[1] == 'restart' for c in calls), 4)

class CoordinatorPolicyTests(unittest.TestCase):
    def fixture(self, mode=None):
        pair = {'id': PAIR, 'iran': 'i', 'foreign': 'f', 'state': 'ACTIVE', 'result': {},
                'runtime': {'link': 'UNCONFIRMED', 'recovery_paused': True, 'pause_id': 'b' * 24,
                    'health': {} if mode is None else {'recovery_policy': mode}}}
        store = mock.Mock()
        store.stopping.return_value = []
        store.pending.return_value = []
        store.overview.return_value = {'nodes': [{'id':'i','telemetry':'CURRENT'}, {'id':'f','telemetry':'CURRENT'}], 'pairs':[pair]}
        store.pair.return_value = pair
        c = Controller(store); c.launch = mock.Mock()
        return c, pair
    def test_stable_default_never_explores_new_protocols(self):
        c, pair = self.fixture()
        c.cycle(); c.cycle()
        c.launch.assert_not_called()
        self.assertEqual(pair['result']['recovery_hold']['state'], 'awaiting-operator')
        self.assertEqual(c.store.update_pair.call_count, 1)
    def test_exploration_requires_opt_in_and_can_be_enabled_after_hold(self):
        c, pair = self.fixture('stable'); c.cycle()
        pair['runtime']['health']['recovery_policy'] = 'explore'; c.cycle()
        c.launch.assert_called_once_with(PAIR, 'b' * 24)
    def test_unknown_policy_does_not_enable_exploration(self):
        c, _ = self.fixture('typo'); c.cycle(); c.launch.assert_not_called()
    def test_exploration_cannot_bypass_watchdog_switch_budget(self):
        c, pair = self.fixture('explore')
        pair['runtime']['health']['switches_30m'] = 3
        c.cycle(); c.launch.assert_not_called()
        pair['runtime']['health']['switches_30m'] = 0
        c.cycle(); c.launch.assert_called_once_with(PAIR, 'b' * 24)
    def test_hold_preserves_internal_state_missing_from_overview(self):
        c, pair = self.fixture()
        full = dict(pair, result={'recovery_starts': [123], 'private_internal_state': 'keep'})
        c.store.pair.return_value = full
        c.cycle(); c.cycle()
        self.assertEqual(full['result']['recovery_starts'], [123])
        self.assertEqual(full['result']['private_internal_state'], 'keep')
        self.assertEqual(c.store.update_pair.call_count, 1)
    def test_new_pause_ids_do_not_reset_recovery_work_budget(self):
        pair = {'id': PAIR, 'result': {'results': [], 'selected': []}}
        store = mock.Mock(); store.pair.return_value = pair
        c = Controller(store); c.both = mock.Mock(); c.rpc = mock.Mock()
        c.recover(PAIR, 'b' * 24)
        self.assertEqual(pair['result']['recovery']['state'], 'exhausted')
        c.recover(PAIR, 'c' * 24)
        self.assertEqual(pair['result']['recovery']['state'], 'cooldown')
        self.assertEqual(len(pair['result']['recovery_starts']), 1)
        c.both.assert_not_called(); c.rpc.assert_not_called()
    def test_expired_work_window_allows_one_new_bounded_episode(self):
        pair = {'id': PAIR, 'result': {'results': [], 'selected': [], 'recovery_starts':[time.time()-1900]}}
        store = mock.Mock(); store.pair.return_value = pair
        Controller(store).recover(PAIR, 'b' * 24)
        self.assertEqual(pair['result']['recovery']['state'], 'exhausted')
        self.assertEqual(len(pair['result']['recovery_starts']), 1)
        self.assertGreater(pair['result']['recovery_starts'][0], time.time()-5)

class SettingsPolicyTests(unittest.TestCase):
    def test_missing_invalid_and_explicit_policy(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(runtime_module,'SETTINGS',pathlib.Path(tmp)/'settings.json'):
            self.assertEqual(runtime_module.recovery_policy(),'stable')
            for v in ('typo', [], 1, None):
                write_json(runtime_module.SETTINGS,{'recovery_policy':v})
                self.assertEqual(runtime_module.recovery_policy(),'stable')
            write_json(runtime_module.SETTINGS,{'recovery_policy':'explore'})
            self.assertEqual(runtime_module.recovery_policy(),'explore')
    def test_foreign_cannot_set_iran_policy(self):
        with mock.patch.object(cli,'root_linux'), mock.patch.object(cli,'node_config',return_value={'role':'foreign'}):
            with self.assertRaises(PronetError): cli.set_recovery_policy('explore')

if __name__ == '__main__': unittest.main()
