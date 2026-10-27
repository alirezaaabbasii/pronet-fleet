import json
import pathlib
import tempfile
import unittest
from unittest import mock

from pronet.common import read_json, write_json
from pronet.runtime import Runtime


class StandbyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.runtime = object.__new__(Runtime)
        self.runtime.identity = {"role": "iran"}
        self.runtime.root = pathlib.Path(self.tmp.name)
        self.directory = self.runtime.root / ('a' * 24)
        self.directory.mkdir()
        self.primary, self.backup = 'bp-l3-pck', 'bp-l3-udp-reverse'
        write_json(self.directory / 'active.json', {})
        write_json(self.directory / 'selection.json', {
            'profiles': [self.primary, self.backup], 'active': self.primary,
            'failures': 0, 'switches': [], 'auto_paused': False})
        write_json(self.directory / 'gateway.json', {'active_backend': ['primary', 2053]})
        for profile, address in [(self.primary, 'primary'), (self.backup, 'backup')]:
            write_json(self.directory / profile / 'plan.json', {'probe': address, 'token': 'test-secret'})
        self.stack = []
        for name, value in [('pronet.runtime.engines.probe_address', lambda p: p['probe']),
                            ('pronet.runtime.engines.data_address', lambda p: (p['probe'], 2053))]:
            patcher = mock.patch(name, side_effect=value)
            self.stack.append(patcher); patcher.start()
        self.runtime.validate = lambda p: p

    def tearDown(self):
        for patcher in reversed(self.stack): patcher.stop()
        self.tmp.cleanup()

    def test_healthy_primary_still_probes_warm_standby(self):
        with mock.patch('pronet.runtime.echo', return_value=220) as probe:
            self.runtime.watchdog()
        self.assertEqual([x.args[0] for x in probe.call_args_list], ['primary', 'backup'])
        selected = read_json(self.directory / 'selection.json')
        self.assertEqual(selected['standby_health'][self.backup]['state'], 'OK')
        self.assertEqual(selected['active'], self.primary)
        self.assertEqual(read_json(self.directory / 'gateway.json')['active_backend'], ['primary', 2053])

    def test_backup_loss_and_recovery_are_reported_without_switching_primary(self):
        def probe(address, *_):
            if address == 'backup': raise TimeoutError('idle path')
            return 220
        with mock.patch('pronet.runtime.echo', side_effect=probe):
            for _ in range(4): self.runtime.watchdog()
        selected = read_json(self.directory / 'selection.json')
        self.assertEqual(selected['active'], self.primary)
        self.assertEqual(selected['failures'], 0)
        self.assertFalse(selected['auto_paused'])
        self.assertEqual(selected['standby_health'][self.backup]['failures'], 4)
        with mock.patch('pronet.runtime.echo', return_value=221): self.runtime.watchdog()
        health = read_json(self.directory / 'selection.json')['standby_health'][self.backup]
        self.assertEqual((health['state'], health['failures']), ('OK', 0))
        events = [json.loads(line)['event'] for line in (self.directory / 'events.jsonl').read_text().splitlines()]
        self.assertEqual(events.count('STANDBY_UNCONFIRMED'), 1)
        self.assertEqual(events.count('STANDBY_RECOVERED'), 1)

    def test_no_switch_when_standby_is_also_down_and_primary_is_kept(self):
        with mock.patch('pronet.runtime.echo', side_effect=TimeoutError('both down')):
            for _ in range(5): self.runtime.watchdog()
        selected = read_json(self.directory / 'selection.json')
        self.assertEqual(selected['active'], self.primary)
        self.assertEqual(selected['switches'], [])
        self.assertEqual(read_json(self.directory / 'gateway.json')['active_backend'], ['primary', 2053])

    def test_primary_loss_still_switches_to_verified_backup(self):
        def probe(address, *_):
            if address == 'primary': raise TimeoutError('primary stopped')
            return 220
        with mock.patch('pronet.runtime.echo', side_effect=probe):
            for _ in range(2): self.runtime.watchdog()
        selected = read_json(self.directory / 'selection.json')
        self.assertEqual(selected['active'], self.backup)
        self.assertEqual(read_json(self.directory / 'gateway.json')['active_backend'], ['backup', 2053])
        self.assertEqual(len(selected['switches']), 1)


    def test_failover_rearms_after_both_paths_return(self):
        # Both paths down (e.g. foreign server quota exhausted): no switch, pause.
        with mock.patch('pronet.runtime.echo', side_effect=TimeoutError('server offline')):
            for _ in range(4): self.runtime.watchdog()
        selected = read_json(self.directory / 'selection.json')
        self.assertTrue(selected['auto_paused'])
        self.assertEqual(selected['active'], self.primary)
        # Recharged: primary healthy again -> failover re-armed after ~1 minute.
        with mock.patch('pronet.runtime.echo', return_value=50):
            self.runtime.watchdog()
            self.assertTrue(read_json(self.directory / 'selection.json')['auto_paused'])
            self.runtime.watchdog()
        selected = read_json(self.directory / 'selection.json')
        self.assertFalse(selected['auto_paused'])
        self.assertEqual(selected['active'], self.primary)
        events = [json.loads(l)['event'] for l in (self.directory / 'events.jsonl').read_text().splitlines()]
        self.assertIn('AUTO_FAILOVER_REARMED', events)

    def test_standby_recovery_rearms_even_if_primary_stays_dead(self):
        with mock.patch('pronet.runtime.echo', side_effect=TimeoutError('both down')):
            for _ in range(3): self.runtime.watchdog()
        self.assertTrue(read_json(self.directory / 'selection.json')['auto_paused'])
        def probe(address, *_):
            if address == 'primary': raise TimeoutError('still dead')
            return 30
        with mock.patch('pronet.runtime.echo', side_effect=probe):
            self.runtime.watchdog()
            self.assertEqual(read_json(self.directory / 'selection.json')['active'], self.primary)
            self.runtime.watchdog()
        selected = read_json(self.directory / 'selection.json')
        self.assertEqual(selected['active'], self.backup)
        self.assertFalse(selected['auto_paused'])
        self.assertEqual(len(selected['switches']), 1)

    def test_one_lucky_backup_reply_does_not_cause_switch(self):
        with mock.patch('pronet.runtime.echo', side_effect=TimeoutError('both down')):
            for _ in range(3): self.runtime.watchdog()
        def probe(address, *_):
            if address == 'primary': raise TimeoutError('dead')
            return 30
        with mock.patch('pronet.runtime.echo', side_effect=probe): self.runtime.watchdog()
        selected = read_json(self.directory / 'selection.json')
        self.assertEqual(selected['active'], self.primary)
        self.assertEqual(selected['standby_health'][self.backup]['healthy_probes'], 1)
        self.assertTrue(selected['auto_paused'])

    def test_old_backup_successes_do_not_count_after_long_monitoring_gap(self):
        import time
        selected = read_json(self.directory / 'selection.json')
        selected.update(failures=10, standby_health={self.backup: {
            'state': 'OK', 'healthy_probes': 100, 'checked_at': time.time() - 600}})
        write_json(self.directory / 'selection.json', selected)
        def probe(address, *_):
            if address == 'primary': raise TimeoutError('dead')
            return 30
        with mock.patch('pronet.runtime.echo', side_effect=probe): self.runtime.watchdog()
        selected = read_json(self.directory / 'selection.json')
        self.assertEqual(selected['active'], self.primary)
        self.assertEqual(selected['standby_health'][self.backup]['healthy_probes'], 1)

    def test_recovered_backup_cannot_bypass_exhausted_switch_budget(self):
        import time
        selected = read_json(self.directory / 'selection.json')
        history = [time.time() - 10, time.time() - 20, time.time() - 30]
        selected.update(auto_paused=True, switches=history, pause_reason='switch-budget')
        write_json(self.directory / 'selection.json', selected)
        def probe(address, *_):
            if address == 'primary': raise TimeoutError('dead')
            return 30
        with mock.patch('pronet.runtime.echo', side_effect=probe):
            for _ in range(4): self.runtime.watchdog()
        selected = read_json(self.directory / 'selection.json')
        self.assertEqual(selected['active'], self.primary)
        self.assertEqual(selected['switches'], history)
        self.assertTrue(selected['auto_paused'])

    def test_switching_rearms_after_budget_window_expires(self):
        import time
        selected = read_json(self.directory / 'selection.json')
        selected.update(auto_paused=True, switches=[time.time()-1900]*3, pause_reason='switch-budget')
        write_json(self.directory / 'selection.json', selected)
        def probe(address, *_):
            if address == 'primary': raise TimeoutError('dead')
            return 30
        with mock.patch('pronet.runtime.echo', side_effect=probe):
            for _ in range(2): self.runtime.watchdog()
        selected = read_json(self.directory / 'selection.json')
        self.assertEqual(selected['active'], self.backup)
        self.assertEqual(len(selected['switches']), 1)

    def test_failover_delay_setting_changes_the_threshold(self):
        import tempfile as tf
        from pronet import runtime
        with tf.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / 'settings.json'
            with mock.patch.object(runtime, 'SETTINGS', path):
                self.assertEqual((runtime.probe_seconds(), runtime.failover_probes()), (60, 2))
                write_json(path, {'failover_seconds': 300})
                self.assertEqual(runtime.failover_probes(), 5)
                write_json(path, {'failover_seconds': 300, 'probe_seconds': 30})
                self.assertEqual(runtime.failover_probes(), 10)
                write_json(path, {'failover_seconds': 5, 'probe_seconds': 1})
                self.assertEqual((runtime.probe_seconds(), runtime.failover_probes()), (60, 2), 'out-of-range values fall back')


if __name__ == '__main__': unittest.main()
