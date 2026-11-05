"""Regression coverage for interrupted retirement and failed setup cleanup."""
import pathlib
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

from pronet import cli, runtime
from pronet.common import PronetError, read_json, write_json
from pronet.controller import Controller
from pronet.report import final_report

PAIR = 'a' * 24
UNIT = 'pronetf-' + PAIR + '-foreign-1-engine.service'


def shown(state='inactive', main='0', control='0', code=0):
    return subprocess.CompletedProcess([], code,
        'LoadState=loaded\nActiveState=%s\nSubState=dead\nResult=success\nMainPID=%s\nControlPID=%s\n' % (state, main, control), '')


class StopTests(unittest.TestCase):
    def stop(self, replies, stop=None):
        with mock.patch.object(runtime, 'service', return_value=stop or subprocess.CompletedProcess([], 0, '', '')), \
             mock.patch.object(runtime, 'command', side_effect=replies), mock.patch.object(runtime.time, 'sleep'):
            runtime.stop_confirmed(UNIT)

    def test_inactive_and_failed_units_with_no_processes_can_be_removed(self):
        for state in ('inactive', 'failed'):
            self.stop([shown(state)])

    def test_stop_can_settle_after_a_canceled_stop_job(self):
        self.stop([shown('deactivating', control='12'), shown()], subprocess.CompletedProcess([], 1, '', 'Job canceled'))

    def test_live_or_unknown_units_keep_ownership_and_identify_the_unit(self):
        for reply in (shown('active', main='123'), shown('failed', main='123'),
                      subprocess.CompletedProcess([], 1, '', 'DBus unavailable'),
                      subprocess.CompletedProcess([], 0, '', '')):
            with self.assertRaises(PronetError) as error:
                self.stop([reply])
            self.assertIn(UNIT, str(error.exception))
            self.assertIn('ownership files retained', str(error.exception))

    def test_deactivating_unit_has_a_bounded_settle_window(self):
        with mock.patch.object(runtime, 'service', return_value=subprocess.CompletedProcess([], 0, '', '')), \
             mock.patch.object(runtime, 'command', return_value=shown('deactivating', control='12')), \
             mock.patch.object(runtime.time, 'monotonic', side_effect=[0, 6]), \
             self.assertRaisesRegex(PronetError, 'ActiveState=deactivating'):
            runtime.stop_confirmed(UNIT)

    def test_stop_timeout_is_followed_by_state_verification(self):
        with mock.patch.object(runtime, 'service', side_effect=PronetError('stop timeout')), \
             mock.patch.object(runtime, 'command', return_value=shown()):
            runtime.stop_confirmed(UNIT)

    def test_unconfirmed_stop_does_not_unlink_the_owned_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            r = object.__new__(runtime.Runtime)
            r.root = root
            r.validate = lambda p: p
            write_json(root / PAIR / 'frp-tls' / 'plan.json', {'role': 'foreign'})
            unit = root / 'unit.service'
            unit.write_text('# Pronet Fleet owner=' + PAIR + '\n')
            with mock.patch.object(runtime, 'unit_path', return_value=unit), \
                 mock.patch.object(runtime, 'service'), \
                 mock.patch.object(runtime, 'stop_confirmed', side_effect=PronetError('still running')), \
                 self.assertRaisesRegex(PronetError, 'still running'):
                r.remove_profile(PAIR, 'frp-tls')
            self.assertTrue(unit.exists())
            self.assertFalse((root / PAIR / 'frp-tls' / 'retired.json').exists())


class CleanupTests(unittest.TestCase):
    def test_incomplete_batch_cleanup_does_not_claim_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = object.__new__(runtime.Runtime)
            r.root = pathlib.Path(tmp)
            r.identity = {'role': 'foreign'}
            directory = r.root / PAIR
            for profile in ('frp-tls', 'bp-stealth'):
                write_json(directory / profile / 'plan.json', {})
            write_json(directory / 'active.json', {'gateway': 'active'})
            r.retire_batch = mock.Mock(side_effect=PronetError('still running'))
            with mock.patch.object(runtime, 'command'), self.assertRaisesRegex(PronetError, 'Cleanup incomplete'):
                r.cleanup(PAIR)
            r.retire_batch.assert_called_once()
            self.assertEqual(set(r.retire_batch.call_args.args[1]), {'frp-tls', 'bp-stealth'})
            self.assertFalse((directory / 'stopped.json').exists())
            self.assertTrue((directory / 'active.json').exists())

    def test_report_never_claims_cleanup_without_confirmation(self):
        for result in ({'error': 'stop failed'}, {'error': 'stop failed', 'cleanup_confirmed': False,
                        'failed_phase': 'measuring', 'warnings': ['Cleanup unconfirmed: foreign still running']}):
            text = '\n'.join(final_report({'state': 'FAILED', 'result': result}))
            self.assertIn('Cleanup is NOT confirmed', text)
            self.assertNotIn('Both servers were cleaned up', text)
            self.assertNotIn('Nothing was activated', text)
        self.assertIn('Cleanup unconfirmed: foreign still running', text)
        self.assertIn('Stage', text)

    def test_status_shows_latest_failure_instead_of_no_tunnel_yet(self):
        data = {'pairs': [
            {'id': PAIR, 'state': 'FAILED', 'request': {'name': 'new'}, 'result': {'error': 'stop failed'}},
            {'id': 'b' * 24, 'state': 'FAILED', 'request': {'name': 'old'}, 'result': {'error': 'old error'}}]}
        lines = []
        with mock.patch.object(cli, 'say', side_effect=lines.append), mock.patch.object(cli, 'hub_config', return_value={}):
            cli.display(data)
        text = '\n'.join(lines)
        self.assertIn('stop failed', text)
        self.assertIn('sudo pronet report ' + PAIR, text)
        self.assertNotIn('No tunnel yet', text)
        self.assertNotIn('old error', text)


class PipelineTests(unittest.TestCase):
    def controller(self):
        return Controller(mock.Mock()), [{'profile': 'frp-tls'}, {'profile': 'bp-stealth'}]

    def test_retirement_failure_never_starts_another_group(self):
        c, plans = self.controller()
        started = []
        def start(pair, batch, number, result, running):
            started.append(number)
            running.add(batch[0]['profile'])
            return []
        c.start_group = start
        c.both = mock.Mock(side_effect=PronetError('foreign stop failed'))
        with mock.patch('pronet.controller.screen_batches', return_value=[[plans[0]], [plans[1]]]), \
             self.assertRaisesRegex(PronetError, 'foreign stop failed'):
            c.screen_all({'id': PAIR}, plans, {'results': [], 'live': {}}, set())
        self.assertEqual(started, [0])

    def test_host_changes_on_both_nodes_stay_outside_measurements(self):
        c, plans = self.controller()
        order = []
        def start(pair, batch, number, result, running):
            order.append(('start', number))
            running.add(batch[0]['profile'])
            return batch
        def measure(pair, batch, number, result):
            order.append(('measure-start', number))
            time.sleep(.02)
            order.append(('measure-end', number))
        c.start_group, c.measure_group = start, measure
        c.both = lambda pair, op, payload, step: order.append(('retire', int(step.rsplit(':', 1)[1])))
        with mock.patch('pronet.controller.screen_batches', return_value=[[plans[0]], [plans[1]]]):
            c.screen_all({'id': PAIR}, plans, {'results': [], 'live': {}}, set())
        self.assertEqual(order, [('start', 0), ('measure-start', 0), ('measure-end', 0), ('retire', 0),
                                 ('start', 1), ('measure-start', 1), ('measure-end', 1), ('retire', 1)])


class BatchRetirementTests(unittest.TestCase):
    def run_retirement(self, fail_echo=False):
        with tempfile.TemporaryDirectory() as tmp:
            r = object.__new__(runtime.Runtime)
            r.root = pathlib.Path(tmp)
            r.identity = {'role': 'foreign'}
            r.validate = lambda p: p
            profiles = ['frp-tls', 'bp-stealth']
            units = r.root / 'units'
            units.mkdir()
            for profile in profiles:
                write_json(r.root / PAIR / profile / 'plan.json', {'role': 'foreign'})
                for kind in ('echo', 'engine'):
                    (units / runtime.unit_name(PAIR, profile, kind, 'foreign')).write_text('# Pronet Fleet owner=' + PAIR + '\n')
            bad = runtime.unit_name(PAIR, profiles[0], 'echo', 'foreign')
            def confirm(name, *args):
                if fail_echo and name == bad:
                    raise PronetError('live process in ' + name)
            calls = []
            def command(args, **kwargs):
                calls.append(args)
                return subprocess.CompletedProcess(args, 0, '', '')
            with mock.patch.object(runtime, 'unit_path', side_effect=lambda name: units / name), \
                 mock.patch.object(runtime, 'command', side_effect=command), \
                 mock.patch.object(runtime, 'service') as service, \
                 mock.patch.object(runtime, 'confirm_stopped', side_effect=confirm), \
                 mock.patch.object(runtime, 'managed_firewall'):
                if fail_echo:
                    with self.assertRaisesRegex(PronetError, 'live process'):
                        r.retire_batch(PAIR, profiles)
                else:
                    self.assertEqual(r.retire_batch(PAIR, profiles), {'retired': profiles})
                service.assert_not_called()
            self.assertEqual(sum(args[1] == 'stop' for args in calls), 1)
            self.assertEqual(sum(args[1] == 'disable' for args in calls), 1)
            self.assertEqual(sum(args[1] == 'daemon-reload' for args in calls), 1)
            disable = next(args for args in calls if args[1] == 'disable')
            self.assertIn('--no-reload', disable)
            self.assertEqual(len(next(args for args in calls if args[1] == 'stop')[2:]), 4)
            self.assertEqual(sorted(path.name for path in units.iterdir()), [bad] if fail_echo else [])
            self.assertEqual((r.root / PAIR / profiles[0] / 'retired.json').exists(), not fail_echo)
            self.assertTrue((r.root / PAIR / profiles[1] / 'retired.json').exists())

    def test_batch_stops_all_carriers_together_with_one_reload(self):
        self.run_retirement()

    def test_unconfirmed_unit_is_retained_while_other_units_are_removed(self):
        self.run_retirement(True)


if __name__ == '__main__':
    unittest.main()
