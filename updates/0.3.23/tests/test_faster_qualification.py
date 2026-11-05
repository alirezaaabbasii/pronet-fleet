"""A short screen must never shorten final qualification or activation checks."""
import contextlib
import pathlib
import tempfile
import unittest
from unittest import mock

from pronet import gaming, runtime
from pronet.common import PronetError
from pronet.wire import LinkLock
from test_gaming import measured


class ScreenTests(unittest.TestCase):
    def test_gaming_only_explicit_initial_screen_uses_short_windows(self):
        stage = dict(measured()['gaming_stages']['idle'], echo_ms=[20]*10, load_reply_mbps=1)
        for kwargs, seconds in (({'screen_only': True}, 3), ({}, 6), ({'long_test': True}, 12)):
            with mock.patch.object(gaming, '_stage', return_value=dict(stage)) as sample, \
                    mock.patch.object(gaming, 'probe', return_value=20), mock.patch.object(gaming.time, 'sleep'):
                row = gaming.benchmark(('127.0.0.1', 1), 'a'*64, **kwargs)
            self.assertTrue(row['passed'], row)
            self.assertEqual([call.args[2] for call in sample.call_args_list], [seconds, seconds])

    def test_runtime_keeps_verification_and_thorough_screen_at_full_size(self):
        engine = runtime.Runtime.__new__(runtime.Runtime)
        engine.validate = lambda p: p
        engine.echo = lambda *args: 20
        for extra, size, idle in (({'screen_only': True}, 262144, 1),
                ({}, 1048576, 3), ({'screen_only': True, 'test_quality': 'thorough'},1048576,3),
                ({'screen_only':True,'long_test':True},4194304,10)):
            plan = dict(profile='frp-tls',token='a'*64,test_quality='balanced'); plan.update(extra)
            with mock.patch.object(runtime.engines,'probe_address',return_value=('127.0.0.1',1)), \
                    mock.patch.object(runtime,'benchmark',return_value={'passed':True}) as bench:
                engine.measure(plan)
            arguments = bench.call_args.kwargs
            self.assertEqual(arguments.get('size',1048576),size)
            self.assertEqual(arguments.get('idle',3),idle)
            if extra.get('screen_only') and not extra.get('long_test'):
                self.assertEqual(arguments.get('rounds',5),5)


class StartBatchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.engine = runtime.Runtime.__new__(runtime.Runtime)
        self.plans=[]
        for name in ('frp-tls','chisel'):
            self.plans.append(dict(pair_id='a'*24,profile=name,role='iran',token='b'*64,inbound_port=2053))
            directory=pathlib.Path(self.directory.name)/name;directory.mkdir()
            runtime.write_json(directory/'plan.json', self.plans[-1])
        self.engine.directory = lambda p: pathlib.Path(self.directory.name)/p['profile']
        self.engine.write_services = lambda *args,**kwargs: None

    def tearDown(self): self.directory.cleanup()

    def test_batch_reloads_once_and_preserves_already_running_units(self):
        active = 'pronetf-'+ 'a'*24 + '-iran-7-engine.service'  # stable frp-tls resource index
        with mock.patch.object(runtime.engines,'install_asset',return_value={}), \
                mock.patch.object(runtime.engines,'render',return_value={'validate':[]}), \
                mock.patch.object(runtime,'command') as command, \
                mock.patch.object(runtime,'active_states',side_effect=lambda names:{name:name==active for name in names}), \
                mock.patch.object(runtime,'service') as service:
            result=self.engine.start_batch(self.plans)['profiles']
        self.assertTrue(all(row.get('started') for row in result.values()),result)
        self.assertEqual(sum(call.args[0]==['systemctl','daemon-reload'] for call in command.call_args_list),1)
        starts=[call.args[0] for call in service.call_args_list if call.args[1]=='start']
        self.assertNotIn(active, starts)
        self.assertEqual(len(starts),3)

    def test_manager_reload_failure_reports_all_staged_profiles_without_starting(self):
        with mock.patch.object(runtime.engines,'install_asset',return_value={}),                 mock.patch.object(runtime.engines,'render',return_value={'validate':[]}),                 mock.patch.object(runtime,'command',side_effect=PronetError('manager busy')),                 mock.patch.object(runtime,'service') as service:
            result=self.engine.start_batch(self.plans)['profiles']
        self.assertEqual(set(result), {'frp-tls','chisel'})
        self.assertTrue(all('manager busy' in row['error'] for row in result.values()))
        service.assert_not_called()

    def test_one_invalid_profile_does_not_block_other_staged_profile(self):
        original = self.engine.directory
        def directory(plan):
            if plan['profile']=='chisel': raise PronetError('ownership changed')
            return original(plan)
        self.engine.directory=directory
        with mock.patch.object(runtime.engines,'install_asset',return_value={}), \
                mock.patch.object(runtime.engines,'render',return_value={'validate':[]}), \
                mock.patch.object(runtime,'command'), \
                mock.patch.object(runtime,'active_states',side_effect=lambda names:dict.fromkeys(names,False)), \
                mock.patch.object(runtime,'service'):
            result=self.engine.start_batch(self.plans)['profiles']
        self.assertTrue(result['frp-tls']['started'])
        self.assertIn('ownership changed',result['chisel']['error'])


if __name__=='__main__':unittest.main()
