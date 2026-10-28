"""Long grouped tests retain their lease and never execute twice concurrently."""
import concurrent.futures
import pathlib
import tempfile
import threading
import time
import unittest
from unittest import mock

from pronet import agent as agent_module
from pronet.agent import Agent, ProgressReporter
from pronet.common import PronetError, secret
from pronet.store import Store


class MeasurementLeaseTests(unittest.TestCase):
    def test_long_test_progress_renews_only_the_current_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = [1000.0]
            key = secret()
            store = Store(pathlib.Path(tmp) / 'hub.db', key, secret(), lambda: clock[0])
            nodes = []
            for number, role in ((1, 'iran'), (2, 'foreign')):
                creds = store.enroll(key, {'role': role, 'name': role, 'public_ip': '192.0.2.%d' % number,
                                          'bind_ip': '192.0.2.%d' % number})
                nodes.append(store.authenticate(creds['node_id'] + ':' + creds['node_secret']))
            pair = store.create_pair(nodes[0], {'name': 'lease', 'public_ip': '192.0.2.1', 'inbound_port': 2053})
            store.join_pair(nodes[1], pair['code'])
            job_id = store.enqueue(pair['pair_id'], nodes[0]['id'], 'benchmark_batch', {'plans': []}, 'measure')
            first = store.claim(nodes[0])
            clock[0] += 170
            store.job_progress_set(nodes[0], job_id, first['lease_proof'], {'frp-tls': {'phase': 'latency', 'pct': 100}})
            clock[0] += 20
            self.assertIsNone(store.claim(nodes[0]), 'active test must not be re-leased after its original 180 seconds')
            clock[0] += 180
            second = store.claim(nodes[0])
            self.assertEqual(second['id'], first['id'])
            self.assertNotEqual(second['lease_proof'], first['lease_proof'])
            with self.assertRaisesRegex(PronetError, 'superseded'):
                store.job_progress_set(nodes[0], job_id, first['lease_proof'], {})

    def test_reporter_refreshes_an_unchanged_queued_measurement_once_per_minute(self):
        client = mock.Mock()
        reporter = ProgressReporter(client, {'id': '1' * 24, 'lease_proof': 'proof'}, 1)
        reporter.done = mock.Mock()
        reporter.done.wait.side_effect = [False, False, False, True]
        with mock.patch.object(agent_module.time, 'monotonic', side_effect=[0, 30, 60]):
            reporter.run()
        self.assertEqual(client.call.call_count, 2)
        self.assertEqual(client.call.call_args_list[0], client.call.call_args_list[1])

    def test_duplicate_measurement_waits_for_cached_result_instead_of_testing_again(self):
        entered, release = threading.Event(), threading.Event()
        def execute(job):
            entered.set()
            if not release.wait(3):
                raise RuntimeError('test did not release measurement')
            return {'measured': True}
        runtime = mock.Mock(execute=mock.Mock(side_effect=execute))
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(agent_module, 'ROOT', pathlib.Path(tmp)):
            agent = Agent({}, runtime=runtime, client=mock.Mock())
            job = {'id': '1' * 24, 'pair_id': '2' * 24, 'op': 'benchmark', 'payload': {}}
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(agent.execute_job, job)
                self.assertTrue(entered.wait(1))
                second = pool.submit(agent.execute_job, dict(job))
                try:
                    time.sleep(.05)
                    self.assertEqual(runtime.execute.call_count, 1)
                finally:
                    release.set()
                self.assertEqual(first.result(timeout=2), second.result(timeout=2))
            self.assertEqual(runtime.execute.call_count, 1)


if __name__ == '__main__':
    unittest.main()
