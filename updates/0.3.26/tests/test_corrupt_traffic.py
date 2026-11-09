"""Optional traffic counters must never take down a tunnel or its watchdog."""
import asyncio
import pathlib
import tempfile
import unittest
from unittest import mock
from pronet import common, gaming, wire, runtime


class TrafficCacheTests(unittest.TestCase):
    def test_zeroed_and_malformed_statistics_do_not_crash_either_gateway(self):
        for payload in (b'\0'*275,b'{"rx_bytes":',b'null',b'[]',b'{"rx_bytes":"oops","tx_bytes":-2,"connections_total":true}',b'{"rx_bytes": NaN}'):
            with self.subTest(payload=payload[:30]),tempfile.TemporaryDirectory() as temp:
                root=pathlib.Path(temp);stats=root/'traffic.json';stats.write_bytes(payload)
                tcp=wire.Gateway(root/'gateway.json',stats)
                udp=gaming.Gateway(root/'gateway.json',stats)
                self.assertEqual([tcp.stats[k] for k in ('rx_bytes','tx_bytes','connections_total')],[0,0,0])
                self.assertEqual(list(udp.base.values()),[0,0,0])
                self.assertEqual(stats.read_bytes(),payload,'Reading telemetry must not rewrite configuration or state')
    def test_valid_counters_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);stats=root/'traffic.json'
            common.write_json(stats,{'rx_bytes':123,'tx_bytes':456,'connections_total':7})
            self.assertEqual(gaming.Gateway(root/'gateway.json',stats).base,{'rx_bytes':123,'tx_bytes':456,'connections_total':7})
            self.assertEqual(wire.Gateway(root/'gateway.json',stats).stats['rx_bytes'],123)
    def test_corrupt_configuration_still_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);config=root/'gateway.json';config.write_bytes(b'\0'*275)
            for factory in (wire.Gateway,gaming.Gateway):
                gateway=factory(config,root/'traffic.json')
                with self.assertRaises(ValueError):asyncio.run(gateway.start())
                self.assertEqual(config.read_bytes(),b'\0'*275)
    def test_invalid_statistics_do_not_break_status_or_traffic_liveness_check(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);directory=root/('a'*24);directory.mkdir();(directory/'traffic.json').write_bytes(b'\0'*275)
            instance=runtime.Runtime.__new__(runtime.Runtime);instance.root=root;instance.identity={'role':'foreign'}
            status=instance.status('a'*24)
            self.assertEqual(status['traffic']['rx_bytes'],0)
            instance.identity={'role':'iran'}
            self.assertFalse(instance.traffic_alive(directory,{'gaming':True,'subnet':'10.244.0.0/30','data_port':2053}))
    def test_unwritable_udp_statistics_do_not_fail_the_gateway_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);gateway=gaming.Gateway(root/'gateway.json',root/'traffic.json')
            gateway.settings={'active_backend':['127.0.0.1',2053]}
            with mock.patch.object(gaming,'write_json',side_effect=OSError('disk full')):
                gateway.snapshot()


if __name__=='__main__':unittest.main()
