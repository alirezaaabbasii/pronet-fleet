"""Unstable carriers, second standby, background repair (0.3.9)."""
import json
import pathlib
import tempfile
import time
import unittest
from unittest import mock

from pronet import runtime as rt
from pronet.common import read_json, write_json
from pronet.controller import Controller, RETEST_AFTER
from pronet.model import ranking


class Base(unittest.TestCase):
    profiles = ("frp-tls", "bp-l3-pck-reverse", "bp-stealth")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.runtime = object.__new__(rt.Runtime)
        self.runtime.identity = {"role": "iran"}
        self.runtime.root = pathlib.Path(self.tmp.name)
        self.dir = self.runtime.root / ("a" * 24)
        self.dir.mkdir()
        write_json(self.dir / "active.json", {})
        write_json(self.dir / "selection.json", {"profiles": list(self.profiles), "active": self.profiles[0],
                                                 "failures": 0, "switches": [], "auto_paused": False})
        write_json(self.dir / "gateway.json", {"active_backend": [self.profiles[0], 1]})
        for name in self.profiles:
            write_json(self.dir / name / "plan.json", {"probe": name, "token": "t"})
        self.patches = [mock.patch("pronet.runtime.engines.probe_address", side_effect=lambda p: p["probe"]),
                        mock.patch("pronet.runtime.engines.data_address", side_effect=lambda p: (p["probe"], 1))]
        for item in self.patches: item.start()
        self.runtime.validate = lambda p: p
        self.clock = [100000.0]
        self.time = mock.patch("pronet.runtime.time.time", side_effect=lambda: self.clock[0])
        self.time.start()

    def tearDown(self):
        self.time.stop()
        for item in reversed(self.patches): item.stop()
        self.tmp.cleanup()

    def cycles(self, down, count):
        """down(name, cycle) -> True when that carrier fails this cycle."""
        for cycle in range(count):
            def probe(address, *_):
                if down(address, cycle):
                    raise TimeoutError("down")
                return 100.0
            with mock.patch("pronet.runtime.echo", side_effect=probe):
                self.runtime.watchdog()
            self.clock[0] += 60

    def selection(self):
        return read_json(self.dir / "selection.json")

    def events(self):
        path = self.dir / "events.jsonl"
        return [json.loads(line)["event"] for line in path.read_text().splitlines()] if path.exists() else []


class UnstableTests(Base):
    def test_flapping_standby_is_flagged_and_never_preferred(self):
        # Standby drops for one probe every fourth cycle (like the real log).
        self.cycles(lambda name, c: name == "bp-l3-pck-reverse" and c % 4 == 3, 16)
        health = self.selection()["standby_health"]
        self.assertTrue(health["bp-l3-pck-reverse"]["unstable"])
        self.assertFalse(health["bp-stealth"]["unstable"])
        self.assertIn("STANDBY_UNSTABLE", self.events())
        # Primary dies: the stable standby is chosen, not the flapping one.
        self.cycles(lambda name, c: name == "frp-tls", 2)
        self.assertEqual(self.selection()["active"], "bp-stealth")

    def test_unstable_primary_moves_new_connections_to_a_proven_standby(self):
        # Each primary outage is one probe: shorter than the failover threshold.
        self.cycles(lambda name, c: name == "frp-tls" and c % 3 == 2, 9)
        selected = self.selection()
        self.assertNotEqual(selected["active"], "frp-tls")
        gateway = read_json(self.dir / "gateway.json")
        self.assertNotIn("failed_backends", gateway, "established sessions are not cut for an unstable primary")
        self.assertTrue(any("primary unstable" in line for line in (self.dir / "events.jsonl").read_text().splitlines()))

    def test_unstable_switch_respects_the_switch_budget(self):
        selected = self.selection()
        selected["switches"] = [self.clock[0] - 10] * 3
        write_json(self.dir / "selection.json", selected)
        self.cycles(lambda name, c: name == "frp-tls" and c % 3 == 2, 9)
        self.assertEqual(self.selection()["active"], "frp-tls")

    def test_all_paths_down_is_recorded_and_cleared(self):
        self.cycles(lambda name, c: True, 3)
        self.assertIsNotNone(self.selection().get("all_down_since"))
        self.cycles(lambda name, c: False, 1)
        self.assertIsNone(self.selection().get("all_down_since"))
        self.assertEqual(self.events().count("ALL_PATHS_DOWN"), 1)
        self.assertEqual(self.events().count("PATH_RESTORED"), 1)

    def test_history_stays_local_and_bounded(self):
        self.cycles(lambda name, c: False, 3)
        self.assertIn("history", self.selection())
        with mock.patch("pronet.runtime.is_active", return_value=True), mock.patch("pronet.runtime.recent_events", return_value=[]):
            for name in self.profiles:
                write_json(self.dir / name / "plan.json", {"probe": name, "token": "t", "role": "iran"})
            heartbeat = self.runtime.status("a" * 24)
        self.assertNotIn("history", heartbeat["selection"], "probe history is not sent to the coordinator")
        rows = rt.record_probe([[self.clock[0] - 10, 1]] * 1000, True, self.clock[0])
        self.assertLessEqual(len(rows), rt.HISTORY_LIMIT)
        self.assertEqual(rt.record_probe([[self.clock[0] - 4000, 0]], True, self.clock[0]), [[self.clock[0], 1]])


class SelectionTests(unittest.TestCase):
    def test_second_standby_prefers_a_third_family(self):
        def row(name, mbps):
            return {"profile": name, "passed": True, "echo_ms": [50, 51], "success_ratio": 1, "upload_mbps": mbps,
                    "download_mbps": mbps, "half_close": True, "after_idle": True, "integrity": True}
        rows = [row("frp-tls", 20), row("bp-stealth", 19), row("bp-l3-pck-reverse", 15), row("bp-l3-udp-reverse", 12)]
        names = [r["profile"] for r in ranking(rows, 2)]
        self.assertEqual(names, ["frp-tls", "bp-l3-pck-reverse", "bp-l3-udp-reverse"])
        self.assertEqual(len(ranking(rows, 1)), 2)


class MaintenanceTests(unittest.TestCase):
    def controller(self, result):
        store = mock.Mock()
        store.pair.return_value = {"result": result}
        return Controller(store)

    def test_retest_only_after_a_sustained_full_outage_and_budget(self):
        now = 1000000
        c = self.controller({"results": [], "maintenance": {}})
        self.assertIsNone(c.maintenance_task({"id": "p"}, {"all_down_since": now - 60}, now))
        self.assertEqual(c.maintenance_task({"id": "p"}, {"all_down_since": now - RETEST_AFTER}, now), "retest")
        c = self.controller({"results": [], "maintenance": {"next_retest_at": now + 10}})
        self.assertIsNone(c.maintenance_task({"id": "p"}, {"all_down_since": now - RETEST_AFTER}, now))

    def test_replace_needs_healthy_primary_unstable_standby_and_a_reserve(self):
        now = 1000000
        ok = {"profile": "rathole-noise", "passed": True, "echo_ms": [50], "success_ratio": 1, "upload_mbps": 5,
              "download_mbps": 5, "half_close": True, "after_idle": True, "integrity": True}
        runtime = {"link": "UP", "profiles": ["frp-tls", "bp-l3-pck-reverse"],
                   "standby_health": {"bp-l3-pck-reverse": {"unstable": True}}}
        c = self.controller({"results": [ok], "selected": ["frp-tls", "bp-l3-pck-reverse"], "maintenance": {}})
        self.assertEqual(c.maintenance_task({"id": "p"}, runtime, now), "replace")
        self.assertIsNone(c.maintenance_task({"id": "p"}, dict(runtime, link="UNCONFIRMED"), now))
        c = self.controller({"results": [ok], "maintenance": {"unstable_seen": {"rathole-noise": now - 60}}})
        self.assertIsNone(c.maintenance_task({"id": "p"}, runtime, now), "a recently unstable carrier is no reserve")


class IdleAgentTests(unittest.TestCase):
    def test_measure_lane_makes_no_requests_while_idle(self):
        from pronet import agent
        instance = object.__new__(agent.Agent)
        import threading
        instance.stop = threading.Event()
        instance.measure_jobs = threading.BoundedSemaphore(2)
        calls = []
        instance.client = mock.Mock(call=lambda *a, **k: calls.append(a) or {"job": None})
        instance.last_job = time.monotonic() - agent.BUSY_WINDOW - 1
        waits = []
        def wait(seconds):
            waits.append(seconds)
            if len(waits) > 5:
                instance.stop.set()
            return instance.stop.is_set()
        with mock.patch.object(instance.stop, "wait", side_effect=wait):
            instance.measure_loop()
        self.assertEqual(calls, [], "an idle agent must not hold extra connections to the hub")


if __name__ == "__main__":
    unittest.main()
