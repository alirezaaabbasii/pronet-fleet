"""Faster setup without changing what is measured (0.3.8)."""
import pathlib
import tempfile
import threading
import time
import unittest
from unittest import mock

from pronet import wire
from pronet.common import secret
from pronet.controller import screen_batches
from pronet.model import DEFAULT_PROFILES
from pronet.wire import LinkLock, ProbeServer, benchmark


class LinkLockTests(unittest.TestCase):
    def test_transfers_never_overlap_and_pings_never_overlap_a_transfer(self):
        link, log, guard = LinkLock(), [], threading.Lock()
        state = {"exclusive": 0, "shared": 0}
        def worker(kind):
            with getattr(link, kind)():
                with guard:
                    state[kind] += 1
                    log.append((state["exclusive"], state["shared"]))
                time.sleep(.02)
                with guard:
                    state[kind] -= 1
        threads = [threading.Thread(target=worker, args=(kind,)) for kind in ["exclusive", "shared"] * 10]
        for thread in threads: thread.start()
        for thread in threads: thread.join(5)
        for exclusive, shared in log:
            self.assertLessEqual(exclusive, 1)
            self.assertFalse(exclusive and shared, "a latency sample overlapped a transfer")


class ParallelBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.keys = [secret() for _ in range(3)]
        self.servers = [ProbeServer(("127.0.0.1", 0), key) for key in self.keys]
        for server in self.servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def tearDown(self):
        for server in self.servers:
            server.shutdown(); server.server_close()

    def test_batch_overlaps_only_idle_waits_and_reports_real_progress(self):
        transfers, guard, active = [], threading.Lock(), [0]
        original = wire.bounded_socket
        def watched(address, timeout, deadline):
            # Every transfer opens a bounded socket inside the exclusive link
            # section (the idle check opens one outside of it).
            return original(address, timeout, deadline)
        progress = {i: [] for i in range(3)}
        link = LinkLock()
        real_exclusive = link.exclusive
        def exclusive():
            ctx = real_exclusive()
            class Wrapped:
                def __enter__(self_inner):
                    ctx.__enter__()
                    with guard:
                        active[0] += 1
                        transfers.append(active[0])
                def __exit__(self_inner, *exc):
                    with guard:
                        active[0] -= 1
                    return ctx.__exit__(*exc)
            return Wrapped()
        link.exclusive = exclusive
        results = {}
        def run(i):
            results[i] = benchmark(self.servers[i].server_address, self.keys[i], rounds=2, size=262144, idle=1,
                                   link=link, progress=lambda phase, f, i=i: progress[i].append((phase, f)))
        started = time.monotonic()
        with mock.patch.object(wire, "bounded_socket", watched):
            threads = [threading.Thread(target=run, args=(i,)) for i in range(3)]
            for thread in threads: thread.start()
            for thread in threads: thread.join(30)
        took = time.monotonic() - started
        self.assertTrue(all(results[i]["passed"] for i in range(3)), results)
        self.assertEqual(max(transfers), 1, "two transfers ran at the same time")
        # Serial would include three 1 s idle checks one after another.
        self.assertLess(took, 3 * 1.0 + 1.5)
        for rows in progress.values():
            phases = [phase for phase, _ in rows]
            self.assertEqual(phases[0], "latency")
            self.assertEqual(phases[-1], "done")
            for name in ("upload", "download", "idle"):
                self.assertIn(name, phases)
            ups = [f for phase, f in rows if phase == "upload"]
            self.assertEqual(ups, sorted(ups))
            self.assertEqual(ups[-1], 1)

    def test_budget_does_not_count_time_waiting_for_another_transfer(self):
        link = LinkLock()
        with link.exclusive():
            done = {}
            thread = threading.Thread(target=lambda: done.update(r=benchmark(
                self.servers[0].server_address, self.keys[0], rounds=1, size=65536, idle=0, budget=3, link=link)))
            thread.start()
            time.sleep(3.5)  # longer than the whole budget
        thread.join(15)
        self.assertTrue(done["r"]["passed"], done["r"])
        self.assertLess(done["r"]["seconds"], 3, "reported time excludes waiting for the link")


class RuntimeBatchTests(unittest.TestCase):
    def test_benchmark_batch_measures_each_carrier_once(self):
        from pronet.runtime import Runtime
        keys = {"frp-tls": secret(), "chisel": secret()}
        servers = {name: ProbeServer(("127.0.0.1", 0), key) for name, key in keys.items()}
        for server in servers.values():
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            runtime = object.__new__(Runtime)
            runtime.validate = lambda plan: plan
            updates = []
            plans = [{"pair_id": "a" * 24, "profile": name, "token": key, "test_quality": "quick"} for name, key in keys.items()]
            with mock.patch("pronet.runtime.engines.probe_address", side_effect=lambda plan: servers[plan["profile"]].server_address):
                result = runtime.benchmark_batch("a" * 24, plans, progress=updates.append)["profiles"]
            self.assertEqual(set(result), set(keys))
            self.assertTrue(all(row["passed"] for row in result.values()), result)
            self.assertTrue(any("frp-tls" in update for update in updates))
            with self.assertRaises(Exception):
                runtime.benchmark_batch("a" * 24, plans + plans[:1])
        finally:
            for server in servers.values():
                server.shutdown(); server.server_close()


class GroupingTests(unittest.TestCase):
    def test_carriers_that_fail_together_share_a_batch_and_none_is_skipped(self):
        from pronet.model import PROFILES
        # Same direction rule as Controller.allocate().
        plans = [{"profile": name, "direction": PROFILES[name].get("direction", "iran-dials")} for name in DEFAULT_PROFILES]
        batches = screen_batches(plans)
        flat = [plan["profile"] for batch in batches for plan in batch]
        self.assertEqual(sorted(flat), sorted(DEFAULT_PROFILES), "every carrier is still tested")
        self.assertTrue(all(len(batch) <= 8 for batch in batches))
        self.assertEqual(len(batches), 3)
        first = {plan["profile"] for plan in batches[0]}
        self.assertIn("frp-tls", first)
        self.assertIn("bp-l3-pck-reverse", first)
        self.assertNotIn("bp-l3-quic", first)
        last = {plan["profile"] for plan in batches[-1]}
        self.assertTrue({"bp-l3-quic", "bp-quic", "frp-quic", "bp-kcp"} <= last)


class HubProgressTests(unittest.TestCase):
    def test_long_poll_returns_as_soon_as_a_job_exists_and_progress_round_trips(self):
        from pronet.hub import Client, HubServer
        from pronet.store import Store
        with tempfile.TemporaryDirectory() as temporary:
            enroll, admin = secret(), secret()
            store = Store(pathlib.Path(temporary) / "h.db", enroll, admin)
            server = HubServer(("127.0.0.1", 0), store)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                url = "http://127.0.0.1:%d" % server.server_port
                creds = {}
                for number, role in ((1, "iran"), (2, "foreign")):
                    creds[role] = store.enroll(enroll, {"role": role, "name": role, "public_ip": "192.0.2.%d" % number,
                                                        "bind_ip": "192.0.2.%d" % number})
                iran = store.authenticate(creds["iran"]["node_id"] + ":" + creds["iran"]["node_secret"])
                foreign = store.authenticate(creds["foreign"]["node_id"] + ":" + creds["foreign"]["node_secret"])
                pair = store.create_pair(iran, {"name": "t", "public_ip": "192.0.2.1", "inbound_port": 2053})
                store.join_pair(foreign, pair["code"])
                client = Client(url, creds["iran"]["node_id"] + ":" + creds["iran"]["node_secret"], test_http=True)
                timer = threading.Timer(1.0, lambda: store.enqueue(pair["pair_id"], iran["id"], "benchmark_batch", {"plans": []}, "s1"))
                timer.start()
                started = time.monotonic()
                job = client.call("/v1/jobs?wait=8", timeout=20)["job"]
                took = time.monotonic() - started
                self.assertIsNotNone(job)
                self.assertGreater(took, .8)
                self.assertLess(took, 3, "the poll must answer when the job appears, not at the end of the wait")
                client.call("/v1/progress", {"job_id": job["id"], "lease_proof": job["lease_proof"],
                                             "progress": {"frp-tls": {"phase": "upload", "pct": 40}}})
                self.assertEqual(store.job_progress(job["id"]), {"frp-tls": {"phase": "upload", "pct": 40}})
                client.call("/v1/result", {"job_id": job["id"], "lease_proof": job["lease_proof"], "result": {"ok": True, "data": {}}})
                self.assertIsNone(store.job_progress(job["id"]), "finished jobs no longer report progress")
                self.assertEqual(client.call("/v1/jobs")["job"], None, "plain polling still works for older agents")
            finally:
                server.shutdown(); server.server_close()


class ProgressReporterTests(unittest.TestCase):
    def test_reporter_sends_only_changes_and_stops_on_an_older_hub(self):
        from pronet.agent import ProgressReporter
        from pronet.common import PronetError
        sent = []
        def call(path, data=None, timeout=15):
            sent.append(data["progress"])
            if len(sent) == 2:
                raise PronetError("Unknown API endpoint")
            return {"ok": True}
        reporter = ProgressReporter(mock.Mock(call=call), {"id": "1" * 24, "lease_proof": "x"}, .05)
        with reporter:
            reporter.update({"frp-tls": {"phase": "latency", "pct": 10}})
            time.sleep(.2)
            time.sleep(.2)  # unchanged: nothing sent
            reporter.update({"frp-tls": {"phase": "upload", "pct": 20}})
            time.sleep(.2)
            reporter.update({"frp-tls": {"phase": "download", "pct": 30}})
            time.sleep(.2)
        self.assertEqual(len(sent), 2, sent)


if __name__ == "__main__":
    unittest.main()
