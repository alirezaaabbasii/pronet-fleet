import concurrent.futures
import contextlib
import http.client
import json
import os
import pathlib
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest import mock

from pronet.common import PronetError, canonical, secret, sign, write_json
from pronet.controller import Controller
from pronet.engines import certificate, render
from pronet.hub import Client, HubServer
from pronet.model import PROFILES, ranking, validate_profile, validate_request
from pronet.store import Store
from pronet.wire import ProbeServer, benchmark, echo, request_frame, response


def identity(role, suffix=1):
    return {"role": role, "name": role + str(suffix), "public_ip": f"192.0.2.{suffix}", "bind_ip": f"192.0.2.{suffix}"}


def setup_request():
    return {"name": "Test Pair", "public_ip": "192.0.2.1", "inbound_port": 2053, "profiles": ["bp-l3-pck"]}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.clock = [1000.0]
        self.enroll, self.admin = secret(), secret()
        self.store = Store(pathlib.Path(self.directory.name) / "state.db", self.enroll, self.admin, lambda: self.clock[0])
        self.iran = self.node("iran", 1)
        self.foreign = self.node("foreign", 2)

    def tearDown(self):
        self.directory.cleanup()

    def node(self, role, number):
        result = self.store.enroll(self.enroll, identity(role, number))
        return self.store.authenticate(result["node_id"] + ":" + result["node_secret"])

    def paired(self):
        result = self.store.create_pair(self.iran, setup_request())
        self.store.join_pair(self.foreign, result["code"])
        return self.store.pair(result["pair_id"])

    def test_bad_enrollment_and_node_auth(self):
        with self.assertRaises(PronetError): self.store.enroll(secret(), identity("iran"))
        with self.assertRaises(PronetError): self.store.authenticate(self.iran["id"] + ":" + secret())
        with self.assertRaises(PronetError): self.store.authenticate("../root:abc")

    def test_bad_telemetry_cannot_break_other_nodes_overview(self):
        for metrics in ({"pairs": "wrong"}, {"resources": []}, {"pairs": [{"id": "a" * 24, "selection": []}]},
                        {"ip_traffic": {"ips": [None]}}):
            with self.assertRaises(PronetError): self.store.heartbeat(self.iran, metrics)
        self.assertEqual(len(self.store.overview()["nodes"]), 2)

    def test_pair_is_one_time_and_opposite_role_only(self):
        created = self.store.create_pair(self.iran, setup_request())
        with self.assertRaises(PronetError): self.store.join_pair(self.iran, created["code"])
        joined = self.store.join_pair(self.foreign, created["code"])
        self.assertEqual(joined["state"], "PAIRED")
        with self.assertRaises(PronetError): self.store.join_pair(self.node("foreign", 3), created["code"])

    def test_expiry_and_attempt_counter_survive_restart(self):
        created = self.store.create_pair(self.iran, setup_request())
        self.clock[0] += created["expires_in"] + 1
        for _ in range(5):
            with self.assertRaises(PronetError): self.store.join_pair(self.foreign, created["code"])
        reopened = Store(self.store.path, self.enroll, self.admin, lambda: self.clock[0])
        with self.assertRaisesRegex(PronetError, "Too many"):
            reopened.join_pair(self.foreign, created["code"])

    def test_concurrent_join_has_exactly_one_winner(self):
        created = self.store.create_pair(self.iran, setup_request())
        peers = [self.node("foreign", n) for n in range(3, 15)]
        def try_join(node):
            try:
                return self.store.join_pair(node, created["code"])["state"]
            except PronetError:
                return "refused"
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(try_join, peers))
        self.assertEqual(results.count("PAIRED"), 1)

    def test_duplicate_endpoint_does_not_make_another_tunnel(self):
        self.store.create_pair(self.iran, setup_request())
        with self.assertRaisesRegex(PronetError, "reserved"):
            self.store.create_pair(self.iran, setup_request())

    def test_jobs_cannot_target_unpaired_nodes_or_arbitrary_shell(self):
        pair = self.paired()
        with self.assertRaises(PronetError): self.store.enqueue(pair["id"], self.node("foreign", 4)["id"], "start", {}, "x")
        with self.assertRaises(PronetError): self.store.enqueue(pair["id"], self.foreign["id"], "shell", {"command": "true"}, "x")

    def test_lease_proof_wrong_node_and_delayed_result(self):
        pair = self.paired()
        job = self.store.enqueue(pair["id"], self.foreign["id"], "inventory", {}, "first")
        first = self.store.claim(self.foreign)
        with self.assertRaises(PronetError): self.store.finish(self.iran, job, first["lease_proof"], {"ok": True})
        self.clock[0] += 181
        second = self.store.claim(self.foreign)
        with self.assertRaisesRegex(PronetError, "superseded"):
            self.store.finish(self.foreign, job, first["lease_proof"], {"ok": True})
        self.store.finish(self.foreign, job, second["lease_proof"], {"ok": True, "data": {"answer": 1}})
        self.store.finish(self.foreign, job, second["lease_proof"], {"ok": True, "data": {"answer": 1}})
        self.assertEqual(self.store.job_result(job)["data"]["answer"], 1)

    def test_idempotency_key_cannot_change_operation_or_payload(self):
        pair = self.paired()
        self.store.enqueue(pair["id"], self.foreign["id"], "inventory", {}, "same")
        with self.assertRaises(PronetError): self.store.enqueue(pair["id"], self.foreign["id"], "start", {}, "same")

    def test_failed_setup_cannot_later_claim_a_stale_start(self):
        pair = self.paired()
        self.store.enqueue(pair["id"], self.foreign["id"], "start", {}, "start")
        self.store.enqueue(pair["id"], self.foreign["id"], "cleanup", {}, "cleanup")
        self.store.update_pair(pair["id"], "FAILED", {"error": "test"})
        self.assertEqual(self.store.claim(self.foreign)["op"], "cleanup")

    def test_stop_intent_survives_inflight_setup_and_refuses_new_jobs(self):
        pair = self.paired()
        self.store.enqueue(pair["id"], self.foreign["id"], "start", {}, "start")
        self.store.request_stop(self.iran, pair["id"])
        request_id = self.store.pair(pair["id"])["result"]["stop_request"]
        self.store.update_pair(pair["id"], "ACTIVE", {"phase": "late-commit"})
        latest = self.store.pair(pair["id"])
        self.assertEqual(latest["state"], "STOPPING")
        self.assertEqual(latest["result"]["stop_request"], request_id)
        self.assertEqual(self.store.pending(), [])
        self.assertIsNone(self.store.claim(self.foreign))
        with self.assertRaises(PronetError):
            self.store.enqueue(pair["id"], self.foreign["id"], "resume", {}, "late-resume")
        self.store.enqueue(pair["id"], self.foreign["id"], "cleanup", {}, "stop-cleanup")
        self.assertEqual(self.store.claim(self.foreign)["op"], "cleanup")
        with self.assertRaises(PronetError):
            self.store.request_stop(self.node("iran", 7), pair["id"])

    def test_overview_does_not_expose_code_credentials_or_plan_secrets(self):
        pair = self.paired()
        token = secret()
        self.store.update_pair(pair["id"], "TRIAL", {"plans": [{"token": token}], "phase": "measuring"})
        raw = json.dumps(self.store.overview())
        self.assertNotIn(token, raw)
        self.assertNotIn(pair["code"], raw)
        self.assertNotIn(self.foreign["credential"], raw)
        self.clock[0] += 46
        self.assertTrue(all(n["telemetry"] == "STALE" for n in self.store.overview()["nodes"]))


class ModelTests(unittest.TestCase):
    def good(self, profile, rate=10, delays=None):
        return dict(profile=profile, passed=True, success_ratio=1, echo_ms=delays or [80, 82, 81, 83],
                    upload_mbps=rate, download_mbps=rate, half_close=True, after_idle=True, integrity=True)

    def test_fast_but_corrupt_or_unstable_is_never_selected(self):
        good = self.good("bp-l3-pck", 20)
        corrupt = dict(self.good("bp-stealth", 2000), integrity=False)
        unstable = dict(self.good("bp-quic", 2000), success_ratio=.9)
        self.assertEqual([r["profile"] for r in ranking([corrupt, unstable, good])], ["bp-l3-pck"])

    def test_missing_and_nan_measurements_are_not_zero_cost_winners(self):
        bad = self.good("bp-stealth", float("nan"))
        missing = dict(self.good("bp-quic"), upload_mbps=None)
        self.assertEqual(ranking([bad, missing]), [])

    def test_standby_prefers_an_independent_carrier_family(self):
        candidates = [self.good("bp-l3-quic", 50), self.good("bp-l3-udp", 49), self.good("bp-stealth", 45)]
        self.assertEqual(ranking(candidates)[1]["profile"], "bp-stealth")

    def test_allocator_avoids_management_ports_and_route_overlap(self):
        store = mock.Mock()
        controller = Controller(store)
        pair = {"id": "a" * 24, "request": validate_request(setup_request()),
                "iran_info": identity("iran", 1), "foreign_info": identity("foreign", 2)}
        inventory = {"ports": [443, 2053, 8443], "ssh_ports": [22, 2222], "routes": ["10.0.0.0/8"], "reserved_subnets": [], "tun": True}
        plans = controller.allocate(pair, {"iran": inventory, "foreign": inventory})
        plan = plans[0]
        self.assertFalse(plan["subnet"].startswith("10."))
        for field in ("control_port", "echo_port", "health_port", "data_port"):
            self.assertNotIn(plan[field], [443, 2053, 8443, 22, 2222])

    def test_request_refuses_unknown_profiles_and_bool_ports(self):
        with self.assertRaises(PronetError): validate_request(dict(setup_request(), inbound_port=True))
        with self.assertRaises(PronetError): validate_request(dict(setup_request(), profiles=["shell"]))
        with self.assertRaises(PronetError): validate_request(dict(setup_request(), name="x\033[2J"))


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.key = secret()
        self.server = ProbeServer(("127.0.0.1", 0), self.key)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()

    def test_real_full_duplex_integrity_half_close_and_idle(self):
        result = benchmark(self.server.server_address, self.key, rounds=3, size=131072, idle=.1)
        self.assertTrue(result["passed"], result)
        self.assertTrue(result["half_close"])

    def test_wrong_auth_and_replay_cannot_access_probe(self):
        with self.assertRaises((OSError, PronetError)): echo(self.server.server_address, secret())
        with socket.create_connection(self.server.server_address) as sock:
            sock.settimeout(2)
            with sock.makefile("rb") as stream:
                frame = request_frame(self.key, "echo")
                sock.sendall(canonical(frame) + b"\n")
                self.assertTrue(response(stream, self.key, frame)["ok"])
                sock.sendall(canonical(frame) + b"\n")
                self.assertEqual(stream.read(1), b"")

    def test_oversized_transfer_is_refused_before_allocation(self):
        with socket.create_connection(self.server.server_address) as sock:
            sock.settimeout(2)
            frame = request_frame(self.key, "download", 1 << 30)
            sock.sendall(canonical(frame) + b"\n")
            self.assertEqual(sock.recv(1), b"")

    def test_total_benchmark_budget_stops_an_unresponsive_peer(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0)); listener.listen(10)
            started = time.monotonic()
            result = benchmark(listener.getsockname(), self.key, rounds=10, budget=.15)
            self.assertFalse(result["passed"])
            self.assertLess(time.monotonic() - started, 1)


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        path = pathlib.Path(cls.directory.name)
        cls.enroll, cls.admin = secret(), secret()
        cls.store = Store(path / "hub.db", cls.enroll, cls.admin)
        certificate(path, "localhost", "127.0.0.1")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(path / "server.crt"), str(path / "server.key"))
        cls.server = HubServer(("127.0.0.1", 0), cls.store, tls=context)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = "https://127.0.0.1:" + str(cls.server.server_port)
        cls.ca = str(path / "server.crt")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(); cls.directory.cleanup()

    def test_real_tls_enrollment_pairing_and_job_result(self):
        enrollment = Client(self.url, self.enroll, self.ca)
        one = enrollment.call("/v1/enroll", identity("iran", 21))
        two = enrollment.call("/v1/enroll", identity("foreign", 22))
        iran = Client(self.url, one["node_id"] + ":" + one["node_secret"], self.ca)
        foreign = Client(self.url, two["node_id"] + ":" + two["node_secret"], self.ca)
        created = iran.call("/v1/pair", dict(setup_request(), public_ip="192.0.2.21", bind_ip="192.0.2.21"))
        foreign.call("/v1/join", {"code": created["code"]})
        job = self.store.enqueue(created["pair_id"], two["node_id"], "inventory", {}, "read")
        claimed = foreign.call("/v1/jobs")["job"]
        foreign.call("/v1/result", {"job_id": job, "lease_proof": claimed["lease_proof"], "result": {"ok": True, "data": {"test": 1}}})
        self.assertEqual(self.store.job_result(job)["data"]["test"], 1)
        self.assertEqual(len(iran.call("/v1/overview")["pairs"]), 1)

    def test_certificate_verification_is_not_silently_skipped(self):
        with self.assertRaises(PronetError): Client(self.url, self.enroll).call("/v1/enroll", identity("iran", 24))

    def test_no_plain_http_or_credential_redirect(self):
        with self.assertRaises(PronetError): Client("http://192.0.2.1:80", "secret")
        with self.assertRaises(PronetError): Client("https://user:pass@example.com", "secret")

    def test_non_json_and_cross_origin_are_refused(self):
        context = ssl.create_default_context(cafile=self.ca)
        connection = http.client.HTTPSConnection("127.0.0.1", self.server.server_port, context=context)
        connection.request("POST", "/v1/enroll", "{}", {"Content-Type": "text/plain"})
        self.assertEqual(connection.getresponse().status, 400)
        connection.close()
        connection = http.client.HTTPSConnection("127.0.0.1", self.server.server_port, context=context)
        connection.request("POST", "/v1/enroll", "{}", {"Content-Type": "application/json", "Origin": "https://attacker.invalid"})
        self.assertEqual(connection.getresponse().status, 403)
        connection.close()


if __name__ == "__main__":
    unittest.main()
