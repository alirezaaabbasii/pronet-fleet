"""0.2.5: one-command join, pinned coordinator trust, batched screening, reports."""
import contextlib
import pathlib
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest import mock

from pronet import cli
from pronet.common import PronetError, secret, write_json
from pronet.controller import Controller
from pronet.engines import certificate
from pronet.report import final_report, progress_lines, reason
from pronet.runtime import Runtime
from pronet.wire import ProbeServer


def bootstrap_with_cert(directory):
    pem = certificate(directory, "127.0.0.1", "127.0.0.1", extra_ips=[])
    return {"schema": 1, "hub_url": "https://127.0.0.1:9443", "enrollment_key": secret(), "ca_pem": pem}


class TokenTests(unittest.TestCase):
    def test_token_round_trip_and_extraction_from_a_pasted_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            bootstrap = bootstrap_with_cert(pathlib.Path(temporary))
            token = cli.make_token(bootstrap, 2053, "0427")
            pasted = "curl -fsSL %s | sudo bash -s -- join %s\n" % (cli.INSTALL_URL, token)
            data = cli.parse_token(pasted)
            self.assertEqual((data["u"], data["k"], data["p"], data["c"]),
                             (bootstrap["hub_url"], bootstrap["enrollment_key"], 2053, "0427"))
            self.assertEqual(len(data["f"]), 64)
            self.assertLess(len(token), 400, "the foreign command must stay easy to copy")

    def test_damaged_or_foreign_tokens_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            token = cli.make_token(bootstrap_with_cert(pathlib.Path(temporary)), 2053, "0427")
        for text in ("", "sudo pronet join", token[:-20], token.replace("PNF1-", "PNF1-xx"),
                     "PNF1-" + "A" * 80):
            with self.assertRaises(PronetError):
                cli.parse_token(text)


class PinnedTrustTests(unittest.TestCase):
    def serve(self, directory):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(directory / "server.crt"), str(directory / "server.key"))
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        def loop():
            for _ in range(4):
                with contextlib.suppress(OSError):
                    connection, _ = listener.accept()
                    with contextlib.suppress(OSError, ssl.SSLError):
                        context.wrap_socket(connection, server_side=True).close()
        threading.Thread(target=loop, daemon=True).start()
        return listener

    def test_coordinator_certificate_is_accepted_only_when_it_matches_the_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            bootstrap = bootstrap_with_cert(directory)
            listener = self.serve(directory)
            try:
                url = "https://127.0.0.1:%d" % listener.getsockname()[1]
                pin = cli.parse_token(cli.make_token(bootstrap, 2053, "1111"))["f"]
                pem = cli.fetch_pinned_ca(url, pin)
                self.assertEqual(ssl.PEM_cert_to_DER_cert(pem), ssl.PEM_cert_to_DER_cert(bootstrap["ca_pem"]))
                with self.assertRaises(PronetError):
                    cli.fetch_pinned_ca(url, "0" * 64)
            finally:
                listener.close()

    def test_unreachable_coordinator_gives_an_actionable_message(self):
        with self.assertRaises(PronetError) as raised:
            cli.fetch_pinned_ca("https://127.0.0.1:1", "0" * 64)
        self.assertIn("port is open", str(raised.exception))


class ProbeBatchTests(unittest.TestCase):
    def test_parallel_reachability_reports_each_carrier_without_waiting_serially(self):
        key = secret()
        server = ProbeServer(("127.0.0.1", 0), key)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                runtime = object.__new__(Runtime)
                runtime.identity = {"role": "iran"}
                runtime.root = pathlib.Path(temporary)
                pair = "a" * 24
                addresses = {"frp-tls": server.server_address, "chisel": ("127.0.0.1", 1), "rathole-noise": ("127.0.0.1", 1)}
                for name in addresses:
                    write_json(runtime.root / pair / name / "plan.json", {"profile": name, "token": key, "role": "iran"})
                runtime.validate = lambda plan: plan
                alive = {"rathole-noise": False}
                with mock.patch("pronet.runtime.engines.probe_address", side_effect=lambda plan: addresses[plan["profile"]]), \
                     mock.patch("pronet.runtime.is_active", side_effect=lambda unit: not unit.endswith("-%d-engine.service" % 18)):
                    started = time.monotonic()
                    result = runtime.probe_batch(pair, list(addresses), seconds=6)["profiles"]
                    took = time.monotonic() - started
            self.assertTrue(result["frp-tls"]["reachable"])
            self.assertFalse(result["chisel"]["reachable"])
            self.assertIn("no end-to-end connectivity", result["chisel"]["reason"])
            self.assertIn("engine exited", result["rathole-noise"]["reason"])
            self.assertLess(took, 9, "carriers must be probed in parallel")
        finally:
            server.shutdown(); server.server_close()

    def test_unreachable_carrier_fails_fast_instead_of_running_a_full_benchmark(self):
        runtime = object.__new__(Runtime)
        runtime.validate = lambda plan: plan
        with mock.patch("pronet.runtime.engines.probe_address", return_value=("127.0.0.1", 1)):
            started = time.monotonic()
            result = runtime.measure({"profile": "chisel", "token": secret()}, wait=2)
        self.assertFalse(result["passed"])
        self.assertLess(time.monotonic() - started, 5)
        self.assertIn("no end-to-end connectivity", result["reason"])


class BatchedControllerTests(unittest.TestCase):
    def test_batch_results_keep_reasons_and_retire_losers_together(self):
        store = mock.Mock()
        store.pair.return_value = {"desired": "run"}
        controller = Controller(store)
        pair = {"id": "1" * 24, "iran": "2" * 24, "foreign_node": "3" * 24,
                "iran_info": {"bind_ip": "192.0.2.1"}, "foreign_info": {"bind_ip": "192.0.2.2"}}
        batch = [{"profile": name, "pair_id": pair["id"]} for name in ("frp-tls", "chisel", "bp-kcp", "wstunnel-wss")]
        calls = []
        def both(pair_, op, payloads, step, timeout=125):
            calls.append(op)
            names = [plan["profile"] for plan in payloads["iran"]["plans"]]
            if op == "prepare_batch":
                return {role: {"profiles": {n: ({"error": "TUN device unavailable"} if n == "bp-kcp" else {"prepared": True})
                                            for n in names}} for role in ("iran", "foreign")}
            return {role: {"profiles": {n: {"started": True} for n in names}} for role in ("iran", "foreign")}
        measured_names = []
        def rpc(pair_, node, op, payload, step, timeout=125, on_progress=None):
            calls.append(op)
            if op == "probe_batch":
                return {"profiles": {"frp-tls": {"reachable": True, "rtt_ms": 90},
                                     "chisel": {"reachable": False, "reason": "no end-to-end connectivity within 20 s"},
                                     "wstunnel-wss": {"reachable": True, "rtt_ms": 95}}}
            names = [plan["profile"] for plan in payload["plans"]]
            measured_names.extend(names)
            return {"profiles": {name: {"profile": name, "passed": True, "echo_ms": [90, 91], "success_ratio": 1,
                                        "upload_mbps": 10, "download_mbps": 9, "integrity": True, "half_close": True,
                                        "after_idle": True} for name in names}}
        controller.both, controller.rpc = both, rpc
        controller.payloads = lambda pair_, plan: {"iran": dict(plan), "foreign": dict(plan)}
        result, running = {"results": []}, set()
        controller.screen_batch(pair, batch, 0, result, running)
        rows = {row["profile"]: row for row in result["results"]}
        self.assertTrue(rows["frp-tls"]["passed"] and rows["wstunnel-wss"]["passed"])
        self.assertEqual(rows["chisel"]["stage"], "reach")
        self.assertEqual(rows["bp-kcp"]["stage"], "prepare")
        self.assertEqual(calls.count("prepare_batch"), 1)
        self.assertEqual(calls.count("start_batch"), 1)
        self.assertEqual(calls.count("probe_batch"), 1)
        self.assertEqual(calls.count("benchmark_batch"), 1, "reachable carriers are measured in one job")
        self.assertEqual(sorted(measured_names), ["frp-tls", "wstunnel-wss"], "only reachable carriers are benchmarked")
        live = result["live"]["carriers"]
        self.assertEqual(live["frp-tls"]["stage"], "passed")
        self.assertEqual(live["chisel"]["stage"], "failed")


def sample_rows():
    def ok(name, up, down, rtt):
        echo = [rtt, rtt + 5, rtt + 12]
        soak = {"profile": name, "passed": True, "echo_ms": echo * 5, "success_ratio": 1, "upload_mbps": up,
                "download_mbps": down, "integrity": True, "half_close": True, "after_idle": True}
        return {"profile": name, "passed": True, "echo_ms": echo, "success_ratio": 1, "upload_mbps": up,
                "download_mbps": down, "integrity": True, "half_close": True, "after_idle": True, "soak": soak}
    return [ok("frp-tls", 5.36, 4.72, 430), ok("bp-l3-udp-reverse", 5.37, 4.16, 436),
            {"profile": "bp-l3-pck", "passed": False, "stage": "reach", "error": "no end-to-end connectivity within 20 s"},
            {"profile": "bp-kcp", "passed": False, "stage": "reach", "error": "no end-to-end connectivity within 20 s"},
            {"profile": "chisel", "passed": False, "echo_ms": [400, 410], "success_ratio": 0.6}]


class ReportTests(unittest.TestCase):
    def pair(self, state="ACTIVE", **result):
        base = {"results": sample_rows(), "selected": ["frp-tls", "bp-l3-udp-reverse"], "active": "frp-tls",
                "endpoint": "194.107.116.227:2053", "inbound": "refused", "timing": {"started": 1000, "finished": 1000 + 462}}
        base.update(result)
        return {"id": "e" * 24, "state": state, "request": {"name": "iran-kharej", "public_ip": "194.107.116.227", "inbound_port": 2053},
                "result": base, "runtime": {}}

    def test_success_report_explains_the_choice_and_the_next_action(self):
        text = "\n".join(final_report(self.pair()))
        self.assertIn("TUNNEL READY", text)
        self.assertIn("Clients       194.107.116.227:2053", text)
        self.assertRegex(text, r"Primary\s+frp-tls\s+5\.4 up / 4\.7 down Mbps")
        self.assertIn("UDP family (primary is TCP)", text)
        self.assertIn("5 tested in 7m42s: 2 passed, 3 failed", text)
        self.assertIn("bp-l3-pck, bp-kcp: no connectivity (blocked or filtered on this route)", text)
        self.assertIn("chisel: unstable (60% of probes answered)", text)
        self.assertIn("a foreign server closer to Iran will be faster", text)
        self.assertIn("listen 0.0.0.0, port 2053", text)
        self.assertIn("sudo pronet report --details", text)
        self.assertNotIn("score (", text, "internal score is not shown to the operator")
        self.assertTrue(text.isascii(), "terminal output must not depend on RTL rendering")
        details = "\n".join(final_report(self.pair(), details=True))
        self.assertIn("ALL CARRIERS", details)
        self.assertIn("longer test:", details)

    def test_report_names_the_blocking_pattern_instead_of_long_lists(self):
        from pronet.report import blocked_patterns
        rows = [{"profile": name, "passed": False, "stage": "reach", "error": "no end-to-end connectivity within 20 s"}
                for name in ("bp-l3-quic", "bp-l3-udp", "frp-quic", "bp-l3-pck", "bp-direct-stealth", "bp-l3-sni")]
        rows.append({"profile": "frp-tls", "passed": True})
        patterns, explained = blocked_patterns(rows)
        self.assertEqual(len(patterns), 2)
        self.assertIn("UDP/QUIC", patterns[0])
        self.assertIn("started by Iran", patterns[1])
        self.assertEqual(explained, {"bp-l3-quic", "bp-l3-udp", "frp-quic", "bp-l3-pck", "bp-direct-stealth", "bp-l3-sni"})
        # No pattern is claimed without evidence (nothing dialed from abroad passed).
        self.assertEqual(blocked_patterns(rows[:-1])[0], ["UDP/QUIC does not get through on this route"])

    def test_failed_setup_report_states_the_reason(self):
        text = "\n".join(final_report(self.pair("FAILED", error="No profile passed all tests.", selected=[])))
        self.assertIn("SETUP DID NOT COMPLETE", text)
        self.assertIn("Reason          No profile passed all tests.", text)
        self.assertIn("Both servers were cleaned up", text)

    def test_progress_view_lists_results_as_they_arrive(self):
        live = {"phase": "screen", "batch": 1, "batches": 3, "order": ["wstunnel-wss", "bp-stealth", "bp-l3-pck-reverse", "chisel"],
                "carriers": {"wstunnel-wss": {"stage": "measuring", "phase": "upload", "pct": 50},
                             "bp-stealth": {"stage": "measuring", "phase": "latency", "pct": 100},
                             "bp-l3-pck-reverse": {"stage": "connecting", "since": 1050, "window": 20},
                             "chisel": {"stage": "waiting"}}}
        pair = self.pair("TRIAL", progress={"tested": 5, "total": 20, "passed": 2}, live=live)
        text = "\n".join(progress_lines(pair, now=1060))
        self.assertIn("Step 2/4  Testing every carrier  (group 1 of 3)", text)
        self.assertIn("5/20 carriers tested, 2 passed", text)
        self.assertRegex(text, r"wstunnel-wss\s+\[#+\.+\]\s+62%  upload test")
        self.assertIn("waiting for the speed-test slot", text)
        self.assertRegex(text, r"bp-l3-pck-reverse\s+\[#+\.+\]\s+22%  connecting  10s / 20s")
        self.assertIn("Waiting: 1 more carriers", text)
        self.assertRegex(text, r"frp-tls\s+5\.4 / 4\.7")
        self.assertEqual(reason({"passed": False, "error": "local engine exited (see logs)"}), "engine exited during start (see logs)")


class StatusViewTests(unittest.TestCase):
    def overview(self, name="iran-kharej"):
        now = time.time()
        return {"server_time": now, "nodes": [
            {"id": "a" * 24, "info": {"name": "iran-1", "public_ip": "192.0.2.1"}, "role": "iran", "telemetry": "CURRENT",
             "age_seconds": 4, "metrics": {"resources": {"cpu_percent": 9.5, "ram_percent": 33.5, "disk_percent": 13.3}}},
            {"id": "b" * 24, "info": {"name": "kharej-1", "public_ip": "192.0.2.2"}, "role": "foreign", "telemetry": "STALE",
             "age_seconds": 400, "metrics": {}}],
            "pairs": [{"id": "e" * 24, "iran": "a" * 24, "foreign": "b" * 24, "state": "ACTIVE",
                       "request": {"name": name, "public_ip": "192.0.2.1", "inbound_port": 2053},
                       "result": {"endpoint": "192.0.2.1:2053", "active": "frp-tls"},
                       "runtime": {"link": "UNCONFIRMED", "active": "frp-tls", "inbound": "UNKNOWN",
                                   "standby_health": {"bp-l3-udp-reverse": {"state": "UNCONFIRMED", "failures": 2}},
                                   "traffic": {"rx_bytes": 10, "tx_bytes": 20}, "health": {"probe_seconds": 60, "failover_seconds": 120},
                                   "switches": [], "events": []}}]}

    def test_problems_are_explained_in_status_and_dashboard(self):
        from pronet.views import tunnels
        row = tunnels(self.overview())[0]
        self.assertEqual(row["status"], "DOWN")
        text = " ".join(row["problems"])
        self.assertIn("Foreign server is not reporting", text)
        self.assertIn("no working fallback", text)

    def test_dashboard_escapes_names_and_renders_fast(self):
        from pronet.hub import dashboard
        data = self.overview('<script>alert(1)</script>')
        started = time.perf_counter()
        for _ in range(50):
            page = dashboard(data)
        per_page = (time.perf_counter() - started) / 50
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script", page.lower().replace("&lt;script", ""))
        self.assertLess(per_page, 0.02, "rendering must stay negligible")


class DashboardExposureTests(unittest.TestCase):
    def test_dashboard_only_at_secret_path_and_port_does_not_identify_itself(self):
        import http.client
        from pronet.hub import HubServer
        from pronet.store import Store
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(pathlib.Path(temporary) / "h.db", secret(), secret())
            token = secret()[:32]
            server = HubServer(("127.0.0.1", 0), store, dashboard_token=token)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                def get(path):
                    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                    connection.request("GET", path)
                    reply = connection.getresponse()
                    body = reply.read().decode()
                    headers = {k.lower(): v for k, v in reply.getheaders()}
                    connection.close()
                    return reply.status, headers, body
                for probe in ("/", "/monitor", "/admin", "/" + token[:-1] + "x/"):
                    status, headers, body = get(probe)
                    self.assertEqual(status, 404, probe)
                    self.assertNotIn("www-authenticate", headers)
                    self.assertNotIn("pronet", (headers.get("server", "") + body).lower())
                status, headers, body = get("/" + token + "/")
                self.assertEqual(status, 200)
                self.assertIn("Pronet Fleet", body)
                self.assertNotIn("server", headers)
                self.assertEqual(get("/" + token)[0], 200)
            finally:
                server.shutdown(); server.server_close()

    def test_dashboard_can_be_disabled(self):
        import http.client
        from pronet.hub import HubServer
        from pronet.store import Store
        with tempfile.TemporaryDirectory() as temporary:
            server = HubServer(("127.0.0.1", 0), Store(pathlib.Path(temporary) / "h.db", secret(), secret()), dashboard_token=None)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                connection.request("GET", "/")
                self.assertEqual(connection.getresponse().status, 404)
            finally:
                server.shutdown(); server.server_close()


if __name__ == "__main__":
    unittest.main()
