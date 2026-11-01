import pathlib
import tempfile
import threading
import time
import unittest
from unittest import mock

from pronet import agent as agent_module
from pronet.agent import Agent
from pronet.common import PronetError, secret
from pronet.controller import Controller
from pronet.hub import Client, HubServer
from pronet.store import Store


class FastEvent(threading.Event):
    def wait(self, timeout=None):
        return super().wait(min(timeout, .02) if timeout is not None else None)


class SimulatedNode:
    """Control-plane fault injection only; this is not a Linux engine test."""
    def __init__(self, role, reject=False):
        self.role, self.reject = role, reject
        self.operations = []
    def execute(self, job):
        operation, payload = job["op"], job["payload"]
        self.operations.append(operation)
        if operation == "inventory":
            from pronet import __version__
            return {"version": __version__, "ips": ["192.0.2.1" if self.role == "iran" else "192.0.2.2"], "ports": [], "ssh_ports": [22],
                    "routes": [], "reserved_subnets": [], "tun": True, "systemd": True, "arch": "amd64", "iptables": True}
        if operation == "prepare_batch":
            return {"profiles": {plan["profile"]: {"profile": plan["profile"], "prepared": True} for plan in payload["plans"]}}
        if operation == "start_batch":
            return {"profiles": {plan["profile"]: {"profile": plan["profile"], "started": True} for plan in payload["plans"]}}
        if operation == "probe_batch":
            return {"profiles": {name: {"reachable": True, "rtt_ms": 20} for name in payload["profiles"]}}
        if operation in ("benchmark", "remeasure"):
            return self.measured(payload["profile"])
        if operation == "benchmark_batch":
            return {"profiles": {plan["profile"]: self.measured(plan["profile"]) for plan in payload["plans"]}}
        if operation == "activate": return {"inbound": "open", "tls": "not-configured"}
        return {"ok": True}
    def measured(self, profile):
        return {"profile": profile, "passed": not self.reject, "echo_ms": [20, 22, 21], "success_ratio": 1,
                "upload_mbps": {"bp-l3-pck-reverse": 29, "chisel": 25}.get(profile, 30), "download_mbps": 30,
                "integrity": not self.reject, "half_close": True, "after_idle": True}
    def watchdog(self): pass


class WorkflowTests(unittest.TestCase):
    def run_workflow(self, fail=False, quality="balanced", profiles=None, expected_selected=None, cleanup_fails=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            enroll, admin = secret(), secret()
            store = Store(root / "hub.db", enroll, admin)
            server = HubServer(("127.0.0.1", 0), store)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            url = "http://127.0.0.1:" + str(server.server_port)
            agents, workers, runtimes, credentials = [], [], [], []
            stop = FastEvent()
            controller = Controller(store, stop)
            try:
                with mock.patch.object(agent_module, "ROOT", root / "nodes"), mock.patch.object(agent_module, "resources", lambda: {"test": True}), \
                     mock.patch.object(agent_module, "JOB_WAIT", 1):
                    for number, role in ((1, "iran"), (2, "foreign")):
                        identity = {"role": role, "name": role, "public_ip": f"192.0.2.{number}", "bind_ip": f"192.0.2.{number}"}
                        cred = store.enroll(enroll, identity); credentials.append(cred)
                        client = Client(url, cred["node_id"] + ":" + cred["node_secret"], test_http=True)
                        runtime = SimulatedNode(role, fail); runtimes.append(runtime)
                        if cleanup_fails and role == "foreign":
                            execute = runtime.execute
                            def execute_with_cleanup_failure(job, execute=execute, runtime=runtime):
                                if job["op"] == "cleanup":
                                    runtime.operations.append("cleanup")
                                    raise PronetError("foreign service still running")
                                return execute(job)
                            runtime.execute = execute_with_cleanup_failure
                        agent = Agent(dict(identity, **cred), runtime=runtime, client=client); agent.stop = FastEvent()
                        agents.append(agent)
                        worker = threading.Thread(target=agent.run, daemon=True); worker.start(); workers.append(worker)
                    iran = store.authenticate(credentials[0]["node_id"] + ":" + credentials[0]["node_secret"])
                    foreign = store.authenticate(credentials[1]["node_id"] + ":" + credentials[1]["node_secret"])
                    created = store.create_pair(iran, {"name": "workflow", "public_ip": "192.0.2.1", "inbound_port": 2053,
                                                      "profiles": profiles or ["bp-l3-pck", "bp-stealth"], "quality": quality})
                    store.join_pair(foreign, created["code"])
                    controller.process(created["pair_id"])
                    pair = store.pair(created["pair_id"])
                    if fail:
                        self.assertEqual(pair["state"], "FAILED")
                        self.assertEqual(pair["result"]["cleanup_confirmed"], not cleanup_fails)
                        self.assertEqual(store.overview()["pairs"][0]["result"]["cleanup_confirmed"], not cleanup_fails)
                        self.assertTrue(all("cleanup" in r.operations for r in runtimes))
                        self.assertTrue(all("activate" not in r.operations for r in runtimes))
                    else:
                        self.assertEqual(pair["state"], "ACTIVE", pair["result"])
                        self.assertEqual(len(pair["result"]["selected"]), min(3, len(profiles or ["a", "b"])))
                        if expected_selected: self.assertEqual(pair["result"]["selected"], expected_selected)
                        if quality == "thorough":
                            self.assertTrue(all(row.get("soak", {}).get("qualification_runs") == 3 for row in pair["result"]["results"]))
                        self.assertTrue(all("commit" in r.operations and "activate" in r.operations for r in runtimes))
                        self.assertNotIn("token", str(store.overview()["pairs"][0]))
                        store.request_stop(iran, created["pair_id"])
                        controller.stop_pair(created["pair_id"])
                        self.assertEqual(store.pair(created["pair_id"])["state"], "STOPPED")
                        self.assertTrue(all("cleanup" in r.operations for r in runtimes))
                    for agent in agents: agent.stop.set()
                    for worker in workers: worker.join(3)
            finally:
                stop.set()
                for agent in agents: agent.stop.set()
                server.shutdown(); server.server_close(); thread.join(3)

    def test_real_http_two_agent_workflow_selects_and_commits_both_ends(self):
        self.run_workflow(False)

    def test_failed_integrity_rolls_back_both_ends_without_public_activation(self):
        self.run_workflow(True)

    def test_failed_cleanup_is_exposed_in_overview_without_activation(self):
        self.run_workflow(True, cleanup_fails=True)

    def test_thorough_mode_requires_three_successful_qualification_runs(self):
        self.run_workflow(False, "thorough")

    def test_near_equal_same_family_paths_do_not_crowd_out_a_healthy_diverse_standby(self):
        # Primary, then a standby from another family, then the remaining
        # qualified carrier as the second standby.
        self.run_workflow(profiles=["bp-l3-pck", "bp-l3-pck-reverse", "chisel"],
                          expected_selected=["bp-l3-pck", "chisel", "bp-l3-pck-reverse"])

    def test_lost_result_does_not_execute_job_twice(self):
        runtime = SimulatedNode("iran")
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(agent_module, "ROOT", pathlib.Path(temporary)):
            agent = Agent({}, runtime=runtime, client=object())
            job = {"id": "1" * 24, "pair_id": "2" * 24, "op": "inventory", "payload": {}}
            first = agent.execute_job(job)
            self.assertEqual(agent.execute_job(job), first)
            self.assertEqual(runtime.operations, ["inventory"])
            with self.assertRaises(PronetError): agent.execute_job(dict(job, payload={"different": True}))

    def test_recovery_episode_has_a_finite_budget_and_is_persisted(self):
        store = mock.Mock()
        rows = []
        for profile in ("bp-l3-pck", "bp-stealth", "bp-kcp", "bp-quic", "bp-l3-udp"):
            rows.append({"profile": profile, "passed": True, "echo_ms": [20], "success_ratio": 1, "upload_mbps": 20,
                         "download_mbps": 20, "half_close": True, "after_idle": True, "integrity": True})
        pair = {"id": "1" * 24, "iran": "2" * 24, "foreign_node": "3" * 24,
                "result": {"results": rows, "selected": ["bp-l3-pck", "bp-stealth"]}}
        store.pair.return_value = pair
        controller = Controller(store)
        controller.both = mock.Mock(return_value={})
        controller.rpc = mock.Mock(return_value={"passed": False})
        controller.recover(pair["id"], "4" * 24)
        self.assertEqual(controller.rpc.call_count, 3)
        self.assertEqual(pair["result"]["recovery"]["state"], "exhausted")
        self.assertEqual(pair["result"]["recovery"]["handled_pause_id"], "4" * 24)

    def test_failed_recovery_commit_restores_the_previous_selection(self):
        store = mock.Mock()
        pair = {"id": "1" * 24, "iran": "2" * 24, "foreign_node": "3" * 24,
                "result": {"selected": ["bp-l3-pck"], "results": [{"profile": "chisel", "passed": True,
                "echo_ms": [20], "success_ratio": 1, "upload_mbps": 20, "download_mbps": 20,
                "half_close": True, "after_idle": True, "integrity": True}]}}
        store.pair.return_value = pair
        controller = Controller(store)
        calls = []
        def operation(pair, op, payloads, step, **kwargs):
            calls.append((op, payloads, step))
            if step.endswith("chisel:commit"): raise PronetError("one end disconnected")
            if op == "resume" and payloads["iran"]["profile"] == "bp-l3-pck" and "restore:" not in step:
                raise PronetError("old transport still unreachable")
            return {}
        controller.both = operation
        controller.rpc = mock.Mock(return_value={"passed": True})
        controller.recover(pair["id"], "4" * 24)
        restored = [payload for op, payload, step in calls if "restore-commit" in step]
        self.assertEqual(restored[0]["iran"]["profiles"], ["bp-l3-pck"])
        self.assertEqual(pair["result"]["selected"], ["bp-l3-pck"])

    def test_operator_stop_never_claims_success_when_one_end_is_unreachable(self):
        store = mock.Mock()
        pair = {"id": "1" * 24, "foreign_node": "3" * 24, "result": {"stop_request": "4" * 24}}
        store.pair.return_value = pair
        controller = Controller(store)
        controller.both = mock.Mock(side_effect=PronetError("foreign unavailable"))
        controller.stop_pair(pair["id"])
        self.assertEqual(store.update_pair.call_args.args[1], "STOP_UNCONFIRMED")
        controller.both = mock.Mock(return_value={})
        controller.stop_pair(pair["id"])
        self.assertEqual(store.update_pair.call_args.args[1], "STOPPED")


if __name__ == "__main__": unittest.main()
