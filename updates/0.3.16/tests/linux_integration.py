#!/usr/bin/env python3
"""Full pair/agents/systemd/tunnels test inside three isolated network namespaces.

Requires explicit invocation as root on Linux systemd. No public listener, host
route, shared firewall flush, reboot, existing panel or existing tunnel changes.
All generated test credentials stay in a mode-0700 temporary directory.
"""
import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import secrets
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

APP = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(APP))
from pronet.common import PronetError, secret, write_json
from pronet.engines import certificate


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, text=True, capture_output=True, timeout=40, **kwargs)


def baseline():
    rules = run(["iptables-save"]).stdout
    rules = re.sub(r"\[\d+:\d+\]", "[0:0]", "\n".join(line for line in rules.splitlines() if not line.startswith("#")))
    routes = run(["ip", "-j", "-4", "route", "show", "table", "all"]).stdout
    return {"firewall": hashlib.sha256(rules.encode()).hexdigest(),
            "routes": json.loads(routes),
            "ip_forward": pathlib.Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()}


def child_action(args):
    from pronet.common import CONFIG, ROOT
    fixture = json.loads(pathlib.Path(args.base, "fixture.json").read_text())
    role = args.role
    address = "198.18.0.1" if role == "iran" else "198.18.0.2"
    from pronet.hub import Client
    if args.child == "enroll":
        client = Client("https://198.18.0.3:9443", fixture["enrollment_key"], str(pathlib.Path(args.base, "cert/server.crt")))
        identity = {"role": role, "name": "isolated-" + role, "public_ip": address, "bind_ip": address}
        credentials = client.call("/v1/enroll", identity)
        write_json(CONFIG / "node.json", dict(identity, **credentials, hub_url=client.url,
                   ca_file=str(pathlib.Path(args.base, "cert/server.crt")), allowed_inbound_ports=[2053]))
    elif args.child == "pair":
        from pronet.cli import node_client
        result = node_client().call("/v1/pair", {"test_only": args.test_only, "emergency": args.profiles == "parsa-spoof", "spoof": {"iran": "198.19.0.1", "foreign": "198.19.0.2"}, "name": "isolated-linux-test", "public_ip": address,
                  "bind_ip": address, "inbound_port": 2053, "profiles": args.profiles.split(","), "standby": 1})
        write_json(pathlib.Path(args.base, "created.json"), result)
    elif args.child == "join":
        from pronet.cli import node_client
        created = json.loads(pathlib.Path(args.base, "created.json").read_text())
        node_client().call("/v1/join", {"code": created["code"]})
    elif args.child == "backend":
        from pronet.wire import ProbeServer
        with ProbeServer(("0.0.0.0", 2053), fixture["application_key"]) as server:
            server.serve_forever()
    elif args.child == "verify":
        from pronet.wire import benchmark
        result = benchmark(("198.18.0.1", 2053), fixture["application_key"], rounds=3, size=262144, idle=.5)
        if not result["passed"]: raise PronetError("Public gateway datapath failed: " + json.dumps(result))
        print(json.dumps(result))
    elif args.child == "cleanup":
        from pronet.cli import node_config
        from pronet.runtime import Runtime
        runtime = Runtime(node_config())
        for path in (ROOT / "pairs").iterdir():
            if path.is_dir() and len(path.name) == 24:
                runtime.cleanup(path.name)


def main(args):
    if sys.platform != "linux" or os.geteuid() != 0 or not pathlib.Path("/run/systemd/system").is_dir():
        raise PronetError("This integration test requires root on a Linux systemd host")
    for name in ("ip", "iptables", "iptables-save", "systemctl", "openssl", "ssh-keygen"):
        if not shutil.which(name): raise PronetError("Required test command missing: " + name)
    from pronet.model import PROFILES
    needs_tun = any(PROFILES.get(name, {}).get("kind") == "l3" and PROFILES[name]["engine"] == "backpack"
                    for name in args.profiles.split(","))
    if needs_tun and not pathlib.Path("/dev/net/tun").exists(): raise PronetError("TUN is unavailable")
    before = baseline()
    test_id = secrets.token_hex(4)
    base = pathlib.Path(tempfile.mkdtemp(prefix="pronet-fleet-test-", dir="/var/tmp"))
    base.chmod(0o700)
    namespaces = {role: "pronettest-" + test_id + "-" + role for role in ("hub", "iran", "foreign")}
    created_namespaces, processes, logs = [], [], []
    report = {"test_id": test_id, "isolated_namespaces": True, "passed": False, "base": str(base)}
    fixture = {"enrollment_key": secret(), "admin_key": secret(), "application_key": secret()}
    write_json(base / "fixture.json", fixture)
    certificate(base / "cert", "198.18.0.3", "198.18.0.3")
    for role in namespaces:
        (base / role / "config").mkdir(parents=True, mode=0o700)
        (base / role / "state").mkdir(mode=0o700)
    hub_config = dict(url="https://198.18.0.3:9443", bind="198.18.0.3", port=9443,
                      enrollment_key=fixture["enrollment_key"], admin_key=fixture["admin_key"],
                      database=str(base / "hub/state/hub.sqlite3"), certificate=str(base / "cert/server.crt"), private_key=str(base / "cert/server.key"))
    write_json(base / "hub/config/hub/hub.json", hub_config)
    def environment(role):
        env = dict(os.environ, PRONET_STATE=str(base / role / "state"), PRONET_CONFIG=str(base / role / "config"))
        if role != "hub": env["PRONET_TEST_NETNS"] = "/run/netns/" + namespaces[role]
        return env
    def in_ns(role, command):
        return ["ip", "netns", "exec", namespaces[role]] + [str(value) for value in command]
    def child(role, action):
        return run(in_ns(role, [sys.executable, __file__, "--child", action, "--base", base, "--role", role,
                               "--profiles", args.profiles] + (["--test-only"] if args.test_only else [])), env=environment(role))
    def start(role, command, name):
        file = open(base / (name + ".log"), "w")
        logs.append(file)
        process = subprocess.Popen(in_ns(role, command), stdout=file, stderr=file, env=environment(role))
        processes.append(process)
        return process
    try:
        for role, namespace in namespaces.items():
            run(["ip", "netns", "add", namespace]); created_namespaces.append(namespace)
            run(["ip", "-n", namespace, "link", "set", "lo", "up"])
        hub_ns = namespaces["hub"]
        run(["ip", "-n", hub_ns, "link", "add", "pnbridge", "type", "bridge"])
        run(["ip", "-n", hub_ns, "address", "add", "198.18.0.3/24", "dev", "pnbridge"])
        run(["ip", "-n", hub_ns, "link", "set", "pnbridge", "up"])
        for index, role in enumerate(("iran", "foreign"), 1):
            left, right = "pl" + test_id[:5] + str(index), "pr" + test_id[:5] + str(index)
            run(["ip", "link", "add", left, "type", "veth", "peer", "name", right])
            run(["ip", "link", "set", left, "netns", namespaces[role]])
            run(["ip", "link", "set", right, "netns", hub_ns])
            run(["ip", "-n", namespaces[role], "link", "set", left, "name", "eth0"])
            run(["ip", "-n", namespaces[role], "address", "add", "198.18.0." + str(index) + "/24", "dev", "eth0"])
            run(["ip", "-n", namespaces[role], "link", "set", "eth0", "up"])
            # Explicit lab-only return route for the synthetic spoof sources.
            run(["ip", "-n", namespaces[role], "route", "add", "198.19.0.0/24", "dev", "eth0"])
            run(["ip", "-n", hub_ns, "link", "set", right, "master", "pnbridge"])
            run(["ip", "-n", hub_ns, "link", "set", right, "up"])
        hub_process = start("hub", [sys.executable, APP / "main.py", "hub-run"], "hub")
        time.sleep(1)
        if hub_process.poll() is not None: raise PronetError("Test hub exited before enrollment")
        for role in ("iran", "foreign"):
            child(role, "enroll")
            start(role, [sys.executable, APP / "main.py", "agent"], role + "-agent")
        start("foreign", [sys.executable, __file__, "--child", "backend", "--base", base, "--role", "foreign"], "backend")
        child("iran", "pair"); child("foreign", "join")
        created = json.loads((base / "created.json").read_text())
        pair_id = created["pair_id"]
        previous = None
        deadline = time.monotonic() + args.timeout
        row = None
        while time.monotonic() < deadline:
            with sqlite3.connect(hub_config["database"], timeout=5) as db:
                row = db.execute("SELECT state,result FROM pairs WHERE id=?", (pair_id,)).fetchone()
            detail = json.loads(row[1])
            state = (row[0], detail.get("phase"), len(detail.get("results", [])))
            if state != previous:
                print("LINUX_TEST", state, flush=True); previous = state
            if row[0] in ("ACTIVE", "FAILED", "STOPPED"): break
            time.sleep(2)
        if args.test_only:
            if not row or row[0] != "STOPPED": raise PronetError("Emergency test did not finish cleanly")
            detail = json.loads(row[1])
            if detail.get("phase") != "emergency-tested" or not detail.get("test_passed"):
                raise PronetError("Emergency test did not pass: " + row[1])
            if detail.get("selected"): raise PronetError("Test-only operation selected an active carrier")
            report.update(test_only=True, setup=detail, passed=True)
            if list((base / "iran/state/pairs").glob("*/gateway.json")):
                raise PronetError("Test-only operation wrote a gateway configuration")
        else:
            if row is None or row[0] != "ACTIVE":
                raise PronetError("Full setup failed: " + (row[1] if row else "no state"))
            detail = json.loads(row[1]); report["setup"] = detail
            report["public_datapath"] = json.loads(child("foreign", "verify").stdout)
            selected = detail["selected"]
            from pronet.runtime import unit_name
            active_unit = unit_name(pair_id, selected[0], "engine", "iran")
            run(["systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", active_unit])
            # Engines can reconnect after the systemd process has restarted.
            # Observe actual recovery under a deadline, not a fixed eight seconds.
            recovery_start = time.monotonic()
            recovery_deadline = recovery_start + 60
            attempts, last_error = 0, ""
            while time.monotonic() < recovery_deadline:
                attempts += 1
                try:
                    report["after_engine_crash"] = json.loads(child("foreign", "verify").stdout)
                    break
                except subprocess.CalledProcessError as error:
                    last_error = error.stderr[-1600:]
                    time.sleep(2)
            else:
                raise PronetError("Datapath did not recover within crash deadline: " + last_error)
            report["engine_recovery_seconds"] = round(time.monotonic()-recovery_start, 2)
            report["engine_recovery_attempts"] = attempts
            if len(selected) >= 2:
                run(["systemctl", "stop", active_unit])
                selection_path = base / "iran/state/pairs" / pair_id / "selection.json"
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline:
                    selection = json.loads(selection_path.read_text())
                    if selection["active"] != selected[0]: break
                    time.sleep(2)
                if selection["active"] == selected[0]: raise PronetError("Warm standby failover did not occur")
                report["failover"] = {"active": selection["active"], "passed": True}
                report["after_failover"] = json.loads(child("foreign", "verify").stdout)
            hub_process.terminate(); hub_process.wait(timeout=10)
            report["hub_independence"] = json.loads(child("foreign", "verify").stdout)
            report["passed"] = True
    except BaseException as error:
        report["error"] = str(error)[:5000]
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
        cleanup_errors = []
        report["owned_resources_removed"] = True
        for role in ("iran", "foreign"):
            try:
                if (base / role / "config/node.json").exists():
                    child(role, "cleanup")
                    links = json.loads(run(in_ns(role, ["ip", "-j", "link", "show"])).stdout)
                    rules = run(in_ns(role, ["iptables-save"])).stdout
                    if any(str(link.get("ifalias", "")).startswith("pronetf:") for link in links) or "pronetf:" in rules:
                        report["owned_resources_removed"] = False
                        raise PronetError("Owned interface or firewall rules survived cleanup")
            except Exception as error: cleanup_errors.append(str(error))
        for namespace in reversed(created_namespaces):
            try: run(["ip", "netns", "delete", namespace])
            except Exception as error: cleanup_errors.append(str(error))
        for file in logs: file.close()
        after = baseline()
        report["host_firewall_unchanged"] = before["firewall"] == after["firewall"]
        report["host_routes_unchanged"] = before["routes"] == after["routes"]
        report["host_forwarding_unchanged"] = before["ip_forward"] == after["ip_forward"]
        report["cleanup_errors"] = cleanup_errors
        report["passed"] = (report["passed"] and not cleanup_errors and report["host_firewall_unchanged"]
                            and report["host_routes_unchanged"] and report["host_forwarding_unchanged"])
        destination = pathlib.Path(args.output or base / "report.json")
        write_json(destination, report)
        print("LINUX_REPORT", destination, flush=True)
        print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--child", choices=["enroll", "pair", "join", "backend", "verify", "cleanup"])
    parser.add_argument("--base"); parser.add_argument("--role", choices=["iran", "foreign"])
    parser.add_argument("--profiles", default="bp-l3-pck,bp-stealth,bp-l3-quic,frp-tls,chisel")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--output")
    parser.add_argument("--test-only", action="store_true")
    args = parser.parse_args()
    if args.child:
        child_action(args)
    else:
        sys.exit(main(args))
