#!/usr/bin/env python3
"""Run real pinned FRP/Chisel binaries with real authenticated traffic.

No systemd, firewall or existing service is touched. All listeners are loopback.
"""
import argparse
import asyncio
import contextlib
import concurrent.futures
import base64
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from pronet import engines
from pronet.common import PronetError, clean, secret
from pronet.wire import Gateway, ProbeServer, benchmark, echo, bridge_server


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_profile(profile, binary_dir):
    with tempfile.TemporaryDirectory(prefix="pronet-native-") as temporary:
        root = pathlib.Path(temporary)
        key = secret()
        echo_server = ProbeServer(("127.0.0.1", 0), key)
        data_server = ProbeServer(("127.0.0.1", 0), key)
        servers = [echo_server, data_server]
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        ports = {echo_server.server_address[1], data_server.server_address[1]}
        def unique():
            for _ in range(100):
                value = free_port()
                if value not in ports:
                    ports.add(value)
                    return value
            raise ValueError("Could not allocate test ports")
        plan = {"pair_id": "a1" * 12, "profile": profile, "token": key, "subnet": "10.244.9.0/30",
                "iran_ip": "127.0.0.1", "foreign_ip": "127.0.0.1", "bind_ip": "127.0.0.1",
                "control_port": unique(), "health_port": unique(), "data_port": unique(),
                "bridge_health_port": unique(), "bridge_data_port": unique(), "probe_front_port": unique(),
                "echo_port": echo_server.server_address[1], "inbound_port": data_server.server_address[1],
                "direction": "iran-dials"}
        iran, foreign = root / "iran", root / "foreign"
        iran.mkdir(); foreign.mkdir()
        if profile.startswith("frp"):
            cert = engines.certificate(iran, "pn-" + plan["pair_id"] + ".invalid", "127.0.0.1")
            (foreign / "peer.crt").write_text(cert)
            binaries = {name: str(binary_dir / name) for name in ("frps", "frpc")}
        elif profile == "chisel":
            plan["server_fingerprint"] = engines.chisel_key(iran)
            binaries = {"chisel": str(binary_dir / "chisel")}
        elif profile.startswith("wstunnel"):
            cert = engines.wstunnel_certificate(iran, "pn-" + plan["pair_id"] + ".invalid", "127.0.0.1")
            (foreign / "peer.crt").write_text(cert)
            binaries = {"wstunnel": str(binary_dir / "wstunnel")}
        elif profile == "rathole-noise":
            from pronet.extra_engines import noise_key
            plan["server_noise_public_key"] = noise_key(iran, str(binary_dir / "rathole"))
            binaries = {"rathole": str(binary_dir / "rathole")}
        else:
            raise PronetError("Unknown native integration profile")
        processes, files = [], []
        loop = asyncio.new_event_loop()
        loop_thread = threading.Thread(target=loop.run_forever, daemon=True)
        loop_thread.start()
        bridges, gateways = [], []
        addresses = {}
        async def start_bridges():
            for source, target in ((plan["bridge_health_port"], plan["echo_port"]), (plan["bridge_data_port"], plan["inbound_port"])):
                async def handler(reader, writer, target=target):
                    await bridge_server(reader, writer, key, ("127.0.0.1", target))
                bridges.append(await asyncio.start_server(handler, "127.0.0.1", source))
            for label, target in (("health", plan["health_port"]), ("data", plan["data_port"])):
                path = root / (label + ".json")
                from pronet.common import write_json
                write_json(path, {"bind_ip": "127.0.0.1", "port": 0, "active_backend": ["127.0.0.1", target], "mode": "framed", "frame_key": key})
                gateway = Gateway(path, root / (label + "-stats.json"))
                addresses[label] = await gateway.start()
                gateways.append(gateway)
        asyncio.run_coroutine_threadsafe(start_bridges(), loop).result(10)
        try:
            for role, directory in (("iran", iran), ("foreign", foreign)):
                # Production validation forbids loopback public addresses. The
                # test deliberately renders onto loopback only, not a live VPS.
                with mock.patch.object(engines, "validate_profile", lambda value: value):
                    recipe = engines.render(dict(plan, role=role), directory, binaries)
                if recipe["validate"]:
                    checked = subprocess.run(recipe["validate"], capture_output=True, timeout=10, text=True)
                    if checked.returncode:
                        raise PronetError(checked.stderr or checked.stdout)
                log = open(directory / "engine.log", "w+")
                files.append(log)
                environment = dict(os.environ, **recipe["environment"])
                processes.append(subprocess.Popen(recipe["command"], stdout=log, stderr=log, env=environment))
                time.sleep(.3)
            deadline = time.monotonic() + 15
            address = addresses["health"]
            while True:
                try:
                    echo(address, key, 1)
                    break
                except (OSError, ValueError, PronetError):
                    if time.monotonic() >= deadline:
                        raise PronetError("Native tunnel did not become reachable")
                    time.sleep(.3)
            health = benchmark(address, key, rounds=4, size=262144, idle=.5)
            public = benchmark(addresses["data"], key, rounds=3, size=262144, idle=.2)
            if not health["passed"] or not public["passed"]:
                raise PronetError("Native health or data path failed: " + json.dumps([health, public]))
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                delays = list(pool.map(lambda _: echo(addresses['data'], key, 4), range(32)))
            # Deliberately wrong CA/fingerprint/public key must not be accepted.
            client = processes[-1]
            client.terminate(); client.wait(timeout=5)
            original_peer = (foreign / 'peer.crt').read_bytes() if (foreign / 'peer.crt').exists() else None
            changed = dict(plan)
            if original_peer is not None:
                wrong = engines.certificate(root / 'wrong-ca', 'untrusted.invalid', '127.0.0.1')
                (foreign / 'peer.crt').write_text(wrong)
            else:
                field = 'server_fingerprint' if profile == 'chisel' else 'server_noise_public_key'
                changed[field] = base64.b64encode(os.urandom(32)).decode()
            with mock.patch.object(engines, 'validate_profile', lambda value:value):
                bad_recipe = engines.render(dict(changed, role='foreign'), foreign, binaries)
            processes[-1] = subprocess.Popen(bad_recipe['command'], stdout=files[-1], stderr=files[-1],
                                             env=dict(os.environ, **bad_recipe['environment']))
            time.sleep(.7)
            for _ in range(4):
                try:
                    echo(address, key, .6)
                except (OSError, ValueError, PronetError):
                    continue
                raise PronetError('Wrong server identity was accepted')
            processes[-1].terminate(); processes[-1].wait(timeout=5)
            if original_peer is not None: (foreign / 'peer.crt').write_bytes(original_peer)
            with mock.patch.object(engines, 'validate_profile', lambda value:value):
                recipe = engines.render(dict(plan, role='foreign'), foreign, binaries)
            environment = dict(os.environ, **recipe['environment'])
            # Killing only the client and relaunching the same pinned config
            # proves a fresh tunnel, not just a surviving preexisting socket.
            processes[-1] = subprocess.Popen(recipe["command"], stdout=files[-1], stderr=files[-1], env=environment)
            deadline = time.monotonic() + 12
            while True:
                try:
                    echo(address, key, 1)
                    break
                except (OSError, ValueError, PronetError):
                    if time.monotonic() >= deadline: raise
                    time.sleep(.3)
            return {"profile": profile, "passed": True, "health": health, "data_path": public, "client_restart": True,
                    "wrong_server_identity_rejected": True, "concurrent_echoes": len(delays), "workers": 8}
        except Exception as error:
            logs = []
            for file in files:
                file.flush(); file.seek(0)
                logs.append(clean(file.read()[-4000:], 4000))
            return {"profile": profile, "passed": False, "error": clean(error, 2000), "logs": logs}
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()
            for file in files: file.close()
            async def close_bridges():
                for gateway in gateways: await gateway.close()
                for bridge in bridges: bridge.close(); await bridge.wait_closed()
                pending = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
                for task in pending: task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
            asyncio.run_coroutine_threadsafe(close_bridges(), loop).result(10)
            loop.call_soon_threadsafe(loop.stop)
            loop_thread.join(5)
            loop.close()
            for server in servers: server.shutdown(); server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binaries", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--profiles", default="frp-tls,frp-quic,chisel")
    args = parser.parse_args()
    results = [run_profile(name, args.binaries.resolve()) for name in args.profiles.split(',')]
    output = json.dumps(results, indent=2)
    if args.output: args.output.write_text(output + "\n")
    print(output)
    sys.exit(0 if all(row["passed"] for row in results) else 1)
