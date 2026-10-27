"""Regression tests for 0.2.4 data-path and service stability fixes."""
import asyncio
import pathlib
import socket
import tempfile
import time
import unittest
from unittest import mock

from pronet import wire
from pronet.common import PronetError, read_json, secret, write_json
from pronet.wire import Gateway, bridge_server


async def streaming_backend(reader, writer, seconds=2.6, chunk=b"x" * 4096):
    # One request line, then a long one-directional download. The client
    # sends nothing more, like a large file or video over VLESS/WS.
    await reader.readline()
    deadline = time.monotonic() + seconds
    sent = 0
    while time.monotonic() < deadline:
        writer.write(chunk)
        await writer.drain()
        sent += len(chunk)
        await asyncio.sleep(.05)
    writer.write(b"END\n")
    await writer.drain()
    writer.close()


async def read_until_end(reader, timeout=8):
    received = bytearray()
    while not received.endswith(b"END\n"):
        data = await asyncio.wait_for(reader.read(65536), timeout)
        if not data:
            break
        received.extend(data)
    return bytes(received)


class OneWayTransferTests(unittest.IsolatedAsyncioTestCase):
    """A silent direction must not kill a connection that is busy the other way."""

    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.directory.name)
        self.backend = await asyncio.start_server(streaming_backend, "127.0.0.1", 0)
        self.patch = mock.patch.object(wire, "IDLE_TIMEOUT", 1)
        self.patch.start()

    async def asyncTearDown(self):
        self.patch.stop()
        self.backend.close()
        await self.backend.wait_closed()
        self.directory.cleanup()

    async def gateway(self, config):
        write_json(self.path / "gateway.json", dict({"bind_ip": "127.0.0.1", "port": 0}, **config))
        gateway = Gateway(self.path / "gateway.json", self.path / "stats.json")
        address = await gateway.start()
        return gateway, address

    async def test_plain_gateway_keeps_one_way_download_alive(self):
        gateway, address = await self.gateway({"active_backend": list(self.backend.sockets[0].getsockname())})
        try:
            reader, writer = await asyncio.open_connection(*address)
            writer.write(b"GET\n")
            await writer.drain()
            data = await read_until_end(reader)
            self.assertTrue(data.endswith(b"END\n"), "download was cut while the upload side was idle")
            writer.close()
        finally:
            await gateway.close()

    async def test_framed_bridge_keeps_one_way_download_alive(self):
        key = secret()
        target = self.backend.sockets[0].getsockname()

        async def handler(reader, writer):
            await bridge_server(reader, writer, key, target)
        bridge = await asyncio.start_server(handler, "127.0.0.1", 0)
        gateway, address = await self.gateway({"active_backend": list(bridge.sockets[0].getsockname()),
                                                "mode": "framed", "frame_key": key})
        try:
            reader, writer = await asyncio.open_connection(*address)
            writer.write(b"GET\n")
            await writer.drain()
            data = await read_until_end(reader)
            self.assertTrue(data.endswith(b"END\n"), "framed download was cut while the upload side was idle")
            writer.close()
        finally:
            await gateway.close()
            bridge.close()
            await bridge.wait_closed()

    async def test_fully_idle_connection_is_still_closed(self):
        async def silent(reader, writer):
            await asyncio.sleep(10)
        server = await asyncio.start_server(silent, "127.0.0.1", 0)
        gateway, address = await self.gateway({"active_backend": list(server.sockets[0].getsockname())})
        try:
            reader, writer = await asyncio.open_connection(*address)
            started = time.monotonic()
            self.assertEqual(await asyncio.wait_for(reader.read(1), 6), b"")
            self.assertLess(time.monotonic() - started, 5)
            writer.close()
        finally:
            await gateway.close()
            server.close()


class FailoverDrainTests(unittest.IsolatedAsyncioTestCase):
    """Connections stuck on a backend the watchdog declared dead are closed."""

    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.directory.name)
        self.hold = asyncio.Event()

        async def blackhole(reader, writer):
            await self.hold.wait()
            writer.close()
            await writer.wait_closed()
        self.dead = await asyncio.start_server(blackhole, "127.0.0.1", 0)
        self.alive = await asyncio.start_server(blackhole, "127.0.0.1", 0)
        self.config = {"bind_ip": "127.0.0.1", "port": 0,
                       "active_backend": list(self.dead.sockets[0].getsockname())}
        write_json(self.path / "gateway.json", self.config)
        self.gateway = Gateway(self.path / "gateway.json", self.path / "stats.json")
        self.address = await self.gateway.start()

    async def asyncTearDown(self):
        self.hold.set()
        await self.gateway.close()
        for server in (self.dead, self.alive):
            server.close()
            await server.wait_closed()
        self.directory.cleanup()

    async def test_switch_without_failure_keeps_existing_connections(self):
        reader, writer = await asyncio.open_connection(*self.address)
        await asyncio.sleep(.2)
        write_json(self.path / "gateway.json", dict(self.config, active_backend=list(self.alive.sockets[0].getsockname())))
        await asyncio.sleep(1.6)
        self.assertEqual(self.gateway.stats["connections_active"], 1)
        writer.close()

    async def test_failover_closes_connections_on_the_failed_backend(self):
        reader, writer = await asyncio.open_connection(*self.address)
        await asyncio.sleep(.2)
        old = self.config["active_backend"]
        write_json(self.path / "gateway.json", dict(self.config, active_backend=list(self.alive.sockets[0].getsockname()),
                                                    failed_backends=[old]))
        self.assertEqual(await asyncio.wait_for(reader.read(1), 4), b"")
        self.assertGreaterEqual(self.gateway.stats.get("drained_on_failover", 0), 1)
        # A new connection follows the new backend and is not drained.
        reader2, writer2 = await asyncio.open_connection(*self.address)
        await asyncio.sleep(1.5)
        self.assertEqual(self.gateway.stats["connections_active"], 1)
        writer.close()
        writer2.close()


class GatewayCapacityTests(unittest.IsolatedAsyncioTestCase):
    async def test_connection_limit_is_reloaded_and_rejections_are_counted(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary)
            hold = asyncio.Event()

            async def backend(reader, writer):
                await hold.wait()
                writer.close()
                await writer.wait_closed()
            server = await asyncio.start_server(backend, "127.0.0.1", 0)
            config = {"bind_ip": "127.0.0.1", "port": 0, "connection_limit": 16,
                      "active_backend": list(server.sockets[0].getsockname())}
            write_json(path / "gateway.json", config)
            gateway = Gateway(path / "gateway.json", path / "stats.json")
            address = await gateway.start()
            self.assertGreaterEqual(gateway.limit, 16)
            try:
                writers = []
                for _ in range(17):
                    _, writer = await asyncio.open_connection(*address)
                    writers.append(writer)
                await asyncio.sleep(.4)
                self.assertEqual(gateway.stats["connections_active"], 16)
                self.assertGreaterEqual(gateway.stats.get("rejected_limit", 0), 1)
                write_json(path / "gateway.json", dict(config, connection_limit=32))
                await asyncio.sleep(1.5)
                self.assertEqual(gateway.limit, 32)
                for writer in writers:
                    writer.close()
                await asyncio.gather(*(writer.wait_closed() for writer in writers), return_exceptions=True)
            finally:
                hold.set()
                await gateway.close()
                server.close()
                await server.wait_closed()

    async def test_stats_persistence_does_not_fsync_on_the_event_loop(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary)
            server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
            write_json(path / "gateway.json", {"bind_ip": "127.0.0.1", "port": 0,
                                               "active_backend": list(server.sockets[0].getsockname())})
            with mock.patch("os.fsync") as fsync:
                gateway = Gateway(path / "gateway.json", path / "stats.json")
                await gateway.start()
                await asyncio.sleep(.2)
                await gateway.close()
            self.assertEqual(fsync.call_count, 0)
            self.assertIn("connections_total", read_json(path / "stats.json"))
            server.close()
            await server.wait_closed()

    async def test_client_and_backend_sockets_use_tcp_keepalive(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary)
            seen = []
            hold = asyncio.Event()

            async def backend(reader, writer):
                await hold.wait()
                writer.close()
                await writer.wait_closed()
            server = await asyncio.start_server(backend, "127.0.0.1", 0)
            write_json(path / "gateway.json", {"bind_ip": "127.0.0.1", "port": 0,
                                               "active_backend": list(server.sockets[0].getsockname())})
            gateway = Gateway(path / "gateway.json", path / "stats.json")
            original = wire.tune_socket

            def spy(sock):
                original(sock)
                seen.append(sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE))
            with mock.patch.object(wire, "tune_socket", side_effect=spy):
                address = await gateway.start()
                _, writer = await asyncio.open_connection(*address)
                await asyncio.sleep(.3)
                writer.close()
            hold.set()
            await gateway.close()
            server.close()
            await server.wait_closed()
            self.assertGreaterEqual(len(seen), 2)
            self.assertTrue(all(seen))


class WatchdogFailoverTests(unittest.TestCase):
    def setUp(self):
        from pronet.runtime import Runtime
        self.tmp = tempfile.TemporaryDirectory()
        self.runtime = object.__new__(Runtime)
        self.runtime.identity = {"role": "iran"}
        self.runtime.root = pathlib.Path(self.tmp.name)
        self.directory = self.runtime.root / ("b" * 24)
        self.directory.mkdir()
        self.primary, self.backup = "bp-l3-pck", "bp-l3-udp-reverse"
        write_json(self.directory / "active.json", {})
        write_json(self.directory / "selection.json", {"profiles": [self.primary, self.backup], "active": self.primary,
                                                       "failures": 0, "switches": [], "auto_paused": False})
        write_json(self.directory / "gateway.json", {"active_backend": ["primary", 2053]})
        for profile, address in [(self.primary, "primary"), (self.backup, "backup")]:
            write_json(self.directory / profile / "plan.json", {"probe": address, "token": "t"})
        self.patches = [mock.patch("pronet.runtime.engines.probe_address", side_effect=lambda p: p["probe"]),
                        mock.patch("pronet.runtime.engines.data_address", side_effect=lambda p: (p["probe"], 2053))]
        for patcher in self.patches: patcher.start()
        self.runtime.validate = lambda p: p

    def tearDown(self):
        for patcher in self.patches: patcher.stop()
        self.tmp.cleanup()

    def test_failover_marks_the_dead_backend_for_draining(self):
        def probe(address, *_):
            if address == "primary": raise TimeoutError("down")
            return 10
        with mock.patch("pronet.runtime.echo", side_effect=probe):
            for _ in range(3): self.runtime.watchdog()
        gateway = read_json(self.directory / "gateway.json")
        self.assertEqual(gateway["active_backend"], ["backup", 2053])
        self.assertEqual(gateway["failed_backends"], [["primary", 2053]])

    def test_healthy_primary_resync_clears_drain_marker(self):
        write_json(self.directory / "gateway.json", {"active_backend": ["other", 1], "failed_backends": [["primary", 2053]]})
        with mock.patch("pronet.runtime.echo", return_value=10):
            self.runtime.watchdog()
        gateway = read_json(self.directory / "gateway.json")
        self.assertEqual(gateway["active_backend"], ["primary", 2053])
        self.assertEqual(gateway["failed_backends"], [])

    def test_missing_standby_record_still_persists_primary_failures(self):
        (self.directory / self.backup / "plan.json").unlink()
        with mock.patch("pronet.runtime.echo", side_effect=TimeoutError("down")):
            for _ in range(3): self.runtime.watchdog()
        selected = read_json(self.directory / "selection.json")
        self.assertEqual(selected["last_probe"], "UNCONFIRMED")
        self.assertTrue(selected["auto_paused"], "recovery must be requested even if a standby record is broken")


class AllocationTests(unittest.TestCase):
    def test_service_ports_avoid_the_ephemeral_range(self):
        from pronet.controller import Controller
        from pronet.model import validate_request
        request = validate_request({"name": "x", "public_ip": "192.0.2.1", "inbound_port": 2053,
                                    "profiles": ["bp-l3-pck", "frp-tls", "chisel", "rathole-noise", "wstunnel-wss"]})
        pair = {"id": "c" * 24, "request": request,
                "iran_info": {"public_ip": "192.0.2.1", "bind_ip": "192.0.2.1"},
                "foreign_info": {"public_ip": "192.0.2.2", "bind_ip": "192.0.2.2"}}
        info = {"ports": [443, 8443, 9443, 22443], "ssh_ports": [22], "routes": [], "reserved_subnets": [], "tun": True,
                "ephemeral_range": [32768, 60999]}
        for _ in range(20):
            for plan in Controller(mock.Mock()).allocate(pair, {"iran": info, "foreign": dict(info, ephemeral_range=[40000, 64999])}):
                for field in ("control_port", "echo_port", "health_port", "data_port", "bridge_data_port",
                              "bridge_health_port", "probe_front_port"):
                    self.assertFalse(32768 <= plan[field] <= 64999, (field, plan[field]))


class ControllerResilienceTests(unittest.TestCase):
    def test_controller_loop_survives_a_storage_error(self):
        import sqlite3
        import threading
        from pronet.controller import Controller
        store = mock.Mock()
        calls = []
        def stopping():
            calls.append(1)
            if len(calls) == 1: raise sqlite3.OperationalError("database is locked")
            return []
        store.stopping.side_effect = stopping
        store.pending.return_value = []
        store.overview.return_value = {"nodes": [], "pairs": []}
        stop = threading.Event()
        controller = Controller(store, stop)
        waits = []
        def wait(seconds):
            waits.append(seconds)
            if len(waits) >= 2: stop.set()
            return stop.is_set()
        import contextlib, io
        with mock.patch.object(stop, "wait", side_effect=wait), contextlib.redirect_stderr(io.StringIO()) as log:
            controller.run()
        self.assertIn("database is locked", log.getvalue())
        self.assertGreaterEqual(len(calls), 2, "controller thread must keep running after an error")


class UnitPolicyTests(unittest.TestCase):
    def test_upgrade_hardens_permanent_units_only(self):
        from pronet import upgrades
        permanent = ("# Pronet Fleet owner=" + "d" * 24 + "\n[Unit]\nStartLimitIntervalSec=600\nStartLimitBurst=5\n[Service]\nType=simple\n"
                     "ExecStart=\"/usr/bin/python3\" \"/opt/pronet-fleet/0.2.3/main.py\" \"managed-gateway\"\n"
                     "Restart=on-failure\nRestartSec=5\nLimitNOFILE=32768\nTasksMax=128\nMemoryMax=384M\n")
        migrated = upgrades.migrated_unit(permanent, "/opt/pronet-fleet/0.2.4/main.py")
        for expected in ("/0.2.4/", "StartLimitIntervalSec=0\n", "Restart=always\n", "LimitNOFILE=65536", "TasksMax=512", "MemoryMax=1G"):
            self.assertIn(expected, migrated)
        self.assertNotIn("StartLimitBurst", migrated)
        temporary = permanent.replace("Restart=on-failure\n", "Restart=no\n") + "RuntimeMaxSec=900\n"
        migrated = upgrades.migrated_unit(temporary, "/opt/pronet-fleet/0.2.4/main.py")
        self.assertIn("StartLimitBurst=5", migrated)
        self.assertIn("Restart=no\n", migrated)
        oneshot = permanent.replace("Owner", "").replace("Type=simple", "Type=oneshot\nRemainAfterExit=yes").replace("Restart=on-failure", "Restart=no")
        self.assertNotIn("Restart=always", upgrades.migrated_unit(oneshot, "/opt/pronet-fleet/0.2.4/main.py"))

    def test_counter_unit_stays_a_valid_oneshot(self):
        from pronet import cli
        from pronet.runtime import write_unit
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "pronetf-counters.service"
            with mock.patch("pronet.runtime.unit_path", return_value=path), \
                 mock.patch("pronet.cli.root_linux"), mock.patch("pronet.cli.command"), \
                 mock.patch("pronet.runtime.service"), mock.patch("pronet.runtime.unit_path", return_value=path):
                import contextlib, io
                with contextlib.redirect_stdout(io.StringIO()):
                    cli.enable_traffic()
            text = path.read_text()
            self.assertIn("Type=oneshot", text)
            self.assertIn("Restart=no\n", text)
            self.assertNotIn("Restart=always", text)

    def test_raised_gateway_limit_on_upgrade(self):
        from pronet import upgrades
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            write_json(root / "pairs" / ("e" * 24) / "gateway.json", {"connection_limit": 1024, "active_backend": ["x", 1]})
            with mock.patch.object(upgrades, "ROOT", root):
                self.assertEqual(upgrades.raise_gateway_limits(), ["e" * 24])
            self.assertEqual(read_json(root / "pairs" / ("e" * 24) / "gateway.json")["connection_limit"], wire.DEFAULT_CONNECTION_LIMIT)


class EngineConfigTests(unittest.TestCase):
    def test_new_pinned_certificates_do_not_expire_after_one_year(self):
        import subprocess
        from pronet.engines import certificate, wstunnel_certificate
        with tempfile.TemporaryDirectory() as temporary:
            for name, make in (("frp", certificate), ("ws", wstunnel_certificate)):
                directory = pathlib.Path(temporary) / name
                make(directory, "pn-test.invalid", "192.0.2.1")
                end = subprocess.run(["openssl", "x509", "-enddate", "-noout", "-checkend", str(5 * 365 * 86400),
                                      "-in", str(directory / "server.crt")], capture_output=True, text=True)
                self.assertEqual(end.returncode, 0, end.stdout)

    def test_frp_uses_a_work_connection_pool(self):
        from pronet.engines import render
        plan = {"pair_id": "f" * 24, "profile": "frp-tls", "token": "a" * 64, "subnet": "10.244.0.0/30",
                "iran_ip": "192.0.2.1", "foreign_ip": "192.0.2.2", "bind_ip": "192.0.2.1", "control_port": 443,
                "echo_port": 20001, "health_port": 20002, "data_port": 20003, "inbound_port": 2053,
                "bridge_data_port": 20004, "bridge_health_port": 20005, "probe_front_port": 20006,
                "direction": "iran-dials"}
        with tempfile.TemporaryDirectory() as temporary:
            server = render(dict(plan, role="iran"), pathlib.Path(temporary) / "i", {"frps": "/x/frps", "frpc": "/x/frpc"})
            client = render(dict(plan, role="foreign", bind_ip="192.0.2.2"), pathlib.Path(temporary) / "f", {"frps": "/x/frps", "frpc": "/x/frpc"})
            self.assertIn("transport.maxPoolCount = 16", (pathlib.Path(temporary) / "i" / "engine.toml").read_text())
            self.assertIn("transport.poolCount = 8", (pathlib.Path(temporary) / "f" / "engine.toml").read_text())
            self.assertEqual(server["validate"][1:3], ["verify", "-c"])
            self.assertEqual(client["validate"][1:3], ["verify", "-c"])


class AgentPollingTests(unittest.TestCase):
    def test_idle_agent_slows_down_and_speeds_up_when_work_arrives(self):
        import threading
        from pronet import agent
        waits, calls = [], []
        instance = object.__new__(agent.Agent)
        instance.stop = threading.Event()
        jobs = iter([None, {"id": "1" * 24, "pair_id": "2" * 24, "op": "status", "lease_proof": "x"}, None])
        def call(path, data=None, timeout=15):
            calls.append(path)
            if path.startswith("/v1/jobs"):
                try:
                    return {"job": next(jobs)}
                except StopIteration:
                    instance.stop.set(); return {"job": None}
            return {"ok": True}
        instance.client = mock.Mock(call=call)
        instance.execute_job = lambda job: {"ok": True}
        clock = [1000.0]
        def wait(seconds):
            waits.append(seconds); clock[0] += seconds
            return instance.stop.is_set()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(agent, "ROOT", pathlib.Path(temporary)), \
             mock.patch.object(instance.stop, "wait", side_effect=wait), \
             mock.patch.object(agent.time, "monotonic", side_effect=lambda: clock[0]):
            clock[0] += 0
            instance.job_loop()
        # Right after start (join/pairing) the hub holds the poll open and
        # answers as soon as a job exists: no sleep between setup steps.
        self.assertTrue(calls[0].startswith("/v1/jobs?wait="), calls)
        self.assertEqual(waits, [], "a long poll needs no client-side sleep")
        self.assertIn("/v1/result", calls)

    def test_agent_falls_back_to_plain_polling_with_an_older_hub(self):
        import threading
        from pronet import agent
        waits, calls = [], []
        instance = object.__new__(agent.Agent)
        instance.stop = threading.Event()
        def call(path, data=None, timeout=15):
            calls.append(path)
            if "?wait=" in path:
                raise PronetError("Unknown API endpoint")
            if len(calls) > 4:
                instance.stop.set()
            return {"job": None}
        instance.client = mock.Mock(call=call)
        def wait(seconds):
            waits.append(seconds)
            return instance.stop.is_set()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(agent, "ROOT", pathlib.Path(temporary)), \
             mock.patch.object(instance.stop, "wait", side_effect=wait):
            instance.job_loop()
        self.assertLessEqual(sum(1 for c in calls if "?wait=" in c), 2, "lanes, then long poll, are tried once each")
        self.assertIn("/v1/jobs", calls)
        self.assertTrue(waits and all(w == agent.JOB_POLL for w in waits))

    def test_idle_interval_is_used_after_the_busy_window(self):
        from pronet import agent
        self.assertGreaterEqual(agent.IDLE_POLL, 5)
        self.assertGreaterEqual(agent.BUSY_WINDOW, 60)


class AgentMaintenanceTests(unittest.TestCase):
    def test_old_completed_job_records_are_pruned(self):
        from pronet import agent
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            now = time.time()
            write_json(root / "jobs" / "old.json", {"fingerprint": "x", "result": {"ok": True}, "completed": now - 30 * 86400})
            write_json(root / "jobs" / "new.json", {"fingerprint": "x", "result": {"ok": True}, "completed": now - 60})
            write_json(root / "jobs" / "running.json", {"fingerprint": "x", "started": now - 30 * 86400})
            instance = object.__new__(agent.Agent)
            with mock.patch.object(agent, "ROOT", root):
                self.assertEqual(instance.prune_jobs(now), 1)
            self.assertEqual(sorted(p.name for p in (root / "jobs").iterdir()), ["new.json", "running.json"])


if __name__ == "__main__":
    unittest.main()
