import asyncio
import json
import pathlib
import tempfile
import threading
import unittest

from pronet.common import canonical, secret, sign, write_json
from pronet.wire import Gateway, ProbeServer, benchmark, bridge_auth, bridge_server, echo, request_frame


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.directory.name)
        self.keys = [secret(), secret()]
        self.servers = [ProbeServer(("127.0.0.1", 0), key) for key in self.keys]
        for server in self.servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        self.config = {"bind_ip": "127.0.0.1", "port": 0, "active_backend": list(self.servers[0].server_address)}
        write_json(self.path / "gateway.json", self.config)
        self.gateway = Gateway(self.path / "gateway.json", self.path / "stats.json")
        self.address = await self.gateway.start()

    async def asyncTearDown(self):
        await self.gateway.close()
        for server in self.servers:
            await asyncio.to_thread(server.shutdown)
            server.server_close()
        self.directory.cleanup()

    async def test_half_close_and_large_transfers_survive_gateway(self):
        result = await asyncio.to_thread(benchmark, self.address, self.keys[0], 3, 262144, .1)
        self.assertTrue(result["passed"], result)
        self.assertGreater(self.gateway.stats["rx_bytes"], 262144)
        self.assertGreater(self.gateway.stats["tx_bytes"], 262144)
        for _ in range(20):
            if not self.gateway.stats["connections_active"]:
                break
            await asyncio.sleep(.02)
        self.assertEqual(self.gateway.stats["connections_active"], 0)

    async def test_switch_only_changes_new_connections(self):
        reader, writer = await asyncio.open_connection(*self.address)
        async def verify_existing():
            frame = request_frame(self.keys[0], "echo")
            writer.write(canonical(frame) + b"\n"); await writer.drain()
            answer = json.loads(await asyncio.wait_for(reader.readline(), 2))
            mac = answer.pop("mac")
            self.assertEqual(mac, sign(self.keys[0], answer))
        await verify_existing()
        self.config["active_backend"] = list(self.servers[1].server_address)
        write_json(self.path / "gateway.json", self.config)
        await asyncio.to_thread(echo, self.address, self.keys[1])
        await verify_existing()
        writer.close(); await writer.wait_closed()

    async def test_unavailable_backend_is_counted_without_process_exit(self):
        self.config["active_backend"] = ["127.0.0.1", 1]
        write_json(self.path / "gateway.json", self.config)
        reader, writer = await asyncio.open_connection(*self.address)
        self.assertEqual(await asyncio.wait_for(reader.read(1), 2), b"")
        writer.close(); await writer.wait_closed()
        self.assertGreater(self.gateway.stats["connection_failures"], 0)
        self.config["active_backend"] = list(self.servers[0].server_address)
        write_json(self.path / "gateway.json", self.config)
        await asyncio.to_thread(echo, self.address, self.keys[0])

    async def test_framed_bridge_preserves_half_close_and_integrity(self):
        async def handler(reader, writer):
            await bridge_server(reader, writer, self.keys[0], self.servers[0].server_address)
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        try:
            self.config.update(active_backend=list(server.sockets[0].getsockname()), mode="framed", frame_key=self.keys[0])
            write_json(self.path / "gateway.json", self.config)
            result = await asyncio.to_thread(benchmark, self.address, self.keys[0], 3, 524288, .1)
            self.assertTrue(result["passed"], result)
        finally:
            server.close(); await server.wait_closed()

    async def test_replayed_bridge_confirmation_cannot_open_a_backend(self):
        opened = []
        async def backend(reader, writer):
            opened.append(True); writer.close(); await writer.wait_closed()
        target = await asyncio.start_server(backend, "127.0.0.1", 0)
        async def handler(reader, writer):
            await bridge_server(reader, writer, self.keys[0], target.sockets[0].getsockname())
        bridge = await asyncio.start_server(handler, "127.0.0.1", 0)
        try:
            reader, writer = await asyncio.open_connection(*bridge.sockets[0].getsockname())
            first = {"v": 1, "op": "bridge", "nonce": "a" * 32}
            writer.write(canonical(dict(first, mac=sign(self.keys[0], first))) + b"\n"); await writer.drain()
            challenge = json.loads(await asyncio.wait_for(reader.readline(), 2))
            old = {"v": 1, "op": "confirm", "nonce": first["nonce"], "challenge": "0" * 32}
            self.assertNotEqual(challenge["challenge"], old["challenge"])
            writer.write(canonical(dict(old, mac=sign(self.keys[0], old))) + b"\n"); await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(1), 2), b"")
            writer.close(); await writer.wait_closed()
            self.assertEqual(opened, [])
        finally:
            bridge.close(); await bridge.wait_closed()
            target.close(); await target.wait_closed()


if __name__ == "__main__":
    unittest.main()
