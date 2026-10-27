"""Several client ports on one tunnel (0.3.3)."""
import asyncio
import pathlib
import platform
import socket
import tempfile
import threading
import unittest
from unittest import mock

from pronet.cli import make_token, parse_token
from pronet.common import PronetError, inbound_ports, parse_ports, secret, write_json
from pronet.model import validate_profile, validate_request
from pronet.runtime import firewall_rules, inbound_report
from pronet.wire import Gateway, ProbeServer, bridge_auth, bridge_server, echo


def free_ports(count, host="127.0.0.1"):
    sockets, numbers = [], []
    for _ in range(count):
        sock = socket.socket()
        sock.bind((host, 0))
        sockets.append(sock)
        numbers.append(sock.getsockname()[1])
    for sock in sockets:
        sock.close()
    return numbers


def plan(**extra):
    base = {"pair_id": "a" * 24, "profile": "bp-l3-pck", "role": "iran", "iran_ip": "192.0.2.1",
            "foreign_ip": "198.51.100.1", "bind_ip": "192.0.2.1", "control_port": 24443, "echo_port": 24444,
            "health_port": 24445, "data_port": 24446, "bridge_data_port": 24447, "bridge_health_port": 24448,
            "probe_front_port": 24449, "inbound_port": 2053, "token": "ab" * 32, "subnet": "10.244.0.0/30",
            "direction": "iran-dials"}
    base.update(extra)
    return base


class PortInputTests(unittest.TestCase):
    def test_operator_port_input(self):
        self.assertEqual(parse_ports("2053"), [2053])
        self.assertEqual(parse_ports(" 2053, 2083 8443 "), [2053, 2083, 8443])
        self.assertEqual(parse_ports("2053،2083"), [2053, 2083])
        self.assertEqual(parse_ports("2080-2083"), [2080, 2081, 2082, 2083])
        self.assertEqual(parse_ports("2053,2053,2083"), [2053, 2083])
        self.assertEqual(parse_ports(2053), [2053])
        for bad in ("", "abc", "0", "70000", "2083-2080", "1000-1100", ",".join(str(2000 + i) for i in range(17))):
            with self.assertRaises(PronetError, msg=bad):
                parse_ports(bad)

    def test_request_keeps_old_single_port_form(self):
        single = validate_request({"name": "x", "public_ip": "192.0.2.1", "inbound_port": 2053})
        self.assertEqual((single["inbound_port"], single["inbound_ports"]), (2053, [2053]))
        multi = validate_request({"name": "x", "public_ip": "192.0.2.1", "inbound_port": 2053,
                                  "inbound_ports": [2053, 2083]})
        self.assertEqual((multi["inbound_port"], multi["inbound_ports"]), (2053, [2053, 2083]))
        with self.assertRaises(PronetError):
            validate_request({"name": "x", "public_ip": "192.0.2.1", "inbound_port": 2083, "inbound_ports": [2053, 2083]})
        with self.assertRaises(PronetError):
            validate_request({"name": "x", "public_ip": "192.0.2.1", "inbound_ports": [2053, 2053]})
        # Records written by 0.3.2 have no inbound_ports.
        self.assertEqual(inbound_ports({"inbound_port": 2053}), [2053])

    def test_plan_ports_must_not_overlap_tunnel_ports(self):
        validate_profile(plan(inbound_ports=[2053, 2083]))
        with self.assertRaises(PronetError):
            validate_profile(plan(inbound_ports=[2053, 24446]))

    def test_join_token_single_port_is_unchanged_and_list_round_trips(self):
        bootstrap = {"hub_url": "https://192.0.2.1:9443", "enrollment_key": "c" * 64, "ca_pem": ""}
        single = parse_token(make_token(bootstrap, 2053, "1234"))
        self.assertEqual(single["p"], 2053)
        multi = parse_token(make_token(bootstrap, [2053, 2083], "1234"))
        self.assertEqual(multi["p"], [2053, 2083])


class FirewallTests(unittest.TestCase):
    def test_single_port_rules_are_identical_to_before(self):
        self.assertEqual(firewall_rules(plan(), "gateway"), firewall_rules(plan(inbound_ports=[2053]), "gateway"))
        self.assertEqual(len(firewall_rules(plan(), "gateway")), 2)

    def test_every_client_port_is_opened(self):
        rules = firewall_rules(plan(inbound_ports=[2053, 2083, 8443]), "gateway")
        opened = {rule[rule.index("--dport") + 1] for rule in rules if "--dport" in rule}
        self.assertEqual(opened, {"2053", "2083", "8443"})
        tunnel = firewall_rules(plan(inbound_ports=[2053, 2083]), "engine")
        self.assertTrue(any("2083" in rule for rule in tunnel))

    def test_inbound_summary_is_open_only_when_all_ports_listen(self):
        states = {2053: "open", 2083: "refused"}
        with mock.patch("pronet.runtime.tcp_state", lambda address: states[address[1]]):
            self.assertEqual(inbound_report(plan(inbound_ports=[2053, 2083])),
                             {"inbound": "refused", "inbound_ports": {"2053": "open", "2083": "refused"}})
            self.assertEqual(inbound_report(plan()), {"inbound": "open"})


class MultiPortGatewayTests(unittest.IsolatedAsyncioTestCase):
    """Two loopback hosts sharing port numbers, without changing host networking."""

    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.directory.name)
        self.ports = free_ports(3)
        self.keys = [secret() for _ in self.ports]
        # Darwin does not assign the whole 127/8 range to loopback as Linux
        # does. Its IPv6 loopback provides a second real host without aliases.
        self.foreign_host = "::1" if platform.system() == "Darwin" else "127.0.0.2"
        class ForeignProbeServer(ProbeServer):
            address_family = socket.AF_INET6 if self.foreign_host == "::1" else socket.AF_INET
        self.inbounds = [ForeignProbeServer((self.foreign_host, number), key) for number, key in zip(self.ports, self.keys)]
        for server in self.inbounds:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        self.token = secret()
        self.bridge = None
        self.gateway = None

    async def asyncTearDown(self):
        if self.gateway:
            await self.gateway.close()
        if self.bridge:
            self.bridge.close()
            await self.bridge.wait_closed()
        for server in self.inbounds:
            await asyncio.to_thread(server.shutdown)
            server.server_close()
        self.directory.cleanup()

    async def start_gateway(self, mode):
        config = {"bind_ip": "127.0.0.1", "port": self.ports[0], "ports": self.ports}
        if mode == "framed":
            async def handler(reader, writer):
                await bridge_server(reader, writer, self.token, (self.foreign_host, self.ports[0]), tuple(self.ports[1:]))
            self.bridge = await asyncio.start_server(handler, "127.0.0.1", 0)
            config.update(mode="framed", frame_key=self.token,
                          active_backend=list(self.bridge.sockets[0].getsockname()))
        else:
            config.update(mode="plain", active_backend=[self.foreign_host, self.ports[0]])
        write_json(self.path / "gateway.json", config)
        self.gateway = Gateway(self.path / "gateway.json", self.path / "stats.json")
        await self.gateway.start()
        self.assertEqual([a[1] for a in self.gateway.addresses()], self.ports)

    async def check_each_port_reaches_its_own_inbound(self):
        for number, key in zip(self.ports, self.keys):
            await asyncio.to_thread(echo, ("127.0.0.1", number), key)
        # The key of port 1's inbound does not work on port 2: traffic really
        # went to the inbound with the same port number.
        with self.assertRaises((OSError, ValueError, PronetError)):
            await asyncio.to_thread(echo, ("127.0.0.1", self.ports[1]), self.keys[0], 2)

    async def test_framed_carrier_forwards_every_port(self):
        await self.start_gateway("framed")
        await self.check_each_port_reaches_its_own_inbound()

    async def test_l3_carrier_forwards_every_port(self):
        await self.start_gateway("plain")
        await self.check_each_port_reaches_its_own_inbound()

    async def test_bridge_refuses_ports_outside_the_tunnel(self):
        await self.start_gateway("framed")
        address = self.bridge.sockets[0].getsockname()
        for wanted in [n for n in (22, 1, 65000) if n not in self.ports]:
            reader, writer = await asyncio.open_connection(*address)
            with self.assertRaises((PronetError, OSError, ValueError, asyncio.IncompleteReadError)):
                await bridge_auth(reader, writer, self.token, port=wanted)
            writer.close()
            await writer.wait_closed()

    async def test_wrong_key_cannot_select_a_port(self):
        await self.start_gateway("framed")
        reader, writer = await asyncio.open_connection(*self.bridge.sockets[0].getsockname())
        with self.assertRaises((PronetError, OSError, ValueError, asyncio.IncompleteReadError)):
            await bridge_auth(reader, writer, secret(), port=self.ports[1])
        writer.close()
        await writer.wait_closed()


if __name__ == "__main__":
    unittest.main()
