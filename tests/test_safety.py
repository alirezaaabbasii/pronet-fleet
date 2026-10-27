import pathlib
import tempfile
import unittest
from unittest import mock

from pronet.accounting import accumulate
from pronet.common import PronetError, atomic_write, write_json
from pronet.model import validate_profile
from pronet.runtime import endpoint_has_nat, endpoint_occupied, firewall_rules, native_nat_reservations, owned_directory, unit_name, write_unit


class SafetyTests(unittest.TestCase):
    def test_counter_reboot_and_reset_preserve_observed_totals(self):
        one = accumulate({}, {"a": 100}, "boot1", 10)
        two = accumulate(one, {"a": 150}, "boot1", 20)
        three = accumulate(two, {"a": 7}, "boot2", 30)
        four = accumulate(three, {"a": 2}, "boot2", 40)
        self.assertEqual([x["totals"]["a"] for x in (one, two, three, four)], [100, 150, 157, 159])
        self.assertEqual(two["rates"]["a"], 5)
        self.assertIsNone(three["rates"]["a"])

    def test_multi_ip_endpoint_checks_do_not_confuse_distinct_addresses(self):
        inventory = {"ports": [2053], "listeners": [{"address": "192.0.2.1", "port": 2053}]}
        self.assertTrue(endpoint_occupied(inventory, "192.0.2.1", 2053))
        self.assertFalse(endpoint_occupied(inventory, "192.0.2.2", 2053))
        inventory["listeners"].append({"address": "::", "port": 2053})
        self.assertTrue(endpoint_occupied(inventory, "192.0.2.2", 2053))

    def test_existing_nat_is_detected_even_without_a_socket_listener(self):
        inventory = {"nat_reserved": [{"destination": "192.0.2.1/32", "first": 2000, "last": 2100}]}
        self.assertTrue(endpoint_has_nat(inventory, "192.0.2.1", 2053))
        self.assertFalse(endpoint_has_nat(inventory, "192.0.2.2", 2053))

    def test_native_nft_nat_and_unknown_maps_reserve_endpoints(self):
        document = {"nftables": [{"rule": {"family": "inet", "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "192.0.2.1"}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 2053}},
            {"dnat": {"addr": "10.0.0.2", "port": 2053}}]}}]}
        info = {"nat_reserved": native_nat_reservations(document)}
        self.assertTrue(endpoint_has_nat(info, "192.0.2.1", 2053))
        self.assertFalse(endpoint_has_nat(info, "192.0.2.2", 2053))
        document["nftables"][0]["rule"]["expr"] = [{"dnat": {"addr": {"map": "@unknown"}}}]
        self.assertTrue(endpoint_has_nat({"nat_reserved": native_nat_reservations(document)}, "192.0.2.2", 12345))

    def test_unit_name_refuses_injection_and_roles_are_isolated(self):
        with self.assertRaises(PronetError): unit_name("../root", "bp-kcp", "engine", "iran")
        self.assertNotEqual(unit_name("a" * 24, "bp-kcp", "engine", "iran"), unit_name("a" * 24, "bp-kcp", "engine", "foreign"))

    def test_atomic_write_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            target = root / "original"; target.write_text("keep")
            path = root / "link"; path.symlink_to(target)
            with self.assertRaises(PronetError): atomic_write(path, "overwrite")
            self.assertEqual(target.read_text(), "keep")

    def test_staging_service_really_expires_instead_of_restarting_forever(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "unit.service"
            with mock.patch("pronet.runtime.unit_path", return_value=path):
                write_unit("pronetf-test.service", "test", ["/usr/bin/true"], pathlib.Path(temporary), temporary=True)
                text = path.read_text()
                self.assertIn("RuntimeMaxSec=900", text)
                self.assertIn("Restart=no\n", text)
                self.assertIn("WorkingDirectory=" + temporary + "\n", text)
                self.assertNotIn('WorkingDirectory="', text)
                self.assertNotIn("Restart=always", text)
                write_unit("pronetf-test.service", "test", ["/usr/bin/true"], pathlib.Path(temporary), temporary=False)
                self.assertNotIn("RuntimeMaxSec", path.read_text())
                self.assertIn("Restart=always", path.read_text())
                self.assertIn("StartLimitIntervalSec=0", path.read_text())

    def test_existing_unmanaged_unit_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "unit.service"
            path.write_text("[Unit]\nDescription=Existing service\n")
            with mock.patch("pronet.runtime.unit_path", return_value=path), self.assertRaises(PronetError):
                write_unit("pronetf-test.service", "test", ["/usr/bin/true"], pathlib.Path(temporary))
            self.assertIn("Existing service", path.read_text())


if __name__ == "__main__": unittest.main()
