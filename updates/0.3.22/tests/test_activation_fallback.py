"""A changed route must not discard qualified committed standbys."""
import unittest
from unittest import mock

from pronet.common import PronetError
from pronet.controller import Controller


class ActivationFallbackTests(unittest.TestCase):
    def setUp(self):
        self.controller = Controller(mock.Mock())
        self.pair = {"id": "a" * 24, "iran": "iran-node"}
        self.names = ["gre", "bp-l3-udp-reverse", "bp-l3-pck-reverse"]
        self.plans = [{"profile": name} for name in self.names]
        self.result = {"phase": "committing", "live": {"now": {}}, "warnings": []}
        self.controller.payloads = mock.Mock(side_effect=lambda pair, plan: {"iran": plan})
        self.controller.both = mock.Mock()

    def verify(self):
        return self.controller.verify_committed(self.pair, self.plans, self.names, self.result)

    def test_success_does_not_restart_or_retest_standbys(self):
        self.controller.rpc = mock.Mock(return_value={"profile": "gre", "passed": True})
        self.assertEqual(self.verify(), self.names)
        self.controller.both.assert_not_called()
        self.assertEqual(self.controller.rpc.call_count, 1)
        self.assertEqual(self.result["phase"], "verifying")

    def test_failed_primary_removed_on_both_nodes_then_standby_proved(self):
        self.controller.rpc = mock.Mock(side_effect=[
            {"profile": "gre", "passed": False, "stage": "reach", "reason": "unreachable"},
            {"profile": self.names[1], "passed": True}])
        self.assertEqual(self.verify(), self.names[1:])
        self.assertEqual(self.result["active"], self.names[1])
        self.assertEqual(self.result["selected"], self.names[1:])
        self.assertEqual(len(self.result["post_commit"]), 2)
        self.controller.both.assert_called_once_with(self.pair, "commit",
            {"iran": {"profiles": self.names[1:]}, "foreign": {"profiles": self.names[1:]}},
            "post-commit:fallback:" + self.names[1])
        self.assertIn("unreachable", self.result["warnings"][0])

    def test_all_failed_never_accepts_unproven_path(self):
        self.controller.rpc = mock.Mock(side_effect=[
            {"profile": name, "passed": False, "reason": "loss too high"} for name in self.names])
        with self.assertRaisesRegex(PronetError, "No qualified carrier passed"):
            self.verify()
        self.assertEqual(self.controller.rpc.call_count, 3)
        self.assertEqual(self.result["phase"], "verifying")

    def test_ownership_or_cleanup_error_aborts_without_using_another_path(self):
        self.controller.rpc = mock.Mock(return_value={"profile": "gre", "passed": False})
        self.controller.both.side_effect = PronetError("Service stop not confirmed")
        with self.assertRaisesRegex(PronetError, "Service stop not confirmed"):
            self.verify()
        self.assertEqual(self.controller.rpc.call_count, 1)

    def test_rpc_timeout_or_operator_stop_is_not_a_quality_failure(self):
        self.controller.rpc = mock.Mock(side_effect=PronetError("Operator requested a stop"))
        with self.assertRaisesRegex(PronetError, "Operator requested"):
            self.verify()
        self.controller.both.assert_not_called()


if __name__ == "__main__":
    unittest.main()
