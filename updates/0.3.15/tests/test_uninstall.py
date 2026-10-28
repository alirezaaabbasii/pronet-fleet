"""`pronet uninstall` removes only what Pronet Fleet owns (0.3.7)."""
import contextlib
import io
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

from pronet import cli

IPTABLES = """-P INPUT ACCEPT
-A INPUT -s 198.51.100.1/32 -d 192.0.2.1/32 -p tcp -m tcp --dport 443 -m comment --comment pronetf:aaaa:bp-stealth:engine -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -m comment --comment "my ssh rule" -j ACCEPT
-A OUTPUT -s 192.0.2.1/32 -p tcp -m tcp --sport 2053 -m comment --comment pronetf:aaaa:gateway -j ACCEPT
"""
NFT = "table inet filter\ntable netdev pronetf_1234abcd\ntable ip nat\n"


class UninstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = pathlib.Path(self.tmp.name)
        self.units, self.control = base / "units", base / "control"
        self.opt, self.state, self.config = base / "opt", base / "state", base / "config"
        self.wrapper = base / "bin-pronet"
        for path in (self.units, self.control, self.opt / "0.3.7", self.state / "pairs", self.config):
            path.mkdir(parents=True)
        (self.units / "pronetf-agent.service").write_text(cli.UNIT_MARKER + "agent\n[Service]\n")
        (self.units / "pronetf-aaaa-gateway.service").write_text(cli.UNIT_MARKER + "aaaa\n[Service]\n")
        (self.units / "pronetf-lookalike.service").write_text("[Service]\n# not ours\n")
        (self.units / "nginx.service").write_text("[Service]\n")
        (self.control / "pronetf-aaaa-gateway.service.d").mkdir()
        (self.config / "node.json").write_text("{}")
        self.wrapper.write_text("#!/bin/sh\n# Managed by Pronet Fleet\nexec true\n")
        self.calls = []
        patches = [mock.patch.object(cli, name, value) for name, value in (
            ("UNIT_DIR", self.units), ("CONTROL_DIR", self.control), ("OPT_ROOT", self.opt),
            ("WRAPPER", self.wrapper), ("ROOT", self.state), ("CONFIG", self.config))]
        patches += [mock.patch.object(cli, "root_linux"), mock.patch.object(cli, "command", self.fake_command),
                    mock.patch.object(cli.shutil, "which", lambda name: "/usr/sbin/" + name)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def fake_command(self, args, timeout=30, check=True, input=None):
        self.calls.append(args)
        out = IPTABLES if args[-1] == "-S" and "filter" in args else NFT if args[1:3] == ["list", "tables"] else ""
        if args[:2] == ["systemctl", "show"]:
            out = "ActiveState=inactive\nMainPID=0\nControlPID=0\n"
        return subprocess.CompletedProcess(args, 0, out, "")

    def run_uninstall(self, answer=None, confirmed=False):
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                mock.patch("builtins.input", lambda prompt: answer or ""):
            done = cli.uninstall(confirmed)
        return done, out.getvalue()

    def test_cancel_changes_nothing(self):
        done, _ = self.run_uninstall("no")
        self.assertFalse(done)
        self.assertEqual(self.calls, [])
        self.assertTrue((self.units / "pronetf-agent.service").exists())
        self.assertTrue(self.config.exists())

    def test_removes_only_owned_resources(self):
        done, text = self.run_uninstall("UNINSTALL")
        self.assertTrue(done)
        self.assertIn("removed", text)
        stopped = [args[-1] for args in self.calls if args[:3] == ["systemctl", "disable", "--now"]]
        self.assertEqual(sorted(stopped), ["pronetf-aaaa-gateway.service", "pronetf-agent.service"])
        self.assertFalse((self.units / "pronetf-agent.service").exists())
        self.assertFalse((self.units / "pronetf-aaaa-gateway.service").exists())
        self.assertTrue((self.units / "pronetf-lookalike.service").exists())
        self.assertTrue((self.units / "nginx.service").exists())
        self.assertFalse((self.control / "pronetf-aaaa-gateway.service.d").exists())
        deleted = [args for args in self.calls if "-D" in args]
        self.assertEqual(len(deleted), 2)
        self.assertTrue(all(any(p.startswith("pronetf:") for p in args) for args in deleted))
        self.assertIn(["nft", "delete", "table", "netdev", "pronetf_1234abcd"], self.calls)
        self.assertFalse(any(args[:2] == ["nft", "delete"] and "pronetf_" not in args[-1] for args in self.calls))
        for path in (self.opt, self.state, self.config, self.wrapper):
            self.assertFalse(path.exists(), path)

    def test_unconfirmed_stop_retains_management_and_never_clears_other_services(self):
        original = self.fake_command
        def call(args, **kwargs):
            if args[:2] == ["systemctl", "show"]:
                return subprocess.CompletedProcess(args, 0, "ActiveState=active\nMainPID=123\nControlPID=0\n", "")
            return original(args, **kwargs)
        with mock.patch.object(cli, "command", side_effect=call):
            done, text = self.run_uninstall(confirmed=True)
        self.assertFalse(done)
        self.assertIn("retained", text)
        for path in (self.opt, self.state, self.config, self.wrapper): self.assertTrue(path.exists())
        self.assertTrue((self.units / "pronetf-agent.service").exists())
        self.assertNotIn(["systemctl", "reset-failed"], self.calls)

    def test_reset_failed_is_always_limited_to_owned_units(self):
        self.run_uninstall(confirmed=True)
        calls = [args for args in self.calls if args[:2] == ["systemctl", "reset-failed"]]
        self.assertEqual(len(calls), 1)
        self.assertTrue(all(name.startswith("pronetf-") for name in calls[0][2:]))
        self.assertEqual(len(calls[0]), 4)

    def test_foreign_wrapper_is_kept(self):
        self.wrapper.write_text("#!/bin/sh\necho someone else\n")
        self.run_uninstall(confirmed=True)
        self.assertTrue(self.wrapper.exists())


if __name__ == "__main__":
    unittest.main()
