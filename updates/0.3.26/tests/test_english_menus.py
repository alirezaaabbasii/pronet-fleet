import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pronet import cli


class EnglishMenusTests(unittest.TestCase):
    def test_role_menus_use_english_and_keep_the_existing_options(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory)
            for role, label in ((None, "Where is THIS server?"),
                                ("iran", "1) New standard tunnel - TCP services"),
                                ("foreign", "1) Join a tunnel - paste the command from Iran")):
                if role is not None:
                    cli.write_json(config / "node.json", {"role": role})
                out = io.StringIO()
                with patch.object(cli, "CONFIG", config), patch.object(cli, "ROOT", config), \
                        patch.object(cli, "ask", return_value="0") as ask, contextlib.redirect_stdout(out):
                    self.assertIs(cli._wizard_once(), False)
                self.assertIn(label, out.getvalue())
                self.assertIn("0) Exit", out.getvalue())
                self.assertEqual(ask.call_args.args[0], "Select")
                if role == "iran":
                    self.assertIn("10) Emergency tunnels and Spoof scan", out.getvalue())

    def test_spoof_scan_stays_in_the_english_emergency_menu(self):
        out = io.StringIO()
        with patch.object(cli, "root_linux"), patch.object(cli, "node_config", return_value={"role": "iran"}), \
                patch.object(cli, "ask", return_value="3"), patch.object(cli, "spoof_scan") as scan, \
                contextlib.redirect_stdout(out):
            cli.emergency_menu()
        scan.assert_called_once_with()
        self.assertIn("3) Scan Iran HTTPS reachability", out.getvalue())

    def test_pending_join_uses_english_after_upgrade_without_changing_token(self):
        token = cli.make_token({"hub_url": "https://192.0.2.1:9443", "enrollment_key": "a" * 64},
                               2053, "b" * 32)
        with tempfile.TemporaryDirectory() as directory:
            saved = Path(directory) / "pending-join.json"
            legacy = ["", "=" * 64, "  سرور ایران آماده است. ادامه روی سرور خارج",
                      "  کل خط زیر را کپی و در ترمینال سرور خارج اجرا کنید.", "=" * 64,
                      cli.install_command(token), "sudo pronet join " + token, ""]
            cli.write_json(saved, {"pair_id": "a" * 24, "lines": legacy})
            with patch.object(cli, "JOIN_FILE", saved):
                lines = cli.join_lines("a" * 24)
            self.assertIn("  IRAN IS READY. NEXT STEP ON YOUR FOREIGN SERVER:", lines)
            self.assertIn("sudo pronet join " + token, lines)
            self.assertIn(cli.install_command(token), lines)
            self.assertEqual(cli.read_json(saved)["lines"], legacy)
