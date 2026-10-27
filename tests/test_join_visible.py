"""The join command must stay on screen until the foreign server joins (0.3.7)."""
import contextlib
import io
import pathlib
import tempfile
import time
import unittest
from unittest import mock

from pronet import cli


def pair(state, pair_id="a" * 24):
    return {"id": pair_id, "iran": "n1", "foreign": None, "state": state, "updated": 0,
            "request": {"name": "t1", "public_ip": "192.0.2.1", "inbound_port": 2053},
            "result": {"phase": "failed", "error": "test end", "results": [], "timing": {}}}


class TTY(io.StringIO):
    def isatty(self):
        return True


class JoinVisibleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.join = pathlib.Path(self.directory.name) / "pending-join.json"
        self.patch = mock.patch.object(cli, "JOIN_FILE", self.join)
        self.patch.start()
        self.command = "curl -fsSL https://example.invalid/get.sh | sudo bash -s -- join PNF1-test"
        cli.write_json(self.join, {"pair_id": "a" * 24, "lines": ["", self.command, ""], "expires": time.time() + 600})

    def tearDown(self):
        self.patch.stop()
        self.directory.cleanup()

    def run_follow(self, states):
        answers = iter([{"pairs": [pair(state)], "nodes": []} for state in states])
        client = mock.Mock()
        client.call.side_effect = lambda *_: next(answers)
        out = TTY()
        with mock.patch.object(cli, "node_client", return_value=client), mock.patch.object(cli.time, "sleep"), \
                mock.patch.object(cli, "hub_config", return_value=None), mock.patch.object(cli.sys, "stdout", out), \
                contextlib.redirect_stdout(out):
            cli.follow("a" * 24)
        return out.getvalue()

    def test_join_command_survives_every_redraw_while_waiting(self):
        text = self.run_follow(["UNPAIRED", "UNPAIRED", "FAILED"])
        screens = text.split("\033[2J\033[H")
        waiting = [screen for screen in screens if "Waiting for the foreign server" in screen]
        self.assertEqual(len(waiting), 2)
        for screen in waiting:
            self.assertIn(self.command, screen)

    def test_join_command_is_not_repeated_after_pairing(self):
        text = self.run_follow(["UNPAIRED", "PAIRED", "FAILED"])
        after = text.split("\033[2J\033[H")[2]
        self.assertNotIn(self.command, after)

    def test_status_view_shows_command_and_id_while_waiting(self):
        out = io.StringIO()
        data = {"pairs": [pair("UNPAIRED")], "nodes": [], "server_time": time.time()}
        with contextlib.redirect_stdout(out), mock.patch.object(cli, "hub_config", return_value=None):
            cli.display(data)
        self.assertIn(self.command, out.getvalue())
        self.assertIn("a" * 24, out.getvalue())

    def test_expired_or_foreign_tunnel_command_is_not_shown(self):
        self.assertEqual(cli.join_lines("b" * 24), [])
        cli.write_json(self.join, {"pair_id": "a" * 24, "lines": ["", self.command, ""], "expires": time.time() - 1})
        lines = cli.join_lines("a" * 24)
        self.assertNotIn(self.command, lines)
        self.assertTrue(any("expired" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
