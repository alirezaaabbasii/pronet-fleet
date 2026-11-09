import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from pronet import cli


class InstallCommandTests(unittest.TestCase):
    def exercise(self, fail=False, late=False):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bindir = root / 'bin'
            bindir.mkdir()
            output = root / 'args.json'
            curl = bindir / 'curl'
            payload = """python3 -c 'import json,os,sys;open(os.environ["TEST_ARGS"],"w").write(json.dumps(sys.argv[1:]))' "$@" """
            curl.write_text(
                '#!' + os.sys.executable + '\n'
                + 'import os,sys\n'
                + 'print("{")\n'
                + 'print(' + repr(payload) + ')\n'
                + 'if os.environ["TEST_FAIL"] == "1": sys.exit(28)\n'
                + 'print("}")\n'
                + 'if os.environ["TEST_LATE"] == "1": sys.exit(18)\n'
            )
            curl.chmod(0o755)
            sudo = bindir / 'sudo'
            sudo.write_text('#!/bin/sh\nexec "$@"\n')
            sudo.chmod(0o755)
            env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ['PATH'],
                       TEST_ARGS=str(output), TEST_FAIL='1' if fail else '0',
                       TEST_LATE='1' if late else '0')
            token = 'PNF1-token-with-space ; touch /must-not-be-created'
            command = cli.install_command(token)
            self.assertEqual(len(command.splitlines()), 1)
            result = subprocess.run(['sh', '-c', command], env=env, capture_output=True, text=True)
            if fail or late:
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(output.read_text()), ['join', token])

    def test_short_command_preserves_join_arguments(self):
        self.exercise()

    def test_interrupted_download_never_runs_partial_bootstrap(self):
        self.exercise(fail=True)

    def test_late_curl_failure_prevents_bootstrap_execution(self):
        self.exercise(late=True)
