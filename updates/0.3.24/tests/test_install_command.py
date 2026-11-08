import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from pronet import cli


class InstallCommandTests(unittest.TestCase):
    def exercise(self, fail=False, bad_first=False):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);bindir=root/'bin';bindir.mkdir()
            output=root/'args.json'
            payload='#!/usr/bin/env bash\nVERSION="'+cli.__version__+'"\npython3 -c '\
                + "'import json,os,sys;open(os.environ[\"TEST_ARGS\"],\"w\").write(json.dumps(sys.argv[1:]))' \"$@\"\n"
            fixture=root/'fixture.sh';fixture.write_text(payload)
            curl=bindir/'curl'
            curl.write_text('#!'+os.sys.executable+'\n'+'''import os,sys,shutil
args=sys.argv[1:]
destination=args[args.index('-o')+1]
if os.environ['TEST_BAD_FIRST']=='1' and any('cdn.jsdelivr.net' in a for a in args):
 open(destination,'w').write('{"error":"temporarily unavailable"}')
else:shutil.copyfile(os.environ['TEST_FIXTURE'],destination)
sys.exit(28 if os.environ['TEST_FAIL']=='1' else 0)
''');curl.chmod(0o755)
            sudo=bindir/'sudo';sudo.write_text('#!/bin/sh\nexec "$@"\n');sudo.chmod(0o755)
            env=dict(os.environ,PATH=str(bindir)+os.pathsep+os.environ['PATH'],TMPDIR=str(root),
                     TEST_ARGS=str(output),TEST_FIXTURE=str(fixture),TEST_FAIL='1' if fail else '0',TEST_BAD_FIRST='1' if bad_first else '0')
            token='PNF1-token-with-space ; touch /must-not-be-created'
            result=subprocess.run(['bash','-c',cli.install_command(token)],env=env,capture_output=True,text=True)
            if fail:
                self.assertNotEqual(result.returncode,0)
                self.assertFalse(output.exists())
            else:
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(json.loads(output.read_text()),['join',token])
            self.assertFalse([p for p in root.iterdir() if p.name.startswith('tmp.')])

    def test_download_completes_before_join_is_executed_and_arguments_are_quoted(self):
        self.exercise()

    def test_incomplete_bootstrap_is_never_executed(self):
        self.exercise(fail=True)

    def test_http_200_error_body_falls_back_before_execution(self):
        self.exercise(bad_first=True)
