"""Run real Bash download code and curl against controlled HTTP endpoints."""
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = b'verified release fixture\n'
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.responses = {}
        self.requests = []
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append((self.path, self.headers.get('Accept')))
                kind = self.path.split('/')[1]
                response = owner.responses.get(kind, (503, b'unavailable'))
                code, body = response[:2]
                quota = getattr(owner, 'api_quota', None)
                if kind == 'api' and quota is not None:
                    if sum('/api/' in r[0] for r in owner.requests) > quota:
                        code, body = 429, b'API request quota exhausted'

                if code == 200:
                    for name, data in getattr(owner, 'path_payloads', {}).items():
                        if self.path.split('?')[0].endswith('/'+name):
                            body=data
                self.send_response(code)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    if len(response) > 2:
                        self.wfile.write(body[:1]); self.wfile.flush()
                        time.sleep(response[2])
                        self.wfile.write(body[1:])
                    else:
                        self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        bindir = self.root/'bin'; bindir.mkdir()
        real_curl = shutil.which('curl')
        if os.sys.platform == 'darwin':
            shim = bindir/'sha256sum'
            shim.write_text('#!/bin/sh\nexec shasum -a 256 -c -\n')
            shim.chmod(0o755)
        wrapper = bindir/'curl'
        wrapper.write_text('#!' + os.sys.executable + '\n' + '''import os,sys
from urllib.parse import urlsplit
args=sys.argv[1:]
for i,arg in enumerate(args):
    if arg.startswith('https://'):
        p=urlsplit(arg)
        kind=('raw' if p.netloc=='raw.githubusercontent.com' else 'cdn' if p.netloc=='cdn.jsdelivr.net' else 'api' if p.netloc=='api.github.com' else 'upstream')
        args[i]=os.environ['TEST_HTTP']+'/'+kind+p.path+('?' + p.query if p.query else '')
os.execv(os.environ['TEST_CURL'],[os.environ['TEST_CURL']]+args)
''')
        wrapper.chmod(0o755)
        self.env = dict(os.environ, PATH=str(bindir)+os.pathsep+os.environ['PATH'],
                        TEST_CURL=real_curl, TEST_HTTP='http://127.0.0.1:'+str(server.server_port),
                        DOWNLOAD_CONNECT_TIMEOUT='1', DOWNLOAD_IDLE_SECONDS='1', DOWNLOAD_MAX_SECONDS='4')

    def run_fetch(self, *, mode='small', upstream='', suffix=''):
        output = self.root/'release.bin'
        script = '''set -eu
OWNER_REPO=example/project
REPO_REF=fixture-v1
say() { printf '%s\\n' "$*"; }
fail() { printf '%s\\n' "$*" >&2; exit 1; }
source "$1"
repo_fetch dist/release.bin "$2" "$3" "$4" "$5"
''' + suffix
        result = subprocess.run(['bash','-c',script,'bash',str(ROOT/'tools/download.sh'),
                                 DIGEST,str(output),upstream,mode],env=self.env,
                                capture_output=True,text=True,timeout=15)
        return result, output

    def test_raw_unavailable_uses_cdn_and_accepts_only_verified_bytes(self):
        self.responses['cdn']=(200,PAYLOAD)
        result, output = self.run_fetch()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(output.read_bytes(),PAYLOAD)
        self.assertEqual([r[0].split('/')[1] for r in self.requests],['raw','cdn'])
        self.assertFalse(output.with_name('release.bin.part').exists())

    def test_large_archive_skips_cdn_and_uses_api_raw_representation(self):
        self.responses['api']=(200,PAYLOAD)
        result, output = self.run_fetch(mode='large')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(output.read_bytes(),PAYLOAD)
        self.assertEqual([r[0].split('/')[1] for r in self.requests],['raw','api'])
        self.assertEqual(self.requests[-1][1],'application/vnd.github.raw+json')
        self.assertIn('ref=fixture-v1',self.requests[-1][0])

    def test_bad_digest_and_http_200_json_are_not_accepted(self):
        self.responses.update(raw=(200,b'corrupt'),cdn=(200,b'{"error":"denied"}'),api=(200,PAYLOAD))
        result, output = self.run_fetch()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(output.read_bytes(),PAYLOAD)
        self.assertEqual(len(self.requests),3)

    def test_all_sources_fail_keeps_existing_destination_and_removes_partial(self):
        output=self.root/'release.bin';output.write_bytes(b'existing verified artifact')
        self.responses.update(raw=(200,b'corrupt'),cdn=(200,b'corrupt'),api=(200,b'corrupt'))
        result, output = self.run_fetch()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(output.read_bytes(),b'existing verified artifact')
        self.assertEqual(len(self.requests),3)
        self.assertFalse(output.with_name('release.bin.part').exists())

    def test_idle_transfer_is_bounded_and_next_source_is_tried(self):
        self.responses.update(raw=(200,PAYLOAD,3),cdn=(200,PAYLOAD))
        started=time.monotonic()
        result, output = self.run_fetch()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(output.read_bytes(),PAYLOAD)
        self.assertLess(time.monotonic()-started,5)
        self.assertEqual([r[0].split('/')[1] for r in self.requests],['raw','cdn'])

    def test_successful_transport_is_preferred_for_later_files(self):
        self.responses['api']=(200,PAYLOAD)
        result, output = self.run_fetch(mode='large',suffix='repo_fetch dist/second.bin "$2" "$3" "" large\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual([r[0].split('/')[1] for r in self.requests],['raw','api','api'])

    def test_locked_upstream_is_used_for_independent_engine(self):
        self.responses['upstream']=(200,PAYLOAD)
        result, output = self.run_fetch(upstream='https://github.com/vendor/engine/releases/download/v1/engine.zip')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(output.read_bytes(),PAYLOAD)
        self.assertEqual([r[0].split('/')[1] for r in self.requests],['raw','upstream'])



    def test_chunked_archive_reassembles_exact_original_and_checks_final_digest(self):
        first,second=PAYLOAD[:9],PAYLOAD[9:]
        self.responses.update(raw=(503,b'unavailable'),cdn=(200,first),api=(200,second))
        # A tiny HTTP fixture routes the second part to a distinct delivery endpoint.
        first_sha=hashlib.sha256(first).hexdigest();second_sha=hashlib.sha256(second).hexdigest()
        script='set -eu\nOWNER_REPO=example/project\nREPO_REF=fixture-v1\nsay() { :; }\nfail() { echo "$*" >&2; exit 1; }\nsource "$1"\nrepo_fetch_parts "$2" "$3" "part1:$4" "part2:$5"\n'
        # Serve contents by path, irrespective of transport.
        self.path_payloads={'part1':first,'part2':second}
        output=self.root/'combined.zip'
        result=subprocess.run(['bash','-c',script,'bash',str(ROOT/'tools/download.sh'),DIGEST,str(output),first_sha,second_sha],env=self.env,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(output.read_bytes(),PAYLOAD)
        self.assertFalse(list(self.root.glob('combined.zip.chunks.*')))


    def test_api_only_archive_does_not_spend_api_quota_on_parts(self):
        self.api_quota=2
        self.responses['api']=(200,PAYLOAD)
        archive=PAYLOAD*3
        self.path_payloads={'full.zip':archive,'part1':PAYLOAD,'part2':PAYLOAD,'part3':PAYLOAD}
        output=self.root/'quota.zip'
        script='set -eu\nOWNER_REPO=example/project\nREPO_REF=fixture-v1\nsay() { :; }\nfail() { echo "$*" >&2; exit 1; }\nsource "$1"\nrepo_fetch_archive full.zip "$2" "$3" "part1:$4" "part2:$4" "part3:$4"\n'
        result=subprocess.run(['bash','-c',script,'bash',str(ROOT/'tools/download.sh'),hashlib.sha256(archive).hexdigest(),str(output),DIGEST],env=self.env,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(output.read_bytes(),archive)
        self.assertLessEqual(sum('/api/' in r[0] for r in self.requests),2)

    def test_bad_final_archive_digest_never_replaces_destination(self):
        self.responses['cdn']=(200,PAYLOAD)
        output=self.root/'combined.zip';output.write_bytes(b'original destination')
        script='set -eu\nOWNER_REPO=example/project\nREPO_REF=fixture-v1\nsay() { :; }\nfail() { echo "$*" >&2; exit 1; }\nsource "$1"\nrepo_fetch_parts "$2" "$3" "one:$4"\n'
        result=subprocess.run(['bash','-c',script,'bash',str(ROOT/'tools/download.sh'),'0'*64,str(output),DIGEST],env=self.env,capture_output=True,text=True,timeout=15)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(output.read_bytes(),b'original destination')
        self.assertTrue(self.requests)
        self.assertFalse(list(self.root.glob('combined.zip.chunks.*')))

    def test_bootstrap_verifies_payload_before_forwarding_join_arguments(self):
        payload=b'#!/bin/bash\nprintf "%s\\n" "$@" > "$TEST_ARGS"\nexit 17\n'
        sha=hashlib.sha256(payload).hexdigest()
        script=(ROOT/'install.sh').read_text()
        import re
        script=re.sub(r'^INSTALLER_SHA256="[a-f0-9]{64}"$', 'INSTALLER_SHA256="'+sha+'"', script, flags=re.M)
        self.responses.update(raw=(200,b'corrupt installer'),cdn=(200,payload))
        output=self.root/'bootstrap-args'
        path=self.root/'bootstrap.sh';path.write_text(script)
        env=dict(self.env,TEST_ARGS=str(output),TMPDIR=str(self.root))
        result=subprocess.run(['bash',str(path),'join','synthetic-token'],env=env,text=True,capture_output=True,timeout=15)
        self.assertEqual(result.returncode,17,result.stderr)
        self.assertEqual(output.read_text().splitlines(),['join','synthetic-token'])
        self.assertFalse(list(self.root.glob('pronet-bootstrap.*')))
        self.assertNotIn('synthetic-token',result.stdout+result.stderr)

    def test_bootstrap_rejects_http_success_with_wrong_content(self):
        script=(ROOT/'install.sh').read_text()
        self.responses.update(raw=(200,b'echo forbidden'),cdn=(200,b'echo forbidden'),api=(200,b'echo forbidden'))
        path=self.root/'bootstrap.sh';path.write_text(script)
        result=subprocess.run(['bash',str(path)],env=dict(self.env,TMPDIR=str(self.root)),capture_output=True,text=True,timeout=15)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(list(self.root.glob('pronet-bootstrap.*')))
        self.assertNotIn('forbidden',result.stdout)


if __name__=='__main__':
    unittest.main()
