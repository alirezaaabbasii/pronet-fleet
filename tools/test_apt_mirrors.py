import importlib.util
import json
import os
import pty
import select
import socket
import struct
import threading
import time
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


class MirrorTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).with_name('iran-apt-mirrors.py')
        self.assertTrue(path.exists(), 'Iran installer mirror selector is missing')
        spec = importlib.util.spec_from_file_location('apt_mirrors', path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_private_sources_preserve_original_and_third_party(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); original = root/'etc'; original.mkdir()
            parts = original/'sources.list.d'; parts.mkdir()
            ubuntu = ('Types: deb\nURIs: https://old.example/ubuntu\n'
                      'Suites: noble noble-updates noble-security\nComponents: main universe\n'
                      'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n')
            docker = 'deb [signed-by=/etc/apt/docker.gpg] https://download.docker.com/linux/ubuntu noble stable\n'
            (parts/'ubuntu.sources').write_text(ubuntu)
            (parts/'docker.list').write_text(docker)
            self.module.make_sources(original, root/'private', 'https://archive.ubuntu.com/ubuntu', 'noble')
            self.assertEqual((parts/'ubuntu.sources').read_text(), ubuntu)
            self.assertEqual((parts/'docker.list').read_text(), docker)
            self.assertEqual((root/'private/sources.list.d/docker.list').read_text(), docker)
            selected = (root/'private/sources.list.d/ubuntu.sources').read_text()
            self.assertIn('URIs: https://archive.ubuntu.com/ubuntu', selected)
            self.assertIn('Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg', selected)

    def test_legacy_ubuntu_sources_and_security_share_selected_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); apt = root/'etc'; apt.mkdir()
            source = 'deb [arch=amd64] https://old.example/ubuntu noble-security main\n'
            (apt/'sources.list').write_text(source)
            self.module.make_sources(apt, root/'private', 'https://mirror.example/ubuntu', 'noble')
            self.assertEqual((apt/'sources.list').read_text(), source)
            self.assertEqual((root/'private/sources.list').read_text(), source.replace('https://old.example/ubuntu', 'https://mirror.example/ubuntu'))

    def test_no_ubuntu_entry_does_not_invent_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); apt = root/'etc'; apt.mkdir()
            with self.assertRaises(ValueError):
                self.module.make_sources(apt, root/'private', 'https://archive.ubuntu.com/ubuntu', 'noble')

    def test_unsigned_metadata_and_http_403_are_rejected(self):
        for status in (22, 0):
            def run(args, **kwargs):
                if args[0] == 'curl':
                    Path(args[args.index('--output')+1]).write_text('not signed')
                    return subprocess.CompletedProcess(args, status, '9999999', '')
                return subprocess.CompletedProcess(args, 1, '', '')
            with patch.object(self.module.subprocess, 'run', side_effect=run):
                result = self.module.probe('https://mirror.example/ubuntu', 'noble', Path('/keyring'))
            self.assertEqual(result['speed'], 0)

    def test_verified_metadata_qualifies(self):
        def run(args, **kwargs):
            if args[0] == 'curl':
                Path(args[args.index('--output')+1]).write_text('Codename: noble\n')
                return subprocess.CompletedProcess(args, 0, '125000', '')
            return subprocess.CompletedProcess(args, 0, '', '')
        with patch.object(self.module.subprocess, 'run', side_effect=run):
            result = self.module.probe('https://mirror.example/ubuntu', 'noble', Path('/keyring'))
        self.assertEqual(result['speed'], 125000)

    def test_arm_uses_ports_not_amd64_archives(self):
        self.assertEqual(self.module.candidates('arm64'), ['https://ports.ubuntu.com/ubuntu-ports'])
        self.assertIn('https://ubuntu.pishgaman.net/ubuntu', self.module.candidates('amd64'))

    def test_dns_probe_checks_real_answer_and_rejects_wrong_id(self):
        self.assertTrue(hasattr(self.module, 'dns_query'), 'Read-only DNS probe is missing')
        for valid in (True, False):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
                server.bind(('127.0.0.1', 0)); server.settimeout(2)
                def respond():
                    request, peer = server.recvfrom(512)
                    ident = request[:2] if valid else bytes(x ^ 255 for x in request[:2])
                    reply = ident + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + request[12:]
                    reply += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('93.184.216.34')
                    server.sendto(reply, peer)
                worker = threading.Thread(target=respond); worker.start()
                result = self.module.dns_query('127.0.0.1', 'example.com', port=server.getsockname()[1], timeout=.2)
                worker.join(2)
                if valid:
                    self.assertIsInstance(result, float)
                    self.assertGreaterEqual(result, 0)
                else:
                    self.assertIsNone(result)

    def test_dns_settings_are_read_only_and_keep_configured_resolvers(self):
        self.assertTrue(hasattr(self.module, 'current_dns'), 'DNS configuration reader is missing')
        with tempfile.TemporaryDirectory() as temp:
            resolv = Path(temp)/'resolv.conf'
            original = '# existing configuration\nnameserver 127.0.0.53\nnameserver 9.9.9.9\n'
            resolv.write_text(original)
            with patch.object(self.module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'Global: 1.1.1.1\nLink 2 (eth0): 8.8.8.8\n', '')):
                servers = self.module.current_dns(resolv)
            self.assertEqual(set(servers), {'127.0.0.53', '9.9.9.9', '1.1.1.1', '8.8.8.8'})
            self.assertEqual(resolv.read_text(), original)

    def test_unreliable_dns_cannot_outrank_complete_resolver(self):
        self.assertTrue(hasattr(self.module, 'dns_probe'), 'DNS suggestion is missing')
        with patch.object(self.module, 'dns_query', side_effect=[1., None, 1., 1., 1., 1.]):
            bad = self.module.dns_probe('1.1.1.1')
        with patch.object(self.module, 'dns_query', return_value=25.):
            good = self.module.dns_probe('9.9.9.9')
        self.assertFalse(bad['complete'])
        self.assertTrue(good['complete'])
        self.assertEqual(good['latency'], 25.)

    def prerequisite_run(self, *, iran=True, failure='', answer=None, bootstrap=False):
        """Run the actual prerequisite block with privileged/network boundaries intercepted."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); binaries = root/'bin'; binaries.mkdir()
            working = root/'tmp'; working.mkdir()
            calls = root/'calls.jsonl'
            bootstrap_marker = root/'bootstrapped'
            release = root/'os-release'; release.write_text('ID=ubuntu\nVERSION_CODENAME=noble\n')
            keyring = root/'ubuntu-keyring.gpg'; keyring.touch()
            def program(name, code):
                path = binaries/name
                path.write_text('#!'+os.sys.executable+'\n'+code)
                path.chmod(0o755)
            program('id', 'print(0)')
            program('uname', 'import sys; print("Linux" if "-s" in sys.argv else "x86_64")')
            program('pronet', 'print("0.0.0")')
            for name in ('ip', 'ss', 'iptables', 'nft', 'ssh-keygen', 'openssl', 'unzip', 'gpgv'):
                program(name, 'pass')
            helper = Path(__file__).with_name('iran-apt-mirrors.py')
            program('dpkg', 'print("amd64")')
            program('curl', 'import shutil,sys; shutil.copyfile('+repr(str(helper))+',sys.argv[sys.argv.index("-o")+1])')
            program('sha256sum', 'import hashlib,sys; h,p=sys.stdin.read().strip().split("  ",1); sys.exit(0 if hashlib.sha256(open(p,"rb").read()).hexdigest()==h else 1)')
            common = 'import json,sys,pathlib\nwith open('+repr(str(calls))+',"a") as f:f.write(json.dumps(sys.argv)+"\\n")\n'
            program('python3', common+('sys.exit(23)\n' if failure == 'selector' else '')+
                    'print("DNS and mirror selection completed")\np=pathlib.Path(sys.argv[sys.argv.index("--directory")+1]); (p/"sources.list.d").mkdir(parents=True); (p/"sources.list").touch()\n')
            program('apt-get', common+('sys.exit(24)\n' if failure == 'install' else '')+('pathlib.Path('+repr(str(bootstrap_marker))+').touch()\n' if bootstrap else ''))
            script = Path(__file__).parents[1]/'get.sh'
            text = script.read_text().split("python3 -c 'import sys; sys.exit",1)[0]+'exit 0\n'
            text = text.replace('[ -d /run/systemd/system ]','true')
            text = text.replace('/usr/local/bin/pronet',str(binaries/'pronet'))
            text = text.replace('/tmp/pronet-apt.',str(working/'pronet-apt.'))
            text = text.replace('/etc/os-release', str(release)).replace('/usr/share/keyrings/ubuntu-archive-keyring.gpg',str(keyring))
            # Force one missing prerequisite independently of host tools.
            text = text.replace('need=""','command() { if [ "$1" = "-v" ] && [ "$2" = "wg" ]; then return 1; fi; builtin command "$@"; }\nneed=""',1)
            if bootstrap:
                text = text.replace('command() { ', 'command() { if [ \"$1\" = \"-v\" ] && [ \"$2\" = \"python3\" ] && [ ! -f '+str(bootstrap_marker)+' ]; then return 1; fi; ', 1)
            local = root/'get.sh'; local.write_text(text)
            args = [] if answer is not None else ['--iran-mirrors'] if iran else ['join', 'synthetic-token']
            env=dict(os.environ,PATH=str(binaries)+os.pathsep+os.environ['PATH'])
            env.pop('PRONET_NO_MENU',None)
            if answer is None:
                result = subprocess.run(['bash',str(local)]+args, text=True,capture_output=True,env=env)
            else:
                pid, terminal = pty.fork()
                if pid == 0:
                    os.execvpe('bash',['bash',str(local)]+args,env)
                output=b''; replied=False; deadline=time.monotonic()+15
                try:
                    while time.monotonic()<deadline:
                        ready,_,_=select.select([terminal],[],[],.1)
                        if not ready: continue
                        try: chunk=os.read(terminal,65536)
                        except OSError: break
                        if not chunk: break
                        output+=chunk
                        if b'Select [2]:' in output and not replied:
                            os.write(terminal,(answer+'\n').encode()); replied=True
                    if not replied:
                        os.kill(pid,9)
                    _, status=os.waitpid(pid,0)
                    result=subprocess.CompletedProcess([],os.waitstatus_to_exitcode(status),output.decode(),output.decode())
                finally:
                    os.close(terminal)
                self.assertTrue(replied,output.decode())
            history = [json.loads(x) for x in calls.read_text().splitlines()] if calls.exists() else []
            self.assertEqual(list(working.iterdir()), [], 'Temporary mirror files survived installation')
            return result, history

    def test_minimal_ubuntu_bootstraps_python_using_private_signed_apt_sources(self):
        result, calls = self.prerequisite_run(bootstrap=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Preparing mirror tester', result.stdout)
        apt = [row for row in calls if Path(row[0]).name == 'apt-get']
        self.assertTrue(any('--download-only' in row and 'python3' in row for row in apt))
        self.assertTrue(any('--no-download' in row and 'python3' in row for row in apt))
        self.assertTrue(all(any(value.startswith('Dir::Etc::sourcelist=') for value in row) for row in apt))

    def test_temporary_sources_removed_after_success(self):
        result, calls = self.prerequisite_run()
        self.assertEqual(result.returncode, 0, result.stderr)
        apt = [x for x in calls if Path(x[0]).name == 'apt-get']
        self.assertEqual(len(apt), 1)
        self.assertIn('install', apt[0])
        self.assertTrue(any(x.startswith('Dir::Etc::sourcelist=') for x in apt[0]))
        self.assertTrue(any(x.startswith('Dir::State::lists=') for x in apt[0]))

    def test_temporary_sources_removed_after_selector_failure(self):
        result, calls = self.prerequisite_run(failure='selector')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(Path(x[0]).name == 'apt-get' for x in calls))

    def test_temporary_sources_removed_after_package_failure(self):
        result, _ = self.prerequisite_run(failure='install')
        self.assertNotEqual(result.returncode, 0)

    def test_ordinary_install_prompts_and_yes_selects_temporary_mirrors(self):
        result,calls=self.prerequisite_run(answer='1')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('IRAN INSTALLATION',result.stdout)
        self.assertLess(result.stdout.index('IRAN INSTALLATION'), result.stdout.index('DNS and mirror selection completed'))
        self.assertLess(result.stdout.index('DNS and mirror selection completed'), result.stdout.index('Installing prerequisites'))
        self.assertTrue(any(Path(x[0]).name=='python3' for x in calls))

    def test_ordinary_install_no_keeps_original_mirror(self):
        result,calls=self.prerequisite_run(answer='2')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(any(Path(x[0]).name=='python3' for x in calls))
        self.assertFalse(any(x.startswith('Dir::') for row in calls for x in row))

    def test_foreign_join_keeps_normal_apt_and_never_runs_selector(self):
        result, calls = self.prerequisite_run(iran=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(Path(x[0]).name == 'python3' for x in calls))
        apt = [x for x in calls if Path(x[0]).name == 'apt-get']
        self.assertEqual(len(apt), 2)
        self.assertFalse(any(x.startswith('Dir::') for row in apt for x in row))

    def test_explicit_iran_flag_refuses_foreign_join(self):
        result = subprocess.run(['bash',str(Path(__file__).parents[1]/'get.sh'),
                                 '--iran-mirrors','join','synthetic-token'], text=True,capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('foreign join command without it', result.stderr)

    def test_incomplete_fast_mirror_falls_back_without_changing_live_sources(self):
        self.assertTrue(hasattr(self.module, 'prepare_indexes'))
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); apt=root/'etc'; apt.mkdir()
            original='deb https://old.example/ubuntu noble-security main\n'
            (apt/'sources.list').write_text(original)
            ranked=[{'url':'https://fast.example/ubuntu'}, {'url':'https://good.example/ubuntu'}]
            with patch.object(self.module.subprocess,'run',side_effect=[
                    subprocess.CompletedProcess([],100),subprocess.CompletedProcess([],0)]):
                winner=self.module.prepare_indexes(apt,root/'private','noble',ranked)
            self.assertEqual(winner['url'],ranked[1]['url'])
            self.assertIn(ranked[1]['url'],(root/'private/sources.list').read_text())
            self.assertEqual((apt/'sources.list').read_text(),original)

    def test_all_index_failures_preserve_live_sources(self):
        self.assertTrue(hasattr(self.module, 'prepare_indexes'))
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); apt=root/'etc'; apt.mkdir()
            original='deb https://old.example/ubuntu noble main\n'
            (apt/'sources.list').write_text(original)
            with patch.object(self.module.subprocess,'run',return_value=subprocess.CompletedProcess([],100)):
                with self.assertRaises(ValueError):
                    self.module.prepare_indexes(apt,root/'private','noble',[{'url':'https://fast.example/ubuntu'}])
            self.assertEqual((apt/'sources.list').read_text(),original)

    def test_package_download_403_tries_next_verified_mirror(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); apt=root/'etc'; apt.mkdir()
            (apt/'sources.list').write_text('deb https://old.example/ubuntu noble main\n')
            ranked=[{'url':'https://fast.example/ubuntu'},{'url':'https://good.example/ubuntu'}]
            replies=[subprocess.CompletedProcess([],status) for status in (0,100,0,0)]
            with patch.object(self.module.subprocess,'run',side_effect=replies) as run:
                winner=self.module.prepare_indexes(apt,root/'private','noble',ranked,packages=['wireguard-tools'])
            self.assertEqual(winner,ranked[1])
            self.assertEqual(run.call_count,4)
            self.assertIn('--download-only',run.call_args_list[1].args[0])
    def test_fourth_healthy_mirror_is_tried_if_first_three_reject_indexes(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); apt=root/'etc'; apt.mkdir()
            (apt/'sources.list').write_text('deb https://old.example/ubuntu noble main\n')
            ranked=[{'url': 'https://mirror%d.example/ubuntu' % n} for n in range(4)]
            with patch.object(self.module.subprocess, 'run', side_effect=[subprocess.CompletedProcess([],n) for n in (100,100,100,0)]):
                winner=self.module.prepare_indexes(apt,root/'private','noble',ranked)
            self.assertEqual(winner, ranked[3])



if __name__ == '__main__':
    unittest.main()
