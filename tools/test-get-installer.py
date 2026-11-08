"""Exercise the real installer without changing the host or contacting Releases.

Use a complete verified source bundle as fixtures. All privileged operations are
intercepted, while ZIP extraction and the package's own checksum verifier run.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile


def exercise(repo, source, base, *, tamper=False, upgrade=False, join=False, transport="raw", mirrors=False):
    with tempfile.TemporaryDirectory(prefix='pronet-installer-test-') as temp:
        root = Path(temp)
        bindir = root / 'bin'; bindir.mkdir()
        systemd = root / 'systemd'; systemd.mkdir()
        if upgrade: (systemd / 'pronetf-agent.service').write_text('fixture')
        requests = root / 'requests.jsonl'
        actions = root / 'actions.jsonl'
        locked = json.loads((source / 'assets.lock.json').read_text())
        version = re.search(r'^VERSION="([^"]+)"', (repo / 'get.sh').read_text(), re.M).group(1)
        files = {
            'https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/dist/pronet-fleet-0.3.12.zip': str(base),
            f'https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/dist/pronet-fleet-{version}-update.zip': str(repo / f'dist/pronet-fleet-{version}-update.zip'),
        }
        for engine in ('paqet', 'backhaul', 'parsa-spoof'):
            for asset in locked[engine]['assets'].values():
                path = source / 'vendor' / asset['name']
                assert hashlib.sha256(path.read_bytes()).hexdigest() == asset['sha256']
                url = 'https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/dist/engines/' + asset['sha256'] + '/' + asset['name']
                files[url] = str(path)
        chunk_info = json.loads((repo/'tools/base-chunks.json').read_text())
        for part in chunk_info['chunks']:
            files['https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/'+part['path']] = str(repo/part['path'])
        helper_path=f'installers/{version}/iran-apt-mirrors.py'
        files['https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/'+helper_path] = str(repo/helper_path)
        for url, path in list(files.items()):
            relative=url.split('/main/',1)[1]
            files['https://cdn.jsdelivr.net/gh/alirezaaabbasii/pronet-fleet@main/'+relative]=path
            files['https://api.github.com/repos/alirezaaabbasii/pronet-fleet/contents/'+relative+'?ref=main']=path
        for engine in ('paqet', 'backhaul', 'parsa-spoof'):
            for asset in locked[engine]['assets'].values():
                files[asset['url']]=str(source/'vendor'/asset['name'])
        mapping = root / 'files.json'; mapping.write_text(json.dumps(files))
        def program(name, body):
            path = bindir / name
            path.write_text('#!' + os.sys.executable + '\n' + body)
            path.chmod(0o755)
        program('id', 'print(0)\n')
        program('uname', "import sys\nprint('x86_64' if '-m' in sys.argv else 'Linux')\n")
        for name in ('ip', 'ss', 'iptables', 'nft', 'wg', 'gpgv'):
            program(name, 'pass\n')
        program('curl', '''import json,os,sys,pathlib,shutil
args=sys.argv[1:];url=args[-1] if args[-1].startswith('https:') else next(x for x in args if x.startswith('https:'))
with open(os.environ['TEST_REQUESTS'],'a') as f:f.write(json.dumps(url)+'\\n')
# Releases and every unexpected host are deliberately unavailable.
files=json.load(open(os.environ['TEST_FILES']))
kind=('raw' if url.startswith('https://raw.githubusercontent.com/') else 'cdn' if url.startswith('https://cdn.jsdelivr.net/') else 'api' if url.startswith('https://api.github.com/') else 'upstream')
mode=os.environ['TEST_TRANSPORT']
if mode=='upstream':
 allowed=kind=='upstream' or (kind=='raw' and '/dist/engines/' not in url)
else:allowed=kind==mode
if not allowed or url not in files:sys.exit(22)
destination=args[args.index('-o')+1]
shutil.copyfile(files[url],destination)
if os.environ.get('TEST_TAMPER') and '/dist/engines/' in url:pathlib.Path(destination).write_bytes(b'corrupt fixture')
''')
        program('python3', 'import os,sys\nif len(sys.argv)>1 and sys.argv[1].endswith("iran-apt-mirrors.py"):sys.exit(0)\nos.execv(sys.executable,[sys.executable]+sys.argv[1:])\n')
        program('sha256sum', '''import hashlib,sys
expected,path=sys.stdin.read().strip().split('  ',1)
sys.exit(0 if hashlib.sha256(open(path,'rb').read()).hexdigest()==expected else 1)
''')
        program('sh', '''import json,os,pathlib,subprocess,sys
args=sys.argv[1:]
with open(os.environ['TEST_ACTIONS'],'a') as f:f.write(json.dumps(args)+'\\n')
if '--verify-only' in args:sys.exit(subprocess.call([sys.executable,str(pathlib.Path(args[0]).with_name('install.py')),'--verify-only']))
''')
        program('pronet', '''import json,os,sys
if sys.argv[1:]==['--version']:print('0.0.0')
else:
 with open(os.environ['TEST_ACTIONS'],'a') as f:f.write(json.dumps(['pronet']+sys.argv[1:])+'\\n')
''')
        script = (repo / 'get.sh').read_text()
        assert '[ -d /run/systemd/system ]' in script
        script = script.replace('[ -d /run/systemd/system ]', '[ -d "' + str(systemd) + '" ]')
        script = script.replace('/usr/local/bin/pronet', str(bindir / 'pronet'))
        script = script.replace('/etc/systemd/system', str(systemd))
        path = root / 'get.sh'; path.write_text(script)
        env = dict(os.environ, PATH=str(bindir)+os.pathsep+os.environ['PATH'],
                   TEST_FILES=str(mapping), TEST_REQUESTS=str(requests), TEST_ACTIONS=str(actions),
                   PRONET_NO_MENU='1', TEST_TAMPER='1' if tamper else '', TEST_TRANSPORT=transport)
        env.pop('PRONET_ZIP', None); env.pop('PRONET_URL', None)
        args = ['join', 'synthetic-test-token'] if join else ['--iran-mirrors'] if mirrors else []
        result = subprocess.run(['bash', str(path)] + args, env=env, text=True, capture_output=True)
        assert requests.exists(), result.stdout + result.stderr
        seen = [json.loads(line) for line in requests.read_text().splitlines()]
        calls = [json.loads(line) for line in actions.read_text().splitlines()] if actions.exists() else []
        if tamper:
            assert result.returncode != 0 and 'checksum mismatch' in result.stderr, result
            assert not calls, calls
        else:
            assert result.returncode == 0, result.stdout + result.stderr
            assert len(seen) >= 8, seen
            if transport=='raw':assert len(seen)==8+int(mirrors),seen
            if transport=='cdn':assert any('/dist/chunks/' in u and u.startswith('https://cdn.jsdelivr.net/') for u in seen),seen
            if transport=='api':assert any(u.startswith('https://api.github.com/') for u in seen),seen
            if transport=='upstream':assert any(u.startswith('https://github.com/') for u in seen),seen
            if mirrors:assert any(helper_path in u for u in seen),seen
            assert len(calls) == (3 if join else 2), calls
            assert '--verify-only' in calls[0], calls
            assert ('--activate-services' in calls[1]) == upgrade, calls
            if join: assert calls[-1] == ['pronet', 'join', 'synthetic-test-token'], calls
        assert not any(u.startswith('https://cdn.jsdelivr.net/') and u.endswith('pronet-fleet-0.3.12.zip') for u in seen),seen
        print('PASS', dict(upgrade=upgrade, join=join, checksum_rejection=tamper, transport=transport, mirrors=mirrors, downloads=len(seen)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--base', type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    for options in ({}, {'upgrade': True}, {'join': True}, {'tamper': True}, {'transport':'cdn'}, {'transport':'api'}, {'transport':'upstream'}, {'transport':'cdn','mirrors':True}, {'transport':'cdn','join':True}, {'transport':'cdn','upgrade':True}):
        exercise(repo, args.source.resolve(), args.base.resolve(), **options)
