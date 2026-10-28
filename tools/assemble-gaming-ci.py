"""Assemble the checked-out independent carrier sources with the immutable vendor/test base."""
import hashlib
import io
import pathlib
import shutil
import sys
import urllib.request
import zipfile

repo=pathlib.Path(__file__).resolve().parents[1]
base=pathlib.Path(sys.argv[1])
base.mkdir(parents=True,exist_ok=True)
url='https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/dist/pronet-fleet-0.3.12.zip'
data=urllib.request.urlopen(url,timeout=60).read()
assert hashlib.sha256(data).hexdigest()=='3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37'
with zipfile.ZipFile(io.BytesIO(data)) as archive: archive.extractall(base)
shutil.copytree(repo/'updates/0.3.18',base/'pronet-fleet-0.3.12',dirs_exist_ok=True)
print(base/'pronet-fleet-0.3.12')

import json,subprocess
source=base/'pronet-fleet-0.3.12'
manifest=json.loads((source/'assets.lock.json').read_text())
for engine in ('paqet','backhaul','parsa-spoof'):
 for asset in manifest[engine]['assets'].values():
  path=source/'vendor'/asset['name']
  subprocess.run(['curl','-fsSL','--retry','3',asset['url'],'-o',str(path)],check=True)
  assert hashlib.sha256(path.read_bytes()).hexdigest()==asset['sha256']
