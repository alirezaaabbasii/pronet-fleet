"""Assemble the checked-out GRE sources with the immutable vendor/test base."""
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
shutil.copytree(repo/'updates/0.3.14',base/'pronet-fleet-0.3.12',dirs_exist_ok=True)
print(base/'pronet-fleet-0.3.12')
