"""Reconstruct legacy and new sources for live-upgrade integration tests."""
import hashlib,pathlib,shutil,subprocess,sys,zipfile,json
repo=pathlib.Path(__file__).resolve().parents[1];root=pathlib.Path(sys.argv[1]);root.mkdir(parents=True,exist_ok=True)
archive=root/'base.zip';subprocess.run(['curl','-fsSL','--retry','3','https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/dist/pronet-fleet-0.3.12.zip','-o',str(archive)],check=True)
assert hashlib.sha256(archive.read_bytes()).hexdigest()=='3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37'
with zipfile.ZipFile(archive) as z:z.extractall(root)
old=root/'0.3.22';(root/'pronet-fleet-0.3.12').rename(old);shutil.copytree(repo/'updates/0.3.22',old,dirs_exist_ok=True)
locked=json.loads((old/'assets.lock.json').read_text())
for engine in ('paqet','backhaul','parsa-spoof'):
 for asset in locked[engine]['assets'].values():
  path=repo/'dist/engines'/asset['sha256']/asset['name'];assert hashlib.sha256(path.read_bytes()).hexdigest()==asset['sha256'];shutil.copyfile(path,old/'vendor'/asset['name'])
new=root/'0.3.23';shutil.copytree(old,new);shutil.copytree(repo/'updates/0.3.23',new,dirs_exist_ok=True)
print(old);print(new)
