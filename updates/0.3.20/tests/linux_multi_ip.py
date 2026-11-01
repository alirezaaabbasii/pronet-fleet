#!/usr/bin/env python3
"""Explicit root-only lab: upgrade a live legacy tunnel, then add same-port IPs.

All networking stays in disposable namespaces. A persistent client checks the
first tunnel throughout management upgrade and creation of additional pairs.
"""
import argparse,contextlib,json,os,pathlib,secrets,shutil,socket,socketserver,sqlite3,subprocess,sys,tempfile,time
APP=pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0,str(APP))
from pronet.common import PronetError,secret,write_json
from pronet.engines import certificate
from linux_integration import baseline

def run(args,**kw):
 return subprocess.run([str(x) for x in args],check=True,text=True,capture_output=True,timeout=kw.pop('timeout',90),**kw)

def child(a):
 from pronet.common import CONFIG,ROOT
 from pronet.cli import node_client,node_config
 f=json.loads((pathlib.Path(a.base)/'fixture.json').read_text());role=a.role
 ip=f['addresses'][role]
 if a.child=='enroll':
  from pronet.hub import Client
  c=Client('https://198.18.0.254:9443',f['enrollment_key'],str(pathlib.Path(a.base)/'cert/server.crt'))
  identity=dict(role='iran' if role=='iran' else 'foreign',name=role,public_ip=ip,bind_ip=ip)
  credentials=c.call('/v1/enroll',identity)
  write_json(CONFIG/'node.json',dict(identity,**credentials,hub_url=c.url,ca_file=str(pathlib.Path(a.base)/'cert/server.crt'),allowed_inbound_ports=[2053]))
 elif a.child=='pair':
  if a.legacy:
   result=node_client().call('/v1/pair',dict(name='legacy',public_ip=ip,bind_ip=ip,inbound_port=2053,profiles=[a.profile],standby=0,gaming=a.gaming))
   write_json(pathlib.Path(a.base)/'created.json',result)
  else:
   from pronet import cli
   # Same public CLI used by operators. Capture only the pairing code privately.
   original=cli.node_client
   class Capture:
    def call(self,path,payload=None):
     result=original().call(path,payload)
     if path=='/v1/pair':write_json(pathlib.Path(a.base)/'created.json',result)
     return result
   cli.node_client=lambda:Capture()
   cli.new_tunnel(2053,name='extra-'+a.public_ip,profiles=[a.profile],standby=False,wait=False,gaming=a.gaming,public_ip=a.public_ip,bind_ip=a.public_ip)
 elif a.child=='join':
  created=json.loads((pathlib.Path(a.base)/'created.json').read_text());node_client().call('/v1/join',dict(code=created['code']))
 elif a.child=='backend':
  prefix=(role+'|').encode()
  if a.gaming:
   with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    s.bind(('0.0.0.0',2053))
    while True:
     data,peer=s.recvfrom(65535);s.sendto(prefix+data,peer)
  else:
   class Handler(socketserver.StreamRequestHandler):
    def handle(self):
     while True:
      line=self.rfile.readline()
      if not line:return
      self.wfile.write(prefix+line);self.wfile.flush()
   class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
   with Server(('0.0.0.0',2053),Handler) as s:s.serve_forever()
 elif a.child=='client':
  result=dict(success=0,errors=[]);path=pathlib.Path(a.base)/'client.json';target=a.public_ip
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if a.gaming else socket.SOCK_STREAM);s.settimeout(3)
  s.connect((target,2053));reader=None if a.gaming else s.makefile('rb')
  while True:
   data=(secrets.token_hex(16)+'\n').encode()
   try:
    s.sendall(data);reply=s.recv(65535) if a.gaming else reader.readline()
    if reply!=b'f1|'+data:raise PronetError('Wrong foreign backend or corrupt stream')
    result['success']+=1
   except Exception as e:result['errors'].append(str(e)[:120])
   write_json(path,result);time.sleep(.1)
 elif a.child=='verify':
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if a.gaming else socket.SOCK_STREAM) as s:
   s.settimeout(4);s.connect((a.public_ip,2053));data=b'own-backend\n';s.sendall(data)
   reply=s.recv(65535) if a.gaming else s.makefile('rb').readline()
   if reply!=(a.expected+'|').encode()+data:raise PronetError('IP reached a different foreign server')
 elif a.child=='upgrade':
  from pronet.upgrades import activate
  wrapper=pathlib.Path(a.base)/'wrapper';wrapper.write_text('#!/bin/sh\n# Managed by Pronet Fleet\n')
  result=activate(APP/'main.py',wrapper.read_bytes(),wrapper)
  if result['restarted']:raise PronetError('Unexpected live carrier restart')
  write_json(pathlib.Path(a.base)/'upgrade.json',result)
 elif a.child=='cleanup':
  from pronet.runtime import Runtime
  r=Runtime(node_config())
  for p in r.root.iterdir():
   if p.is_dir() and len(p.name)==24:r.cleanup(p.name)

def main(a):
 if sys.platform!='linux' or os.geteuid()!=0:raise PronetError('Explicit root Linux lab only')
 if list(pathlib.Path('/etc/systemd/system').glob('pronetf-*.service')):raise PronetError('Run on a disposable host without existing Pronet units')
 before=baseline();base=pathlib.Path(tempfile.mkdtemp(prefix='pronet-multi-ip-',dir='/var/tmp'));base.chmod(0o700)
 roles=['hub','iran']+['f'+str(i) for i in range(1,a.count+1)];tag=secrets.token_hex(4)
 # Use the production helper's deliberately restricted lab namespace names.
 ns={r:'pronettest-'+(tag if r in ('hub','iran') else secrets.token_hex(4))+'-'+(r if r in ('hub','iran') else 'foreign') for r in roles};created=[];processes=[];files=[];pair_ids=[]
 addresses=dict(hub='198.18.0.254',iran='198.18.0.1',**{'f'+str(i):'198.18.0.'+str(i+1) for i in range(1,a.count+1)})
 client_ips=['198.18.0.1']+['198.18.0.'+str(i+10) for i in range(1,a.count)]
 fixture=dict(addresses=addresses,enrollment_key=secret(),admin_key=secret())
 write_json(base/'fixture.json',fixture);certificate(base/'cert','198.18.0.254','198.18.0.254')
 for role in roles:
  (base/role/'config').mkdir(parents=True);(base/role/'state').mkdir()
 cfg=dict(url='https://198.18.0.254:9443',bind='198.18.0.254',port=9443,enrollment_key=fixture['enrollment_key'],admin_key=fixture['admin_key'],database=str(base/'hub/state/hub.sqlite3'),certificate=str(base/'cert/server.crt'),private_key=str(base/'cert/server.key'))
 write_json(base/'hub/config/hub/hub.json',cfg)
 def env(role):
  e=dict(os.environ,PRONET_CONFIG=str(base/role/'config'),PRONET_STATE=str(base/role/'state'))
  if role!='hub':e['PRONET_TEST_NETNS']='/run/netns/'+ns[role]
  return e
 def command(role,args):return ['ip','netns','exec',ns[role]]+[str(x) for x in args]
 def start(role,args,name):
  f=open(base/(name+'.log'),'w');files.append(f);p=subprocess.Popen(command(role,args),env=env(role),stdout=f,stderr=f);processes.append(p);return p
 def action(role,what,**options):
  args=[sys.executable,__file__,'--child',what,'--base',base,'--role',role,'--profile',a.profile]
  if a.gaming:args+=['--gaming']
  for k,v in options.items():args+=['--'+k.replace('_','-')]+([] if v is True else [v])
  return run(command(role,args),env=env(role),timeout=180)
 def await_active(pid):
  deadline=time.monotonic()+600
  while time.monotonic()<deadline:
   with sqlite3.connect(cfg['database']) as db:row=db.execute('SELECT state,result FROM pairs WHERE id=?',(pid,)).fetchone()
   if row[0]=='ACTIVE':return json.loads(row[1])
   if row[0]=='FAILED':
    data=json.loads(row[1]);details=[(r.get('profile'),r.get('reason')) for r in data.get('results',[])]
    raise PronetError('Pair failed: '+str(data.get('error'))+'; results='+str(details))
   time.sleep(1)
  raise PronetError('Pair setup timed out')
 def pids(pid):
  names=[p.name for p in pathlib.Path('/etc/systemd/system').glob('pronetf-'+pid+'-*.service')]
  rows={n:int(run(['systemctl','show',n,'-p','MainPID','--value']).stdout.strip()) for n in names}
  if not rows or not all(rows.values()):raise PronetError('A permanent service is not running')
  return rows
 def healthy_client():
  p=base/'client.json'
  if not p.exists():return 0
  r=json.loads(p.read_text())
  if r['errors']:raise PronetError('Original connection interrupted: '+str(r['errors']))
  return r['success']
 report=dict(passed=False,mode='udp' if a.gaming else 'tcp',count=a.count)
 try:
  for role in roles:run(['ip','netns','add',ns[role]]);created.append(ns[role]);run(['ip','-n',ns[role],'link','set','lo','up'])
  run(['ip','-n',ns['hub'],'link','add','br0','type','bridge']);run(['ip','-n',ns['hub'],'address','add',addresses['hub']+'/24','dev','br0']);run(['ip','-n',ns['hub'],'link','set','br0','up'])
  for i,role in enumerate(roles[1:]):
   left='p'+tag+str(i);right='q'+tag+str(i)
   run(['ip','link','add',left,'type','veth','peer','name',right]);run(['ip','link','set',left,'netns',ns[role]]);run(['ip','link','set',right,'netns',ns['hub']])
   run(['ip','-n',ns[role],'link','set',left,'name','eth0']);run(['ip','-n',ns[role],'address','add',addresses[role]+'/24','dev','eth0']);run(['ip','-n',ns[role],'link','set','eth0','up'])
   run(['ip','-n',ns['hub'],'link','set',right,'master','br0']);run(['ip','-n',ns['hub'],'link','set',right,'up'])
  for ip in client_ips[1:]:run(['ip','-n',ns['iran'],'address','add',ip+'/24','dev','eth0'])
  old=pathlib.Path(a.old_source);hub=start('hub',[sys.executable,old/'main.py','hub-run'],'hub-old');time.sleep(1)
  agents={}
  for role in roles[1:]:
   action(role,'enroll');agents[role]=start(role,[sys.executable,old/'main.py','agent'],role+'-agent-old')
   if role!='iran':start(role,[sys.executable,__file__,'--child','backend','--base',base,'--role',role]+(['--gaming'] if a.gaming else []),role+'-backend')
  action('iran','pair',legacy=True);action('f1','join');pid=json.loads((base/'created.json').read_text())['pair_id'];pair_ids.append(pid);await_active(pid)
  snapshot=pids(pid)
  client=start('hub',[sys.executable,__file__,'--child','client','--base',base,'--role','hub','--public-ip',client_ips[0]]+(['--gaming'] if a.gaming else []),'persistent-client')
  deadline=time.monotonic()+10
  while healthy_client()<10 and time.monotonic()<deadline:time.sleep(.2)
  if healthy_client()<10:raise PronetError('Initial persistent client not ready')
  action('iran','upgrade')
  # Only management processes restart. All carrier/gateway PIDs and the original
  # client's TCP socket (or UDP socket) must remain intact through this step.
  for p in [hub]+list(agents.values()):p.terminate();p.wait(timeout=15)
  hub=start('hub',[sys.executable,APP/'main.py','hub-run'],'hub-new')
  for role in roles[1:]:agents[role]=start(role,[sys.executable,APP/'main.py','agent'],role+'-agent-new')
  deadline=time.monotonic()+20
  while time.monotonic()<deadline:
   with sqlite3.connect(cfg['database']) as db:metrics=[json.loads(row[0]) for row in db.execute('SELECT metrics FROM nodes')]
   if metrics and all(m.get('version')=='0.3.20' for m in metrics):break
   time.sleep(.5)
  else:raise PronetError('Updated management versions were not reported')
  if pids(pid)!=snapshot:raise PronetError('Upgrade restarted a live carrier or gateway')
  for index,ip in enumerate(client_ips[1:],2):
   action('iran','pair',public_ip=ip);action('f'+str(index),'join');new=json.loads((base/'created.json').read_text())['pair_id'];pair_ids.append(new);result=await_active(new)
   action('hub','verify',public_ip=ip,expected='f'+str(index))
   if pids(pid)!=snapshot:raise PronetError('New pair restarted the original tunnel')
   healthy_client();print('MULTI_IP_ACTIVE',ip+':2053','foreign',index,flush=True)
  for index,ip in enumerate(client_ips,1):action('hub','verify',public_ip=ip,expected='f'+str(index))
  report.update(passed=True,client_endpoints=[ip+':2053' for ip in client_ips],original_service_pids_unchanged=True,continuous_client=healthy_client(),original_connection_errors=0)
 except BaseException as e:
  report['error']=str(e)[:1000]
  if isinstance(e,subprocess.CalledProcessError):report['child_error']=str(e.stderr)[-2500:]
 finally:
  for p in reversed(processes):
   if p.poll() is None:
    p.terminate()
    try:p.wait(timeout=10)
    except subprocess.TimeoutExpired:p.kill();p.wait()
  errors=[]
  for role in roles[1:]:
   if (base/role/'config/node.json').exists():
    try:action(role,'cleanup')
    except Exception as e:errors.append(str(e)[:300])
  for name in reversed(created):
   try:run(['ip','netns','delete',name])
   except Exception as e:errors.append(str(e)[:300])
  for f in files:f.close()
  after=baseline();report.update(cleanup_errors=errors,owned_resources_removed=not errors and not any(pathlib.Path('/etc/systemd/system').glob('pronetf-*.service')),host_firewall_unchanged=before['firewall']==after['firewall'],host_routes_unchanged=before['routes']==after['routes'],host_forwarding_unchanged=before['ip_forward']==after['ip_forward'])
  if errors or not all(report[k] for k in ('owned_resources_removed','host_firewall_unchanged','host_routes_unchanged','host_forwarding_unchanged')):report['passed']=False
 print('MULTI_IP_REPORT',json.dumps(report,sort_keys=True),flush=True)
 return 0 if report['passed'] else 1

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--child',choices=['enroll','pair','join','backend','client','verify','upgrade','cleanup']);p.add_argument('--base');p.add_argument('--role');p.add_argument('--public-ip');p.add_argument('--expected');p.add_argument('--legacy',action='store_true');p.add_argument('--profile',default='frp-tls');p.add_argument('--gaming',action='store_true');p.add_argument('--count',type=int,default=4);p.add_argument('--old-source');a=p.parse_args()
 if a.child:child(a)
 else:sys.exit(main(a))
