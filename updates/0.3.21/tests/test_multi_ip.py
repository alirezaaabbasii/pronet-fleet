import contextlib,io,json,tempfile,unittest
from pathlib import Path
from unittest import mock
from pronet import cli,runtime
from pronet.common import PronetError,secret,write_json
from pronet.controller import Controller
from pronet.model import validate_request
from pronet.store import Store
from test_native_gre import plan

class MultiIPTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
  self.config=dict(role='iran',public_ip='192.0.2.1',bind_ip='192.0.2.1',node_id='a'*24,allowed_inbound_ports=[2053])
  self.info=dict(ips=['192.0.2.'+str(i) for i in range(1,5)],ports=[],ssh_ports=[22],routes=[],reserved_subnets=[],tun=True)
 def tearDown(self):self.temp.cleanup()
 def test_four_ips_same_client_port_different_foreign_nodes(self):
  key=secret();store=Store(self.root/'hub.db',key,secret())
  def node(role,ip):
   c=store.enroll(key,dict(role=role,name=ip,public_ip=ip,bind_ip=ip));return store.authenticate(c['node_id']+':'+c['node_secret'])
  iran=node('iran','192.0.2.1');ids=[]
  for i in range(1,5):
   req=dict(name='pair'+str(i),public_ip='192.0.2.'+str(i),inbound_port=2053,profiles=['gre'],dedicated_address=True)
   created=store.create_pair(iran,req);store.join_pair(node('foreign','198.51.100.'+str(i)),created['code']);ids.append(created['pair_id'])
   with self.assertRaisesRegex(PronetError,'reserved'):store.create_pair(iran,req)
  self.assertEqual(len(set(ids)),4);self.assertEqual(len({store.pair(p)['foreign_node'] for p in ids}),4)
 def test_authorization_keeps_identity_and_restarts_nothing(self):
  write_json(self.root/'node.json',self.config)
  with mock.patch.object(cli,'CONFIG',self.root),mock.patch.object(cli,'command') as command:
   cli.authorize_address('192.0.2.2','192.0.2.2',self.info);cli.authorize_port(2053);command.assert_not_called()
  saved=json.loads((self.root/'node.json').read_text());self.assertEqual(saved['public_ip'],'192.0.2.1')
  self.assertEqual(saved['allowed_addresses'],[dict(public_ip='192.0.2.2',bind_ip='192.0.2.2')])
 def test_unassigned_ip_never_writes_config(self):
  with mock.patch.object(cli,'write_json') as write:
   with self.assertRaisesRegex(PronetError,'not assigned'):cli.authorize_address('192.0.2.99','192.0.2.99',self.info)
   write.assert_not_called()
 def test_running_agent_reads_local_permission_without_restart(self):
  r=object.__new__(runtime.Runtime);r.identity=dict(self.config)
  p=plan();p.update(bind_ip='192.0.2.2',iran_ip='192.0.2.2',inbound_port=2053)
  with mock.patch.object(runtime,'CONFIG',self.root):
   with self.assertRaises(PronetError):r.validate(p)
   write_json(self.root/'node.json',dict(self.config,allowed_addresses=[dict(public_ip='192.0.2.2',bind_ip='192.0.2.2')]))
   self.assertIs(r.validate(p),p)
   old=plan();old.update(bind_ip='192.0.2.1',iran_ip='192.0.2.1',inbound_port=2053);self.assertIs(r.validate(old),old)
 def test_other_node_file_cannot_authorize_ip(self):
  r=object.__new__(runtime.Runtime);r.identity=dict(self.config);p=plan();p.update(bind_ip='192.0.2.2',iran_ip='192.0.2.2',inbound_port=2053)
  write_json(self.root/'node.json',dict(self.config,node_id='b'*24,allowed_addresses=[dict(public_ip='192.0.2.2',bind_ip='192.0.2.2')]))
  with mock.patch.object(runtime,'CONFIG',self.root),self.assertRaises(PronetError):r.validate(p)
 def test_foreign_cannot_use_iran_extra_ip_permission(self):
  r=object.__new__(runtime.Runtime);r.identity=dict(self.config,role='foreign',allowed_addresses=[dict(public_ip='192.0.2.2',bind_ip='192.0.2.2')])
  p=plan('foreign');p.update(bind_ip='192.0.2.2',foreign_ip='192.0.2.2',inbound_port=2053)
  with self.assertRaises(PronetError):r.validate(p)
 def test_allocator_uses_selected_source_peer_and_unique_internal_ports(self):
  c=Controller(mock.Mock());req=validate_request(dict(name='second',public_ip='192.0.2.2',inbound_port=2053,profiles=['gre'],dedicated_address=True))
  pair=dict(id='c'*24,request=req,iran_info=self.config,foreign_info=dict(public_ip='198.51.100.2',bind_ip='198.51.100.2'))
  p=c.allocate(pair,dict(iran=self.info,foreign=self.info))[0];payloads=c.payloads(pair,p)
  self.assertEqual(p['iran_ip'],'192.0.2.2');self.assertEqual(payloads['iran']['bind_ip'],'192.0.2.2');self.assertEqual(payloads['foreign']['iran_ip'],'192.0.2.2');self.assertEqual(payloads['foreign']['bind_ip'],'198.51.100.2')
  ports=[p[k] for k in ('control_port','echo_port','health_port','data_port','bridge_data_port','bridge_health_port','probe_front_port')];self.assertEqual(len(set(ports)),7);self.assertNotIn(2053,ports)
  pair['request'].pop('dedicated_address');old=c.allocate(pair,dict(iran=self.info,foreign=self.info))[0]
  self.assertEqual(old['iran_ip'],'192.0.2.1');self.assertEqual(c.payloads(pair,old)['iran']['bind_ip'],'192.0.2.1')
 def test_picker_vertical_and_selects_second(self):
  info=dict(self.info,ips=['8.8.8.'+str(i) for i in range(1,5)]);config=dict(self.config,public_ip='8.8.8.1',bind_ip='8.8.8.1');out=io.StringIO()
  with mock.patch.object(cli,'ask',return_value='2'),contextlib.redirect_stdout(out):self.assertEqual(cli.tunnel_address(config,info,interactive=True),('8.8.8.2','8.8.8.2'))
  self.assertIn('1) 8.8.8.1\n',out.getvalue());self.assertIn('2) 8.8.8.2\n',out.getvalue())
 def test_string_address_mode_rejected(self):
  with self.assertRaises(PronetError):validate_request(dict(name='test',public_ip='192.0.2.1',dedicated_address='yes'))
 def test_learning_keeps_each_dedicated_ip_separate(self):
  from pronet.learning import route_key
  p=dict(iran_info=self.config,foreign_info=dict(public_ip='198.51.100.1'),request=dict(public_ip='192.0.2.1',dedicated_address=True))
  first=route_key(p);p['request']['public_ip']='192.0.2.2';self.assertNotEqual(first,route_key(p))
  p['request']['dedicated_address']=False;self.assertEqual(first,route_key(p))
if __name__=='__main__':unittest.main()
