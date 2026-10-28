import asyncio
import copy
import os
import pathlib
import socket
import tempfile
import unittest
from unittest import mock
from pronet import gaming,model,cli
from pronet.common import PronetError,secret,write_json
from test_core import setup_request


def measured(profile='gre',delay=20,loss=0,jitter=2):
    stage=dict(sent=600,received=600,loss_percent=loss,p50_ms=delay-2,p95_ms=delay,p99_ms=delay+5,jitter_p95_ms=jitter,max_gap_ms=22,integrity_errors=0)
    return dict(gaming=True,profile=profile,passed=True,after_idle=True,integrity=True,echo_ms=[delay]*10,
                success_ratio=1-loss/100,upload_mbps=1,download_mbps=1,half_close=False,gaming_stages={'idle':dict(stage),'loaded':dict(stage)})


class QualityTests(unittest.TestCase):
    def test_request_limits_gaming_to_real_datagram_carriers(self):
        request=setup_request();request['gaming']=True;request.pop('profiles',None)
        result=model.validate_request(request)
        self.assertEqual(result['profiles'],gaming.GAMING_PROFILES)
        for name in ('frp-tls','backhaul-tcp','parsa-spoof'):
            with self.assertRaises(PronetError):model.validate_request(dict(request,profiles=[name]))
    def test_gaming_latency_wins_over_bandwidth(self):
        slow=measured('bp-l3-udp',90);slow.update(upload_mbps=1000,download_mbps=1000)
        fast=measured('gre',20)
        self.assertEqual(model.ranking([slow,fast])[0]['profile'],'gre')
    def test_loss_jitter_tail_and_loaded_latency_reject_independently(self):
        for field,value in [('loss_percent',2),('jitter_p95_ms',35),('p95_ms',300),('p99_ms',400),('max_gap_ms',400),('sent',3)]:
            row=measured();row['gaming_stages']['loaded'][field]=value
            self.assertEqual(model.ranking([row]),[],(field,value))
        row=measured();row['gaming_stages']['loaded'].update(p95_ms=80,p99_ms=90)
        self.assertEqual(model.ranking([row]),[])
    def test_missing_measurement_cannot_pass_gaming_ranking(self):
        row=measured();row['gaming_stages']={}
        self.assertIsNone(gaming.score(row))
    def test_nan_metrics_are_never_qualified(self):
        row=measured();row['gaming_stages']['loaded']['p95_ms']=float('nan')
        self.assertIsNone(gaming.score(row))
    def test_wire_format_authentication_direction_and_replay(self):
        key=os.urandom(32);sid=os.urandom(8);p=gaming.pack(key,3,2053,sid,5,b'payload')
        self.assertEqual(gaming.unpack(key,p),(3,2053,sid,5,b'payload'))
        with self.assertRaises(ValueError):gaming.unpack(os.urandom(32),p)
        with self.assertRaises(ValueError):gaming.unpack(key,p[:-1]+b'!')
        w=gaming.ReplayWindow()
        self.assertTrue(w.accept(10));self.assertTrue(w.accept(8));self.assertFalse(w.accept(8));self.assertTrue(w.accept(200));self.assertFalse(w.accept(10))
    def test_menus_display_each_choice_on_its_own_line(self):
        with mock.patch.object(cli,'say') as say:
            cli.menu_options([('1','First'),('2','Second'),('0','Back')])
        lines=[args[0] for args,_ in say.call_args_list]
        self.assertEqual(len(lines),3)
        self.assertTrue(all(sum(mark in line for mark in ('1)','2)','0)'))==1 for line in lines))


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.key=secret();self.relays=[];self.sockets=[]
        class Echo(asyncio.DatagramProtocol):
            def connection_made(self,t):self.transport=t
            def datagram_received(self,data,addr):self.transport.sendto(data,addr)
        self.transport,_=await asyncio.get_running_loop().create_datagram_endpoint(Echo,local_addr=('127.0.0.1',0))
        self.port=self.transport.get_extra_info('sockname')[1]
        foreign=gaming.DatagramRelay(self.key,foreign=True,ports=[self.port],peer='127.0.0.1')
        self.foreign=await gaming.listen(('127.0.0.1',0),foreign);self.relays.append(self.foreign)
        backend=self.foreign.transport.get_extra_info('sockname')
        self.public=await gaming.listen(('127.0.0.1',0),gaming.DatagramRelay(self.key,backend=backend,client_port=self.port));self.relays.append(self.public)
        self.address=self.public.transport.get_extra_info('sockname')
    async def asyncTearDown(self):
        for r in self.relays:r.close()
        for s in self.sockets:s.close()
        self.transport.close();await asyncio.sleep(.01)
    def client(self):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setblocking(False);s.connect(self.address);self.sockets.append(s);return s
    async def test_multiple_clients_datagram_boundaries_and_reply_isolation(self):
        loop=asyncio.get_running_loop();a,b=self.client(),self.client()
        for i in range(20):
            pa=os.urandom(1200 if i%2 else 64);pb=os.urandom(512)
            await loop.sock_sendall(a,pa);await loop.sock_sendall(b,pb)
            self.assertEqual(await asyncio.wait_for(loop.sock_recv(a,65000),1),pa)
            self.assertEqual(await asyncio.wait_for(loop.sock_recv(b,65000),1),pb)
        self.assertEqual(len(self.foreign.sessions),2)
    async def test_wrong_key_and_unauthorized_destination_create_no_session(self):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setblocking(False);self.sockets.append(s)
        target=self.foreign.transport.get_extra_info('sockname');loop=asyncio.get_running_loop()
        for key,port in ((os.urandom(32),self.port),(bytes.fromhex(self.key),self.port+1)):
            await loop.sock_sendto(s,gaming.pack(key,3,port,os.urandom(8),0,b'hi'),target)
        await asyncio.sleep(.05);self.assertFalse(self.foreign.sessions)
    async def test_real_probe_and_paced_measurement(self):
        target=self.foreign.transport.get_extra_info('sockname')
        delay=await asyncio.to_thread(gaming.probe,target,self.key)
        self.assertLess(delay,200)
        result=await asyncio.to_thread(gaming.benchmark,target,self.key)
        self.assertTrue(result['passed'],result['errors'])
        self.assertGreaterEqual(result['gaming_stages']['idle']['sent'],250)
        self.assertEqual(result['gaming_stages']['loaded']['loss_percent'],0)
    async def test_session_cap_and_expiry_are_bounded(self):
        with mock.patch.object(gaming,'MAX_SESSIONS',1):
            loop=asyncio.get_running_loop();a,b=self.client(),self.client()
            await loop.sock_sendall(a,b'a');self.assertEqual(await asyncio.wait_for(loop.sock_recv(a,20),1),b'a')
            await loop.sock_sendall(b,b'b');await asyncio.sleep(.05)
            self.assertEqual(len(self.public.sessions),1)
            for row in self.public.sessions.values():row.at-=gaming.SESSION_IDLE+1
            self.public.expire();self.assertFalse(self.public.sessions)
