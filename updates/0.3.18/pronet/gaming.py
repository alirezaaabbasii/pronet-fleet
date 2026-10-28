"""Bounded authenticated datagram probes and WireGuard UDP relay.

Never logs payloads or changes host routing/sysctls. UDP sessions keep datagram
boundaries and independent sockets. A carrier change recreates sessions; the
WireGuard peer can roam after authenticating the next packet. This is not a
promise of seamless game-session recovery.
"""
from __future__ import annotations
import asyncio
import collections
import contextlib
import hashlib
import hmac
import math
import os
import pathlib
import select
import socket
import statistics
import struct
import sys
import time

from .common import PronetError, read_json, write_json, utc

HEADER = struct.Struct('!4sBH8sQ')
MAGIC = b'PNG1'
TAG = 16
MAX_PACKET = 65000
MAX_SESSIONS = 1024
SESSION_IDLE = 120
# Explicit eligibility: datagrams travel over an L3 carrier, never a TCP bridge.
GAMING_PROFILES = ['gre', 'bp-l3-udp', 'bp-l3-udp-reverse', 'bp-l3-quic',
                   'bp-l3-quic-reverse', 'bp-l3-udp-fec', 'bp-l3-pck',
                   'bp-l3-pck-reverse', 'bp-l3-pck-fec', 'bp-l3-sni']


def pack(key, kind, port, session, sequence, payload):
    head = HEADER.pack(MAGIC, kind, port, session, sequence)
    body = head + payload
    return body + hmac.digest(key, body, 'sha256')[:TAG]


def unpack(key, packet):
    if not HEADER.size + TAG <= len(packet) <= MAX_PACKET:
        raise ValueError('Invalid UDP frame size')
    body, tag = packet[:-TAG], packet[-TAG:]
    if not hmac.compare_digest(hmac.digest(key, body, 'sha256')[:TAG], tag):
        raise ValueError('Invalid UDP frame authentication')
    magic, kind, port, session, sequence = HEADER.unpack(body[:HEADER.size])
    if magic != MAGIC or kind not in (1, 2, 3, 4):
        raise ValueError('Invalid UDP frame')
    return kind, port, session, sequence, body[HEADER.size:]


class ReplayWindow:
    """Allow bounded reordering, rejecting duplicate and stale packets."""
    def __init__(self): self.top = -1; self.bits = 0
    def accept(self, sequence):
        if sequence > self.top:
            shift = sequence - self.top
            self.bits = ((self.bits << shift) | 1) & ((1 << 128) - 1) if shift < 128 else 1
            self.top = sequence
            return True
        delta = self.top - sequence
        if delta >= 128 or self.bits & (1 << delta): return False
        self.bits |= 1 << delta
        return True


def percentile(values, q):
    return sorted(values)[max(0, math.ceil(len(values)*q)-1)] if values else None


def quality(stages):
    """Conservative gaming defaults; speed is not the ranking reward."""
    reasons = []
    for name, row in stages.items():
        fields=('sent','received','loss_percent','p95_ms','p99_ms','jitter_p95_ms','max_gap_ms')
        if any(type(row.get(k)) not in (int,float) or not math.isfinite(row[k]) or row[k]<0 for k in fields):
            reasons.append(name+': missing or invalid UDP metrics');continue
        if row['sent'] < 100 or row['received'] < 100: reasons.append(name + ': too few samples')
        if row['loss_percent'] > 1: reasons.append(name + ': packet loss exceeds 1%')
        if row['p95_ms'] is None or row['p95_ms'] > 250: reasons.append(name + ': p95 exceeds 250 ms')
        if row['p99_ms'] is None or row['p99_ms'] > 350: reasons.append(name + ': p99 exceeds 350 ms')
        if row['jitter_p95_ms'] is None or row['jitter_p95_ms'] > 25: reasons.append(name + ': jitter exceeds 25 ms')
        if row['max_gap_ms'] > 300: reasons.append(name + ': reply gap exceeds 300 ms')
    idle, loaded = stages.get('idle', {}), stages.get('loaded', {})
    if idle.get('p95_ms') is not None and loaded.get('p95_ms') is not None:
        if loaded['p95_ms'] - idle['p95_ms'] > 50: reasons.append('latency under controlled load increased by over 50 ms')
    return reasons


def probe(address, token, timeout=2):
    key, session = bytes.fromhex(token), os.urandom(8)
    payload = os.urandom(64)
    message = pack(key, 1, 0, session, 0, payload)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout); sock.connect(tuple(address)); start = time.monotonic()
        sock.send(message)
        deadline = start + timeout
        while time.monotonic() < deadline:
            sock.settimeout(max(.001, deadline-time.monotonic()))
            try: kind, port, sid, seq, data = unpack(key, sock.recv(MAX_PACKET))
            except ValueError: continue
            if (kind, port, sid, seq, data) == (2, 0, session, 0, payload):
                return (time.monotonic()-start)*1000
    raise PronetError('Authenticated UDP probe timed out')


def _stage(address, token, seconds, loaded=False, progress=None):
    key, session = bytes.fromhex(token), os.urandom(8)
    sent, received, delays, arrivals, seen = {}, {}, [], [], set()
    wrong, reordered, last_sequence = 0, 0, -1
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(tuple(address)); sock.setblocking(False)
        start = time.monotonic(); finish = start+seconds; next_send = start
        next_load = start; sequence = 0; load_sequence = 1 << 40
        while time.monotonic() < finish+.8:
            now = time.monotonic()
            if now < finish and now >= next_send:
                # Every fifth probe checks a 1200-byte UDP payload (plus frame).
                size = 1200 if sequence % 5 == 0 else (512 if sequence % 2 else 64)
                payload = hashlib.sha256(session+struct.pack('!Q',sequence)).digest()
                payload = (payload*((size+31)//32))[:size]
                sent[sequence]=(time.monotonic(),payload)
                try:
                    sock.send(pack(key,1,0,session,sequence,payload))
                except (BlockingIOError, ConnectionRefusedError, OSError): pass
                sequence += 1; next_send = now+.02
            # ~1 Mbit/s payload each way, paced separately from latency probes.
            if loaded and now < finish and now >= next_load:
                with contextlib.suppress(OSError): sock.send(pack(key,1,0,session,load_sequence,b'L'*1000))
                load_sequence += 1; next_load = now+.008
            readable, _, _ = select.select([sock],[],[],.002)
            if readable:
                for _ in range(128):
                    try: packet = sock.recv(MAX_PACKET)
                    except (BlockingIOError, OSError): break
                    try: kind, port, sid, seq, payload = unpack(key,packet)
                    except ValueError: wrong += 1; continue
                    if kind != 2 or sid != session or port != 0: wrong += 1; continue
                    if seq >= 1 << 40:
                        if loaded and payload == b'L'*1000: received[seq]=True
                        continue
                    if seq not in sent or payload != sent[seq][1]: wrong += 1; continue
                    if seq in seen: continue
                    seen.add(seq); at = time.monotonic()
                    if seq < last_sequence: reordered += 1
                    last_sequence=max(last_sequence,seq)
                    delays.append((at-sent[seq][0])*1000);arrivals.append(at)
            if progress: progress(min(1,(now-start)/seconds))
    jitter = [abs(b-a) for a,b in zip(delays,delays[1:])]
    # Include silence at either end, but exclude the bounded final drain period.
    gaps = [b-a for a,b in zip([start]+arrivals,arrivals+[finish]) if b>=a]
    return {'sent':len(sent),'received':len(seen),'loss_percent':round(100*(1-len(seen)/max(1,len(sent))),3),
            'p50_ms':percentile(delays,.5),'p95_ms':percentile(delays,.95),'p99_ms':percentile(delays,.99),
            'jitter_p95_ms':percentile(jitter,.95),'max_gap_ms':round(max(gaps,default=seconds)*1000,3),
            'reordered':reordered,'integrity_errors':wrong,'echo_ms':delays,
            'load_reply_mbps':len(received)*1000*8/seconds/1e6 if loaded else 0}


def benchmark(address, token, long_test=False, progress=None):
    duration = 12 if long_test else 6
    stages = {}
    for index, name in enumerate(('idle','loaded')):
        stages[name] = _stage(address,token,duration,loaded=name=='loaded',
                              progress=(lambda fraction,i=index: progress(name,(i+fraction)/2)) if progress else None)
    # Idle recovery is tested again after controlled load, not an unbounded flood.
    time.sleep(1)
    after_idle = False
    with contextlib.suppress(OSError, PronetError): probe(address,token);after_idle=True
    errors = quality(stages)
    if any(s['integrity_errors'] for s in stages.values()):errors.append('UDP integrity/authentication failed')
    if not after_idle:errors.append('UDP did not recover after load/idle')
    samples=[v for s in stages.values() for v in s['echo_ms']]
    loaded=stages['loaded']
    return {'gaming':True,'passed':not errors,'echo_ms':samples,'success_ratio':min(s['received']/max(1,s['sent']) for s in stages.values()),
            'upload_mbps':loaded['load_reply_mbps'],'download_mbps':loaded['load_reply_mbps'],
            'half_close':False,'after_idle':after_idle,'integrity':not any(s['integrity_errors'] for s in stages.values()),
            'gaming_stages':stages,'errors':errors,'reason':'; '.join(errors),'utc':utc(),
            'payload_bytes':1200,'load_scope':'paced UDP echo ~1 Mbit/s each direction; not saturation or a capacity estimate',
            'recommended_wireguard_mtu_ipv4':1160,'minimum_wireguard_mtu_ipv6':1280}


def score(row):
    stages=row.get('gaming_stages',{})
    if not row.get('gaming') or not row.get('passed') or not row.get('after_idle') or not row.get('integrity'):return None
    if set(stages) != {'idle','loaded'} or quality(stages):return None
    # Negative cost; the caller sorts descending. Penalize loss far more than throughput.
    return -sum(s['loss_percent']*100 + s['p95_ms'] + .5*s['p99_ms'] + 3*s['jitter_p95_ms'] for s in stages.values())


class Session:
    def __init__(self,sock,session,port,source):
        self.sock=sock;self.session=session;self.port=port;self.source=source
        self.at=time.monotonic();self.sequence=0;self.replay=ReplayWindow()


class DatagramRelay(asyncio.DatagramProtocol):
    """One pair-owned foreign relay or public Iran listener. No worker per packet."""
    def __init__(self,token,foreign=False,ports=(),backend=None,client_port=None,target='127.0.0.1',peer=None):
        self.key=bytes.fromhex(token);self.foreign=foreign;self.ports=set(ports)
        self.backend=tuple(backend) if backend else None;self.client_port=client_port;self.target=target;self.peer=peer
        self.sessions=collections.OrderedDict();self.transport=None;self.closed=False;self.rx_at=0
        self.window=0;self.count=0
    def connection_made(self,transport):
        self.transport=transport;self.loop=asyncio.get_running_loop();self.timer=self.loop.call_later(10,self.expire)
    def datagram_received(self,data,addr):
        # Hard packet/second and session bounds also cover unauthenticated public input.
        now=time.monotonic()
        if int(now)!=self.window:self.window=int(now);self.count=0
        self.count+=1
        if self.count>20000 or len(data)>MAX_PACKET-HEADER.size-TAG:return
        if self.foreign:
            if self.peer and addr[0]!=self.peer:return
            try:kind,port,sid,sequence,payload=unpack(self.key,data)
            except ValueError:return
            if kind==1 and port==0 and 64<=len(payload)<=1200:
                self.transport.sendto(pack(self.key,2,0,sid,sequence,payload),addr);return
            if kind!=3 or port not in self.ports:return
            key=(addr,sid,port)
            if key not in self.sessions:
                if len(self.sessions)>=MAX_SESSIONS:
                    oldest=next(iter(self.sessions))
                    if now-self.sessions[oldest].at<10:return
                    self.drop(oldest)
                try:self.make_session(key,((self.target.get(str(port),'127.0.0.1') if isinstance(self.target,dict) else self.target),port),sid,port,addr)
                except OSError:return
            row=self.sessions[key]
            if not row.replay.accept(sequence):return
            message=payload
        else:
            key=addr
            if key not in self.sessions:
                if len(self.sessions)>=MAX_SESSIONS:return
                try:self.make_session(key,self.backend,os.urandom(8),self.client_port,addr)
                except OSError:return
            row=self.sessions[key]
            message=pack(self.key,3,row.port,row.session,row.sequence,data);row.sequence+=1
        row.at=now;self.sessions.move_to_end(key)
        with contextlib.suppress(OSError):row.sock.send(message)
    def make_session(self,key,target,sid,port,source):
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.setblocking(False)
        if sys.platform=='linux': sock.setsockopt(socket.SOL_IP,10,0)  # IP_MTU_DISCOVER=DONT, this socket only
        try:sock.connect(tuple(target))
        except OSError:sock.close();raise
        row=Session(sock,sid,port,source);self.sessions[key]=row
        self.loop.add_reader(sock.fileno(),self.reply,key)
    def reply(self,key):
        row=self.sessions.get(key)
        if not row:return
        for _ in range(64):
            try:data=row.sock.recv(MAX_PACKET)
            except (BlockingIOError,OSError):break
            if self.foreign:
                message=pack(self.key,4,row.port,row.session,row.sequence,data);row.sequence+=1
            else:
                try:kind,port,sid,seq,message=unpack(self.key,data)
                except ValueError:continue
                if (kind,port,sid)!=(4,row.port,row.session) or not row.replay.accept(seq):continue
                self.rx_at=time.time()
            row.at=time.monotonic()
            self.transport.sendto(message,row.source)
    def expire(self):
        now=time.monotonic()
        for key,row in list(self.sessions.items()):
            if now-row.at>SESSION_IDLE:self.drop(key)
        if not self.closed:self.timer=self.loop.call_later(10,self.expire)
    def drop(self,key):
        row=self.sessions.pop(key,None)
        if row:self.loop.remove_reader(row.sock.fileno());row.sock.close()
    def close(self):
        self.closed=True
        if hasattr(self,'timer'):self.timer.cancel()
        for key in list(self.sessions):self.drop(key)
        if self.transport:self.transport.close()
    def connection_lost(self,exc):
        self.close()


async def listen(address,relay,freebind=False):
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.setblocking(False)
    try:
        if freebind:sock.setsockopt(socket.SOL_IP,15,1)
        if sys.platform=='linux':sock.setsockopt(socket.SOL_IP,10,0)  # allow bounded WG datagrams to fragment
        sock.bind(tuple(address))
        await asyncio.get_running_loop().create_datagram_endpoint(lambda:relay,sock=sock)
    except BaseException:sock.close();raise
    return relay


class Gateway:
    def __init__(self,config,stats):self.config=pathlib.Path(config);self.stats=pathlib.Path(stats);self.relays=[];self.task=None;self.closed=False
    async def start(self):
        self.settings=read_json(self.config);await self.open(self.settings)
        self.task=asyncio.create_task(self.maintain())
    async def open(self,config):
        try:
            for port in config['ports']:
                relay=DatagramRelay(config['frame_key'],backend=config['active_backend'],client_port=port)
                self.relays.append(await listen((config['bind_ip'],port),relay))
        except BaseException:
            for relay in self.relays:relay.close()
            self.relays=[];raise
    async def maintain(self):
        count=0
        while not self.closed:
            await asyncio.sleep(1);config=read_json(self.config)
            if any(config.get(k)!=self.settings.get(k) for k in ('active_backend','frame_key')):
                # Keep public sockets bound. Closing then rebinding in one loop
                # tick races the transport's deferred close (EADDRINUSE).
                for relay in self.relays:
                    for key in list(relay.sessions):relay.drop(key)
                    relay.key=bytes.fromhex(config['frame_key'])
                    relay.backend=tuple(config['active_backend']);relay.rx_at=0
                self.settings=config
            count+=1
            if count%5==0:
                seen=max((r.rx_at for r in self.relays),default=0)
                write_json(self.stats,{'backend_rx_at':{'%s:%s'%tuple(self.settings['active_backend']):seen},
                                      'udp_sessions':sum(len(r.sessions) for r in self.relays)})
    async def close(self):
        self.closed=True
        if self.task:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):await self.task
        for relay in self.relays:relay.close()
