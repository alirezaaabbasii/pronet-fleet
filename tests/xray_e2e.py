#!/usr/bin/env python3
"""Disposable, real Xray WS/TLS and XHTTP client tests through an Iran gateway.

Never edits an existing panel. Refuses an occupied inbound. The foreign test
outbound is restricted to one local HTTP sink. Transfer share.json via SSH/SFTP.
"""
import argparse
import concurrent.futures
import contextlib
import hashlib
import http.client
import http.server
import json
import os
import pathlib
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
import zipfile

ARCHIVE_SHA = '0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978'
MAX_BYTES = 4 * 1024 * 1024


def put(path, value):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value, indent=2)); path.chmod(0o600)


def binary(archive, work):
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA:
        raise ValueError('Official Xray test archive checksum mismatch')
    target = work / 'xray'
    with zipfile.ZipFile(archive) as source:
        members = [entry for entry in source.infolist() if entry.filename == 'xray' and not entry.is_dir()]
        if len(members) != 1: raise ValueError('Invalid Xray archive')
        data = source.read(members[0])
        if target.is_symlink(): raise ValueError('Refusing test binary symlink')
        if not target.exists() or target.read_bytes() != data:
            temporary = target.with_suffix('.new')
            temporary.write_bytes(data); temporary.chmod(0o700); temporary.replace(target)
    target.chmod(0o700)
    return target


def occupied(address):
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(address)


def stream_settings(mode, tls):
    value = {'network': mode, 'security': 'tls', 'tlsSettings': tls}
    if mode == 'ws': value['wsSettings'] = {'path': '/pronet-e2e'}
    else: value['xhttpSettings'] = {'path': '/pronet-e2e', 'mode': 'auto'}
    return value


class Sink(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args): pass
    def answer(self, data):
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('X-Pronet-SHA256', hashlib.sha256(data).hexdigest())
        self.end_headers(); self.wfile.write(data); self.wfile.flush()
    def do_GET(self):
        if urllib.parse.urlsplit(self.path).path != '/payload': self.send_error(404); return
        self.answer(os.urandom(262144))
    def do_POST(self):
        size = int(self.headers.get('Content-Length', '0'))
        if urllib.parse.urlsplit(self.path).path != '/payload' or not 0 < size <= MAX_BYTES: self.send_error(400); return
        self.connection.settimeout(20)
        data = self.rfile.read(size)
        if len(data) != size: self.send_error(400); return
        self.answer(data)


def server(args, program):
    from pronet.engines import wstunnel_certificate
    work = args.work
    occupied(('0.0.0.0', args.port)); occupied(('127.0.0.1', args.sink_port))
    ca = wstunnel_certificate(work / 'cert', 'pronet-e2e.invalid', args.foreign_ip)
    path = work / 'share.json'
    if path.exists(): fixture = json.loads(path.read_text())
    else:
        fixture = {'schema': 1, 'id': str(uuid.uuid4()), 'ca_pem': ca, 'server_name': 'pronet-e2e.invalid',
                   'port': args.port, 'sink_port': args.sink_port}
        put(path, fixture)
    config = {'log': {'loglevel': 'warning'},
        'inbounds': [{'listen': '0.0.0.0', 'port': args.port, 'protocol': 'vless',
            'settings': {'clients': [{'id': fixture['id']}], 'decryption': 'none'},
            'streamSettings': stream_settings(args.mode, {'alpn': ['http/1.1'] if args.mode == 'ws' else ['h2'],
                'certificates': [{'certificateFile': str(work/'cert/server.crt'), 'keyFile': str(work/'cert/server.key')} ]})}],
        'outbounds': [{'tag': 'block', 'protocol': 'blackhole'}, {'tag': 'sink', 'protocol': 'freedom', 'settings': {'finalRules': [
            {'action': 'allow', 'network': 'tcp', 'ip': ['127.0.0.1/32'], 'port': str(args.sink_port)},
            {'action': 'block', 'blockDelay': '0-0'}]}}],
        'routing': {'rules': [{'type': 'field', 'ip': ['127.0.0.1'], 'port': str(args.sink_port), 'outboundTag': 'sink'}]}}
    put(work / 'server.json', config)
    subprocess.run([str(program), 'run', '-test', '-config', str(work/'server.json')], check=True, capture_output=True)
    sink = http.server.ThreadingHTTPServer(('127.0.0.1', args.sink_port), Sink)
    threading.Thread(target=sink.serve_forever, daemon=True).start()
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT): signal.signal(sig, lambda *_: stop.set())
    with open(work/'server.log', 'a') as log:
        child = subprocess.Popen([str(program), 'run', '-config', str(work/'server.json')], stdout=log, stderr=log)
        try:
            print(json.dumps({'state': 'STARTED', 'mode': args.mode, 'port': args.port, 'share': str(path)}), flush=True)
            while not stop.wait(.5):
                if child.poll() is not None: raise RuntimeError('Disposable Xray server exited')
        finally:
            if child.poll() is None:
                child.terminate()
                try: child.wait(5)
                except subprocess.TimeoutExpired: child.kill(); child.wait()
            sink.shutdown(); sink.server_close()


def proxy_connection(proxy, sink_port):
    sock = socket.create_connection(('127.0.0.1', proxy), timeout=20)
    def exact(size):
        value = b''
        while len(value) < size:
            data = sock.recv(size-len(value))
            if not data: raise EOFError('SOCKS test connection closed')
            value += data
        return value
    try:
        sock.sendall(bytes([5, 1, 0]))
        if exact(2) != bytes([5, 0]): raise ValueError('SOCKS authentication negotiation failed')
        sock.sendall(bytes([5, 1, 0, 1]) + socket.inet_aton('127.0.0.1') + struct.pack('!H', sink_port))
        answer = exact(4)
        if answer[:3] != bytes([5, 0, 0]): raise ValueError('SOCKS fixed target rejected')
        if answer[3] == 1: exact(4)
        elif answer[3] == 4: exact(16)
        elif answer[3] == 3: exact(exact(1)[0])
        else: raise ValueError('Invalid SOCKS response')
        exact(2)
        conn = http.client.HTTPConnection('127.0.0.1', sink_port, timeout=20)
        conn.sock = sock
        return conn
    except BaseException:
        sock.close(); raise


def request(proxy, sink_port, upload=None, connection=None):
    own = connection is None
    conn = connection or proxy_connection(proxy, sink_port)
    try:
        url = '/payload'
        conn.request('GET' if upload is None else 'POST', url, body=upload)
        reply = conn.getresponse()
        body = reply.read(MAX_BYTES + 1)
        if reply.status != 200 or len(body) > MAX_BYTES or hashlib.sha256(body).hexdigest() != reply.getheader('X-Pronet-SHA256'):
            raise ValueError('Xray end-to-end integrity failed: HTTP ' + str(reply.status) + ', bytes=' + str(len(body)))
        if upload is not None and body != upload: raise ValueError('Xray end-to-end upload integrity failed')
        return len(body)
    finally:
        if own: conn.close()


def client(args, program):
    fixture = json.loads((args.work/'share.json').read_text())
    occupied(('127.0.0.1', args.proxy_port))
    cert = args.work/'peer-ca.pem'; cert.write_text(fixture['ca_pem']); cert.chmod(0o600)
    config = {'log': {'loglevel': 'warning'},
        'inbounds': [{'listen': '127.0.0.1', 'port': args.proxy_port, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}],
        'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': args.gateway_ip, 'port': fixture['port'],
            'users': [{'id': fixture['id'], 'encryption': 'none'}]}]},
            'streamSettings': stream_settings(args.mode, {'allowInsecure': False, 'disableSystemRoot': True,
                'serverName': fixture['server_name'], 'alpn': ['http/1.1'] if args.mode == 'ws' else ['h2'],
                'certificates': [{'certificateFile': str(cert), 'usage': 'verify'}]})}]}
    put(args.work/'client.json', config)
    subprocess.run([str(program), 'run', '-test', '-config', str(args.work/'client.json')], check=True, capture_output=True)
    result = {'mode': args.mode, 'gateway': args.gateway_ip + ':' + str(fixture['port']), 'passed': False,
              'tls_verification': 'private-ca-and-server-name', 'client': 'Xray v26.10.21'}
    with open(args.work/'client.log', 'a') as log:
        child = subprocess.Popen([str(program), 'run', '-config', str(args.work/'client.json')], stdout=log, stderr=log)
        try:
            time.sleep(1)
            if child.poll() is not None: raise RuntimeError('Disposable Xray client exited')
            start = time.monotonic()
            result['stage'] = 'download'
            request(args.proxy_port, fixture['sink_port'])
            result['stage'] = 'upload'
            request(args.proxy_port, fixture['sink_port'], os.urandom(1048576))
            result['stage'] = 'concurrency'
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                transferred = list(pool.map(lambda _: request(args.proxy_port, fixture['sink_port']), range(12)))
            with contextlib.closing(proxy_connection(args.proxy_port, fixture['sink_port'])) as conn:
                request(args.proxy_port, fixture['sink_port'], connection=conn)
                time.sleep(args.idle)
                request(args.proxy_port, fixture['sink_port'], connection=conn)
            result.update(stage='complete', passed=True, upload_integrity=True, download_integrity=True, concurrent_requests=len(transferred),
                          idle_seconds=args.idle, after_idle=True, seconds=round(time.monotonic()-start, 2))
        except Exception as error:
            result['error'] = type(error).__name__ + ': ' + str(error)[:300]
        finally:
            if child.poll() is None:
                child.terminate()
                try: child.wait(5)
                except subprocess.TimeoutExpired: child.kill(); child.wait()
    put(args.work/(args.mode+'-report.json'), result)
    print(json.dumps(result, indent=2), flush=True)
    return 0 if result['passed'] else 1


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('role', choices=['server','client'])
    parser.add_argument('--mode', choices=['ws','xhttp'], required=True)
    parser.add_argument('--app-root', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent.parent)
    parser.add_argument('--work', type=pathlib.Path, required=True)
    parser.add_argument('--archive', type=pathlib.Path, required=True)
    parser.add_argument('--foreign-ip'); parser.add_argument('--gateway-ip')
    parser.add_argument('--port', type=int, default=2053)
    parser.add_argument('--sink-port', type=int, default=18080)
    parser.add_argument('--proxy-port', type=int, default=10808)
    parser.add_argument('--idle', type=int, default=45)
    args=parser.parse_args()
    if not 0 <= args.idle <= 120: raise ValueError('Invalid idle budget')
    args.work.mkdir(parents=True, exist_ok=True, mode=0o700)
    sys.path.insert(0,str(args.app_root))
    program=binary(args.archive,args.work)
    if args.role=='server': server(args,program); return 0
    return client(args,program)


if __name__=='__main__': sys.exit(main())
