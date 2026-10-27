"""Authenticated, bounded test service and a half-close preserving TCP gateway."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import socket
import socketserver
import ssl
import struct
import threading
import time

from .common import PronetError, canonical, read_json, sign, utc, write_json

MAX_TRANSFER = 4 * 1024 * 1024
IDLE_TIMEOUT = 1800


def receive_line(stream, maximum=4096):
    line = stream.readline(maximum + 1)
    if not line or len(line) > maximum or not line.endswith(b"\n"):
        raise PronetError("Invalid protocol frame")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise PronetError("Object required")
    return value


def read_exact(stream, size):
    value = bytearray()
    while len(value) < size:
        chunk = stream.read(min(65536, size - len(value)))
        if not chunk:
            raise PronetError("Truncated transfer")
        value.extend(chunk)
    return bytes(value)


class ProbeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, key, freebind=False):
        self.key = key
        self.slots = threading.BoundedSemaphore(16)
        self.nonces = {}
        self.nonce_lock = threading.Lock()
        self.freebind = freebind
        super().__init__(address, ProbeHandler)

    def server_bind(self):
        if self.freebind:
            self.socket.setsockopt(socket.SOL_IP, 15, 1)  # Linux IP_FREEBIND
        super().server_bind()

    def process_request(self, request, client_address):
        if not self.slots.acquire(False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass  # Invalid/unauthenticated input is not a log amplification API.

    def accept_nonce(self, nonce):
        if not isinstance(nonce, str) or len(nonce) != 32:
            return False
        try:
            bytes.fromhex(nonce)
        except ValueError:
            return False
        with self.nonce_lock:
            current = time.monotonic()
            self.nonces = {k: v for k, v in self.nonces.items() if current - v < 120}
            if nonce in self.nonces or len(self.nonces) >= 8192:
                return False
            self.nonces[nonce] = current
            return True


class ProbeHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        for _ in range(12):
            request = receive_line(self.rfile)
            mac = request.pop("mac", "")
            if (not isinstance(mac, str) or not hmac.compare_digest(sign(self.server.key, request), mac)
                    or not self.server.accept_nonce(request.get("nonce"))):
                return
            if set(request) != {"nonce", "op", "size"}:
                return
            size = request["size"]
            if type(size) is not int or not 0 <= size <= MAX_TRANSFER:
                return
            operation = request["op"]
            result = {"nonce": request["nonce"], "op": operation}
            if operation == "echo" and size == 0:
                result["ok"] = True
                self.reply(result)
            elif operation == "upload" and size > 0:
                payload = read_exact(self.rfile, size)
                # Respond only after the sender's half-close. This finds a class
                # of tunnel bugs that an echo without EOF cannot detect.
                if self.rfile.read(1) != b"":
                    return
                result.update(size=size, sha256=hashlib.sha256(payload).hexdigest())
                self.reply(result)
                return
            elif operation == "download" and size > 0:
                payload = os.urandom(size)
                result.update(size=size, sha256=hashlib.sha256(payload).hexdigest())
                self.reply(result)
                self.wfile.write(payload)
                self.wfile.flush()
                return
            else:
                return

    def reply(self, result):
        self.wfile.write(canonical(dict(result, mac=sign(self.server.key, result))) + b"\n")
        self.wfile.flush()


def request_frame(key, operation, size=0):
    value = {"nonce": secrets.token_hex(16), "op": operation, "size": size}
    return dict(value, mac=sign(key, value))


def response(stream, key, request):
    result = receive_line(stream)
    mac = result.pop("mac", "")
    if (not isinstance(mac, str) or not hmac.compare_digest(sign(key, result), mac)
            or result.get("nonce") != request["nonce"] or result.get("op") != request["op"]):
        raise PronetError("Probe response authentication failed")
    return result


def echo(address, key, timeout=4):
    started = time.monotonic()
    with socket.create_connection(address, timeout=timeout) as sock:
        sock.settimeout(timeout)
        with sock.makefile("rb") as stream:
            frame = request_frame(key, "echo")
            sock.sendall(canonical(frame) + b"\n")
            if not response(stream, key, frame).get("ok"):
                raise PronetError("Echo failed")
    return (time.monotonic() - started) * 1000


@contextlib.contextmanager
def bounded_socket(address, timeout, deadline):
    remaining = min(timeout, deadline - time.monotonic())
    if remaining <= 0:
        raise TimeoutError("Benchmark time budget exhausted")
    with socket.create_connection(address, timeout=remaining) as sock:
        sock.settimeout(remaining)
        def expire():
            with contextlib.suppress(OSError): sock.shutdown(socket.SHUT_RDWR)
        timer = threading.Timer(remaining, expire)
        timer.daemon = True
        timer.start()
        try:
            yield sock
        finally:
            timer.cancel()


class LinkLock:
    """Keeps measurements on one Iran<->foreign link from disturbing each other.

    Latency samples may run together (a few hundred bytes each), but never
    while a throughput transfer is running, and transfers run strictly one at
    a time. Idle checks take no lock: they send nothing while they wait.
    """
    def __init__(self):
        self._condition = threading.Condition()
        self._shared = 0
        self._exclusive = False
        self._waiting_exclusive = 0

    @contextlib.contextmanager
    def shared(self):
        with self._condition:
            # Writer preference: a queued transfer is not starved by pings.
            while self._exclusive or self._waiting_exclusive:
                self._condition.wait()
            self._shared += 1
        try:
            yield
        finally:
            with self._condition:
                self._shared -= 1
                self._condition.notify_all()

    @contextlib.contextmanager
    def exclusive(self):
        with self._condition:
            self._waiting_exclusive += 1
            try:
                while self._exclusive or self._shared:
                    self._condition.wait()
            finally:
                self._waiting_exclusive -= 1
            self._exclusive = True
        try:
            yield
        finally:
            with self._condition:
                self._exclusive = False
                self._condition.notify_all()


TRANSFER_CHUNK = 65536


def benchmark(address, key, rounds=5, size=1024 * 1024, idle=3, timeout=15, budget=70, link=None, progress=None):
    """Latency, upload, download, half-close and idle survival of one carrier.

    With ``link`` several carriers can be measured at once without changing
    any measured number: transfers and latency samples never overlap another
    carrier's transfer, and time spent waiting for the link does not count
    against this carrier's budget. ``progress(phase, fraction)`` reports real
    progress (completed probes, bytes moved, idle seconds).
    """
    if not 1 <= rounds <= 20 or not 1 <= size <= MAX_TRANSFER or not 0 <= idle <= 15:
        raise PronetError("Invalid benchmark budget")
    report = progress or (lambda phase, fraction: None)
    started = time.monotonic()
    deadline = [started + budget]
    waited = [0.0]
    @contextlib.contextmanager
    def hold(kind):
        if link is None:
            yield
            return
        before = time.monotonic()
        with getattr(link, kind)():
            pause = time.monotonic() - before
            waited[0] += pause
            deadline[0] += pause
            yield
    result = dict(passed=False, echo_ms=[], success_ratio=0, upload_mbps=None, download_mbps=None,
                  half_close=False, after_idle=False, integrity=False, utc=utc(), payload_bytes=size)
    errors = []
    report("latency", 0)
    with hold("shared"):
        for index in range(rounds):
            try:
                remaining = deadline[0] - time.monotonic()
                if remaining <= 0: break
                result["echo_ms"].append(round(echo(address, key, min(timeout, 4, remaining)), 3))
            except (OSError, ValueError, PronetError) as error:
                errors.append(type(error).__name__)
            report("latency", (index + 1) / rounds)
            time.sleep(.2)
    result["success_ratio"] = len(result["echo_ms"]) / rounds
    try:
        payload = os.urandom(size)
        with hold("exclusive"):
            report("upload", 0)
            with bounded_socket(address, timeout, deadline[0]) as sock:
                with sock.makefile("rb") as stream:
                    frame = request_frame(key, "upload", size)
                    transfer_start = time.monotonic()
                    sock.sendall(canonical(frame) + b"\n")
                    view = memoryview(payload)
                    for offset in range(0, size, TRANSFER_CHUNK):
                        sock.sendall(view[offset:offset + TRANSFER_CHUNK])
                        report("upload", min(size, offset + TRANSFER_CHUNK) / size)
                    sock.shutdown(socket.SHUT_WR)
                    answer = response(stream, key, frame)
                    result["half_close"] = answer.get("size") == size and answer.get("sha256") == hashlib.sha256(payload).hexdigest()
                    result["upload_mbps"] = round(size * 8 / max(.000001, time.monotonic() - transfer_start) / 1e6, 3)
            report("download", 0)
            with bounded_socket(address, timeout, deadline[0]) as sock:
                with sock.makefile("rb") as stream:
                    frame = request_frame(key, "download", size)
                    transfer_start = time.monotonic()
                    sock.sendall(canonical(frame) + b"\n")
                    answer = response(stream, key, frame)
                    parts, received = [], 0
                    while received < size:
                        part = read_exact(stream, min(TRANSFER_CHUNK, size - received))
                        parts.append(part)
                        received += len(part)
                        report("download", received / size)
                    downloaded = b"".join(parts)
                    result["integrity"] = (answer.get("size") == size
                                           and answer.get("sha256") == hashlib.sha256(downloaded).hexdigest()
                                           and result["half_close"])
                    result["download_mbps"] = round(size * 8 / max(.000001, time.monotonic() - transfer_start) / 1e6, 3)
        report("idle", 0)
        with bounded_socket(address, max(timeout, idle + 5), deadline[0]) as sock:
            with sock.makefile("rb") as stream:
                frame = request_frame(key, "echo")
                sock.sendall(canonical(frame) + b"\n")
                response(stream, key, frame)
                waited_idle = 0.0
                while waited_idle < idle:
                    step = min(.5, idle - waited_idle)
                    time.sleep(step)
                    waited_idle += step
                    report("idle", waited_idle / idle)
                frame = request_frame(key, "echo")
                sock.sendall(canonical(frame) + b"\n")
                result["after_idle"] = response(stream, key, frame).get("ok") is True
        result["passed"] = all((result["success_ratio"] == 1, result["half_close"], result["integrity"], result["after_idle"]))
    except (OSError, ValueError, PronetError) as error:
        errors.append(type(error).__name__)
    result["errors"] = errors
    # Reported time excludes waiting for other carriers' transfers.
    result["seconds"] = round(time.monotonic() - started - waited[0], 3)
    report("done", 1)
    return result


def tcp_state(address, timeout=2):
    try:
        with socket.create_connection(address, timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "refused"
    except (OSError, TimeoutError):
        return "unconfirmed"


def tls_state(address, sni, timeout=4):
    if not sni:
        return "not-configured"
    try:
        with socket.create_connection(address, timeout=timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=sni):
                return "verified"
    except ssl.SSLError:
        return "certificate-or-handshake-failed"
    except OSError:
        return "unconfirmed"


async def async_frame_json(reader):
    raw = await asyncio.wait_for(reader.readline(), 8)
    if len(raw) > 2048 or not raw.endswith(b"\n"):
        raise PronetError("Invalid bridge handshake")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise PronetError("Invalid bridge handshake object")
    return value


async def bridge_auth(reader, writer, key, server=False, port=None, allowed_ports=()):
    """Mutual HMAC handshake of one bridged connection.

    Client side: ``port`` optionally selects one of the pair's extra client
    ports; it is covered by the MAC, and omitted for the primary port so the
    handshake stays identical to older versions. Server side: returns the
    selected port, or None for the primary port. Only ``allowed_ports`` can be
    selected; no other target is ever accepted from the network.
    """
    if server:
        request = await async_frame_json(reader)
        mac = request.pop("mac", "")
        if (set(request) - {"port"} != {"v", "op", "nonce"} or request["v"] != 1 or request["op"] != "bridge"
                or not isinstance(request["nonce"], str) or len(request["nonce"]) != 32
                or not isinstance(mac, str) or not hmac.compare_digest(mac, sign(key, request))):
            raise PronetError("Bridge client authentication failed")
        selected = request.get("port")
        if "port" in request and (type(selected) is not int or selected not in allowed_ports):
            raise PronetError("Bridge port is not allowed for this tunnel")
        challenge = secrets.token_hex(16)
        answer = {"v": 1, "nonce": request["nonce"], "challenge": challenge, "ok": True}
        writer.write(canonical(dict(answer, mac=sign(key, answer))) + b"\n")
        await asyncio.wait_for(writer.drain(), 60)
        confirm = await async_frame_json(reader)
        mac = confirm.pop("mac", "")
        if (confirm != {"v": 1, "op": "confirm", "nonce": request["nonce"], "challenge": challenge}
                or not isinstance(mac, str) or not hmac.compare_digest(mac, sign(key, confirm))):
            raise PronetError("Bridge key confirmation failed")
        return selected
    else:
        request = {"v": 1, "op": "bridge", "nonce": secrets.token_hex(16)}
        if port is not None:
            request["port"] = port
        writer.write(canonical(dict(request, mac=sign(key, request))) + b"\n")
        await asyncio.wait_for(writer.drain(), 60)
        answer = await async_frame_json(reader)
        mac = answer.pop("mac", "")
        challenge = answer.get("challenge")
        if (not isinstance(challenge, str) or len(challenge) != 32
                or answer != {"v": 1, "nonce": request["nonce"], "challenge": challenge, "ok": True}
                or not isinstance(mac, str) or not hmac.compare_digest(mac, sign(key, answer))):
            raise PronetError("Bridge server authentication failed")
        confirm = {"v": 1, "op": "confirm", "nonce": request["nonce"], "challenge": challenge}
        writer.write(canonical(dict(confirm, mac=sign(key, confirm))) + b"\n")
        await asyncio.wait_for(writer.drain(), 60)


def tune_socket(sock):
    """TCP keepalive frees resources held by vanished mobile clients/peers.

    Without it a client that loses coverage keeps two sockets and a task alive
    until the long idle timeout. Values: probe after 60 s idle, every 15 s, give
    up after 4 misses (about two minutes).
    """
    if sock is None:
        return
    with contextlib.suppress(OSError, AttributeError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 15)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 4)


async def _idle_deadline_read(read):
    """Distinguish our idle deadline from a transport's TimeoutError.

    A failed StreamReader raises the same stored exception on every read.
    Retrying that exception spins without yielding on Python 3.12 and can
    exhaust memory with cancelled timer handles before any monitor runs.
    """
    timeout = getattr(asyncio, "timeout", None)
    if timeout is not None:
        deadline = timeout(IDLE_TIMEOUT)
        try:
            async with deadline:
                return False, await read()
        except TimeoutError:
            if not deadline.expired():
                raise
            return True, None
        finally:
            # The timeout context retains its task; do not retain it in a
            # failed task traceback after the context has exited.
            deadline = None

    # Python 3.10: wait reports expiry separately from the child's exception.
    task = asyncio.ensure_future(read())
    done = pending = None
    try:
        done, pending = await asyncio.wait((task,), timeout=IDLE_TIMEOUT)
        if done:
            return False, task.result()
        return True, None
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        if done is not None:
            done.clear()
            pending.clear()
        task = None


async def idle_read(read, activity):
    """Read with a connection-wide idle timeout, preserving one-way traffic."""
    while True:
        expired, data = await _idle_deadline_read(read)
        if expired:
            if time.monotonic() - activity[0] < IDLE_TIMEOUT:
                continue
            raise asyncio.TimeoutError("Connection idle deadline expired")
        activity[0] = time.monotonic()
        return data


async def framed_stream(raw_reader, raw_writer, frame_reader, frame_writer, count_out=None, count_in=None):
    """FIN/ACK records preserve half-close through engines that close on TCP EOF.

    The underlying tunnel socket stays open until BOTH logical directions have
    finished and their FIN records have been acknowledged. No arbitrary target
    address is accepted from the network.
    """
    write_lock = asyncio.Lock()
    sent_fin = asyncio.Event()
    acknowledged = asyncio.Event()
    activity = [time.monotonic()]
    async def send(kind, payload=b""):
        async with write_lock:
            frame_writer.write(struct.pack("!BI", kind, len(payload)) + payload)
            await asyncio.wait_for(frame_writer.drain(), 60)
    async def upload():
        while True:
            data = await idle_read(lambda: raw_reader.read(65536), activity)
            if not data:
                sent_fin.set()
                await send(1)
                await asyncio.wait_for(acknowledged.wait(), 30)
                return
            await send(0, data)
            if count_out: count_out(len(data))
    async def download():
        received_fin = False
        while True:
            header = await idle_read(lambda: frame_reader.readexactly(5), activity)
            kind, size = struct.unpack("!BI", header)
            if kind == 0 and not received_fin and 0 < size <= 65536:
                payload = await asyncio.wait_for(frame_reader.readexactly(size), 30)
                raw_writer.write(payload)
                await asyncio.wait_for(raw_writer.drain(), 60)
                if count_in: count_in(len(payload))
            elif kind == 1 and size == 0 and not received_fin:
                received_fin = True
                with contextlib.suppress(OSError, RuntimeError):
                    raw_writer.write_eof()
                    await asyncio.wait_for(raw_writer.drain(), 60)
                await send(2)
            elif kind == 2 and size == 0 and sent_fin.is_set() and not acknowledged.is_set():
                acknowledged.set()
            else:
                raise PronetError("Invalid bridge record")
            if received_fin and acknowledged.is_set():
                return
    tasks = [asyncio.create_task(upload()), asyncio.create_task(download())]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            if not task.done(): task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # A failed child stores this frame in its traceback. Keeping the child
        # list (or the loop variable) here forms a cycle retaining both socket
        # readers and their buffers until a full cyclic collection.
        tasks.clear()
        task = None


async def bridge_server(reader, writer, key, target, allowed_ports=()):
    """target = (host, primary port); a signed handshake may select another
    port from allowed_ports on the same host."""
    remote = None
    try:
        selected = await bridge_auth(reader, writer, key, server=True, allowed_ports=allowed_ports)
        if selected is not None:
            target = (target[0], selected)
        backend, remote = await asyncio.wait_for(asyncio.open_connection(*target), 5)
        await framed_stream(backend, remote, reader, writer)
    except (OSError, ValueError, PronetError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass
    except Exception:
        pass  # One malformed session must never stop the bridge listener.
    finally:
        for stream in (remote, writer):
            if stream is not None:
                stream.close()
                with contextlib.suppress(OSError, asyncio.TimeoutError): await asyncio.wait_for(stream.wait_closed(), 5)


DEFAULT_CONNECTION_LIMIT = 8192
MAX_CONNECTION_LIMIT = 32768
LISTEN_BACKLOG = 4096


def backend_key(value):
    try:
        return (str(value[0]), int(value[1]))
    except (TypeError, ValueError, IndexError):
        return None


class Gateway:
    """Public listener stays fixed; NEW connections follow an active switch.

    Existing connections stay on their backend after an ordinary switch. When
    the watchdog declares a backend dead (failed_backends in the config), the
    connections still bound to it are closed so clients reconnect at once
    through the new path instead of hanging on a black hole.
    """
    def __init__(self, config_path, stats_path):
        self.config_path, self.stats_path = config_path, stats_path
        self.stats = read_json(stats_path, {"rx_bytes": 0, "tx_bytes": 0, "connections_total": 0})
        self.stats["connections_active"] = 0
        self.server = None
        self.servers = []
        self.writer_task = None
        self.config_task = None
        self.clients = set()
        self.backends = {}
        self.config = {}
        self.config_stamp = None
        self.drained = set()
        self.limit = DEFAULT_CONNECTION_LIMIT

    def load_config(self, force=False):
        # stat() is cheap; the JSON is parsed only when the file changed.
        try:
            info = os.stat(self.config_path)
            stamp = (info.st_mtime_ns, info.st_size, info.st_ino)
        except OSError:
            return self.config
        if force or stamp != self.config_stamp:
            config = read_json(self.config_path)
            if not isinstance(config, dict):
                raise PronetError("Invalid gateway configuration")
            self.config, self.config_stamp = config, stamp
            limit = config.get("connection_limit", DEFAULT_CONNECTION_LIMIT)
            if type(limit) is not int:
                limit = DEFAULT_CONNECTION_LIMIT
            self.limit = max(16, min(MAX_CONNECTION_LIMIT, limit))
            self.apply_failover(config)
        return self.config

    def apply_failover(self, config):
        failed = {backend_key(item) for item in config.get("failed_backends", []) or []} - {None}
        active = backend_key(config.get("active_backend"))
        failed.discard(active)
        fresh = failed - self.drained
        self.drained = failed
        if not fresh:
            return
        closed = 0
        for task, backend in list(self.backends.items()):
            if backend in fresh and not task.done():
                task.cancel()
                closed += 1
        if closed:
            self.stats["drained_on_failover"] = self.stats.get("drained_on_failover", 0) + closed

    async def start(self):
        """Listen on the primary port and on every extra client port.

        A connection on the primary port is forwarded exactly as before. A
        connection on an extra port goes to the same port behind the tunnel
        (plain: same host, that port; framed: the port is named in the signed
        bridge handshake).
        """
        config = self.load_config(force=True)
        ports = [config["port"]] + [p for p in config.get("ports", []) if p != config["port"]]
        try:
            for index, number in enumerate(ports):
                def handler(reader, writer, target=None if index == 0 else number):
                    return self.handle(reader, writer, target)
                self.servers.append(await asyncio.start_server(handler, config["bind_ip"], number, limit=65536,
                                                               backlog=LISTEN_BACKLOG, reuse_address=True))
        except OSError:
            for server in self.servers:
                server.close()
            self.servers = []
            raise
        self.server = self.servers[0]
        self.writer_task = asyncio.create_task(self.persist())
        self.config_task = asyncio.create_task(self.watch_config())
        return self.server.sockets[0].getsockname()

    def addresses(self):
        return [server.sockets[0].getsockname() for server in self.servers]

    async def watch_config(self):
        while True:
            await asyncio.sleep(1)
            with contextlib.suppress(OSError, ValueError, PronetError):
                self.load_config()

    def save_stats(self):
        # Statistics only: atomic but not fsynced, so a slow disk can never
        # pause every forwarded connection on this event loop.
        self.stats["utc"] = utc()
        with contextlib.suppress(OSError, PronetError):
            write_json(self.stats_path, self.stats, durable=False)

    async def persist(self):
        previous = (time.monotonic(), self.stats["rx_bytes"], self.stats["tx_bytes"])
        while True:
            current = time.monotonic()
            elapsed = current - previous[0]
            if elapsed >= .5:
                self.stats["rx_Bps"] = round((self.stats["rx_bytes"] - previous[1]) / elapsed, 1)
                self.stats["tx_Bps"] = round((self.stats["tx_bytes"] - previous[2]) / elapsed, 1)
                self.stats["activity"] = "ACTIVE" if self.stats["rx_Bps"] + self.stats["tx_Bps"] > 0 else "IDLE"
            previous = (current, self.stats["rx_bytes"], self.stats["tx_bytes"])
            self.stats["connection_limit"] = self.limit
            self.save_stats()
            await asyncio.sleep(5)

    async def pipe(self, reader, writer, counter, activity):
        while True:
            chunk = await idle_read(lambda: reader.read(65536), activity)
            if not chunk:
                with contextlib.suppress(OSError, RuntimeError):
                    writer.write_eof()
                    await asyncio.wait_for(writer.drain(), 60)
                return
            writer.write(chunk)
            await asyncio.wait_for(writer.drain(), 60)
            self.stats[counter] += len(chunk)

    async def handle(self, reader, writer, target_port=None):
        current = asyncio.current_task()
        self.clients.add(current)
        remote_writer = None
        accepted = False
        try:
            try:
                config = self.load_config()
            except (OSError, ValueError, PronetError):
                config = self.config
            if self.stats["connections_active"] >= self.limit:
                self.stats["rejected_limit"] = self.stats.get("rejected_limit", 0) + 1
                return
            backend = config.get("active_backend")
            if not backend:
                return
            accepted = True
            self.stats["connections_active"] += 1
            self.stats["connections_total"] += 1
            self.backends[current] = backend_key(backend)
            tune_socket(writer.get_extra_info("socket"))
            framed = config.get("mode") == "framed"
            address = backend if framed or target_port is None else (backend[0], target_port)
            remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection(*address), 5)
            tune_socket(remote_writer.get_extra_info("socket"))
            if framed:
                await bridge_auth(remote_reader, remote_writer, config["frame_key"], port=target_port)
                def outgoing(size): self.stats["rx_bytes"] += size
                def incoming(size): self.stats["tx_bytes"] += size
                await framed_stream(reader, writer, remote_reader, remote_writer, outgoing, incoming)
                return
            activity = [time.monotonic()]
            tasks = [asyncio.create_task(self.pipe(reader, remote_writer, "rx_bytes", activity)),
                     asyncio.create_task(self.pipe(remote_reader, writer, "tx_bytes", activity))]
            try:
                await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                tasks.clear()
                task = None
        except (OSError, ValueError, KeyError, TypeError, PronetError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            self.stats["connection_failures"] = self.stats.get("connection_failures", 0) + 1
        finally:
            if accepted:
                self.stats["connections_active"] -= 1
            self.backends.pop(current, None)
            for stream in (writer, remote_writer):
                if stream is not None:
                    stream.close()
                    with contextlib.suppress(OSError, asyncio.TimeoutError, asyncio.CancelledError):
                        await asyncio.wait_for(stream.wait_closed(), 5)
            self.clients.discard(current)
            current = None

    async def close(self):
        for server in self.servers:
            server.close()
        # Cancel live sessions BEFORE waiting: since Python 3.12 wait_closed()
        # also waits for every client connection, which turned a service stop
        # into a 15 s SIGKILL timeout while users were connected.
        for task in list(self.clients):
            task.cancel()
        if self.clients:
            await asyncio.gather(*list(self.clients), return_exceptions=True)
        for server in self.servers:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(server.wait_closed(), 5)
        for task in (self.config_task, self.writer_task):
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        self.save_stats()
