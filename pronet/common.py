from __future__ import annotations

import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
import pathlib
import re
import secrets
import subprocess
import tempfile
import time

MAX_BODY = 2 * 1024 * 1024
ROOT = pathlib.Path(os.environ.get("PRONET_STATE", "/var/lib/pronet-fleet"))
CONFIG = pathlib.Path(os.environ.get("PRONET_CONFIG", "/etc/pronet-fleet"))
APP = pathlib.Path(__file__).resolve().parent.parent


class PronetError(Exception):
    pass


def now():
    return time.time()


def utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{24}", value):
        raise PronetError("Invalid resource ID")
    return value


def ipv4(value):
    try:
        ip = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise PronetError("A literal IPv4 address is required")
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local or int(ip) == 0xffffffff:
        raise PronetError("Address is not a usable server address")
    return str(ip)


def port(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise PronetError("Port must be an integer from 1 to 65535")
    return value


MAX_INBOUND_PORTS = 16


def port_list(value):
    """Validated, ordered, duplicate-free list of client ports (first = primary)."""
    values = [value] if isinstance(value, int) and not isinstance(value, bool) else value
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_INBOUND_PORTS:
        raise PronetError("Give 1 to %d client ports" % MAX_INBOUND_PORTS)
    values = [port(item) for item in values]
    if len(set(values)) != len(values):
        raise PronetError("Client ports must not repeat")
    return values


def parse_ports(text):
    """Operator input such as "2053", "2053,2083 8443" or "2080-2083" -> [ports]."""
    if isinstance(text, (int, list)) and not isinstance(text, bool):
        return port_list(text)
    tokens = [t for t in re.split(r"[\s,;،]+", str(text or "").strip()) if t]
    if not tokens:
        raise PronetError("Enter at least one port")
    values = []
    for token in tokens:
        match = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", token)
        if not match:
            raise PronetError("'%s' is not a port. Example: 2053,2083,8443 or 2080-2083" % token)
        low = int(match.group(1))
        high = int(match.group(2)) if match.group(2) else low
        if high < low or high - low >= MAX_INBOUND_PORTS:
            raise PronetError("Invalid port range '%s'" % token)
        for number in range(low, high + 1):
            if number not in values:
                values.append(number)
    return port_list(values)


def inbound_ports(data):
    """Client ports of a request/plan; records from before 0.3.3 only had inbound_port."""
    ports = data.get("inbound_ports")
    if ports is None:
        return [port(data["inbound_port"])]
    ports = port_list(ports)
    if "inbound_port" in data and data["inbound_port"] != ports[0]:
        raise PronetError("Primary client port mismatch")
    return ports


def secret():
    return secrets.token_hex(32)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def sign(key, value):
    return hmac.new(bytes.fromhex(key), canonical(value), hashlib.sha256).hexdigest()


def clean(value, limit=400):
    value = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))
    value = re.sub(r"(?i)(token|password|secret|authorization)[=: ]+\S+", r"\1=[REDACTED]", value)
    return re.sub(r"\b[a-fA-F0-9]{64,}\b", "[REDACTED]", value)[:limit]


def read_json(path, default=None):
    try:
        with open(path, "rb") as file:
            raw = file.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise PronetError("State file too large")
        return json.loads(raw)
    except FileNotFoundError:
        if default is not None:
            return default
        raise


def atomic_write(path, data, mode=0o600, durable=True):
    # durable=False still replaces atomically (readers never see a partial
    # file) but skips fsync. Use it only for frequently rewritten statistics
    # on a latency-sensitive path, never for identity, plans or selection.
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or path.parent.is_symlink():
        raise PronetError("Refusing symlink state path")
    if isinstance(data, str):
        data = data.encode()
    fd, temporary = tempfile.mkstemp(prefix=".pronet-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            if durable:
                os.fsync(file.fileno())
        os.replace(temporary, path)
        if durable:
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def write_json(path, data, durable=True):
    atomic_write(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n", durable=durable)


@contextlib.contextmanager
def lock(path, blocking=True):
    import fcntl
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        yield
    finally:
        os.close(fd)


def command(args, timeout=30, check=True, input=None):
    try:
        result = subprocess.run(args, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, text=True, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PronetError(clean(error))
    if check and result.returncode:
        raise PronetError(clean(result.stderr or result.stdout or "Command failed"))
    return result


def event(path, kind, detail):
    # Bounded local log; credentials and control characters are removed.
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() and path.stat().st_size > 512 * 1024:
        os.replace(path, path.with_suffix(".previous"))
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, canonical({"utc": utc(), "event": kind, "detail": clean(detail)}) + b"\n")
    finally:
        os.close(fd)
