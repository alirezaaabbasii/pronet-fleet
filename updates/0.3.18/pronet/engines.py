"""Pinned assets and configuration-only adapters. No arbitrary shell templates."""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import pathlib
import platform
import re
import tarfile
import zipfile

from .common import APP, PronetError, atomic_write, command, read_json, write_json
from .model import PROFILES, iface, tunnel_ips, validate_profile


CERT_DAYS = "3650"


def architecture():
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine(), "unsupported")


def install_asset(engine, destination, arch=None, vendor=None):
    manifest = read_json(APP / "assets.lock.json")
    if engine not in manifest:
        raise PronetError("Unknown engine")
    row = manifest[engine]
    arch = arch or architecture()
    if arch not in ("amd64", "arm64"):
        raise PronetError("Supported server architectures: amd64, arm64")
    asset = row["assets"][arch]
    archive = pathlib.Path(vendor or APP / "vendor") / asset["name"]
    if not archive.is_file() or archive.is_symlink():
        raise PronetError("Verified offline engine archive missing: " + asset["name"])
    raw = archive.read_bytes()
    if hashlib.sha256(raw).hexdigest() != asset["sha256"]:
        raise PronetError("Engine archive checksum mismatch")
    destination = pathlib.Path(destination) / engine / row["version"] / arch
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    names = ["frpc", "frps"] if engine == "frp" else [engine]
    extracted = {}
    if engine == "chisel":
        extracted["chisel"] = gzip.decompress(raw)
    elif asset.get("format") == "raw":
        extracted[engine] = raw
    elif engine == "rathole":
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                name = pathlib.PurePosixPath(member.filename).name
                if name in names:
                    if member.is_dir() or member.file_size > 100 * 1024 * 1024 or name in extracted:
                        raise PronetError("Unsafe or duplicate engine member")
                    extracted[name] = bundle.read(member)
    else:
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle.getmembers():
                name = pathlib.PurePosixPath(member.name).name
                if name in names or name == asset.get("binary"):
                    name = engine if name == asset.get("binary") else name
                    if not member.isfile() or member.size > 100 * 1024 * 1024 or name in extracted:
                        raise PronetError("Unsafe or duplicate engine member")
                    extracted[name] = bundle.extractfile(member).read()
    if set(extracted) != set(names):
        raise PronetError("Engine archive does not contain expected binaries")
    for name, binary in extracted.items():
        path = destination / name
        if path.is_symlink():
            raise PronetError("Refusing engine symlink")
        # Reverify from the immutable pinned archive, even when already installed.
        if not path.exists() or hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(binary).digest():
            atomic_write(path, binary, 0o700)
    return {name: str(destination / name) for name in names}


def certificate(directory, server_name, address, extra_ips=()):
    directory = pathlib.Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert, key = directory / "server.crt", directory / "server.key"
    if cert.exists() and key.exists():
        return cert.read_text()
    if not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", server_name):
        raise PronetError("Invalid certificate name")
    import ipaddress
    ip = str(ipaddress.IPv4Address(address))
    for extra in extra_ips:
        ip += ",IP:" + str(ipaddress.IPv4Address(extra))
    config = """[req]
distinguished_name=dn
x509_extensions=ext
prompt=no
[dn]
CN={name}
[ext]
subjectAltName=DNS:{name},IP:{ip}
basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign
extendedKeyUsage=serverAuth
""".format(name=server_name, ip=ip)
    atomic_write(directory / "openssl.cnf", config)
    # Trust is pinned per pair/hub (never public PKI), so a short lifetime adds
    # no security but silently broke every FRP pair and the hub after a year.
    command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", CERT_DAYS,
             "-keyout", str(key), "-out", str(cert), "-config", str(directory / "openssl.cnf")], timeout=30)
    key.chmod(0o600)
    cert.chmod(0o600)
    return cert.read_text()


def chisel_key(directory):
    directory = pathlib.Path(directory)
    key = directory / "chisel-key.pem"
    if not key.exists():
        command(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)])
        key.chmod(0o600)
    public = command(["ssh-keygen", "-y", "-f", str(key)]).stdout.strip().split()
    if len(public) < 2 or public[0] != "ecdsa-sha2-nistp256":
        raise PronetError("Could not derive Chisel server fingerprint")
    return base64.b64encode(hashlib.sha256(base64.b64decode(public[1])).digest()).decode()


def wstunnel_certificate(directory, server_name, address):
    """Private CA and a CA:false leaf, compatible with strict rustls checks."""
    directory = pathlib.Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", server_name): raise PronetError("Invalid certificate name")
    import ipaddress
    address = str(ipaddress.IPv4Address(address))
    ca, ca_key = directory / "ca.crt", directory / "ca.key"
    cert, key = directory / "server.crt", directory / "server.key"
    if not ca.exists() or not ca_key.exists():
        command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                 "-keyout", str(ca_key), "-out", str(ca), "-subj", "/CN=PronetPairCA",
                 "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], timeout=30)
    if not cert.exists() or not key.exists():
        extension = directory / "leaf.ext"
        atomic_write(extension, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:" + server_name + ",IP:" + address + "\n")
        csr = directory / "server.csr"
        command(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                 "-out", str(csr), "-subj", "/CN=" + server_name], timeout=30)
        command(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
                 "-CAcreateserial", "-out", str(cert), "-days", CERT_DAYS, "-extfile", str(extension)])
    for path in (ca, ca_key, cert, key): path.chmod(0o600)
    return ca.read_text()


def toml_table(name, values):
    return "[" + name + "]\n" + "".join(k + " = " + json.dumps(v) + "\n" for k, v in values.items())


def render(plan, directory, binaries):
    validate_profile(plan)
    directory = pathlib.Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    spec = PROFILES[plan["profile"]]
    iran = plan["role"] == "iran"
    control = plan["control_port"]
    iran_tun, foreign_tun = tunnel_ips(plan)
    mappings = [(plan["health_port"], plan["bridge_health_port"]), (plan["data_port"], plan["bridge_data_port"])]
    path = directory / "engine.toml"
    environment = {}
    local_bind = plan["bind_ip"]
    if spec["engine"] == "native-gre":
        return {"native": "gre", "command": [], "validate": None, "environment": {}}
    if spec["engine"] in ("paqet", "backhaul", "parsa-spoof"):
        from .carrier_engines import render
        return render(plan, directory, binaries)
    if spec["engine"] == "backpack":
        if spec["kind"] == "l3":
            dial = iran == (plan["direction"] == "iran-dials")
            peer_public = plan["foreign_ip"] if iran else plan["iran_ip"]
            local, peer = (iran_tun, foreign_tun) if iran else (foreign_tun, iran_tun)
            values = {"mode": "dial" if dial else "listen", "addr": f"{peer_public if dial else local_bind}:{control}",
                      "carrier": spec["carrier"], "token": plan["token"], "iface": iface(plan),
                      "local_ip": local + "/30", "peer_ip": peer, "encap": "gre", "mtu": 1280,
                      "auto_mtu": True, "mss_clamp": -1, "txqueuelen": 256, "qdisc": "fq_codel"}
            if plan.get('gaming'):
                values.update(mtu=1280,txqueuelen=64,qdisc='fq_codel')
            if spec.get("fec"):
                values.update(fec_data=10, fec_parity=3)
            text = toml_table("l3", values)
        elif spec["kind"] == "direct":
            values = {"role": "iran" if iran else "kharej", "transport": spec["carrier"],
                      "addr": f"{plan['foreign_ip'] if iran else local_bind}:{control}",
                      "token": plan["token"], "nodelay": True, "sessions": 1, "retry_interval": 3,
                      "dial_timeout": 8, "keepalive_period": 30, "accept_udp": False}
            if iran:
                values["ports"] = [f"127.0.0.1:{src}=127.0.0.1:{dst}" for src, dst in mappings]
            text = toml_table("direct", values)
        else:
            values = {"transport": spec["carrier"], "token": plan["token"], "nodelay": True,
                      "keepalive_period": 30, "log_level": "warn", "web_port": 0, "pprof": False,
                      "skip_optz": True, "accept_udp": False}
            if iran:
                values.update(bind_addr=f"{local_bind}:{control}", heartbeat=15,
                              ports=[f"127.0.0.1:{src}=127.0.0.1:{dst}" for src, dst in mappings])
            else:
                values.update(remote_addr=f"{plan['iran_ip']}:{control}", retry_interval=3,
                              dial_timeout=8, connection_pool=4)
            if spec["carrier"] == "kcp":
                values.update(kcp_mtu=1200, kcp_nodelay=1, kcp_interval=20, kcp_resend=2,
                              kcp_nocongestion=0, kcp_sndwnd=512, kcp_rcvwnd=512,
                              kcp_datashards=10, kcp_parityshards=3)
            text = toml_table("server" if iran else "client", values)
        atomic_write(path, text)
        return {"command": [binaries["backpack"], "-c", str(path)],
                "validate": [binaries["backpack"], "check", "-c", str(path)], "environment": environment}

    if spec["engine"] == "frp":
        if iran:
            text = (f'bindAddr = {json.dumps(local_bind)}\nbindPort = {control}\nproxyBindAddr = "127.0.0.1"\n'
                    f'auth.method = "token"\nauth.token = "{plan["token"]}"\n'
                    'transport.tls.force = true\ntransport.maxPoolCount = 16\n' +
                    f'transport.tls.certFile = {json.dumps(str(directory / "server.crt"))}\n' +
                    f'transport.tls.keyFile = {json.dumps(str(directory / "server.key"))}\n' +
                    'allowPorts = [' + ','.join('{single = %d}' % src for src, _ in mappings) + ']\n')
            if spec["carrier"] == "quic":
                text += f"quicBindPort = {control}\n"
            binary = binaries["frps"]
        else:
            text = (f'serverAddr = "{plan["iran_ip"]}"\nserverPort = {control}\n'
                    'loginFailExit = false\n' + f'auth.method = "token"\nauth.token = "{plan["token"]}"\n'
                    # Pre-opened work connections remove one Iran<->foreign round
                    # trip from every new user connection (frp default is 0).
                    f'transport.protocol = "{spec["carrier"]}"\ntransport.tls.enable = true\ntransport.poolCount = 8\n' +
                    f'transport.tls.trustedCaFile = {json.dumps(str(directory / "peer.crt"))}\n' +
                    f'transport.tls.serverName = "pn-{plan["pair_id"]}.invalid"\n')
            for index, (src, dst) in enumerate(mappings):
                text += f'\n[[proxies]]\nname = "pn{index}"\ntype = "tcp"\nlocalIP = "127.0.0.1"\nlocalPort = {dst}\nremotePort = {src}\n'
            binary = binaries["frpc"]
        text = 'log.to = "console"\nlog.level = "warn"\n' + text
        atomic_write(path, text)
        return {"command": [binary, "-c", str(path)], "validate": [binary, "verify", "-c", str(path)], "environment": environment}

    if spec["engine"] == "chisel":
        binary = binaries["chisel"]
        if iran:
            users = {"pronet:" + plan["token"]: [r"^R:127\.0\.0\.1:" + str(src) + "$" for src, _ in mappings]}
            write_json(directory / "users.json", users)
            args = [binary, "server", "--host", local_bind, "--port", str(control), "--reverse",
                    "--keyfile", str(directory / "chisel-key.pem"), "--authfile", str(directory / "users.json"),
                    "--keepalive", "25s"]
        else:
            fingerprint = plan.get("server_fingerprint", "")
            if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", fingerprint):
                raise PronetError("Chisel server fingerprint missing")
            args = [binary, "client", "--fingerprint", fingerprint, "--keepalive", "25s", "--max-retry-interval", "30s",
                    f"http://{plan['iran_ip']}:{control}"]
            args += [f"R:127.0.0.1:{src}:127.0.0.1:{dst}" for src, dst in mappings]
            environment["AUTH"] = "pronet:" + plan["token"]  # Never expose credentials in argv.
        return {"command": args, "validate": None, "environment": environment}
    from .extra_engines import render_extra
    return render_extra(plan, directory, binaries)


def probe_address(plan):
    spec = PROFILES[plan["profile"]]
    if spec["kind"] == "l3":
        ip_iran, ip_foreign = tunnel_ips(plan)
        return (ip_foreign if plan["role"] == "iran" else ip_iran, plan["echo_port"])
    return ("127.0.0.1", plan["probe_front_port"])


def data_address(plan):
    if plan.get('gaming'):
        return (tunnel_ips(plan)[1],plan['data_port'])
    return (tunnel_ips(plan)[1], plan["inbound_port"]) if PROFILES[plan["profile"]]["kind"] == "l3" else ("127.0.0.1", plan["data_port"])
