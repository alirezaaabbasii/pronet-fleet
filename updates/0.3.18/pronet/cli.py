from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hashlib
import ipaddress
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.parse

from . import __version__, engines
from .common import (APP, CONFIG, ROOT, PronetError, atomic_write, canonical, clean, command,
                     identifier, inbound_ports, ipv4, lock, parse_ports, port_list, read_json, secret, write_json)
from .model import DEFAULT_PROFILES, EMERGENCY_PROFILES, NORMAL_PROFILES, PROFILES, tunnel_ips

INSTALL_URL = "https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/get.sh"
TOKEN_PREFIX = "PNF1-"
JOIN_FILE = CONFIG / "pending-join.json"
START_ON_IRAN = ("Start on your IRAN server first: run the same install command there and choose 1. "
                 "When it finishes it prints one command; copy it and run it on this foreign server.")
HUB_PORTS = (9443, 8443, 7443, 10443, 20443)
REQUIRED_TOOLS = ("ip", "ss", "iptables", "iptables-save", "systemctl", "openssl", "ssh-keygen")


# ---------------------------------------------------------------- helpers

def root_linux():
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise PronetError("This needs Linux and root. Run it with sudo.")


def node_config():
    return read_json(CONFIG / "node.json")


def node_client():
    from .hub import Client
    config = node_config()
    return Client(config["hub_url"], config["node_id"] + ":" + config["node_secret"], config.get("ca_file"))


def say(text=""):
    print(text, flush=True)


def ask(prompt, default=""):
    shown = " [%s]" % default if default != "" else ""
    try:
        value = input("%s%s: " % (prompt, shown)).strip()
    except EOFError:
        value = ""
    return value or str(default)


def ports_argument(text):
    """argparse type for --port: 2053 or 2053,2083,8443."""
    try:
        return parse_ports(text)
    except PronetError as error:
        raise argparse.ArgumentTypeError(clean(error))


def check_tools():
    missing = [name for name in REQUIRED_TOOLS if not shutil.which(name)]
    if missing:
        raise PronetError("Missing system tools: " + ", ".join(missing)
                          + ". On Debian/Ubuntu install: python3 iproute2 iptables openssl openssh-client")


def route_source(target="1.1.1.1"):
    """IPv4 this host uses to reach target (the address peers will see unless NAT)."""
    with contextlib.suppress(PronetError, ValueError, IndexError, KeyError, TypeError):
        route = json.loads(command(["ip", "-j", "-4", "route", "get", target]).stdout)[0]
        return route.get("prefsrc")
    return None


def is_global(address):
    with contextlib.suppress(ValueError):
        return ipaddress.ip_address(address).is_global
    return False


def guess_public_ip(local_ips):
    source = route_source()
    if source and is_global(source):
        return source
    return next((ip for ip in local_ips if is_global(ip)), "")


def start_service(name, owner, args, directory):
    from .runtime import write_unit, service
    write_unit(name, owner, args, directory, temporary=False)
    command(["systemctl", "daemon-reload"])
    service(name, "enable")
    service(name, "start")


def open_firewall_port(number):
    """Open the coordinator port only in a host firewall that is ACTIVE."""
    if shutil.which("ufw"):
        status = command(["ufw", "status"], check=False).stdout
        if "Status: active" in status:
            command(["ufw", "allow", "%d/tcp" % number], check=False)
            return "ufw: allowed %d/tcp" % number
    if shutil.which("firewall-cmd") and command(["firewall-cmd", "--state"], check=False).returncode == 0:
        command(["firewall-cmd", "--permanent", "--add-port=%d/tcp" % number], check=False)
        command(["firewall-cmd", "--reload"], check=False)
        return "firewalld: allowed %d/tcp" % number
    return ""


# ------------------------------------------------------------ coordinator

def init_hub(args, quiet=False):
    root_linux()
    from .hub import Client
    Client(args.url, "validation-only")  # Validate URL before creating anything.
    parsed = urllib.parse.urlsplit(args.url)
    try:
        address = socket.gethostbyname(parsed.hostname)
    except OSError:
        raise PronetError("Coordinator host name does not resolve; check the IP or DNS.")
    listen_port = parsed.port or 443
    directory = CONFIG / "hub"
    path = directory / "hub.json"
    if path.exists():
        raise PronetError("A coordinator is already configured here; it was not overwritten.")
    with socket.socket() as sock:
        try:
            sock.bind((args.bind, listen_port))
        except OSError:
            raise PronetError("Port %d is already in use on this server." % listen_port)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    (ROOT / "hub").mkdir(parents=True, exist_ok=True, mode=0o700)
    if bool(args.cert) != bool(args.key):
        raise PronetError("Give the certificate and key together.")
    if args.cert:
        cert = pathlib.Path(args.cert).read_text()
        key = pathlib.Path(args.key).read_text()
        atomic_write(directory / "server.crt", cert)
        atomic_write(directory / "server.key", key)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(directory / "server.crt"), str(directory / "server.key"))
        ca_pem = pathlib.Path(args.ca).read_text() if args.ca else ""
    else:
        # 127.0.0.1 is included so an agent on this same host can reach the
        # coordinator locally even when the host cannot hairpin its public IP.
        cert = engines.certificate(directory, parsed.hostname, address, extra_ips=["127.0.0.1"])
        ca_pem = cert
    config = {"url": args.url.rstrip("/"), "bind": args.bind, "port": listen_port,
              "enrollment_key": secret(), "admin_key": secret(), "certificate": str(directory / "server.crt"),
              "private_key": str(directory / "server.key"), "database": str(ROOT / "hub" / "hub.sqlite3"),
              "dashboard": True, "dashboard_token": secret()[:32]}
    write_json(path, config)
    bootstrap = {"schema": 1, "hub_url": config["url"], "enrollment_key": config["enrollment_key"], "ca_pem": ca_pem}
    write_json(CONFIG / "pronet-bootstrap.json", bootstrap)
    atomic_write(CONFIG / "hub-admin-password", config["admin_key"] + "\n")
    # The hub has no need for root or access to node configuration/engines.
    import pwd
    try:
        account = pwd.getpwnam("pronet-fleet-hub")
    except KeyError:
        command(["useradd", "--system", "--home-dir", str(ROOT / "hub"), "--shell", "/usr/sbin/nologin", "pronet-fleet-hub"])
        account = pwd.getpwnam("pronet-fleet-hub")
    CONFIG.chmod(0o711)
    ROOT.chmod(0o711)
    for base in (directory, ROOT / "hub"):
        os.chown(base, account.pw_uid, account.pw_gid)
        for child in base.iterdir():
            os.chown(child, account.pw_uid, account.pw_gid)
    from .runtime import write_unit, unit_path, service
    name = "pronetf-hub.service"
    write_unit(name, "hub", ["/usr/bin/python3", str(APP / "main.py"), "hub-run"], ROOT / "hub", temporary=False)
    content = unit_path(name).read_text().replace("Type=simple\n", "Type=simple\nUser=pronet-fleet-hub\nGroup=pronet-fleet-hub\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=strict\nReadWritePaths=" + str(ROOT / "hub") + "\n")
    if listen_port < 1024:
        content = content.replace("NoNewPrivileges=true\n", "NoNewPrivileges=true\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n")
    atomic_write(unit_path(name), content, 0o644)
    command(["systemctl", "daemon-reload"])
    service(name, "enable")
    service(name, "start")
    firewall = open_firewall_port(listen_port)
    if not quiet:
        say("Coordinator created: " + config["url"])
        say("Bootstrap file (secret): %s" % (CONFIG / "pronet-bootstrap.json"))
        say("Dashboard password (user admin): %s" % (CONFIG / "hub-admin-password"))
        if firewall:
            say(firewall)
        say("Port %d must also be open in any datacenter/cloud firewall." % listen_port)
    return bootstrap


def wait_for_port(host, number, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError):
            with socket.create_connection((host, number), timeout=1):
                return True
        time.sleep(.5)
    return False


def ensure_local_hub(public_ip):
    """Use the coordinator on this host, creating it on the first free port."""
    bootstrap_path = CONFIG / "pronet-bootstrap.json"
    if bootstrap_path.exists():
        return read_json(bootstrap_path), False
    for candidate in HUB_PORTS:
        with socket.socket() as sock:
            try:
                sock.bind(("0.0.0.0", candidate))
            except OSError:
                continue
        bootstrap = init_hub(argparse.Namespace(url="https://%s:%d" % (public_ip, candidate), bind="0.0.0.0",
                                                cert=None, key=None, ca=None), quiet=True)
        if not wait_for_port("127.0.0.1", candidate):
            raise PronetError("The coordinator service did not start; check: journalctl -u pronetf-hub")
        return bootstrap, True
    raise PronetError("No free port for the coordinator (tried %s)." % ", ".join(map(str, HUB_PORTS)))


def local_hub_url(bootstrap):
    """Agents on the coordinator host talk to it over loopback when the
    coordinator certificate covers 127.0.0.1 (certificates made by >= 0.2.5)."""
    hub = read_json(CONFIG / "hub" / "hub.json", {})
    if not (hub and hub.get("url") == bootstrap["hub_url"] and bootstrap.get("ca_pem")):
        return bootstrap["hub_url"]
    try:
        context = ssl.create_default_context(cadata=bootstrap["ca_pem"])
        with socket.create_connection(("127.0.0.1", hub["port"]), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname="127.0.0.1"):
                pass
    except (OSError, ssl.SSLError, ValueError):
        return bootstrap["hub_url"]
    return "https://127.0.0.1:%d" % hub["port"]


# ------------------------------------------------------------ join token

def make_token(bootstrap, inbound_port, code):
    pem = bootstrap.get("ca_pem") or ""
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest() if pem else ""
    ports = port_list(inbound_port)
    # One port keeps the exact token format of earlier versions.
    data = {"u": bootstrap["hub_url"], "k": bootstrap["enrollment_key"], "f": fingerprint,
            "p": ports[0] if len(ports) == 1 else ports, "c": code}
    return TOKEN_PREFIX + base64.urlsafe_b64encode(canonical(data)).decode().rstrip("=")


def parse_token(text):
    match = re.search(re.escape(TOKEN_PREFIX) + r"([A-Za-z0-9_-]{40,2048})", text or "")
    if not match:
        raise PronetError("No join token found. Paste the full command shown on the Iran server.")
    raw = match.group(1)
    try:
        data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except (ValueError, TypeError):
        raise PronetError("The join token is damaged; copy it again in one piece.")
    if (not isinstance(data, dict) or set(data) != {"u", "k", "f", "p", "c"}
            or not isinstance(data["u"], str) or not data["u"].startswith("https://")
            or not isinstance(data["k"], str) or not re.fullmatch(r"[a-f0-9]{64}", data["k"])
            or not isinstance(data["f"], str) or not re.fullmatch(r"([a-f0-9]{64})?", data["f"])
            or not isinstance(data["c"], str) or not re.fullmatch(r"\d{4}", data["c"])):
        raise PronetError("The join token is not valid.")
    port_list(data["p"])
    return data


def fetch_pinned_ca(url, fingerprint):
    """Download the coordinator certificate and accept it ONLY if it matches
    the SHA-256 pin carried in the join token (no trust on first use)."""
    parsed = urllib.parse.urlsplit(url)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls:
                der = tls.getpeercert(binary_form=True)
    except OSError as error:
        raise PronetError("Cannot reach the coordinator at %s (%s). Check that the port is open on the Iran server "
                          "and in its datacenter firewall." % (url, clean(error)))
    if hashlib.sha256(der).hexdigest() != fingerprint:
        raise PronetError("Coordinator certificate does not match the join token. Stopped for safety.")
    return ssl.DER_cert_to_PEM_cert(der)


# ------------------------------------------------------------ nodes

def register_node(role, bootstrap, name, public, bind, inbound_port, hub_url=None):
    from .hub import Client
    from .runtime import inventory
    root_linux()
    check_tools()
    if (CONFIG / "node.json").exists():
        raise PronetError("This server is already registered; its identity was not overwritten.")
    info = inventory()
    if not info["systemd"] or info["arch"] not in ("amd64", "arm64"):
        raise PronetError("Linux with systemd on amd64 or arm64 is required.")
    if ipv4(bind) not in info["ips"]:
        raise PronetError("IP %s is not assigned to this server (for NAT, give the local IP as bind IP)." % bind)
    public = ipv4(public)
    allowed_ports = port_list(inbound_port)
    for allowed_port in allowed_ports:
        if allowed_port in info["ssh_ports"]:
            raise PronetError("Port %d is used by SSH." % allowed_port)
    if set(bootstrap) != {"schema", "hub_url", "enrollment_key", "ca_pem"} or bootstrap["schema"] != 1:
        raise PronetError("Invalid bootstrap data.")
    name = re.sub(r"[^\w.\-]", "-", name or socket.gethostname())[:60] or role
    CONFIG.mkdir(parents=True, exist_ok=True, mode=0o700)
    ca_file = None
    if bootstrap["ca_pem"]:
        atomic_write(CONFIG / "hub-ca.pem", bootstrap["ca_pem"])
        ca_file = str(CONFIG / "hub-ca.pem")
    hub_url = hub_url or bootstrap["hub_url"]
    client = Client(hub_url, bootstrap["enrollment_key"], ca_file)
    identity = {"role": role, "public_ip": public, "bind_ip": bind, "name": name}
    credentials = client.call("/v1/enroll", identity)
    identity.update(credentials, hub_url=hub_url, ca_file=ca_file, allowed_inbound_ports=allowed_ports)
    write_json(CONFIG / "node.json", identity)
    start_service("pronetf-agent.service", "agent", ["/usr/bin/python3", str(APP / "main.py"), "agent"], ROOT)
    with contextlib.suppress(OSError, PronetError):
        enable_traffic(quiet=True)
    return identity


def authorize_port(inbound_port):
    """Allow extra client ports on an already registered node (local consent:
    the operator is running this command on this server)."""
    config = node_config()
    allowed = config.get("allowed_inbound_ports", [2053])
    missing = [number for number in port_list(inbound_port) if number not in allowed]
    if not missing:
        return config
    from .runtime import inventory
    ssh = inventory()["ssh_ports"]
    for number in missing:
        if number in ssh:
            raise PronetError("Port %d is used by SSH." % number)
    config["allowed_inbound_ports"] = allowed + missing
    write_json(CONFIG / "node.json", config)
    command(["systemctl", "restart", "pronetf-agent.service"], check=False)
    time.sleep(1)
    return config


def init_node(args):
    """Advanced/legacy: register with an explicit bootstrap file."""
    bootstrap = read_json(args.bootstrap)
    register_node(args.role, bootstrap, args.name, args.public_ip, args.bind_ip, args.port)
    say("Registered: %s (%s)" % (args.name, args.role))


def port_problem(info, bind_ip, number):
    from .runtime import endpoint_has_nat, endpoint_occupied
    if number in info["ssh_ports"]:
        return "port %d is used by SSH" % number
    if endpoint_occupied(info, bind_ip, number):
        return "port %d is already in use on this server" % number
    if endpoint_has_nat(info, bind_ip, number):
        return "an existing NAT rule already uses port %d" % number
    return ""


# ------------------------------------------------------------ flows

def setup_iran(args=None, interactive=True, gaming=False):
    """Iran: coordinator (if needed) + registration + new tunnel, in one flow."""
    from .runtime import inventory
    root_linux()
    check_tools()
    info = inventory()
    registered = (CONFIG / "node.json").exists()
    if registered:
        config = node_config()
        if config["role"] != "iran":
            raise PronetError("This server is registered as foreign.")
        public, bind = config["public_ip"], config["bind_ip"]
    else:
        detected = getattr(args, "public_ip", None) or guess_public_ip(info["ips"])
        public = ask("Public IPv4 of this Iran server", detected) if interactive else detected
        ipv4(public)
        if public in info["ips"]:
            bind = public
        else:
            local = getattr(args, "bind_ip", None) or route_source() or ""
            bind = ask("This server is behind NAT. Local IPv4 to bind", local) if interactive else local
    default_port = ",".join(str(x) for x in port_list(getattr(args, "port", None) or ([51820] if gaming else [2053])))
    if interactive:
        say("Client port(s) on Iran. One port, or several separated by commas, e.g. 2053,2083,8443")
        say("(each foreign WireGuard UDP inbound must use the same port)" if gaming else "(each foreign panel inbound must use the same port)")
    while True:
        value = ask("Client port(s)", default_port) if interactive else default_port
        try:
            numbers = parse_ports(value)
        except PronetError as error:
            if not interactive:
                raise
            say("  " + clean(error) + ". Each port is a number from 1 to 65535.")
            continue
        problems = [p for p in (port_problem(info, bind, number) for number in numbers) if p]
        if not problems:
            break
        if not interactive:
            raise PronetError("; ".join(problems).capitalize() + "; choose other ports with --port.")
        for problem in problems:
            say("  " + problem.capitalize() + ".")
        say("  Choose other ports.")
    number = numbers if len(numbers) > 1 else numbers[0]
    if not registered:
        bootstrap, created = ensure_local_hub(public)
        if created:
            say("Coordinator started on this server: " + bootstrap["hub_url"])
        register_node("iran", bootstrap, getattr(args, "name", None) or socket.gethostname(), public, bind, number,
                      hub_url=local_hub_url(bootstrap))
        say("This server is registered as IRAN.")
    else:
        authorize_port(number)
    new_tunnel(number, name=getattr(args, "tunnel_name", None), quality=getattr(args, "quality", None) or "balanced",
               sni=getattr(args, "sni", "") or "", wait=not getattr(args, "no_wait", False), gaming=gaming or getattr(args,"gaming",False))


def new_tunnel(inbound_port=None, name=None, quality="balanced", sni="", profiles=None, standby=True, wait=True,
               direction="iran-dials", spoof=None, emergency=False, test_only=False, full_test=False, gaming=False):
    config = node_config()
    if config["role"] != "iran":
        raise PronetError("Create tunnels on the Iran server.")
    ports = port_list(inbound_port or config.get("allowed_inbound_ports", [2053])[0])
    if any(number not in config.get("allowed_inbound_ports", [2053]) for number in ports):
        config = authorize_port(ports)
    name = name or "tunnel-" + time.strftime("%m%d-%H%M")
    from .gaming import GAMING_PROFILES
    request = {"gaming":gaming, "name": name, "public_ip": config["public_ip"], "bind_ip": config["bind_ip"],
               "inbound_port": ports[0], "profiles": profiles or list(GAMING_PROFILES if gaming else EMERGENCY_PROFILES if emergency else DEFAULT_PROFILES),
               "standby": 1 if standby else 0, "direction": direction, "sni": sni, "quality": "thorough" if gaming else quality, "spoof": spoof or config.get("spoof_sources", {}), "emergency": emergency, "test_only": test_only, "full_test": full_test}
    if len(ports) > 1:
        request["inbound_ports"] = ports
    created = node_client().call("/v1/pair", request)
    bootstrap = read_json(CONFIG / "pronet-bootstrap.json", {})
    lines = ["", "=" * 64, "  IRAN IS READY. NEXT STEP ON YOUR FOREIGN SERVER:",
             "  copy the whole line below, paste it on the foreign server, press Enter", "=" * 64]
    if bootstrap:
        token = make_token(bootstrap, ports, created["code"])
        lines += ["", "curl -fsSL %s | sudo bash -s -- join %s" % (INSTALL_URL, token), "",
                  "(already installed there?  sudo pronet join %s )" % token,
                  "Valid for %d minutes. It contains a secret: paste it only on your own server." % (created["expires_in"] // 60)]
    else:
        lines += ["", "sudo pronet join %s" % created["code"], "",
                  "Valid for %d minutes." % (created["expires_in"] // 60)]
    lines.append("")
    # Kept root-only next to the enrollment key it is derived from, so the
    # live views can show it again until the foreign server has joined.
    with contextlib.suppress(OSError, PronetError):
        write_json(JOIN_FILE, {"pair_id": created["pair_id"], "lines": lines,
                               "expires": time.time() + created["expires_in"]})
    for line in lines:
        say(line)
    if wait:
        outcome=follow(created["pair_id"])
        if isinstance(outcome,dict): offer_advanced(outcome)
    else:
        say("Progress: sudo pronet watch")


def join(text, public_ip=None, name=None):
    """Foreign: one command registers (if needed) and joins the tunnel."""
    root_linux()
    text = (text or "").strip()
    if not text:
        raise PronetError(START_ON_IRAN)
    if re.fullmatch(r"\d{4}", text):
        if not (CONFIG / "node.json").exists():
            raise PronetError(START_ON_IRAN)
        code, data = text, None
    else:
        data = parse_token(text)
        code = data["c"]
    if not (CONFIG / "node.json").exists():
        check_tools()
        from .runtime import inventory
        info = inventory()
        say("Checking the coordinator %s ..." % data["u"])
        pem = fetch_pinned_ca(data["u"], data["f"]) if data["f"] else ""
        bootstrap = {"schema": 1, "hub_url": data["u"], "enrollment_key": data["k"], "ca_pem": pem}
        hub_host = socket.gethostbyname(urllib.parse.urlsplit(data["u"]).hostname)
        bind = route_source(hub_host) or guess_public_ip(info["ips"])
        if public_ip:
            public = public_ip
        elif bind and is_global(bind):
            public = bind
        else:
            public = ask("This server is behind NAT. Its public IPv4", guess_public_ip(info["ips"]))
        for number in port_list(data["p"]):
            problem = port_problem(info, bind, number) if number in info["ssh_ports"] else ""
            if problem:
                raise PronetError(problem.capitalize() + ".")
        register_node("foreign", bootstrap, name or socket.gethostname(), public, bind, data["p"])
        say("This server is registered as FOREIGN (%s, client port %s)." % (public, ",".join(str(x) for x in port_list(data["p"]))))
    else:
        config = node_config()
        if config["role"] != "foreign":
            raise PronetError("This server is registered as Iran. Run join on the foreign server.")
        if data:
            if data["u"].rstrip("/") != config["hub_url"].rstrip("/"):
                raise PronetError("This server belongs to another coordinator (%s)." % config["hub_url"])
            authorize_port(data["p"])
    result = node_client().call("/v1/join", {"code": code})
    say("Paired (tunnel %s)." % result["pair_id"][:8])
    say("The Iran server now measures every carrier and installs the best one (usually 5-10 minutes).")
    say("Progress and the final report are shown on the Iran server (sudo pronet watch).")
    port_numbers = port_list((data or {}).get("p") or node_config().get("allowed_inbound_ports", [2053])[0])
    for port_number in port_numbers:
        if not _listening(port_number):
            say("")
            say("Reminder: nothing listens on port %d here yet. Create your panel inbound on 0.0.0.0:%d." % (port_number, port_number))


def _listening(number):
    with contextlib.suppress(OSError):
        with socket.create_connection(("127.0.0.1", number), timeout=1):
            return True
    return False


# ------------------------------------------------------------ monitoring

def find_pair(data, pair_id=None):
    pairs = data.get("pairs", [])
    if pair_id:
        return next((pair for pair in pairs if pair["id"] == pair_id or pair["id"].startswith(pair_id)), None)
    return pairs[0] if pairs else None


def join_lines(pair_id):
    """The join command of a tunnel still waiting for its foreign server."""
    try:
        saved = read_json(JOIN_FILE, {})
    except (OSError, ValueError, PronetError):
        return []
    if not isinstance(saved, dict) or saved.get("pair_id") != pair_id or not isinstance(saved.get("lines"), list):
        return []
    if time.time() > saved.get("expires", 0):
        return ["", "The join command of this tunnel has expired. On Iran run: sudo pronet  ->  1) New tunnel", ""]
    return [line for line in saved["lines"] if isinstance(line, str)]


def terminal_style():
    from .ui import Style, fancy_terminal
    tty = sys.stdout.isatty()
    return Style(fancy=fancy_terminal(), color=tty)


def follow(pair_id):
    from .report import final_report, progress_lines, reason
    interactive = sys.stdout.isatty()
    style = terminal_style()
    say("Live progress (Ctrl+C to leave; setup continues in the background)")
    last_stage, reported = "", set()
    try:
        while True:
            try:
                data = node_client().call("/v1/overview")
            except PronetError as error:
                say("  coordinator unreachable, retrying: " + clean(error))
                time.sleep(5)
                continue
            pair = find_pair(data, pair_id)
            if pair is None:
                raise PronetError("Tunnel not found.")
            if pair["state"] in ("ACTIVE", "FAILED", "STOPPED", "STOP_UNCONFIRMED"):
                if interactive:
                    print("\033[2J\033[H", end="")
                for line in final_report(pair, data.get("nodes"), style=style, dashboard=dashboard_url(hub_config() or {}) or None):
                    say(line)
                return pair
            lines = progress_lines(pair, now=data.get("server_time"), style=style)
            if interactive:
                # Redraw in place, like `watch`, so the screen stays readable.
                frame = ["", "  Pronet Fleet %s" % __version__ + "   " + style.dim("Ctrl+C leaves this view; setup continues"),
                         style.rule()]
                if pair["state"] == "UNPAIRED":
                    # The redraw must not wipe the command the operator still has to copy.
                    frame += join_lines(pair_id)
                frame += lines + [style.rule()]
                print("\033[2J\033[H" + "\n".join(frame), flush=True)
                time.sleep(1)
            else:
                # Log-friendly: print stage changes and each finished carrier once.
                stage = lines[1].split("   elapsed")[0].strip() if len(lines) > 1 else lines[0].strip()
                if stage != last_stage:
                    say(stage)
                    last_stage = stage
                for row in pair.get("result", {}).get("results", []):
                    name = row.get("profile")
                    if name and name not in reported:
                        reported.add(name)
                        say("  %s %s %s" % ("PASS" if row.get("passed") else "FAIL", name,
                                            "" if row.get("passed") else reason(row)))
                time.sleep(3)
    except KeyboardInterrupt:
        say("")
        say("Left the live view. Setup continues; see it again with: sudo pronet watch")


def display(data, style=None):
    from .views import servers, tunnels
    from .report import progress_lines
    style = style or terminal_style()
    stamp = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(data.get("server_time") or time.time()))
    out = style.banner("Pronet Fleet %s" % __version__, stamp)
    out += ["", style.section("SERVERS")]
    def share(value):
        return "%d%%" % round(value) if isinstance(value, (int, float)) else "-"
    for row in servers(data):
        state = style.paint("online ", "32") if row["online"] else style.paint("OFFLINE", "31")
        load = ("CPU %s  RAM %s  Disk %s" % (share(row["cpu"]), share(row["ram"]), share(row["disk"]))
                if row["online"] else "last seen %s" % row["seen"])
        out.append("    %s %-12s %-7s %-15s %s %s" % (
            style.dot(row["online"]), clean(row["name"], 12), row["role"].upper(), row["ip"], state, style.dim(load)))
    rows = tunnels(data)
    for row in rows:
        badge = {"UP": style.paint("[ UP ]", "1;32"), "DOWN": style.paint("[ DOWN ]", "1;31")}.get(
            row["status"], style.paint("[ %s ]" % row["status"], "1;33"))
        out += ["", style.rule()]
        out.append("  TUNNEL %s   %s" % (style.paint(clean(row["name"], 30), "1"), badge))
        out.append("  " + style.dim("%s -> %s" % (clean(row["iran"], 20), clean(row["foreign"], 20))))
        if row["state"] != "ACTIVE":
            pair = next(p for p in data["pairs"] if p["id"] == row["id"])
            out += progress_lines(pair, now=data.get("server_time"), style=style)[1:]
            if pair.get("state") == "UNPAIRED":
                out += join_lines(pair["id"])
            out.append(style.field("ID", row["id"]))
            continue
        out += ["", style.section("CONNECTION")]
        out.append(style.field("Clients", row["endpoint"]))
        out.append(style.field("Panel", "inbound port %s: %s" % (row["port"], style.ok(row["inbound"]) if row["inbound_ok"]
                                                                 else style.paint(row["inbound"], "31"))))
        rtt = "   %d ms" % row["rtt"] if isinstance(row["rtt"], (int, float)) else ""
        out += ["", style.section("CARRIERS")]
        up = "   up %g%% last hour" % row["uptime"] if isinstance(row.get("uptime"), (int, float)) else ""
        out.append(style.field("Active", "%s%s%s" % (row["active"], rtt, up)))
        for item in row["standby"] or [{"name": "none", "ok": True, "text": ""}]:
            text = item["text"] if item["ok"] else style.paint(item["text"], "31")
            out.append(style.field("Standby", "%s   %s" % (item["name"], text)))
        pair = next(p for p in data["pairs"] if p["id"] == row["id"])
        health = (pair.get("runtime") or {}).get("health") or {}
        if health:
            seconds = health.get("failover_seconds") or 0
            out.append(style.field("Failover", "check every %ss, switch after ~%s down, policy %s" % (
                health.get("probe_seconds", "?"), ("%d min" % (seconds // 60)) if seconds and seconds % 60 == 0 else "%ss" % seconds,
                health.get("recovery_policy", "?"))))
        out.append(style.field("Last switch", row["last_switch"]))
        if row.get("off_main"):
            if row.get("main_ready"):
                out.append(style.warn("On a standby; main carrier %s is ready again. Return: sudo pronet switch %s"
                                      % (row["main"], row["id"])))
            else:
                out.append(style.dim("    On a standby; main carrier %s is not answering yet." % row["main"]))
        t = row["traffic"]
        out += ["", style.section("TRAFFIC")]
        out.append(style.field("Total", "down %s / up %s" % (t["down_total"], t["up_total"])))
        out.append(style.field("Now", "down %s / up %s Mbps, %s connections" % (
            t["down_now"], t["up_now"], t["connections"] if t["connections"] is not None else "-")))
        if row["events"]:
            out += ["", style.section("RECENT EVENTS")]
            for item in row["events"][-3:]:
                out.append("    %s  %s %s" % (style.dim(item.get("utc", "")[5:16].replace("T", " ")), item.get("event", ""),
                                             style.dim(clean(item.get("detail", ""), 50))))
        if row["problems"]:
            out += ["", style.section("NEEDS ATTENTION")]
            out += ["    " + style.warn(problem) for problem in row["problems"]]
        out += ["", style.field("Tunnel ID", row["id"])]
    if not rows:
        failed = [pair for pair in data.get("pairs", []) if pair.get("state") == "FAILED"]
        if failed:
            latest = failed[0]
            out += ["", "  No active tunnel. A setup attempt failed: " + clean(latest.get("request", {}).get("name", latest["id"]))]
            out.append(style.field("Reason", clean(latest.get("result", {}).get("error", "unknown"))))
            out.append(style.field("Details", "sudo pronet report " + latest["id"] + " --details"))
        else:
            out += ["", "  No tunnel yet. On the Iran server run: sudo pronet  ->  1) New tunnel"]
    out += ["", style.rule()]
    if hub_config():
        out.append("  " + style.dim("Web dashboard: sudo pronet dashboard   |   Details: sudo pronet report --details"))
    for line in out:
        say(line)


def hub_config():
    path = CONFIG / "hub" / "hub.json"
    return read_json(path, {}) if os.access(path, os.R_OK) else {}


def dashboard_url(config=None):
    config = config if config is not None else hub_config()
    if not config.get("url") or not config.get("dashboard", True) or not config.get("dashboard_token"):
        return ""
    return config["url"].rstrip("/") + "/" + config["dashboard_token"] + "/"


def save_hub_config(config):
    """hub.json belongs to the unprivileged hub account; keep it that way."""
    import pwd
    path = CONFIG / "hub" / "hub.json"
    write_json(path, config)
    with contextlib.suppress(KeyError, OSError):
        account = pwd.getpwnam("pronet-fleet-hub")
        os.chown(path, account.pw_uid, account.pw_gid)
    # Restarting the coordinator never touches running tunnels.
    command(["systemctl", "restart", "pronetf-hub.service"], check=False)


def show_dashboard(action=None):
    root_linux()
    config = hub_config()
    if not config:
        raise PronetError("The coordinator (and its dashboard) runs on your Iran server; run this command there.")
    changed = False
    if action == "off":
        config["dashboard"], changed = False, True
    elif action in ("on", None) and (not config.get("dashboard", True) or not config.get("dashboard_token")):
        config["dashboard"] = True
        config.setdefault("dashboard_token", secret()[:32])
        changed = True
    elif action == "new-link":
        config.update(dashboard=True, dashboard_token=secret()[:32])
        changed = True
    elif action not in (None, "on"):
        raise PronetError("Use: sudo pronet dashboard [on|off|new-link]")
    if changed:
        save_hub_config(config)
    style = terminal_style()
    out = style.banner("WEB DASHBOARD", "read-only")
    if not config.get("dashboard", True):
        out += ["", style.field("Status", style.paint("OFF", "31")),
                style.field("Turn on", "sudo pronet dashboard on")]
    else:
        out += ["", style.field("Link", style.paint(dashboard_url(config), "1"), 2, 12), "",
                "  " + style.warn("Keep this link private: the secret part of the address is the login."),
                "  - The browser warns once (self-signed certificate): Advanced -> Proceed.",
                "  - Refreshes every 15 s and adds no work to the tunnel.",
                "", style.section("OPTIONS"),
                style.field("New link", "sudo pronet dashboard new-link   " + style.dim("(old link stops working)"), 4, 12),
                style.field("Turn off", "sudo pronet dashboard off", 4, 12)]
    out += [style.rule()]
    for line in out:
        say(line)


def monitor(watch=False, json_output=False):
    while True:
        data = node_client().call("/v1/overview")
        if json_output:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            if watch and sys.stdout.isatty():
                print("\033[2J\033[H", end="")
            display(data)
        if not watch:
            return
        # Refresh fast while a tunnel is being set up (live progress bars).
        setting_up = any(p.get("state") not in ("ACTIVE", "FAILED", "STOPPED") for p in data.get("pairs", []))
        time.sleep(1 if setting_up else 5)


def show_report(pair_id=None, details=False):
    from .report import final_report, progress_lines
    data = node_client().call("/v1/overview")
    pair = find_pair(data, pair_id)
    if pair is None:
        raise PronetError("No tunnel found.")
    style = terminal_style()
    if pair["state"] in ("ACTIVE", "FAILED", "STOPPED"):
        lines = final_report(pair, data.get("nodes"), style=style, details=details,
                             dashboard=dashboard_url(hub_config() or {}) or None)
    else:
        lines = progress_lines(pair, now=data.get("server_time"), style=style)
    for line in lines:
        say(line)



def run_hub():
    from .controller import Controller
    from .hub import HubServer
    from .store import Store
    config = read_json(CONFIG / "hub" / "hub.json")
    store = Store(config["database"], config["enrollment_key"], config["admin_key"])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config["certificate"], config["private_key"])
    stop = threading.Event()
    token = config.get("dashboard_token") if config.get("dashboard", True) else None
    server = HubServer((config["bind"], config["port"]), store, tls=context, public_url=config["url"], dashboard_token=token)
    controller = Controller(store, stop)
    threading.Thread(target=controller.run, daemon=True, name="controller").start()
    def terminate(*_):
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        server.serve_forever(poll_interval=.5)
    finally:
        stop.set()
        server.server_close()


RESTART_SHORT = 60       # an engine that exits within a minute of starting


def restart_delay(directory, now=None):
    """Extra wait before an engine that keeps exiting starts again.

    Most engines retry inside one process; one that exits when its peer is
    unreachable would otherwise be restarted every few seconds for as long as
    the other server is down (each start runs Python and firewall checks).
    After three quick exits in a row the wait doubles from 5 s up to 60 s; one
    normal run resets it. Works on every systemd version.
    """
    now = time.time() if now is None else now
    path = pathlib.Path(directory) / "engine-starts.json"
    state = read_json(path, {}) if path.exists() else {}
    last = state.get("last") if type(state.get("last")) in (int, float) else None
    streak = state.get("streak", 0) if type(state.get("streak")) is int else 0
    streak = streak + 1 if last is not None and 0 <= now - last < RESTART_SHORT else 0
    delay = 0 if streak < 3 else min(60, 5 * 2 ** (streak - 3))
    with contextlib.suppress(OSError, PronetError):
        write_json(path, {"last": now + delay, "streak": streak})
    return delay


def managed_run(directory, kind):
    root_linux()
    from .runtime import owned_directory
    directory = owned_directory(directory)
    plan = read_json(directory / "plan.json")
    if kind == "engine":
        if plan.get("profile") == "gre":
            from .native_gre import run
            stop = threading.Event()
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, lambda *_: stop.set())
            delay = restart_delay(directory)
            if delay:
                stop.wait(delay)
            if not stop.is_set():
                run(plan, stop)
            return
        if plan.get("profile") == "parsa-spoof":
            from .spoof_wg import run
            stop = threading.Event()
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, lambda *_: stop.set())
            delay = restart_delay(directory)
            if delay: stop.wait(delay)
            if not stop.is_set(): run(plan, directory, stop)
            return
        recipe = read_json(directory / "launch.json")
        args = recipe["command"]
        binary = pathlib.Path(args[0]).resolve()
        if not binary.is_relative_to((ROOT / "engines").resolve()):
            raise PronetError("Engine executable is outside managed storage")
        delay = restart_delay(directory)
        if delay:
            time.sleep(delay)
        env = os.environ.copy()
        for key, value in recipe.get("environment", {}).items():
            if key not in ("AUTH", "SSL_CERT_FILE", "SSL_CERT_DIR", "WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX", "RUST_LOG", "TOKIO_WORKER_THREADS") or not isinstance(value, str) or "\n" in value:
                raise PronetError("Invalid engine environment")
            env[key] = value
        os.execve(str(binary), args, env)
    elif kind == "echo":
        from .wire import ProbeServer, Gateway, bridge_server
        addresses = [("127.0.0.1", plan["echo_port"])]
        if PROFILES[plan["profile"]]["kind"] == "l3":
            addresses.append((tunnel_ips(plan)[0 if plan["role"] == "iran" else 1], plan["echo_port"]))
        servers = []
        for address in addresses:
            server = ProbeServer(address, plan["token"], freebind=address[0] != "127.0.0.1")
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        async def auxiliary():
            stop = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGTERM, signal.SIGINT): loop.add_signal_handler(sig, stop.set)
            bridges, frontend = [], None
            udp=None
            if plan.get('gaming'):
                from .gaming import DatagramRelay,listen
                own,peer=tunnel_ips(plan) if plan['role']=='iran' else tuple(reversed(tunnel_ips(plan)))
                from .runtime import udp_listeners
                rows=udp_listeners() if plan['role']=='foreign' else []
                targets={str(port):plan['bind_ip'] if any(r['port']==port and r['address']==plan['bind_ip'] for r in rows) else '127.0.0.1' for port in inbound_ports(plan)}
                udp=await listen((own,plan['data_port']),DatagramRelay(plan['token'],foreign=True,target=targets,
                    ports=inbound_ports(plan) if plan['role']=='foreign' else (),peer=peer),freebind=True)
            if PROFILES[plan["profile"]]["kind"] != "l3":
                if plan["role"] == "foreign":
                    extra = tuple(inbound_ports(plan)[1:])
                    for source, target, allowed in ((plan["bridge_health_port"], plan["echo_port"], ()),
                                                    (plan["bridge_data_port"], plan["inbound_port"], extra)):
                        async def handler(reader, writer, target=target, allowed=allowed):
                            await bridge_server(reader, writer, plan["token"], ("127.0.0.1", target), allowed)
                        bridges.append(await asyncio.start_server(handler, "127.0.0.1", source, backlog=4096))
                else:
                    path = directory / "probe-front.json"
                    write_json(path, {"bind_ip": "127.0.0.1", "port": plan["probe_front_port"], "mode": "framed",
                                      "frame_key": plan["token"], "active_backend": ["127.0.0.1", plan["health_port"]]})
                    frontend = Gateway(path, directory / "probe-stats.json")
                    await frontend.start()
            await stop.wait()
            for server in bridges:
                server.close()
                # Python 3.12+ waits for live sessions here; do not block stop.
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(server.wait_closed(), 3)
            if frontend: await frontend.close()
            if udp: udp.close()
        asyncio.run(auxiliary())
        for server in servers:
            server.shutdown()
            server.server_close()
    else:
        raise PronetError("Invalid managed resource")


def managed_gateway(pair_id):
    root_linux()
    identifier(pair_id)
    from .wire import Gateway
    async def run():
        directory = ROOT / "pairs" / pair_id
        config=read_json(directory/'gateway.json')
        if config.get('gaming'):
            from .gaming import Gateway as UDPGateway
            gateway=UDPGateway(directory/'gateway.json',directory/'traffic.json')
        else:
            gateway = Gateway(directory / "gateway.json", directory / "traffic.json")
        await gateway.start()
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        try:
            if config.get('gaming'):
                waiter=asyncio.create_task(stop.wait())
                done,_=await asyncio.wait([waiter,gateway.task],return_when=asyncio.FIRST_COMPLETED)
                if gateway.task in done:gateway.task.result()
                waiter.cancel()
            else:await stop.wait()
        finally:await gateway.close()
    asyncio.run(run())


def repair(pair_id, restart=False):
    root_linux()
    identifier(pair_id)
    from .runtime import Runtime, is_active, service, unit_name
    runtime = Runtime(node_config())
    directory = ROOT / "pairs" / pair_id
    if (directory / "stopped.json").exists():
        raise PronetError("This tunnel was removed from this server; create a new one.")
    with lock(ROOT / "host-operation.lock"):
        selected = read_json(directory / "selection.json")
        for profile in selected["profiles"]:
            plan = runtime.validate(read_json(directory / profile / "plan.json"))
            for kind in ("engine", "echo"):
                name = unit_name(pair_id, profile, kind, plan["role"])
                if restart or not is_active(name):
                    service(name, "reset-failed")
                    service(name, "restart" if restart else "start")
        if runtime.identity["role"] == "iran" and (directory / "active.json").exists():
            gateway = "pronetf-" + pair_id + "-gateway.service"
            if restart or not is_active(gateway):
                service(gateway, "reset-failed")
                service(gateway, "restart" if restart else "start")
        selected.update(auto_paused=False, failures=0, switches=[])
        write_json(directory / "selection.json", selected)
    print("Done. Only this tunnel's services on this server were touched.")


def enable_traffic(quiet=False):
    root_linux()
    from .runtime import write_unit, unit_path, service
    name = "pronetf-counters.service"
    write_unit(name, "counters", ["/usr/bin/python3", str(APP / "main.py"), "managed-counters"], ROOT, temporary=False)
    path = unit_path(name)
    text = path.read_text().replace("Type=simple\n", "Type=oneshot\nRemainAfterExit=yes\n").replace("Restart=always\n", "Restart=no\n")
    if "Restart=no\n" not in text:
        raise PronetError("Counter unit template changed; refusing an invalid oneshot unit")
    atomic_write(path, text, 0o644)
    command(["systemctl", "daemon-reload"])
    service(name, "enable")
    service(name, "reset-failed")
    service(name, "restart")  # Adds missing counters without resetting existing ones.
    if not quiet:
        print("Per-IP traffic counters enabled; filter and NAT rules were not changed.")



def health_summary():
    from .runtime import failover_probes, probe_seconds
    probes = failover_probes()
    return ("Health probe every %d s. Switch to standby after %d failed probes in a row "
            "(primary fully down about %d-%d s) and only if the standby answers."
            % (probe_seconds(), probes, (probes - 1) * probe_seconds(), probes * probe_seconds()))


def save_setting(key, value, low, high):
    from .runtime import SETTINGS
    root_linux()
    if not low <= value <= high:
        raise PronetError("Choose %d to %d seconds." % (low, high))
    settings = read_json(SETTINGS, {})
    settings[key] = value
    write_json(SETTINGS, settings)


def failover_delay(seconds=None):
    if seconds is not None:
        save_setting("failover_seconds", seconds, 10, 1800)
    say(health_summary())
    if seconds is not None:
        say("Saved. Applies within one probe cycle; no restart needed. Run it on the Iran server.")


def probe_interval(seconds=None):
    if seconds is not None:
        save_setting("probe_seconds", seconds, 5, 300)
    say(health_summary())
    if seconds is not None:
        say("Saved. Applies after the current cycle; no restart needed. Run it on the Iran server.")


def notify_command(option="status", token=None, chat=None, lang=None):
    """Telegram alerts. Configured and sent on the FOREIGN server."""
    from . import notify
    root_linux()
    if node_config().get("role") != "foreign":
        say("Telegram is filtered in Iran: alerts are sent from the FOREIGN server.")
        say("Run on the foreign server:  sudo pronet notify telegram")
        return
    config = notify.load_config()
    if option == "telegram":
        if not token:
            say("1) In Telegram, open @BotFather, send /newbot and copy the bot token.")
            say("2) Send any message to your new bot (or add it as admin to a channel).")
            import getpass
            token = getpass.getpass("Bot token (hidden): ")
        if not chat:
            say("Chat id: your numeric id (ask @userinfobot) or a channel name like @mychannel.")
            chat = input("Chat id: ").strip()
        if lang is None:
            lang = (input("Message language [en/fa] (Enter = en): ").strip().lower() or "en")
        notify.save_config(token, chat, lang if lang in notify.TEXT else "en")
        config = notify.load_config()
        option = "test"
    if option in ("on", "off"):
        if not config:
            raise PronetError("Telegram is not set up yet: sudo pronet notify telegram")
        stored = read_json(notify.NOTIFY_FILE, {})
        stored["enabled"] = option == "on"
        write_json(notify.NOTIFY_FILE, stored)
        say("Telegram alerts " + ("enabled" if option == "on" else "disabled") + ". No restart needed.")
        return
    if option == "test":
        if not config:
            raise PronetError("Telegram is not set up yet: sudo pronet notify telegram")
        notify.send_telegram(config, notify.render({"kind": "TEST", "detail": node_config().get("name", "foreign")},
                                                   config["lang"]))
        say("Test message sent. Alerts are active (no restart needed).")
        return
    if not config:
        say("Telegram alerts: not set up.  Set up: sudo pronet notify telegram")
        return
    say("Telegram alerts: " + ("ON" if config["enabled"] else "OFF") + "   chat " + config["chat_id"]
        + "   language " + config["lang"] + "   token ****" + config["token"][-4:])
    say("Sent for: tunnel down / restored, carrier switch, unstable carrier, standby replaced,")
    say("re-test, a server that stops reporting, and the Iran server unreachable (5+ min).")


def switch_carrier(pair_id=None, profile=None):
    """Operator switch on the Iran server: back to the main carrier by default."""
    root_linux()
    from .runtime import Runtime
    if node_config().get("role") != "iran":
        raise PronetError("Run this on the Iran server")
    if pair_id is None:
        active = [path.parent.name for path in sorted((ROOT / "pairs").glob("*/active.json"))
                  if not (path.parent / "stopped.json").exists()]
        if len(active) != 1:
            raise PronetError("Several tunnels exist; name one: sudo pronet switch ID [CARRIER]  (IDs: sudo pronet status)"
                              if active else "No active tunnel on this server")
        pair_id = active[0]
    identifier(pair_id)
    if profile is not None and profile not in PROFILES:
        raise PronetError("Unknown carrier %s (list: sudo pronet profiles)" % profile)
    with lock(ROOT / "host-operation.lock"):
        result = Runtime(node_config()).manual_switch(pair_id, profile)
    if not result["switched"]:
        say("%s is already the active carrier; nothing changed." % result["active"])
        return
    say("Switched: new connections now use %s (rtt %s ms)." % (result["active"], result["rtt_ms"]))
    say("Connections already open stay on the previous carrier until they end.")
    say("Automatic failover stays on; this switch does not use its 30-minute budget.")


def set_recovery_policy(policy=None):
    from .runtime import SETTINGS, recovery_policy
    if policy is not None:
        root_linux()
        if node_config()["role"] != "iran":
            raise PronetError("Set recovery policy on the Iran server")
        if policy not in ("stable", "explore"):
            raise PronetError("Recovery policy must be stable or explore")
        settings = read_json(SETTINGS, {})
        settings["recovery_policy"] = policy
        write_json(SETTINGS, settings)
    say("Recovery policy: " + recovery_policy())
    say("stable: fail over only between committed carriers; new carrier exploration requires operator opt-in.")
    say("explore: automatic new-carrier recovery, limited to one episode / 30 minutes.")
    say("An echo OK confirms the carrier probe only, not application throughput.")




def memory_command(action='status'):
    root_linux()
    if node_config()['role']!='iran': raise PronetError('Manage carrier memory on Iran')
    data=node_client().call('/v1/memory',{'action':action})
    say('Carrier memory: %d summary records, %d / %d bytes; coordinator-local, no background probes' %
        (data['records'],data['bytes'],data['max_bytes']))
    if action=='clear': say('Carrier statistics cleared. Active tunnels were not changed.')
    for row in data['profiles']:
        say('  %-20s %s  %d/%d successful independent observations, %d routes, %d days' %
            (row['profile']+' ['+row.get('mode','normal')+']','OUT OF ORDINARY TESTS' if row['retired'] else 'learning',row['success'],row['n'],
             row['routes_observed_at_least'],row['days_observed']))


def offer_advanced(pair):
    result=pair.get('result',{}) if pair else {}
    if not (result.get('advanced_available') and result.get('cleanup_confirmed')): return
    say('No ordinary carrier qualified. Advanced testing ignores memory and includes retired and emergency carriers.')
    if not sys.stdin.isatty():
        say('To request it explicitly: sudo pronet advanced ' + pair['id'])
        return
    menu_options([('1','Run advanced test'),('0','Finish')])
    if ask('Select','0')=='1': advanced_test(pair['id'])


def advanced_test(pair_id=None, iran_source=None, foreign_source=None):
    root_linux()
    config=node_config()
    if config['role']!='iran': raise PronetError('Start advanced tests on Iran')
    if pair_id is None:
        data=node_client().call('/v1/overview')
        pair=next((p for p in data.get('pairs',[]) if p['state']=='FAILED' and p.get('result',{}).get('advanced_available') and p.get('result',{}).get('cleanup_confirmed')),None)
        if not pair: raise PronetError('No cleaned-up failed ordinary qualification is available for advanced retry')
        pair_id=pair['id']
    known=node_client().call('/v1/overview')
    selected=next((p for p in known.get('pairs',[]) if p['id']==pair_id),{})
    gaming=selected.get('request',{}).get('gaming',False)
    if gaming:
        created=node_client().call('/v1/advanced',{'pair_id':pair_id,'spoof':{}})
        say('Gaming advanced retry: all supported gaming L3 carriers; memory exclusions bypassed.')
        return follow(created['pair_id'])
    sources=dict(config.get('spoof_sources',{}))
    if iran_source or foreign_source: sources={'iran':iran_source,'foreign':foreign_source}
    if not sources and sys.stdin.isatty():
        say('Spoof needs both sender source addresses. Leave blank to skip only Spoof; all other supported carriers are tested.')
        iran=ask('Iran sender spoof source (Enter to skip)','')
        if iran: sources={'iran':iran,'foreign':ask('Foreign sender spoof source','')}
    from .model import validate_spoof
    sources=validate_spoof(sources)
    if not sources: say('Spoof omitted: sender source addresses were not provided.')
    created=node_client().call('/v1/advanced',{'pair_id':pair_id,'spoof':sources})
    say('Advanced test explicitly requested. Retired carriers and all supported ordinary protocols are included.')
    return follow(created['pair_id'])


def emergency_sources(iran_source=None, foreign_source=None):
    root_linux()
    config = node_config()
    if config["role"] != "iran": raise PronetError("Start emergency tests on Iran")
    saved = config.get("spoof_sources", {})
    from .model import validate_spoof
    sources = validate_spoof({"iran": iran_source or saved.get("iran"), "foreign": foreign_source or saved.get("foreign")})
    return sources


def emergency_menu():
    root_linux()
    if node_config()["role"] != "iran": raise PronetError("Start emergency tests on Iran")
    say("Emergency tunnels - manual only; excluded from normal and automatic tests")
    menu_options([('1','Test Spoof only, then clean up'),('2','Test and activate an emergency Spoof tunnel'),('0','Back')])
    say("These use a separate pairing. A server already in use must not be stopped automatically.")
    choice = ask("Select", "0")
    if choice == "0": return
    if choice not in ("1", "2"): raise PronetError("Choose 0, 1 or 2")
    config = node_config()
    saved = config.get("spoof_sources", {})
    say("The source addresses below are spoof sources, not the real server IPs.")
    iran = ask("Source address used by Iran sender", saved.get("iran", ""))
    foreign = ask("Source address used by foreign sender", saved.get("foreign", ""))
    sources = emergency_sources(iran, foreign)
    ports = parse_ports(ask("Client port(s)", "2053"))
    new_tunnel(ports, name="emergency-" + time.strftime("%m%d-%H%M"), profiles=list(EMERGENCY_PROFILES),
               standby=False, spoof=sources, emergency=True, test_only=choice == "1")


def menu_options(options):
    for key,label in options:
        say('  %2s) %s' % (key,label))


def menu_header():
    config=read_json(CONFIG/'node.json',{})
    say('')
    say('=' * 64)
    say('  PRONET FLEET  %s' % __version__)
    say('  Automatic Iran <-> foreign tunnels')
    say('-' * 64)
    say('  Server : %s' % config.get('name',socket.gethostname()))
    say('  Role   : %s' % config.get('role','not enrolled').upper())
    if config.get('public_ip'): say('  IPv4   : %s' % config['public_ip'])
    # Local state only: opening a menu never waits for a coordinator/network call.
    active=sum(1 for path in (ROOT/'pairs').glob('*/active.json') if not (path.parent/'stopped.json').exists())
    say('  Local  : %d installed tunnel(s)' % active)
    say('  Modes  : Standard TCP | Gaming UDP | Emergency (manual)')
    say('=' * 64)
    say('')


def wizard():
    menu_header()
    if not (CONFIG / "node.json").exists():
        say("Where is THIS server?")
        say("  1) Iran      (always start here)")
        say("  2) Foreign   (needs the command printed by your Iran server)")
        say("  3) Advanced  (coordinator only / existing bootstrap file)")
        say("  4) Gaming tunnel (Iran; WireGuard UDP)")
        say("  0) Exit")
        choice = ask("Select", "1")
        if choice == "0": return
        if choice == "1":
            setup_iran()
        elif choice == "2":
            text = input("Paste the command from your Iran server (Enter if you have not set up Iran yet): ").strip()
            if not text:
                raise PronetError(START_ON_IRAN)
            join(text)
        elif choice == "4":
            setup_iran(gaming=True)
        elif choice == "3":
            advanced_menu()
        else:
            raise PronetError("Choose 0, 1, 2, 3 or 4.")
        return
    config = node_config()
    if config["role"] == "iran":
        say('  CREATE A TUNNEL')
        menu_options([('1','New standard tunnel - TCP services'),('2','Gaming tunnel - WireGuard / UDP')])
        say('')
        say('  STATUS AND MANAGEMENT')
        menu_options([('3','Live status'),('4','Last setup report'),('5','Web dashboard link'),
                      ('6','Automatic recovery policy'),('7','Return a tunnel to its main carrier')])
        say('')
        say('  TESTING AND DIAGNOSTICS')
        menu_options([('8','Emergency tunnels - manual only'),('9','Carrier memory - compact statistics'),
                      ('10','Advanced retry - after failed ordinary testing'),('0','Exit')])
        say('')
        choice = ask('Select','1')
        if choice == '1': setup_iran()
        elif choice == '2': setup_iran(gaming=True)
        elif choice == '3': monitor(watch=True)
        elif choice == '4': show_report()
        elif choice == '5': show_dashboard()
        elif choice == '6':
            set_recovery_policy()
            menu_options([('1','Stable - keep known paths'),('2','Explore - allow automatic tests during sustained outages'),('0','Back')])
            option=ask('Recovery policy','0')
            if option in ('1','2'):set_recovery_policy('stable' if option=='1' else 'explore')
            elif option!='0':raise PronetError('Choose 0, 1 or 2')
        elif choice == '7': switch_carrier(ask('Tunnel ID (Enter if there is only one)','') or None)
        elif choice == '8': emergency_menu()
        elif choice == '9': memory_command('status')
        elif choice == '10': advanced_test()
        elif choice == '0': return
        else: raise PronetError('Choose one of the listed menu numbers')

    else:
        menu_options([('1','Join a tunnel - paste the command from Iran'),('2','Live status'),('3','Telegram alerts'),('0','Exit')])
        choice = ask("Select", "1")
        if choice == "2":
            monitor(watch=True)
        elif choice == "3":
            notify_command("status")
            from .notify import load_config
            if not load_config() or ask("Set up again? (y/N)", "n").lower().startswith("y"):
                notify_command("telegram")
        elif choice == '0': return
        elif choice == '1':
            text = input("Paste the command from your Iran server: ").strip()
            if not text:
                raise PronetError(START_ON_IRAN)
            join(text)


UNIT_DIR = pathlib.Path("/etc/systemd/system")
CONTROL_DIR = pathlib.Path("/etc/systemd/system.control")
OPT_ROOT = pathlib.Path("/opt/pronet-fleet")
WRAPPER = pathlib.Path("/usr/local/bin/pronet")
UNIT_MARKER = "# Pronet Fleet owner="


def uninstall(confirmed=False):
    """Remove everything Pronet Fleet created on THIS server.

    Only resources Pronet owns are touched: pronetf-* units carrying the owner
    marker, firewall rules tagged "pronetf:", nft tables named pronetf_*, and
    its own directories. Panels, other tunnels and the operator's firewall
    policy are left alone.
    """
    root_linux()
    units = sorted(path for path in UNIT_DIR.glob("pronetf-*.service")
                   if path.is_file() and not path.is_symlink() and path.read_text().startswith(UNIT_MARKER))
    say("This removes Pronet Fleet completely from THIS server:")
    say("  %d services (tunnels, agent, coordinator), their firewall rules and traffic counters," % len(units))
    say("  /opt/pronet-fleet, /etc/pronet-fleet, /var/lib/pronet-fleet and the pronet command.")
    say("Tunnels using this server stop now. Panels and other tunnels are not touched.")
    say("Run it on the other server of each tunnel as well.")
    if not confirmed and ask("Type UNINSTALL to continue") != "UNINSTALL":
        say("Cancelled. Nothing was changed.")
        return False
    problems = []
    def attempt(args):
        result = command(args, timeout=60, check=False)
        if result.returncode:
            problems.append(" ".join(args[:3]) + ": " + clean(result.stderr or result.stdout or "failed", 120))
    for path in units:
        # Stopping runs each unit's ExecStopPost, which removes its own firewall rules.
        attempt(["systemctl", "disable", "--now", path.name])
    stopped = True
    for path in units:
        shown = command(["systemctl", "show", path.name, "--property=ActiveState,MainPID,ControlPID"], timeout=10, check=False)
        props = dict(line.split("=", 1) for line in shown.stdout.splitlines() if "=" in line)
        if (shown.returncode or props.get("ActiveState") not in ("inactive", "failed")
                or props.get("MainPID") != "0" or props.get("ControlPID") != "0"):
            problems.append(path.name + ": stop unconfirmed; ownership and code retained")
            stopped = False
    if stopped:
        from .runtime import managed_firewall
        for path in (ROOT / "pairs").glob("*/*/plan.json"):
            try:
                managed_firewall(path.parent, "engine", "down")
            except PronetError as error:
                problems.append(clean(error))
                stopped = False
    if not stopped:
        say("Uninstall did not complete. Management files were retained for a safe retry:")
        for problem in problems: say("  " + problem)
        return False
    for path in units:
        with contextlib.suppress(OSError):
            path.unlink()
    for base in (UNIT_DIR, CONTROL_DIR):
        for path in base.glob("pronetf-*.service.d"):
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path, ignore_errors=True)
    command(["systemctl", "daemon-reload"], check=False)
    if units:
        command(["systemctl", "reset-failed"] + [path.name for path in units], check=False)
    iptables = shutil.which("iptables")
    if iptables:
        import shlex
        for table in ("filter", "raw", "mangle"):
            listing = command([iptables, "-w", "5", "-t", table, "-S"], check=False).stdout
            for line in listing.splitlines():
                parts = shlex.split(line)
                if (len(parts) > 2 and parts[0] == "-A" and "--comment" in parts
                        and parts[parts.index("--comment") + 1].startswith("pronetf:")):
                    attempt([iptables, "-w", "5", "-t", table, "-D"] + parts[1:])
    if shutil.which("nft"):
        for line in command(["nft", "list", "tables"], check=False).stdout.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[0] == "table" and parts[2].startswith("pronetf_"):
                attempt(["nft", "delete", "table", parts[1], parts[2]])
    for directory in (ROOT, CONFIG):
        if directory.is_dir() and not directory.is_symlink():
            shutil.rmtree(directory, ignore_errors=True)
    if WRAPPER.is_file() and not WRAPPER.is_symlink() and WRAPPER.read_text(errors="replace").startswith("#!/bin/sh\n# Managed by Pronet Fleet\n"):
        WRAPPER.unlink()
    # Last: this command itself runs from here.
    if OPT_ROOT.is_dir() and not OPT_ROOT.is_symlink():
        shutil.rmtree(OPT_ROOT, ignore_errors=True)
    say("")
    if problems:
        say("Pronet Fleet was removed, with warnings:")
        for line in problems:
            say("  " + line)
    else:
        say("Pronet Fleet was removed from this server.")
    say("Install again: curl -fsSL %s | sudo bash" % INSTALL_URL)
    return True


def advanced_menu():
    say('Advanced setup')
    menu_options([('1','Coordinator only on this server'),('2','Register with a bootstrap file (Iran or foreign)'),('0','Back')])
    choice = ask('Select','0')
    if choice == "0": return
    if choice == "1":
        url = ask("Coordinator HTTPS address", "https://%s:9443" % (guess_public_ip([]) or "SERVER_IP"))
        init_hub(argparse.Namespace(url=url, bind="0.0.0.0", cert=None, key=None, ca=None))
    elif choice == "2":
        menu_options([('1','Iran'),('2','Foreign')])
        role = {'1':'iran','2':'foreign'}.get(ask('Server role','1'))
        if not role:
            raise PronetError("Choose 1 or 2.")
        path = ask("Bootstrap file", "/root/pronet-bootstrap.json")
        public = ask("Public IPv4", guess_public_ip([]))
        bind = ask("Local IPv4 to bind", public)
        numbers = parse_ports(ask("Client port(s), e.g. 2053 or 2053,2083", "2053"))
        number = numbers if len(numbers) > 1 else numbers[0]
        register_node(role, read_json(path), socket.gethostname(), public, bind, number)
        say("Registered as %s." % role.upper())
        if role == "iran":
            new_tunnel(number)
        else:
            join(ask("4-digit code from Iran"))
    else:
        raise PronetError("Choose 0, 1 or 2.")


def main():
    parser = argparse.ArgumentParser(prog="pronet", description="Pronet Fleet: Iran <-> foreign tunnels with automatic carrier selection")
    parser.add_argument("--version", action="version", version=__version__)
    subs = parser.add_subparsers(dest="action")
    subs.add_parser("menu", help="interactive menu (default)")
    iran = subs.add_parser("setup-iran", help="non-interactive Iran setup (coordinator + registration + tunnel)")
    iran.add_argument("--public-ip"); iran.add_argument("--bind-ip"); iran.add_argument("--port", type=ports_argument, default=[2053])
    iran.add_argument("--name"); iran.add_argument("--tunnel-name"); iran.add_argument("--sni", default="")
    iran.add_argument("--quality", choices=["quick", "balanced", "thorough"], default="balanced")
    iran.add_argument("--no-wait", action="store_true")
    iran.add_argument("--gaming", action="store_true")
    subs.add_parser("gaming",help="Iran: gaming UDP tunnel for WireGuard")
    joining = subs.add_parser("join", help="foreign: join with the command/token from Iran, or a 4-digit code")
    joining.add_argument("token"); joining.add_argument("--public-ip"); joining.add_argument("--name")
    setup = subs.add_parser("pair", help="Iran: create another tunnel")
    setup.add_argument("--name"); setup.add_argument("--port", type=ports_argument)
    setup.add_argument("--profiles"); setup.add_argument("--no-standby", action="store_true")
    setup.add_argument("--direction", choices=["iran-dials", "foreign-dials"], default="iran-dials")
    setup.add_argument("--sni", default="")
    setup.add_argument("--spoof-iran", help="source IPv4 used by the Iran spoof sender")
    setup.add_argument("--spoof-foreign", help="source IPv4 used by the foreign spoof sender")
    setup.add_argument("--quality", choices=["quick", "balanced", "thorough"], default="balanced")
    setup.add_argument("--no-wait", action="store_true")
    setup.add_argument("--gaming",action="store_true")
    setup.add_argument("--full-test", action="store_true", help="test all selected ordinary carriers without using learned exclusions")
    emergency = subs.add_parser("emergency", help="separate manual emergency tunnel tests and setup")
    emergency.add_argument("--test-only", action="store_true")
    emergency.add_argument("--activate", action="store_true")
    emergency.add_argument("--port", type=ports_argument)
    emergency.add_argument("--name")
    emergency.add_argument("--spoof-iran")
    emergency.add_argument("--spoof-foreign")
    emergency.add_argument("--no-wait", action="store_true")
    advanced = subs.add_parser('advanced', help='explicitly retry every supported carrier after ordinary qualification failed')
    advanced.add_argument('pair_id', nargs='?')
    advanced.add_argument('--spoof-iran'); advanced.add_argument('--spoof-foreign')
    memory = subs.add_parser('memory', help='compact coordinator carrier statistics')
    memory.add_argument('action', nargs='?', choices=['status','clear'], default='status')
    report = subs.add_parser("report", help="final setup report"); report.add_argument("pair_id", nargs="?")
    report.add_argument("--details", action="store_true", help="also list every carrier with its result")
    policy = subs.add_parser("recovery-policy", help="stable (default) or opt-in automatic carrier exploration")
    policy.add_argument("policy", choices=["stable", "explore"], nargs="?")
    board = subs.add_parser("dashboard", help="Iran: web dashboard link (on|off|new-link)")
    board.add_argument("option", nargs="?", choices=["on", "off", "new-link"])
    delay = subs.add_parser("failover-delay", help="Iran: seconds of total primary outage before switching to standby")
    delay.add_argument("seconds", nargs="?", type=int)
    interval = subs.add_parser("probe-interval", help="Iran: seconds between health probes of each path")
    interval.add_argument("seconds", nargs="?", type=int)
    spoof = subs.add_parser("spoof-sources", help="Iran: configure the source IPv4 used by each spoof sender")
    spoof.add_argument("iran_source"); spoof.add_argument("foreign_source")
    subs.add_parser("status"); subs.add_parser("watch"); subs.add_parser("json")
    switch = subs.add_parser("switch", help="Iran: move new connections back to the main carrier (or to CARRIER)")
    switch.add_argument("pair_id", nargs="?"); switch.add_argument("profile", nargs="?")
    alerts = subs.add_parser("notify", help="foreign: Telegram alerts (telegram|test|on|off|status)")
    alerts.add_argument("option", nargs="?", default="status", choices=["telegram", "test", "on", "off", "status"])
    alerts.add_argument("--token", help="bot token (prompted, hidden, when omitted)")
    alerts.add_argument("--chat", help="chat id or @channel")
    alerts.add_argument("--lang", choices=["en", "fa"])
    remove_all = subs.add_parser("uninstall", help="remove Pronet Fleet completely from this server")
    remove_all.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    subs.add_parser("doctor"); subs.add_parser("profiles")
    hub = subs.add_parser("hub-init", help="advanced: coordinator only")
    hub.add_argument("--url", required=True)
    hub.add_argument("--bind", default="0.0.0.0")
    hub.add_argument("--cert"); hub.add_argument("--key"); hub.add_argument("--ca")
    node = subs.add_parser("node-init", help="advanced: register with a bootstrap file")
    node.add_argument("--role", choices=["iran", "foreign"], required=True)
    node.add_argument("--bootstrap", required=True); node.add_argument("--name", required=True)
    node.add_argument("--public-ip", required=True); node.add_argument("--bind-ip", required=True)
    node.add_argument("--port", type=ports_argument, default=[2053])
    subs.add_parser("hub-run"); subs.add_parser("agent")
    subs.add_parser("traffic-enable"); subs.add_parser("managed-counters")
    for name in ("repair", "restart", "remove", "remove-local", "logs"):
        item = subs.add_parser(name); item.add_argument("pair_id")
    managed = subs.add_parser("managed-run"); managed.add_argument("directory"); managed.add_argument("kind", choices=["engine", "echo"])
    gateway = subs.add_parser("managed-gateway"); gateway.add_argument("pair_id")
    firewall = subs.add_parser("managed-firewall"); firewall.add_argument("directory"); firewall.add_argument("kind", choices=["engine", "echo", "gateway"]); firewall.add_argument("operation", choices=["up", "down"])
    args = parser.parse_args()
    try:
        if args.action in (None, "menu"):
            wizard()
        elif args.action == "setup-iran": setup_iran(args, interactive=False)
        elif args.action == "join": join(args.token, args.public_ip, args.name)
        elif args.action == "pair":
            from .gaming import GAMING_PROFILES
            profiles = list(GAMING_PROFILES if args.gaming else NORMAL_PROFILES) if args.profiles == "all" else args.profiles.split(",") if args.profiles else None
            new_tunnel(args.port, args.name, args.quality, args.sni, profiles, not args.no_standby, not args.no_wait, args.direction,
                       {"iran": args.spoof_iran, "foreign": args.spoof_foreign} if args.spoof_iran or args.spoof_foreign else None, full_test=args.full_test, gaming=args.gaming)
        elif args.action == "report": show_report(args.pair_id, args.details)
        elif args.action == "recovery-policy": set_recovery_policy(args.policy)
        elif args.action == "failover-delay": failover_delay(args.seconds)
        elif args.action == "dashboard": show_dashboard(args.option)
        elif args.action == "gaming": setup_iran(gaming=True)
        elif args.action == "probe-interval": probe_interval(args.seconds)
        elif args.action == "hub-init": init_hub(args)
        elif args.action == "hub-run": run_hub()
        elif args.action == "node-init": init_node(args)
        elif args.action == "agent":
            root_linux()
            from .agent import Agent
            agent = Agent(node_config())
            signal.signal(signal.SIGTERM, lambda *_: agent.stop.set())
            signal.signal(signal.SIGINT, lambda *_: agent.stop.set())
            agent.run()
        elif args.action in ("status", "watch", "json"): monitor(args.action == "watch", args.action == "json")
        elif args.action == "spoof-sources":
            root_linux()
            config = node_config()
            if config["role"] != "iran": raise PronetError("Configure spoof sources on Iran")
            from .model import validate_spoof
            config["spoof_sources"] = validate_spoof({"iran": args.iran_source, "foreign": args.foreign_source})
            write_json(CONFIG / "node.json", config)
            say("Spoof sources saved for NEW tunnels. Existing tunnels are unchanged.")
        elif args.action == 'advanced': advanced_test(args.pair_id,args.spoof_iran,args.spoof_foreign)
        elif args.action == 'memory': memory_command(args.action)
        elif args.action == "emergency":
            if args.test_only and args.activate: raise PronetError("Choose test-only or activate")
            if args.test_only or args.activate:
                sources = emergency_sources(args.spoof_iran, args.spoof_foreign)
                new_tunnel(args.port, args.name, profiles=list(EMERGENCY_PROFILES), standby=False,
                           wait=not args.no_wait, spoof=sources, emergency=True, test_only=args.test_only)
            else:
                emergency_menu()
        elif args.action == "profiles":
            from .report import describe
            for name, spec in PROFILES.items(): print("%-20s %s%s" % (name, describe(name), " [EMERGENCY: manual only]" if spec.get("emergency") else ""))
        elif args.action == "traffic-enable": enable_traffic()
        elif args.action == "managed-counters":
            root_linux()
            from .accounting import enable
            enable(node_config()["node_id"])
        elif args.action == "switch": switch_carrier(args.pair_id, args.profile)
        elif args.action == "notify": notify_command(args.option, args.token, args.chat, args.lang)
        elif args.action == "uninstall": uninstall(args.yes)
        elif args.action == "doctor":
            from .runtime import inventory
            root_linux()
            print(json.dumps(inventory(), ensure_ascii=False, indent=2))
        elif args.action in ("repair", "restart"): repair(args.pair_id, args.action == "restart")
        elif args.action == "remove-local":
            root_linux()
            from .runtime import Runtime
            with lock(ROOT / "host-operation.lock"):
                print(json.dumps(Runtime(node_config()).cleanup(args.pair_id)))
        elif args.action == "remove":
            identifier(args.pair_id)
            result = node_client().call("/v1/stop", {"pair_id": args.pair_id})
            print("Stop requested on both servers:", result["state"])
            print("Confirm with: sudo pronet status")
        elif args.action == "logs":
            identifier(args.pair_id)
            path = ROOT / "pairs" / args.pair_id / "events.jsonl"
            if path.exists():
                for line in path.read_text().splitlines()[-40:]: print(clean(line, 1000))
            command_result = command(["journalctl", "--no-pager", "-n", "50", "-o", "cat", "-u", "pronetf-" + args.pair_id + "-*.service"], check=False)
            for line in command_result.stdout.splitlines(): print(clean(line, 1000))
        elif args.action == "managed-run": managed_run(args.directory, args.kind)
        elif args.action == "managed-gateway": managed_gateway(args.pair_id)
        elif args.action == "managed-firewall":
            root_linux()
            from .runtime import managed_firewall
            managed_firewall(args.directory, args.kind, args.operation)
    except KeyboardInterrupt:
        print("\nStopped. Tunnel services keep running.")
    except (PronetError, OSError, ValueError, KeyError) as error:
        print("Pronet: " + clean(error), file=sys.stderr)
        raise SystemExit(1)
