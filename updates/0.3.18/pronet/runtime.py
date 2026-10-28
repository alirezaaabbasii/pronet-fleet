"""Linux operations confined to resources owned by this installation."""
from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import pathlib
import platform
import re
import secrets
import shutil
import shlex
import socket
import time

from . import engines
from .common import (APP, CONFIG, ROOT, PronetError, atomic_write, clean, command, inbound_ports,
                     event, identifier, lock, read_json, utc, write_json)
from .model import PROFILES, iface, tunnel_ips, validate_profile
from .wire import DEFAULT_CONNECTION_LIMIT, LinkLock, benchmark, echo, tcp_state, tls_state


MAX_BATCH = 8
MANUAL_SWITCH_GAP = 30     # seconds between two operator switches of one tunnel
MAX_SELECTED = 3           # primary + two warm standbys
REACH_WAIT = 20
DEFAULT_PROBE_SECONDS = 60       # one health probe of each path per minute
DEFAULT_FAILOVER_SECONDS = 180   # primary fully down this long before switching (3 failed checks)
REARM_SECONDS = 120              # primary healthy this long before failover re-arms
SETTINGS = CONFIG / "settings.json"


def _setting(key, default, low, high):
    try:
        value = read_json(SETTINGS, {}).get(key, default)
    except (OSError, ValueError, PronetError):
        return default
    return value if type(value) is int and low <= value <= high else default


def recent_events(path, limit=6):
    """Last few tunnel events (failover, standby lost/recovered) for the status views."""
    try:
        with open(path, "rb") as file:
            file.seek(0, 2)
            file.seek(max(0, file.tell() - 16384))
            lines = file.read().decode(errors="replace").splitlines()[-limit:]
    except OSError:
        return []
    rows = []
    for line in lines:
        try:
            row = json.loads(line)
            rows.append({"utc": str(row.get("utc", ""))[:20], "event": str(row.get("event", ""))[:40],
                         "detail": clean(row.get("detail", ""), 120)})
        except ValueError:
            continue
    return rows


def probe_seconds():
    return _setting("probe_seconds", DEFAULT_PROBE_SECONDS, 5, 300)


def failover_seconds():
    return _setting("failover_seconds", DEFAULT_FAILOVER_SECONDS, 10, 1800)


def recovery_policy():
    """Stable never launches a new carrier family during a live outage."""
    try:
        value = read_json(SETTINGS, {}).get("recovery_policy", "stable")
    except (OSError, ValueError, PronetError):
        return "stable"
    return value if value in ("stable", "explore") else "stable"


def recent_switches(selection, now=None):
    now = time.time() if now is None else now
    return [stamp for stamp in selection.get("switches", [])
            if type(stamp) in (int, float) and now - 1800 <= stamp <= now]


HISTORY_WINDOW = 3600      # seconds of probe history kept per carrier
HISTORY_LIMIT = 400        # bound on stored samples per carrier
UNSTABLE_EPISODES = 3      # outages in the window that mark a STANDBY unstable (replacing it touches no user)
PRIMARY_UNSTABLE_EPISODES = 4   # outages in the window before NEW connections leave the primary
PROVEN_SAMPLES = 5         # failure-free samples needed before a carrier is called proven-stable
SOFT_SWITCH_DWELL = 7200   # no "unstable" switch within 2 h of any switch
MANUAL_HOLD = 86400        # an operator's choice is only left for a real outage, for 24 h
# One health check = up to CHECK_ATTEMPTS echoes; it fails only if all fail
# and the carrier delivered no user data recently. A single slow or lost
# probe on a busy, lossy route is not an outage.
CHECK_ATTEMPTS = 3
CHECK_TIMEOUT = 5
RETRY_GAP = 2
TRAFFIC_ALIVE = 30         # user data received through a carrier this recently proves it works


def retry_pause(seconds):
    time.sleep(seconds)


def record_probe(history, ok, now=None):
    """Append one probe result; keep only the recent window (bounded)."""
    now = time.time() if now is None else now
    rows = [row for row in (history or []) if isinstance(row, list) and len(row) == 2
            and type(row[0]) in (int, float) and now - HISTORY_WINDOW <= row[0] <= now + 60]
    rows.append([round(now, 1), 1 if ok else 0])
    return rows[-HISTORY_LIMIT:]


def outage_episodes(history):
    """Number of separate outages (runs of failed probes) in the window."""
    episodes, previous = 0, 1
    for _, ok in history or []:
        if not ok and previous:
            episodes += 1
        previous = ok
    return episodes


def is_unstable(history, episodes=UNSTABLE_EPISODES):
    """Repeated short outages: each may be shorter than the failover threshold,
    yet users of such a path see a drop every few minutes."""
    return outage_episodes(history) >= episodes


def uptime(history):
    rows = history or []
    return round(100.0 * sum(ok for _, ok in rows) / len(rows), 1) if rows else None


def is_proven(history):
    rows = history or []
    return len(rows) >= PROVEN_SAMPLES and all(ok for _, ok in rows)


def failover_probes():
    """Consecutive failed primary probes (one per watchdog cycle) before failover."""
    return max(2, -(-failover_seconds() // probe_seconds()))


def rearm_probes():
    return max(2, -(-REARM_SECONDS // probe_seconds()))


def existing_raw_ports():
    """Read only address fields of running, same-namespace legacy raw engines.

    Never export command lines, credentials or configuration contents.
    Unknown raw installations fail preflight rather than silently sharing a port.
    """
    known, unresolved = set(), []
    namespace = os.readlink("/proc/self/ns/net")
    for directory in pathlib.Path("/proc").iterdir():
        if not directory.name.isdigit(): continue
        try:
            if os.readlink(directory / "ns/net") != namespace: continue
            name = (directory / "comm").read_text().strip().lower()
            if not any(value in name for value in ("backpack", "paqet", "udp2raw", "pingtunnel")): continue
            executable = pathlib.Path(os.readlink(directory / "exe"))
            if executable.is_relative_to((ROOT / "engines").resolve()): continue
            arguments = (directory / "cmdline").read_bytes().decode(errors="replace").split("\x00")
            candidates = []
            for flag in ("-c", "--config"):
                if flag in arguments and arguments.index(flag) + 1 < len(arguments):
                    candidates.append(pathlib.Path(arguments[arguments.index(flag) + 1]))
            found = set()
            for candidate in candidates:
                if (candidate.suffix.lower() not in (".toml", ".yaml", ".yml", ".json") or not candidate.is_absolute()
                        or not any(candidate.is_relative_to(pathlib.Path(base)) for base in ("/etc/pronet-backpack", "/etc/backpack", "/etc/paqet", "/root/BackPack"))):
                    continue
                if candidate.stat().st_size > 131072: continue
                content = candidate.read_text()
                for match in re.finditer(r'(?:addr|bind_addr|remote_addr|local_addr|address)["\s]*[:=]\s*["\']?[^\s"\']*:(\d{1,5})', content):
                    value = int(match.group(1))
                    if 1 <= value <= 65535: found.add(value)
            if found:
                known.update(found)
            else:
                unresolved.append(name)
        except (OSError, ValueError, IndexError):
            continue
    return sorted(known), sorted(set(unresolved))


def endpoint_occupied(info, address, target_port):
    if "listeners" not in info:
        return target_port in info["ports"]
    return any(row["port"] == target_port and row["address"] in ("*", "0.0.0.0", "::", address, "::ffff:" + address)
               for row in info["listeners"] + info.get("udp_listeners", []))


def endpoint_has_nat(info, address, target_port):
    return any(ipaddress.ip_address(address) in ipaddress.ip_network(row["destination"])
               and row["first"] <= target_port <= row["last"] for row in info.get("nat_reserved", []))


def native_nat_reservations(document):
    """Reserve native nft DNAT/redirect targets, including complex named maps.

    Unknown expressions reserve all IPv4 endpoints instead of assuming a port
    is free. This reads rules only; it never adopts or rewrites existing rules.
    """
    result = []
    for entry in document.get("nftables", []):
        rule = entry.get("rule", {})
        expressions = rule.get("expr", [])
        if rule.get("family") == "ip6" or not any(isinstance(x, dict) and ("dnat" in x or "redirect" in x) for x in expressions):
            continue
        destination, first, last = "0.0.0.0/0", 1, 65535
        for expression in expressions:
            match = expression.get("match", {}) if isinstance(expression, dict) else {}
            if match.get("op") != "==": continue
            left, right = match.get("left", {}), match.get("right")
            if not isinstance(left, dict): continue
            payload = left.get("payload", {})
            try:
                if payload.get("protocol") == "ip" and payload.get("field") == "daddr":
                    if isinstance(right, str): destination = str(ipaddress.IPv4Network(right, strict=False))
                    elif isinstance(right, dict) and "prefix" in right:
                        value = right["prefix"]
                        destination = str(ipaddress.IPv4Network(str(value["addr"]) + "/" + str(value["len"]), strict=False))
                if payload.get("protocol") == "tcp" and payload.get("field") == "dport":
                    if isinstance(right, int) and not isinstance(right, bool): first = last = right
                    elif isinstance(right, dict) and "range" in right: first, last = map(int, right["range"])
            except (ValueError, KeyError, TypeError):
                destination, first, last = "0.0.0.0/0", 1, 65535
        result.append({"destination": destination, "first": first, "last": last})
    return result


def resources():
    result = {"hostname": socket.gethostname(), "cores": os.cpu_count(), "utc": utc()}
    if platform.system() != "Linux":
        return result
    try:
        memory = {}
        for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            memory[key] = int(value.strip().split()[0]) * 1024
        result.update(ram_percent=round(100 * (1 - memory["MemAvailable"] / memory["MemTotal"]), 1),
                      ram_total_mb=memory["MemTotal"] // 1048576,
                      ram_used_mb=(memory["MemTotal"] - memory["MemAvailable"]) // 1048576,
                      swap_used_mb=(memory["SwapTotal"] - memory["SwapFree"]) // 1048576,
                      uptime_seconds=int(float(pathlib.Path("/proc/uptime").read_text().split()[0])))
        disk = shutil.disk_usage(ROOT)
        result["disk_percent"] = round(100 * disk.used / disk.total, 1)
        fields = [int(x) for x in pathlib.Path("/proc/stat").read_text().splitlines()[0].split()[1:9]]
        previous = read_json(ROOT / "cpu-sample.json", {})
        total, idle = sum(fields), fields[3] + fields[4]
        if previous and total > previous["total"]:
            result["cpu_percent"] = round(max(0, min(100, 100 * (1 - (idle - previous["idle"]) / (total - previous["total"])))), 1)
        write_json(ROOT / "cpu-sample.json", {"total": total, "idle": idle})
    except (OSError, ValueError, KeyError) as error:
        result["resource_error"] = clean(error)
    return result


def inventory():
    addresses = json.loads(command(["ip", "-j", "-4", "address", "show"]).stdout)
    ips = [x["local"] for link in addresses for x in link.get("addr_info", [])]
    routes = json.loads(command(["ip", "-j", "-4", "route", "show", "table", "all"]).stdout)
    ports, ssh_ports, listeners, udp_listeners = set(), set(), [], []
    output = command(["ss", "-H", "-lntup"]).stdout
    for line in output.splitlines():
        columns = line.split()
        if len(columns) < 5:
            continue
        with contextlib.suppress(ValueError):
            value = int(columns[4].rsplit(":", 1)[1])
            ports.add(value)
            if columns[0] == 'udp':
                udp_listeners.append({'address':columns[4].rsplit(':',1)[0].strip('[]'),'port':value})
            if columns[0] == "tcp":
                listeners.append({"address": columns[4].rsplit(":", 1)[0].strip("[]"), "port": value})
            if "sshd" in line:
                ssh_ports.add(value)
    reservations = []
    for path in (ROOT / "pairs").glob("*/*/plan.json"):
        try:
            if (path.parent.parent / "stopped.json").exists(): continue
            plan = read_json(path)
            ports.update(plan[key] for key in ("control_port", "echo_port", "health_port", "data_port", "bridge_data_port", "bridge_health_port", "probe_front_port"))
            reservations.append(plan["subnet"])
        except (OSError, ValueError, KeyError):
            continue
    try:
        # Read-only snapshot fingerprint makes later unexpected changes visible.
        before_rules = command(["iptables-save"]).stdout
    except PronetError:
        before_rules = "unavailable"
    import hashlib
    raw_ports, unresolved_raw = existing_raw_ports()
    ports.update(raw_ports)
    nat_reserved = []
    nft_readable = True
    if shutil.which("nft"):
        try:
            nat_reserved.extend(native_nat_reservations(json.loads(command(["nft", "-j", "list", "ruleset"]).stdout)))
        except (PronetError, ValueError, TypeError):
            nft_readable = False
    for line in before_rules.splitlines():
        if not line.startswith("-A "):
            continue
        fields = shlex.split(line)
        def option(name, fallback=None):
            return fields[fields.index(name) + 1] if name in fields else fallback
        if option("-j") not in ("DNAT", "REDIRECT") or option("-p", "tcp") not in ("tcp", "all"):
            continue
        destination = option("-d", "0.0.0.0/0")
        if "!" in fields:
            destination = "0.0.0.0/0"  # Conservatively reserve inverted/complex rules.
        text = option("--dport", option("--dports", "1:65535"))
        for item in text.split(","):
            try:
                bounds = [int(x) for x in item.replace("-", ":").split(":")]
                nat_reserved.append({"destination": destination, "first": bounds[0], "last": bounds[-1]})
            except ValueError:
                nat_reserved.append({"destination": "0.0.0.0/0", "first": 1, "last": 65535})
    ephemeral_range = [32768, 60999]
    with contextlib.suppress(OSError, ValueError):
        low, high = (int(x) for x in pathlib.Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()[:2])
        ephemeral_range = [low, high]
    from . import __version__
    ram_total_mb = None
    with contextlib.suppress(OSError, ValueError, IndexError):
        for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                ram_total_mb = int(line.split()[1]) // 1024
    return {"version": __version__, "ram_total_mb": ram_total_mb, "ips": ips, "ports": sorted(ports), "listeners": listeners, "udp_listeners": udp_listeners, "ephemeral_range": ephemeral_range, "ssh_ports": sorted(ssh_ports | {22}), "nat_reserved": nat_reserved,
            "unresolved_raw_engines": unresolved_raw, "firewall_readable": before_rules != "unavailable" and nft_readable,
            "routes": [row["dst"] for row in routes if row.get("dst") not in (None, "default")],
            "reserved_subnets": reservations, "tun": pathlib.Path("/dev/net/tun").exists(),
            "systemd": pathlib.Path("/run/systemd/system").is_dir(), "arch": engines.architecture(),
            "iptables": bool(shutil.which("iptables")), "resources": resources(),
            "firewall_fingerprint": hashlib.sha256(re.sub(r"\[\d+:\d+\]", "[0:0]", "\n".join(x for x in before_rules.splitlines() if not x.startswith("#"))).encode()).hexdigest()}


def systemd_quote(value):
    if not isinstance(value, str) or any(ord(c) < 32 for c in value):
        raise PronetError("Invalid service argument")
    return '"' + value.replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"') + '"'


def systemd_path(value):
    # WorkingDirectory is a single path setting, not an ExecStart word list.
    # Quotes are literal there and make an otherwise absolute path invalid.
    value = str(value)
    if not value.startswith("/") or any(ord(c) < 32 for c in value):
        raise PronetError("Service directory must be an absolute path")
    return value.replace("%", "%%")


def unit_name(pair_id, profile, kind, role):
    identifier(pair_id)
    if profile not in PROFILES or kind not in ("engine", "echo") or role not in ("iran", "foreign"):
        raise PronetError("Unknown service resource")
    return "pronetf-" + pair_id + "-" + role + "-" + str(list(PROFILES).index(profile)) + "-" + kind + ".service"


def unit_path(name):
    if not name.startswith("pronetf-") or not name.endswith(".service") or "/" in name or ".." in name:
        raise PronetError("Refusing unmanaged service")
    return pathlib.Path("/etc/systemd/system") / name


def write_unit(name, owner, args, working_directory, temporary=True, firewall_kind=None):
    path = unit_path(name)
    marker = "# Pronet Fleet owner=" + owner + "\n"
    if path.is_symlink() or (path.exists() and not path.read_text().startswith(marker)):
        raise PronetError("Service already exists outside this pair")
    # Permanent services must never enter a terminal "failed" state: with the
    # old 5-starts-per-10-minutes limit, a boot-time race (IP not yet assigned,
    # xtables lock held by Docker) or a brief upstream outage left a committed
    # carrier dead until someone logged in. Temporary trial services keep the
    # bounded limit and still expire.
    limits = "StartLimitIntervalSec=600\nStartLimitBurst=5\n" if temporary else "StartLimitIntervalSec=0\n"
    text = marker + "[Unit]\nDescription=Pronet Fleet isolated tunnel resource\nAfter=network-online.target\nWants=network-online.target\n" + limits + "[Service]\nType=simple\n"
    text += "WorkingDirectory=" + systemd_path(working_directory) + "\n"
    for key, value in (("PRONET_STATE", str(ROOT)), ("PRONET_CONFIG", str(CONFIG))):
        text += "Environment=" + systemd_quote(key + "=" + value) + "\n"
    # Used only by the privileged Linux integration harness; never accepted
    # from network jobs or generated by the normal installer.
    namespace = os.environ.get("PRONET_TEST_NETNS", "")
    if namespace:
        import re
        if not re.fullmatch(r"/run/netns/pronettest-[a-f0-9]{8}-(iran|foreign)", namespace):
            raise PronetError("Invalid isolated test namespace")
        text += "NetworkNamespacePath=" + namespace + "\n"
    text += "ExecStart=" + " ".join(systemd_quote(str(x)) for x in args) + "\n"
    if firewall_kind:
        prefix = ["/usr/bin/python3", str(APP / "main.py"), "managed-firewall", str(working_directory), firewall_kind]
        text += "ExecStartPre=" + " ".join(map(systemd_quote, prefix + ["up"])) + "\n"
        text += "ExecStopPost=" + " ".join(map(systemd_quote, prefix + ["down"])) + "\n"
    # Restart=always also covers an engine that exits 0 on a lost peer.
    # Capacity: a commercial gateway holds thousands of sockets; 384M/128 tasks
    # risked OOM-kill or pthread_create failure of Go engines under load.
    text += ("Restart=no\n" if temporary else "Restart=always\n") + "RestartSec=5\nTimeoutStopSec=15\nKillMode=control-group\nUMask=0077\nLimitNOFILE=65536\nTasksMax=512\nMemoryMax=1G\n"
    version = systemd_version()
    if not temporary and version >= 254:
        # A peer that stays down for hours: restarts slow to one a minute.
        text += "RestartSteps=5\nRestartMaxDelaySec=60\n"
    if version >= 240:
        # A dead peer makes engines log every retry; journald keeps a sample.
        text += "LogRateLimitIntervalSec=60\nLogRateLimitBurst=30\n"
    if temporary:
        text += "RuntimeMaxSec=900\n"
    text += "[Install]\nWantedBy=multi-user.target\n"
    atomic_write(path, text, 0o644)


_SYSTEMD = []


def systemd_version():
    """systemd major version (0 when unknown); read once per process."""
    if not _SYSTEMD:
        version = 0
        with contextlib.suppress(PronetError, ValueError, IndexError):
            words = command(["systemctl", "--version"], timeout=10, check=False).stdout.split()
            if words and words[0] == "systemd":
                version = int(words[1].split(".")[0].split("~")[0])
        _SYSTEMD.append(version)
    return _SYSTEMD[0]


def active_states(names):
    """{unit: True/False} with ONE systemctl call (heartbeats run often)."""
    names = list(names)
    if not names:
        return {}
    lines = command(["systemctl", "is-active"] + names, check=False).stdout.split()
    if len(lines) != len(names):
        return {name: is_active(name) for name in names}
    return {name: state == "active" for name, state in zip(names, lines)}


def service(name, action):
    unit_path(name)
    if action not in ("start", "stop", "restart", "enable", "disable", "reset-failed"):
        raise PronetError("Unsupported service action")
    return command(["systemctl", action, name], timeout=35, check=action not in ("stop", "disable", "reset-failed"))


def is_active(name):
    return command(["systemctl", "is-active", name], check=False).stdout.strip() == "active"


def stop_confirmed(name):
    # A canceled/timed-out stop can still be completing its ExecStopPost.
    # Observe the unit before deciding, and never remove ownership of a live
    # process. Keep diagnostics even when systemctl itself failed.
    detail = ""
    try:
        stopped = service(name, "stop")
        if stopped.returncode:
            detail = clean(stopped.stderr or stopped.stdout)
    except PronetError as error:
        detail = clean(error)
    confirm_stopped(name, detail)


def confirm_stopped(name, detail="", deadline=None):
    """Verify a completed stop request, also used after a batched stop."""
    deadline = time.monotonic() + 5 if deadline is None else deadline
    props = {}
    while True:
        try:
            shown = command(["systemctl", "show", name,
                             "--property=LoadState,ActiveState,SubState,Result,MainPID,ControlPID"],
                            timeout=5, check=False)
            props = dict(line.split("=", 1) for line in shown.stdout.splitlines() if "=" in line)
        except PronetError as error:
            detail = clean(error)
            break
        state = props.get("ActiveState", "unknown")
        if (shown.returncode == 0 and state in ("inactive", "failed")
                and props.get("MainPID") == "0" and props.get("ControlPID") == "0"):
            return
        if (shown.returncode or state not in ("deactivating", "activating", "reloading")
                or time.monotonic() >= deadline):
            detail = detail or clean(shown.stderr)
            break
        time.sleep(.25)
    status = ", ".join(key + "=" + props.get(key, "unknown")
                       for key in ("LoadState", "ActiveState", "SubState", "Result", "MainPID", "ControlPID"))
    raise PronetError("Service stop unconfirmed: %s (%s); ownership files retained%s"
                      % (name, status, "; " + detail if detail else ""))


def owned_directory(path):
    path = pathlib.Path(path)
    base = (ROOT / "pairs").resolve()
    if path.is_symlink() or not path.resolve().is_relative_to(base):
        raise PronetError("Refusing directory outside managed pairs")
    relative = path.resolve().relative_to(base)
    if len(relative.parts) != 2 or relative.parts[1] not in PROFILES:
        raise PronetError("Invalid managed directory")
    identifier(relative.parts[0])
    return path


def firewall_rules(plan, kind):
    spec = PROFILES[plan["profile"]]
    iran = plan["role"] == "iran"
    peer = plan["foreign_ip"] if iran else plan["iran_ip"]
    tag = "pronetf:" + plan["pair_id"] + ":" + plan["profile"] + ":" + kind
    rules = []
    def add(chain, match):
        rules.append([chain] + match + ["-m", "comment", "--comment", tag, "-j", "ACCEPT"])
    if kind == "engine" and spec["engine"] == "parsa-spoof":
        peer = plan["spoof"]["foreign" if iran else "iran"]
    if kind == "engine":
        # PCK's engine owns its raw packet/RST guard; ordinary carrier permits
        # are still restricted to this pair's IP and port, never all traffic.
        protocols = ["udp"] if spec["family"] == "udp" else ["tcp"]
        if spec["family"] == "gre":
            protocols = []
            add("INPUT", ["-s", peer, "-d", plan["bind_ip"], "-p", "47"])
            add("OUTPUT", ["-d", peer, "-s", plan["bind_ip"], "-p", "47"])
        if spec["family"] == "icmp":
            protocols = []
            add("INPUT", ["-s", peer, "-d", plan["bind_ip"], "-p", "icmp"])
            add("OUTPUT", ["-d", peer, "-s", plan["bind_ip"], "-p", "icmp"])
        if spec["engine"] == "frp" and spec["carrier"] == "quic":
            protocols = ["tcp", "udp"]
        for protocol in protocols:
            for field in ("--dport", "--sport"):
                add("INPUT", ["-s", peer, "-d", plan["bind_ip"], "-p", protocol, field, str(plan["control_port"])])
                add("OUTPUT", ["-d", peer, "-s", plan["bind_ip"], "-p", protocol, field, str(plan["control_port"])])
        if spec["kind"] == "l3":
            own, other = tunnel_ips(plan) if iran else tuple(reversed(tunnel_ips(plan)))
            for number in inbound_ports(plan):
                for field in ("--dport", "--sport"):
                    add("INPUT", ["-i", iface(plan), "-s", other, "-d", own, "-p", "tcp", field, str(number)])
                    add("OUTPUT", ["-o", iface(plan), "-s", own, "-d", other, "-p", "tcp", field, str(number)])
        if plan.get('gaming'):
            own, other = tunnel_ips(plan) if iran else tuple(reversed(tunnel_ips(plan)))
            for field in ('--dport','--sport'):
                add('INPUT',['-i',iface(plan),'-s',other,'-d',own,'-p','udp',field,str(plan['data_port'])])
                add('OUTPUT',['-o',iface(plan),'-s',own,'-d',other,'-p','udp',field,str(plan['data_port'])])
    elif kind == "echo":
        if spec["kind"] == "l3":
            own, other = tunnel_ips(plan) if iran else tuple(reversed(tunnel_ips(plan)))
            for field in ("--dport", "--sport"):
                add("INPUT", ["-i", iface(plan), "-s", other, "-d", own, "-p", "tcp", field, str(plan["echo_port"])])
                add("OUTPUT", ["-o", iface(plan), "-s", own, "-d", other, "-p", "tcp", field, str(plan["echo_port"])])
    elif kind == "gateway" and iran:
        tag = "pronetf:" + plan["pair_id"] + ":gateway"
        for number in inbound_ports(plan):
            add("INPUT", ["-d", plan.get("gateway_bind_ip", plan["bind_ip"]), "-p", "udp" if plan.get("gaming") else "tcp", "--dport", str(number)])
            add("OUTPUT", ["-s", plan.get("gateway_bind_ip", plan["bind_ip"]), "-p", "udp" if plan.get("gaming") else "tcp", "--sport", str(number)])
    else:
        raise PronetError("Invalid managed firewall scope")
    if kind == "engine" and spec["engine"] == "parsa-spoof":
        real_peer = plan["foreign_ip"] if iran else plan["iran_ip"]
        for rule in rules:
            if rule[0] == "OUTPUT" and "-o" not in rule:
                rule[rule.index("-d") + 1] = real_peer
                rule[rule.index("-s") + 1] = plan["spoof"][plan["role"]]
    return rules


def managed_firewall(directory, kind, action):
    directory = owned_directory(directory)
    if action not in ("up", "down"):
        raise PronetError("Invalid rule action")
    plan = validate_profile(read_json(directory / "plan.json"))
    if kind == "engine" and action == "down" and plan["profile"] == "gre":
        # ExecStopPost also runs after an engine SIGKILL or partial startup.
        from .native_gre import down
        down(plan)
    if kind == "engine" and plan["profile"] == "parsa-spoof" and action == "down":
        from .spoof_wg import down
        down(plan)
    if kind == "engine" and PROFILES[plan["profile"]]["engine"] in ("paqet", "parsa-spoof"):
        from .carrier_engines import packet_firewall
        packet_firewall(plan, action)
    executable = shutil.which("iptables")
    if not executable:
        raise PronetError("iptables compatibility tool is required; existing firewall is not replaced")
    for chain, *rule in firewall_rules(plan, kind):
        exists = command([executable, "-w", "5", "-C", chain] + rule, check=False).returncode == 0
        if action == "up" and not exists:
            command([executable, "-w", "5", "-I", chain, "1"] + rule)
        elif action == "down" and exists:
            command([executable, "-w", "5", "-D", chain] + rule, check=False)


def udp_listeners():
    rows=[]
    for line in command(['ss','-H','-lntup']).stdout.splitlines():
        fields=line.split()
        if len(fields)<5 or fields[0]!='udp':continue
        try:
            host,number=fields[4].rsplit(':',1)
            rows.append({'address':host.strip('[]'),'port':int(number)})
        except ValueError:continue
    return rows


def inbound_report(plan):
    """Panel inbound state on the foreign node. "inbound" stays the single
    summary older views use: open only when EVERY client port listens."""
    if plan.get('gaming'):
        rows=udp_listeners()
        states={str(number):'open' if any(r['port']==number and r['address'] in ('0.0.0.0','*','127.0.0.1',plan['bind_ip']) for r in rows) else 'unconfirmed' for number in inbound_ports(plan)}
        return {'inbound':'open' if all(v=='open' for v in states.values()) else 'unconfirmed','inbound_ports':states,'protocol':'udp','wireguard_handshake':'not-tested'}
    states = {str(number): tcp_state(("127.0.0.1", number)) for number in inbound_ports(plan)}
    values = set(states.values())
    summary = "open" if values == {"open"} else "refused" if "refused" in values else "unconfirmed"
    result = {"inbound": summary}
    if len(states) > 1:
        result["inbound_ports"] = states
    return result


def _no_progress(update):
    return None


_LINK = LinkLock()   # one per agent process: measurements of every job share the link


class Runtime:
    # execute() accepts a per-job progress callback ({profile: {"phase", "pct"}}).
    accepts_progress = True

    @property
    def link(self):
        return _LINK

    def __init__(self, identity):
        self.identity = identity
        self.root = ROOT / "pairs"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def validate(self, plan):
        validate_profile(plan)
        if plan["role"] != self.identity["role"] or plan["bind_ip"] != self.identity["bind_ip"]:
            raise PronetError("Job does not match this node's fixed identity")
        own_public = plan["iran_ip"] if plan["role"] == "iran" else plan["foreign_ip"]
        if own_public != self.identity["public_ip"]:
            raise PronetError("Job public IP differs from enrollment")
        allowed = self.identity.get("allowed_inbound_ports", [2053])
        if any(number not in allowed for number in inbound_ports(plan)):
            raise PronetError("Inbound port was not locally authorized during enrollment")
        return plan

    def directory(self, plan):
        self.validate(plan)
        return self.root / plan["pair_id"] / plan["profile"]

    def prepare(self, plan, info=None):
        directory = self.directory(plan)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        previous = read_json(directory / "plan.json", {})
        immutable = ("token", "subnet", "control_port", "echo_port", "health_port", "data_port", "inbound_port",
                     "bridge_data_port", "bridge_health_port", "probe_front_port", "direction", "gaming")
        if previous and (any(previous.get(k) != plan.get(k) for k in immutable)
                         or inbound_ports(previous) != inbound_ports(plan)):
            raise PronetError("Existing profile differs; refusing overwrite")
        info = info or inventory()
        if plan["bind_ip"] not in info["ips"]:
            raise PronetError("Bind IP is not assigned to this host (public NAT address must be configured separately)")
        if plan["role"] == "iran" and plan.get("gateway_bind_ip", plan["bind_ip"]) not in info["ips"]:
            raise PronetError("Public gateway bind address is not assigned to Iran")
        if not info["systemd"] or not info["iptables"]:
            raise PronetError("Linux systemd and iptables tools are required")
        if any(number in info["ssh_ports"] for number in inbound_ports(plan)):
            raise PronetError("Requested inbound port belongs to SSH")
        if not previous:
            for key in ("control_port", "echo_port", "health_port", "data_port", "bridge_data_port", "bridge_health_port", "probe_front_port"):
                if plan[key] in info["ports"]:
                    raise PronetError("A reserved port became occupied; no existing service was changed")
            network = ipaddress.ip_network(plan["subnet"])
            if PROFILES[plan["profile"]]["kind"] == "l3":
                if PROFILES[plan["profile"]]["engine"] not in ("native-gre", "parsa-spoof") and not info["tun"]:
                    raise PronetError("TUN device unavailable")
                for destination in info["routes"] + info["reserved_subnets"]:
                    with contextlib.suppress(ValueError):
                        if network.overlaps(ipaddress.ip_network(destination)):
                            raise PronetError("Tunnel subnet overlaps an existing route")
        if plan["profile"] == "parsa-spoof":
            from .spoof_wg import requirements
            requirements()
        write_json(directory / "plan.json", plan)
        (directory / "retired.json").unlink(missing_ok=True)
        write_json(directory / "before.json", info) if not (directory / "before.json").exists() else None
        engine = PROFILES[plan["profile"]]["engine"]
        binaries = {} if engine == "native-gre" else engines.install_asset(engine, ROOT / "engines")
        reply = {"profile": plan["profile"], "prepared": True}
        if plan["role"] == "iran" and engine in ("frp", "wstunnel"):
            make_cert = engines.wstunnel_certificate if engine == "wstunnel" else engines.certificate
            reply["server_cert"] = make_cert(directory, "pn-" + plan["pair_id"] + ".invalid", plan["iran_ip"])
        if plan["role"] == "iran" and engine == "chisel":
            reply["server_fingerprint"] = engines.chisel_key(directory)
        if plan["role"] == "iran" and engine == "rathole":
            from .extra_engines import noise_key
            reply["server_noise_public_key"] = noise_key(directory, binaries["rathole"])
        if engine == "parsa-spoof":
            from .spoof_wg import public_key
            reply["wg_public_key"] = public_key(directory)
        return reply

    def start(self, plan):
        directory = self.directory(plan)
        previous = read_json(directory / "plan.json")
        if (any(previous.get(k) != plan.get(k) for k in ("token", "subnet", "control_port", "echo_port", "health_port", "data_port", "inbound_port", "bridge_data_port", "bridge_health_port", "probe_front_port", "direction", "gaming"))
                or inbound_ports(previous) != inbound_ports(plan)):
            raise PronetError("Profile changed after preparation")
        write_json(directory / "plan.json", plan)
        (directory / "retired.json").unlink(missing_ok=True)
        if plan.get("server_cert"):
            certificate = plan["server_cert"]
            if not isinstance(certificate, str) or len(certificate) > 16384 or not certificate.startswith("-----BEGIN CERTIFICATE-----"):
                raise PronetError("Invalid peer certificate")
            atomic_write(directory / "peer.crt", certificate)
        engine = PROFILES[plan["profile"]]["engine"]
        binaries = {} if engine == "native-gre" else engines.install_asset(engine, ROOT / "engines")
        recipe = engines.render(plan, directory, binaries)
        if recipe["validate"]:
            command(recipe["validate"])
        write_json(directory / "launch.json", recipe)
        self.write_services(plan, temporary=not (directory / "committed.json").exists())
        command(["systemctl", "daemon-reload"])
        for kind in ("engine", "echo"):
            name = unit_name(plan["pair_id"], plan["profile"], kind, plan["role"])
            service(name, "reset-failed")
            if not is_active(name):
                service(name, "start")
        return {"started": True, "profile": plan["profile"]}

    def quiet(self):
        """Engine preparation and start-up use CPU and send setup traffic.
        Never do it while another carrier's throughput transfer is running."""
        return self.link.shared()

    def prepare_batch(self, plans):
        """Prepare several carriers with ONE host inventory (it walks /proc,
        iptables and nft, so per-carrier inventories cost seconds each)."""
        with self.quiet():
            info = inventory()
        replies = {}
        for plan in plans[:MAX_BATCH]:
            name = plan.get("profile")
            try:
                with self.quiet():
                    replies[name] = self.prepare(plan, info)
            except Exception as error:
                replies[str(name)] = {"error": clean(error)}
        return {"profiles": replies}

    def start_batch(self, plans):
        replies = {}
        for plan in plans[:MAX_BATCH]:
            name = plan.get("profile")
            try:
                with self.quiet():
                    replies[name] = self.start(plan)
            except Exception as error:
                replies[str(name)] = {"error": clean(error)}
        return {"profiles": replies}

    def probe_batch(self, pair_id, profiles, seconds=REACH_WAIT, progress=_no_progress):
        """Wait for end-to-end reachability of several carriers IN PARALLEL.

        Each carrier is reported as soon as its first authenticated echo
        succeeds, or as failed when its temporary engine exits (no restart is
        configured for trial units) or the shared deadline passes.
        """
        import concurrent.futures
        identifier(pair_id)
        if not isinstance(profiles, list) or len(profiles) > MAX_BATCH or any(p not in PROFILES for p in profiles):
            raise PronetError("Invalid probe batch")
        seconds = max(5, min(60, int(seconds)))
        deadline = time.monotonic() + seconds
        def probe(profile):
            try:
                plan = self.validate(read_json(self.root / pair_id / profile / "plan.json"))
            except (OSError, ValueError, KeyError, PronetError) as error:
                return profile, {"reachable": False, "reason": "plan unavailable: " + clean(error)}
            address = engines.probe_address(plan)
            unit = unit_name(pair_id, profile, "engine", plan["role"])
            started = time.monotonic()
            while time.monotonic() < deadline:
                try:
                    delay = self.echo(plan,2)
                    progress({profile: {"phase": "connected", "pct": 100}})
                    return profile, {"reachable": True, "rtt_ms": round(delay, 1),
                                     "seconds": round(time.monotonic() - started, 1)}
                except (OSError, ValueError, PronetError):
                    pass
                if time.monotonic() - started > 3 and not is_active(unit):
                    return profile, {"reachable": False, "reason": "local engine exited (see: sudo pronet logs " + pair_id + ")"}
                time.sleep(1)
            return profile, {"reachable": False, "reason": "no end-to-end connectivity within %d s" % seconds}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(profiles))) as pool:
            results = dict(pool.map(probe, profiles))
        return {"profiles": results}

    def local_plans(self, pair_id, profiles):
        identifier(pair_id)
        if (not isinstance(profiles, list) or not 1 <= len(profiles) <= MAX_BATCH
                or len(set(profiles)) != len(profiles) or any(p not in PROFILES for p in profiles)):
            raise PronetError("Invalid carrier list")
        plans, missing = [], {}
        for profile in profiles:
            try:
                plans.append(self.validate(read_json(self.root / pair_id / profile / "plan.json")))
            except (OSError, ValueError, KeyError, PronetError) as error:
                missing[profile] = clean(error)
        return plans, missing

    def resume_batch(self, pair_id, profiles):
        """Start carriers again from their own stored plans (same ports and
        credentials as when they were tested), e.g. to re-test or to replace
        an unstable standby. Never touches committed carriers' sessions."""
        plans, missing = self.local_plans(pair_id, profiles)
        replies = {name: {"error": "plan unavailable: " + text} for name, text in missing.items()}
        if (self.root / pair_id / "stopped.json").exists():
            raise PronetError("Operator removed this pair; automatic recovery refused")
        for plan in plans:
            try:
                with self.quiet():
                    self.start(plan)
                    for kind in ("engine", "echo"):
                        name = unit_name(pair_id, plan["profile"], kind, plan["role"])
                        service(name, "reset-failed")
                        if not is_active(name):
                            service(name, "start")
                replies[plan["profile"]] = {"started": True}
            except Exception as error:
                replies[plan["profile"]] = {"error": clean(error)}
        return {"profiles": replies}

    def benchmark_batch(self, pair_id, plans, long_test=False, progress=_no_progress):
        if isinstance(plans, dict) and "profiles" in plans:
            loaded, missing = self.local_plans(pair_id, plans["profiles"])
            result = (self.benchmark_batch(pair_id, [dict(plan, long_test=long_test) for plan in loaded], progress=progress)
                      if loaded else {"profiles": {}})
            for name, text in missing.items():
                result["profiles"][name] = {"profile": name, "passed": False, "echo_ms": [], "success_ratio": 0,
                                            "error": "plan unavailable: " + text, "stage": "benchmark"}
            return result
        """Measure several reachable carriers in one job.

        Throughput transfers still run one at a time (LinkLock) so no carrier's
        numbers are shared with another; only idle waits and latency samples
        between transfers overlap. The result of each carrier is the same as
        a separate benchmark job.
        """
        import concurrent.futures
        identifier(pair_id)
        if not isinstance(plans, list) or not 1 <= len(plans) <= MAX_BATCH:
            raise PronetError("Invalid benchmark batch")
        if any(not isinstance(p, dict) or p.get("pair_id") != pair_id or p.get("profile") not in PROFILES for p in plans):
            raise PronetError("Job pair identity mismatch")
        if len({p["profile"] for p in plans}) != len(plans):
            raise PronetError("Duplicate carrier in benchmark batch")
        def run(plan):
            try:
                return plan["profile"], self.measure(plan, link=self.link, progress=progress)
            except Exception as error:
                return plan["profile"], {"profile": plan["profile"], "passed": False, "echo_ms": [], "success_ratio": 0,
                                         "error": clean(error), "stage": "benchmark"}
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(plans)) as pool:
            return {"profiles": dict(pool.map(run, plans))}

    def retire_batch(self, pair_id, profiles):
        identifier(pair_id)
        if (not isinstance(profiles, list) or len(profiles) > len(PROFILES)
                or len(set(profiles)) != len(profiles) or any(p not in PROFILES for p in profiles)):
            raise PronetError("Invalid retire batch")
        names = []
        # Verify every existing unit's ownership BEFORE asking systemd to act.
        for profile in profiles:
            directory = self.root / pair_id / profile
            if not (directory / "plan.json").exists():
                continue
            if directory.is_symlink():
                raise PronetError("Refusing removal of unowned profile")
            plan = self.validate(read_json(directory / "plan.json"))
            for kind in ("echo", "engine"):
                name = unit_name(pair_id, profile, kind, plan["role"])
                path = unit_path(name)
                if path.is_symlink() or (path.exists() and not path.read_text().startswith("# Pronet Fleet owner=" + pair_id + "\n")):
                    raise PronetError("Service ownership changed; refusing removal: " + name)
                if path.exists():
                    names.append(name)
        stopped, errors, detail = {}, [], ""
        if names:
            # disable normally reloads the manager on EVERY call. No reload is
            # needed until all stopped owned files have been removed.
            command(["systemctl", "disable", "--no-reload"] + names, timeout=35, check=False)
            try:
                reply = command(["systemctl", "stop"] + names, timeout=35, check=False)
                if reply.returncode:
                    detail = clean(reply.stderr or reply.stdout)
            except PronetError as error:
                detail = clean(error)
            deadline = time.monotonic() + 5
            for name in names:
                try:
                    confirm_stopped(name, detail, deadline)
                    stopped[name] = None
                except PronetError as error:
                    stopped[name] = clean(error)
            confirmed = [name for name in names if stopped[name] is None]
            if confirmed:
                command(["systemctl", "reset-failed"] + confirmed, check=False)
        for profile in profiles:
            if (self.root / pair_id / profile / "plan.json").exists():
                try:
                    self.remove_profile(pair_id, profile, stop_results=stopped)
                except PronetError as error:
                    errors.append(profile + ": " + clean(error))
        if names:
            command(["systemctl", "daemon-reload"])
        if errors:
            raise PronetError("Retirement incomplete: " + "; ".join(errors))
        return {"retired": profiles}

    def write_services(self, plan, temporary):
        directory = self.directory(plan)
        for kind in ("engine", "echo"):
            args = ["/usr/bin/python3", str(APP / "main.py"), "managed-run", str(directory), kind]
            write_unit(unit_name(plan["pair_id"], plan["profile"], kind, plan["role"]), plan["pair_id"], args,
                       directory, temporary=temporary, firewall_kind=kind)

    def echo(self, plan, timeout=2):
        if plan.get('gaming'):
            from .gaming import probe
            own,peer=tunnel_ips(plan) if plan['role']=='iran' else tuple(reversed(tunnel_ips(plan)))
            return probe((peer,plan['data_port']),plan['token'],timeout)
        return echo(engines.probe_address(plan),plan['token'],timeout)

    def measure(self, plan, wait=None, link=None, progress=_no_progress):
        self.validate(plan)
        name = plan.get("profile")
        report = progress
        def progress(phase, fraction):
            report({name: {"phase": phase, "pct": max(0, min(100, int(fraction * 100)))}})
        address = engines.probe_address(plan)
        wait = wait if wait is not None else plan.get("reach_wait", REACH_WAIT)
        deadline = time.monotonic() + wait
        reached = False
        while time.monotonic() < deadline:
            try:
                self.echo(plan,2)
                reached = True
                break
            except (OSError, ValueError, PronetError):
                time.sleep(1)
        if not reached:
            # Fast-fail: an unreachable carrier used to spend another ~60 s in
            # benchmark timeouts before reporting the same failure.
            return {"profile": plan["profile"], "passed": False, "echo_ms": [], "success_ratio": 0,
                    "upload_mbps": None, "download_mbps": None, "half_close": False, "after_idle": False,
                    "integrity": False, "utc": utc(), "stage": "reach", "errors": ["unreachable"],
                    "reason": "no end-to-end connectivity within %d s" % wait}
        if plan.get('gaming'):
            from .gaming import benchmark as udp_benchmark
            own,peer=tunnel_ips(plan) if plan['role']=='iran' else tuple(reversed(tunnel_ips(plan)))
            with (link or self.link).exclusive():
                result=udp_benchmark((peer,plan['data_port']),plan['token'],plan.get('long_test') is True,progress)
            result.update(profile=plan['profile'],stage='soak' if plan.get('long_test') else 'screen')
            return result
        if plan.get("long_test") is True:
            if plan.get("test_quality") == "quick":
                result = benchmark(address, plan["token"], rounds=6, size=1024 * 1024, idle=3, budget=70, link=link, progress=progress)
            else:
                result = benchmark(address, plan["token"], rounds=15, size=4 * 1024 * 1024, idle=10, timeout=20, budget=80, link=link, progress=progress)
            result["stage"] = "soak"
        else:
            if plan.get("test_quality") == "quick":
                result = benchmark(address, plan["token"], rounds=3, size=262144, idle=1, link=link, progress=progress)
            else:
                result = benchmark(address, plan["token"], link=link, progress=progress)
            result["stage"] = "screen"
        result["profile"] = plan["profile"]
        return result

    def commit(self, pair_id, profiles, automatic=False, rescue=False, expect_active=None):
        identifier(pair_id)
        if (not isinstance(profiles, list) or not 1 <= len(profiles) <= MAX_SELECTED
                or len(set(profiles)) != len(profiles) or any(p not in PROFILES for p in profiles)):
            raise PronetError("Commit requires one winner and at most two standbys")
        previous = read_json(self.root / pair_id / "selection.json", {})
        if expect_active and self.identity["role"] == "iran" and previous.get("active") not in (None, expect_active):
            # The watchdog switched paths after the coordinator decided:
            # never undo that switch with a stale selection.
            raise PronetError("The active carrier changed in the meantime; selection not changed")
        now = time.time()
        switches = recent_switches(previous, now)
        # A rescue (every committed path down, bounded to one per hour by the
        # coordinator) may replace a dead primary even when the budget is used.
        if (automatic and not rescue and self.identity["role"] == "iran" and previous.get("active")
                and previous["active"] != profiles[0] and len(switches) >= 3):
            # Enforce locally under the agent operation lock as well. Hub
            # telemetry can lag behind a watchdog switch by several seconds.
            raise PronetError("Automatic carrier selection blocked by the rolling switch budget")
        # A controller recovery changing the selected primary is also a
        # switch. It must not bypass the watchdog's rolling budget.
        if previous.get("active") and previous["active"] != profiles[0]:
            switches.append(now)
        plans = []
        for profile in profiles:
            directory = self.root / pair_id / profile
            plan = self.validate(read_json(directory / "plan.json"))
            self.write_services(plan, temporary=False)
            write_json(directory / "committed.json", {"utc": utc()})
            plans.append(plan)
        command(["systemctl", "daemon-reload"])
        for plan in plans:
            for kind in ("engine", "echo"):
                name = unit_name(pair_id, plan["profile"], kind, plan["role"])
                service(name, "enable")
                service(name, "reset-failed")
                # A retained, committed service still carries user sessions.
                # Do not restart it just to record a different primary choice.
                if plan["profile"] not in previous.get("profiles", []) or not is_active(name):
                    service(name, "restart")
        # Empty failed preparations own no unit. Retire the rest together so
        # commit does not repeat per-service manager reloads and stop waits.
        retire = [directory.name for directory in (self.root / pair_id).iterdir()
                  if directory.is_dir() and directory.name in PROFILES and directory.name not in profiles
                  and (directory / "plan.json").is_file()]
        if retire:
            self.retire_batch(pair_id, retire)
        selection = {"profiles": profiles, "active": profiles[0], "failures": 0, "switches": switches,
                     "auto_paused": False, "utc": utc()}
        # Keep what is known about carriers that stay committed.
        if isinstance(previous.get("history"), dict):
            selection["history"] = {k: v for k, v in previous["history"].items() if k in profiles}
        if previous.get("active") == profiles[0]:
            for key in ("healthy_probes", "rtt_ms", "last_probe"):
                if key in previous:
                    selection[key] = previous[key]
        write_json(self.root / pair_id / "selection.json", selection)
        return {"committed": profiles}

    def activate(self, pair_id):
        identifier(pair_id)
        selected = read_json(self.root / pair_id / "selection.json")
        directory = self.root / pair_id / selected["active"]
        plan = self.validate(read_json(directory / "plan.json"))
        if plan["role"] != "iran":
            result = dict(inbound_report(plan), gateway="not-required")
            write_json(self.root / pair_id / "active.json", result)
            return result
        name = "pronetf-" + pair_id + "-gateway.service"
        config_path = self.root / pair_id / "gateway.json"
        current_inventory = inventory()
        bind_ip = plan.get("gateway_bind_ip", plan["bind_ip"])
        ports = inbound_ports(plan)
        for number in ports:
            if endpoint_has_nat(current_inventory, bind_ip, number):
                raise PronetError("An external NAT rule took port %d during setup; it was not modified" % number)
        if not config_path.exists():
            # The OS bind is authoritative and happens before publishing success.
            for number in ports:
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if plan.get("gaming") else socket.SOCK_STREAM) as sock:
                    try:
                        sock.bind((bind_ip, number))
                    except OSError as error:
                        raise PronetError("Port %d on %s is already in use (%s)" % (number, bind_ip, clean(error)))
        write_json(config_path, {"bind_ip": bind_ip, "port": ports[0], "ports": ports,
                                "active_backend": list(engines.data_address(plan)), "connection_limit": DEFAULT_CONNECTION_LIMIT,
                                "mode": "plain" if PROFILES[plan["profile"]]["kind"] == "l3" else "framed", "frame_key": plan["token"], "gaming":plan.get("gaming",False)})
        write_unit(name, pair_id, ["/usr/bin/python3", str(APP / "main.py"), "managed-gateway", pair_id],
                   directory, temporary=False, firewall_kind="gateway")
        command(["systemctl", "daemon-reload"])
        service(name, "enable")
        service(name, "reset-failed")
        if not is_active(name):
            service(name, "start")
        time.sleep(.3)
        if not is_active(name):
            raise PronetError("Public gateway could not bind; inspect pair logs")
        address = (plan.get("gateway_bind_ip", plan["bind_ip"]), plan["inbound_port"])
        if plan.get('gaming'):
            listeners=udp_listeners()
            if any(not any(row['port']==number and row['address']==bind_ip for row in listeners) for number in ports):
                raise PronetError('Gaming UDP gateway did not bind every authorized client port')
            result={'gateway':'active','local_endpoint':'udp-listening','protocol':'udp','external_client_test':'not-performed'}
            write_json(self.root/pair_id/'active.json',result)
            return result
        result = {"gateway": "active", "local_endpoint": tcp_state(address), "tls": tls_state(address, plan.get("sni", "")),
                  "external_client_test": "not-performed"}
        if len(ports) > 1:
            result["local_endpoints"] = {str(number): tcp_state((bind_ip, number)) for number in ports}
        write_json(self.root / pair_id / "active.json", result)
        return result

    def remove_profile(self, pair_id, profile, stop_results=None):
        directory = self.root / identifier(pair_id) / profile
        if profile not in PROFILES or directory.is_symlink() or not (directory / "plan.json").is_file():
            raise PronetError("Refusing removal of unowned profile")
        plan = self.validate(read_json(directory / "plan.json"))
        errors = []
        for kind in ("echo", "engine"):
            name = unit_name(pair_id, profile, kind, plan["role"])
            path = unit_path(name)
            marker = "# Pronet Fleet owner=" + pair_id + "\n"
            if path.exists() and not path.read_text().startswith(marker):
                errors.append(name + ": service ownership changed; refusing removal")
                continue
            if path.exists():
                try:
                    if stop_results is None or name not in stop_results:
                        service(name, "disable")
                        stop_confirmed(name)
                        service(name, "reset-failed")
                    elif stop_results[name] is not None:
                        raise PronetError(stop_results[name])
                    path.unlink()
                except PronetError as error:
                    errors.append(clean(error))
                    continue
            with contextlib.suppress(PronetError):
                managed_firewall(directory, kind, "down")
        # Keep files as a root-only recovery record; do not reallocate old slots
        # while an external process could still be using them.
        if errors:
            raise PronetError("; ".join(errors))
        write_json(directory / "retired.json", {"utc": utc()})

    def cleanup(self, pair_id):
        directory = self.root / identifier(pair_id)
        errors = []
        name = "pronetf-" + pair_id + "-gateway.service"
        path = unit_path(name)
        if self.identity["role"] == "iran" and path.exists():
            if not path.read_text().startswith("# Pronet Fleet owner=" + pair_id + "\n"):
                raise PronetError("Gateway ownership mismatch")
            try:
                service(name, "disable")
                stop_confirmed(name)
                path.unlink()
            except PronetError as error:
                errors.append(clean(error))
        if directory.exists():
            profiles = [child.name for child in directory.iterdir()
                        if child.is_dir() and child.name in PROFILES and (child / "plan.json").is_file()]
            if profiles:
                try:
                    self.retire_batch(pair_id, profiles)
                except PronetError as error:
                    errors.append(clean(error))
            if not errors:
                write_json(directory / "stopped.json", {"utc": utc()})
                (directory / "active.json").unlink(missing_ok=True)
        command(["systemctl", "daemon-reload"])
        if errors:
            raise PronetError("Cleanup incomplete: " + "; ".join(errors))
        return {"cleaned": pair_id}

    def status(self, pair_id):
        directory = self.root / identifier(pair_id)
        selected = read_json(directory / "selection.json", {})
        # The raw probe history stays local; heartbeats carry only its summary.
        selected = {k: v for k, v in selected.items() if k != "history"}
        result = {"id": pair_id, "selection": selected, "profiles": {},
                  "traffic": read_json(directory / "traffic.json", {}), "active": read_json(directory / "active.json", {})}
        units, plan = {}, None
        for profile in selected.get("profiles", []):
            plan = self.validate(read_json(directory / profile / "plan.json"))
            units[profile] = unit_name(pair_id, profile, "engine", plan["role"])
        states = active_states(units.values())
        for profile, name in units.items():
            result["profiles"][profile] = {"engine_active": states.get(name, False)}
        if plan is not None and self.identity["role"] == "foreign":
            result.update(inbound_report(plan))   # same client ports for every carrier
        if (directory / "stopped.json").exists():
            result["state"] = "STOPPED"
        if self.identity["role"] == "iran":
            result["health"] = {"probe_seconds": 5 if plan and plan.get("gaming") else probe_seconds(), "failover_seconds": 15 if plan and plan.get("gaming") else failover_seconds(),
                                "failover_probes": 3 if plan and plan.get("gaming") else failover_probes(), "recovery_policy": recovery_policy(),
                                "probe_scope": "authenticated-udp-carrier-only" if plan and plan.get("gaming") else "carrier-echo-only", "switches_30m": len(recent_switches(selected)),
                                "switch_limit_30m": 3, "standby_required_probes": 2}
            result["events"] = recent_events(directory / "events.jsonl")
        return result

    def watch_interval(self):
        for path in self.root.glob('*/gateway.json'):
            if (path.parent/'active.json').exists() and not (path.parent/'stopped.json').exists() and read_json(path,{}).get('gaming'):
                return min(5,probe_seconds())
        return probe_seconds()

    def watchdog(self):
        if self.identity["role"] != "iran":
            return
        mixed_cadence=self.watch_interval()<probe_seconds()
        for directory in self.root.iterdir():
            if not directory.is_dir() or not (directory / "active.json").exists() or (directory / "stopped.json").exists():
                continue
            try:
                with lock(directory / "watchdog.lock", blocking=False):
                    config=read_json(directory/'gateway.json',{})
                    if mixed_cadence:
                        interval=5 if config.get('gaming') else probe_seconds()
                        checked=getattr(self,'_watch_times',{})
                        if time.monotonic()-checked.get(str(directory),-1e9)<interval: continue
                        checked[str(directory)]=time.monotonic();self._watch_times=checked
                    self.watch_pair(directory)
            except (BlockingIOError, OSError, ValueError, KeyError, PronetError) as error:
                event(ROOT / "agent-events.jsonl", "WATCHDOG_ERROR", error)

    def probe(self, directory, profile):
        plan = self.validate(read_json(directory / profile / "plan.json"))
        return plan, self.check(directory, plan)

    def check(self, directory, plan):
        """One health check. Returns the echo time in ms, or None when the
        echo failed but users' data is flowing through the carrier."""
        error = None
        for attempt in range(2 if plan.get("gaming") else CHECK_ATTEMPTS):
            started = time.monotonic()
            try:
                return self.echo(plan,1 if plan.get("gaming") else CHECK_TIMEOUT)
            except (OSError, ValueError, PronetError) as failure:
                error = failure
            if attempt + 1 < (2 if plan.get("gaming") else CHECK_ATTEMPTS) and time.monotonic() - started < RETRY_GAP:
                retry_pause(RETRY_GAP)   # a refused connection (engine restarting): wait a moment
        if self.traffic_alive(directory, plan):
            return None
        raise error

    def traffic_alive(self, directory, plan):
        if self.identity.get("role") != "iran":
            return False
        seen = (read_json(directory / "traffic.json", {}) or {}).get("backend_rx_at") or {}
        stamp = seen.get("%s:%s" % tuple(engines.data_address(plan))) if isinstance(seen, dict) else None
        return type(stamp) in (int, float) and 0 <= time.time() - stamp <= (10 if plan.get("gaming") else TRAFFIC_ALIVE)

    def switch_to(self, directory, selected, plan, candidate, other, close_old, reason, manual=False):
        previous = selected["active"]
        gateway = read_json(directory / "gateway.json")
        # Sessions bound to a dead primary are black-holed: close them so
        # clients reconnect at once through the new path. Otherwise nothing is
        # drained (an old list must not cut a healthy path on a later switch).
        gateway["failed_backends"] = [list(engines.data_address(plan))] if close_old else []
        gateway["active_backend"] = list(engines.data_address(other))
        gateway["mode"] = "plain" if PROFILES[candidate]["kind"] == "l3" else "framed"
        gateway["frame_key"] = other["token"]
        write_json(directory / "gateway.json", gateway)
        # An operator switch does not use the automatic 30-minute budget.
        switches = recent_switches(selected) + ([] if manual else [time.time()])
        selected.update(active=candidate, failures=0, healthy_probes=0, switches=switches, pause_reason=None,
                        last_switch_at=time.time())
        event(directory / "events.jsonl", "MANUAL_SWITCH" if manual else "FAILOVER",
              "%s -> %s (%s)" % (previous, candidate, reason))

    def manual_switch(self, pair_id, profile=None, now=None):
        """Operator switch (CLI or dashboard), Iran only. Default target: the
        primary chosen at setup. Only NEW connections move; sessions on the
        current carrier continue until they end. The target must answer a
        fresh probe right now."""
        if self.identity["role"] != "iran":
            raise PronetError("Switch the carrier on the Iran server")
        directory = self.root / identifier(pair_id)
        if (directory / "stopped.json").exists() or not (directory / "active.json").exists():
            raise PronetError("This tunnel is not active on this server")
        now = time.time() if now is None else now
        with lock(directory / "watchdog.lock"):
            selected = read_json(directory / "selection.json")
            profiles = selected.get("profiles") or []
            target = profile or (profiles[0] if profiles else None)
            if target not in profiles:
                raise PronetError("%s is not one of this tunnel's carriers: %s" % (target, ", ".join(profiles)))
            if target == selected.get("active"):
                return {"switched": False, "active": target, "reason": "already active"}
            last = selected.get("manual_switch_at")
            if type(last) in (int, float) and 0 <= now - last < MANUAL_SWITCH_GAP:
                raise PronetError("A switch was made %d s ago; wait %d s" % (now - last, MANUAL_SWITCH_GAP - (now - last)))
            plan = self.validate(read_json(directory / selected["active"] / "plan.json"))
            try:
                other, delay = self.probe(directory, target)
            except (OSError, ValueError, KeyError, PronetError):
                raise PronetError("%s is not answering right now; nothing was changed" % target)
            reason = "operator" + (", back to the main carrier" if target == profiles[0] else "")
            self.switch_to(directory, selected, plan, target, other, False, reason, manual=True)
            selected["manual_switch_at"] = now
            write_json(directory / "selection.json", selected)
            return {"switched": True, "active": target, "rtt_ms": round(delay, 2) if delay is not None else None}

    @staticmethod
    def soft_switch_allowed(selected, now):
        """An unstable-but-working primary is left only if it has kept the job
        for a while; an operator's choice only for a real outage, for 24 h."""
        last, manual = selected.get("last_switch_at"), selected.get("manual_switch_at")
        if type(last) in (int, float) and 0 <= now - last < SOFT_SWITCH_DWELL:
            return False
        return not (type(manual) in (int, float) and 0 <= now - manual < MANUAL_HOLD)

    def watch_pair(self, directory):
        selected = read_json(directory / "selection.json")
        active = selected["active"]
        plan = self.validate(read_json(directory / active / "plan.json"))
        now = time.time()
        history = selected.get("history") if isinstance(selected.get("history"), dict) else {}
        history = {name: rows for name, rows in history.items() if name in selected["profiles"]}
        try:
            delay = self.check(directory, plan)
            history[active] = record_probe(history.get(active), True, now)
            healthy = selected.get("healthy_probes", 0) + 1
            selected.update(failures=0, last_probe="OK", by_traffic=delay is None,
                            rtt_ms=round(delay, 2) if delay is not None else selected.get("rtt_ms"), healthy_probes=healthy)
            if selected.get("auto_paused") and healthy >= rearm_probes():
                # The path came back by itself (e.g. a server whose traffic
                # quota was recharged). Re-arm automatic failover; the
                # 30-minute switch budget still applies.
                if len(recent_switches(selected)) < 3:
                    selected.update(auto_paused=False, pause_id=None, pause_reason=None)
                    event(directory / "events.jsonl", "AUTO_FAILOVER_REARMED",
                          "primary healthy again for %d probes" % healthy)
            gateway = read_json(directory / "gateway.json")
            desired = list(engines.data_address(plan))
            if gateway.get("active_backend") != desired:
                # A working primary is not a failover: keep established sessions.
                gateway.update(active_backend=desired, frame_key=plan["token"], failed_backends=[],
                               mode="plain" if PROFILES[active]["kind"] == "l3" else "framed")
                write_json(directory / "gateway.json", gateway)
        except (OSError, ValueError, PronetError):
            history[active] = record_probe(history.get(active), False, now)
            selected["failures"] += 1
            selected["healthy_probes"] = 0
            selected["last_probe"] = "UNCONFIRMED"
        # Exercise every warm carrier even while the primary works: keeps idle
        # UDP mappings in use and reports an unhealthy or unstable standby
        # before it is needed. A backup probe never restarts the primary.
        previous_health = selected.get("standby_health", {})
        health = {}
        for candidate in selected["profiles"]:
            if candidate == active:
                continue
            previous = previous_health.get(candidate, {})
            last_checked = previous.get("checked_at", 0)
            fresh = (type(last_checked) in (int, float)
                     and 0 <= now - last_checked <= probe_seconds() * 2 + 12)
            row = {"utc": utc()}
            try:
                _, delay = self.probe(directory, candidate)
                history[candidate] = record_probe(history.get(candidate), True, now)
                row.update(state="OK", failures=0, rtt_ms=round(delay, 2) if delay is not None else previous.get("rtt_ms"),
                           checked_at=now,
                           healthy_probes=(previous.get("healthy_probes", 0) if fresh else 0) + 1)
                if previous.get("failures", 0) >= 3:
                    event(directory / "events.jsonl", "STANDBY_RECOVERED", candidate)
            except (OSError, ValueError, KeyError, PronetError):
                history[candidate] = record_probe(history.get(candidate), False, now)
                failures = previous.get("failures", 0) + 1
                row.update(state="UNCONFIRMED", failures=failures, healthy_probes=0)
                if failures == 3:
                    event(directory / "events.jsonl", "STANDBY_UNCONFIRMED", candidate)
            row["episodes"] = outage_episodes(history[candidate])
            row["unstable"] = is_unstable(history[candidate])
            row["proven"] = is_proven(history[candidate])
            row["uptime"] = uptime(history[candidate])
            if row["unstable"] and not previous.get("unstable"):
                event(directory / "events.jsonl", "STANDBY_UNSTABLE",
                      "%s: %d outages in 30 minutes" % (candidate, row["episodes"]))
            health[candidate] = row
        selected["standby_health"] = health
        selected["history"] = history
        active_unstable = is_unstable(history.get(active), PRIMARY_UNSTABLE_EPISODES)
        selected["active_uptime"] = uptime(history.get(active))
        if active_unstable and not selected.get("active_unstable"):
            event(directory / "events.jsonl", "ACTIVE_UNSTABLE",
                  "%s: %d outages in 30 minutes" % (active, outage_episodes(history.get(active))))
        selected["active_unstable"] = active_unstable
        selected["active_episodes"] = outage_episodes(history.get(active))
        # Every committed path down at once: remembered for the coordinator,
        # which may start an automatic re-test after a sustained outage.
        any_ok = selected["failures"] == 0 or any(row.get("state") == "OK" for row in health.values())
        if any_ok:
            if selected.get("all_down_since"):
                event(directory / "events.jsonl", "PATH_RESTORED",
                      "a committed path answers again after %d s" % (now - selected["all_down_since"]))
            selected.pop("all_down_since", None)
        elif not selected.get("all_down_since"):
            selected["all_down_since"] = now
            event(directory / "events.jsonl", "ALL_PATHS_DOWN", "no committed carrier answers")
        switches = recent_switches(selected)
        def eligible(name, require_proven=False):
            row = health.get(name, {})
            if row.get("state") != "OK" or row.get("healthy_probes", 0) < 2:
                return False
            return row.get("proven") if require_proven else True
        # Best long-term record first: not unstable, fewest failed checks in the
        # last hour, then the setup ranking. A momentary rtt does not decide.
        rank = {name: index for index, name in enumerate(selected["profiles"])}
        ordered = sorted((name for name in selected["profiles"] if name != active),
                         key=lambda name: (bool(health.get(name, {}).get("unstable")),
                                           sum(1 for _, ok in history.get(name) or [] if not ok), rank[name]))
        if (selected.get("auto_paused") and len(switches) < 3
                and any(eligible(name) and not health[name].get("unstable") for name in ordered)):
            # Recovery of a backup must also re-arm switching: the primary may
            # remain dead. Never reset the switch budget.
            selected.update(auto_paused=False, pause_id=None, pause_reason=None)
            event(directory / "events.jsonl", "STANDBY_FAILOVER_REARMED",
                  "A committed standby passed consecutive probes; switch budget is available")
        if selected["failures"] >= (3 if plan.get("gaming") else failover_probes()) and not selected.get("auto_paused"):
            if len(switches) >= 3:
                selected["auto_paused"] = True
                selected["pause_reason"] = "switch-budget"
                selected["pause_id"] = secrets.token_hex(12)
                event(directory / "events.jsonl", "RECOVERY_BUDGET_EXHAUSTED",
                      "Automatic switches paused for this 30-minute window; probes continue")
            else:
                for candidate in ordered:
                    if not eligible(candidate):
                        continue
                    try:
                        # Fresh confirmation right before switching. A missing or
                        # invalid record must not abort the cycle.
                        other, _ = self.probe(directory, candidate)
                    except (OSError, ValueError, KeyError, PronetError):
                        continue
                    self.switch_to(directory, selected, plan, candidate, other, True,
                                   "primary down" + (", standby unstable" if health[candidate].get("unstable") else ""))
                    break
                else:
                    # A backup which just returned needs another successful
                    # cycle. Keep monitoring.
                    if not any(row.get("state") == "OK" for row in health.values()):
                        selected["auto_paused"] = True
                        selected["pause_reason"] = "no-healthy-standby"
                        selected["pause_id"] = secrets.token_hex(12)
                        event(directory / "events.jsonl", "NO_HEALTHY_STANDBY",
                              "Committed paths are not confirmed; probes continue")
        elif (active_unstable and not selected.get("auto_paused") and len(switches) < 3
              and self.soft_switch_allowed(selected, now)):
            # The primary answers most probes but keeps dropping for a few
            # minutes. Move NEW connections to a standby that has been fully
            # stable; established sessions are left alone.
            for candidate in ordered:
                if not eligible(candidate, require_proven=True) or health[candidate].get("unstable"):
                    continue
                try:
                    other, _ = self.probe(directory, candidate)
                except (OSError, ValueError, KeyError, PronetError):
                    continue
                self.switch_to(directory, selected, plan, candidate, other, False, "primary unstable")
                break
        selected["utc"] = utc()
        write_json(directory / "selection.json", selected)

    def execute(self, job, progress=_no_progress):
        operation, payload = job["op"], job["payload"]
        pair_id = identifier(job["pair_id"])
        if operation == "inventory":
            return inventory()
        if operation in ("prepare", "start", "benchmark"):
            if payload.get("pair_id") != pair_id:
                raise PronetError("Job pair identity mismatch")
            if operation == "prepare":
                return self.prepare(payload)
            if operation == "start":
                return self.start(payload)
            return self.measure(payload)
        if operation in ("prepare_batch", "start_batch"):
            plans = payload.get("plans")
            if not isinstance(plans, list) or not 1 <= len(plans) <= MAX_BATCH:
                raise PronetError("Invalid carrier batch")
            if any(not isinstance(p, dict) or p.get("pair_id") != pair_id for p in plans):
                raise PronetError("Job pair identity mismatch")
            return self.prepare_batch(plans) if operation == "prepare_batch" else self.start_batch(plans)
        if operation == "benchmark_batch":
            if "profiles" in payload:
                return self.benchmark_batch(pair_id, {"profiles": payload.get("profiles")}, payload.get("long_test") is True,
                                            progress=progress)
            return self.benchmark_batch(pair_id, payload.get("plans"), progress=progress)
        if operation == "resume_batch":
            return self.resume_batch(pair_id, payload.get("profiles"))
        if operation == "probe_batch":
            return self.probe_batch(pair_id, payload.get("profiles"), payload.get("seconds", REACH_WAIT), progress=progress)
        if operation == "retire_batch":
            profiles = payload.get("profiles")
            if not isinstance(profiles, list):
                raise PronetError("Invalid retire batch")
            return self.retire_batch(pair_id, profiles)
        if operation == "switch":
            profile = payload.get("profile")
            if profile is not None and profile not in PROFILES:
                raise PronetError("Unknown profile")
            return self.manual_switch(pair_id, profile)
        if operation == "commit":
            expect = payload.get("expect_active")
            return self.commit(pair_id, payload["profiles"], automatic=payload.get("automatic") is True,
                               rescue=payload.get("rescue") is True,
                               expect_active=expect if expect in PROFILES else None)
        if operation == "retire":
            if payload["profile"] not in PROFILES:
                raise PronetError("Unknown profile")
            if not (self.root / pair_id / payload["profile"] / "plan.json").exists():
                return {"retired": payload["profile"], "already_absent": True}
            self.remove_profile(pair_id, payload["profile"])
            return {"retired": payload["profile"]}
        if operation == "resume":
            profile = payload.get("profile")
            if profile not in PROFILES: raise PronetError("Unknown recovery profile")
            directory = self.root / pair_id / profile
            if (self.root / pair_id / "stopped.json").exists():
                raise PronetError("Operator removed this pair; automatic recovery refused")
            plan = self.validate(read_json(directory / "plan.json"))
            self.start(plan)
            for kind in ("engine", "echo"):
                name = unit_name(pair_id, profile, kind, plan["role"])
                service(name, "reset-failed")
                service(name, "restart")
            return {"resumed": profile}
        if operation == "remeasure":
            profile = payload.get("profile")
            if profile not in PROFILES: raise PronetError("Unknown recovery profile")
            plan = self.validate(read_json(self.root / pair_id / profile / "plan.json"))
            return self.measure(dict(plan, long_test=True))
        if operation == "activate":
            return self.activate(pair_id)
        if operation == "cleanup":
            return self.cleanup(pair_id)
        if operation == "status":
            return self.status(pair_id)
        raise PronetError("Unknown operation; no remote shell is available")
