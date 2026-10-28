from __future__ import annotations

import ipaddress
import math
import statistics

from .common import PronetError, identifier, inbound_ports, ipv4, port, port_list

# Enabled profiles have real configuration renderers. Other research entries are
# deliberately not advertised as supported adapters.
PROFILES = {
    "bp-l3-pck": {"engine": "backpack", "kind": "l3", "carrier": "pck", "family": "raw-tcp"},
    "bp-l3-quic": {"engine": "backpack", "kind": "l3", "carrier": "quic", "family": "udp"},
    "bp-l3-udp": {"engine": "backpack", "kind": "l3", "carrier": "udp", "family": "udp"},
    "bp-stealth": {"engine": "backpack", "kind": "reverse", "carrier": "stealth", "family": "tcp"},
    "bp-quic": {"engine": "backpack", "kind": "reverse", "carrier": "quic", "family": "udp"},
    "bp-kcp": {"engine": "backpack", "kind": "reverse", "carrier": "kcp", "family": "udp"},
    "bp-pck": {"engine": "backpack", "kind": "reverse", "carrier": "pck", "family": "raw-tcp"},
    "frp-tls": {"engine": "frp", "kind": "reverse", "carrier": "tcp", "family": "tcp"},
    "frp-quic": {"engine": "frp", "kind": "reverse", "carrier": "quic", "family": "udp"},
    "chisel": {"engine": "chisel", "kind": "reverse", "carrier": "ssh", "family": "tcp"},
    "bp-direct-stealth": {"engine": "backpack", "kind": "direct", "carrier": "stealth", "family": "tcp"},
    "bp-l3-pck-reverse": {"engine": "backpack", "kind": "l3", "carrier": "pck", "family": "raw-tcp", "direction": "foreign-dials"},
    "bp-l3-quic-reverse": {"engine": "backpack", "kind": "l3", "carrier": "quic", "family": "udp", "direction": "foreign-dials"},
    "bp-l3-udp-reverse": {"engine": "backpack", "kind": "l3", "carrier": "udp", "family": "udp", "direction": "foreign-dials"},
    "bp-l3-pck-fec": {"engine": "backpack", "kind": "l3", "carrier": "pck", "family": "raw-tcp", "fec": True},
    "bp-l3-udp-fec": {"engine": "backpack", "kind": "l3", "carrier": "udp", "family": "udp", "fec": True},
    "bp-l3-sni": {"engine": "backpack", "kind": "l3", "carrier": "sni", "family": "raw-tcp"},
    "bp-l3-xdi": {"engine": "backpack", "kind": "l3", "carrier": "xdi", "family": "icmp", "experimental": True},
    "rathole-noise": {"engine": "rathole", "kind": "reverse", "carrier": "noise", "family": "tcp"},
    "wstunnel-wss": {"engine": "wstunnel", "kind": "reverse", "carrier": "websocket", "family": "tcp"},
    "wstunnel-h2": {"engine": "wstunnel", "kind": "reverse", "carrier": "http2", "family": "tcp"},
    # Append only: existing service/interface indices must remain stable.
    "gre": {"engine": "native-gre", "kind": "l3", "carrier": "gre", "family": "gre"},
    "paqet": {"engine": "paqet", "kind": "direct", "carrier": "kcp", "family": "raw-tcp"},
    "backhaul-tcp": {"engine": "backhaul", "kind": "reverse", "carrier": "tcp", "family": "tcp"},
    "backhaul-tcpmux": {"engine": "backhaul", "kind": "reverse", "carrier": "tcpmux", "family": "tcp"},
    "parsa-spoof": {"engine": "parsa-spoof", "kind": "l3", "carrier": "tcp", "family": "spoof", "conditional": True, "emergency": True},
}
EMERGENCY_PROFILES = [name for name, spec in PROFILES.items() if spec.get("emergency")]
NORMAL_PROFILES = [name for name, spec in PROFILES.items() if not spec.get("emergency")]
DEFAULT_PROFILES = [name for name in NORMAL_PROFILES if not PROFILES[name].get("experimental")]


def validate_request(data):
    if not isinstance(data, dict):
        raise PronetError("Request must be an object")
    allowed = {"name", "public_ip", "bind_ip", "inbound_port", "inbound_ports", "profiles", "standby", "direction", "sni", "quality", "spoof", "emergency", "test_only", "advanced", "full_test", "gaming"}
    if set(data) - allowed:
        raise PronetError("Unknown setup field")
    name = data.get("name", "")
    if not isinstance(name, str) or not 1 <= len(name) <= 60 or any(ord(c) < 32 for c in name):
        raise PronetError("Name must contain 1–60 printable characters")
    advanced = data.get('advanced', False)
    full_test = data.get('full_test', False)
    if type(advanced) is not bool or type(full_test) is not bool:
        raise PronetError('Invalid explicit full-test mode')
    emergency = data.get("emergency", False)
    test_only = data.get("test_only", False)
    if type(emergency) is not bool or type(test_only) is not bool or (test_only and not emergency):
        raise PronetError("Test-only mode belongs to the manual emergency section")
    gaming = data.get('gaming', False)
    if type(gaming) is not bool or (gaming and (emergency or test_only)):
        raise PronetError('Invalid gaming mode')
    from .gaming import GAMING_PROFILES
    profiles = data.get("profiles", GAMING_PROFILES if gaming else EMERGENCY_PROFILES if emergency else DEFAULT_PROFILES)
    if (not isinstance(profiles, list) or not 1 <= len(profiles) <= len(PROFILES)
            or len(set(profiles)) != len(profiles) or any(p not in PROFILES for p in profiles)):
        raise PronetError("Choose supported, unique profiles")
    if gaming and any(p not in GAMING_PROFILES for p in profiles):
        raise PronetError('Gaming requires supported datagram-capable L3 carriers')
    if not advanced and any(bool(PROFILES[name].get("emergency")) != emergency for name in profiles):
        raise PronetError("Emergency carriers must be tested separately using pronet emergency")
    standby = data.get("standby", 1)
    if type(standby) is not int or not 0 <= standby <= 1:
        raise PronetError("At most one warm standby is supported")
    direction = data.get("direction", "iran-dials")
    if direction not in ("iran-dials", "foreign-dials"):
        raise PronetError("Invalid L3 dial direction")
    quality = data.get("quality", "balanced")
    if quality not in ("quick", "balanced", "thorough"): raise PronetError("Invalid test quality mode")
    sni = data.get("sni", "")
    import re
    if sni and (not isinstance(sni, str) or len(sni) > 253 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", sni)):
        raise PronetError("Invalid TLS SNI")
    if "inbound_ports" in data:
        ports = inbound_ports(data)
    else:
        ports = port_list(data.get("inbound_port", 2053))
    spoof = validate_spoof(data.get("spoof", {}))
    return dict(gaming=gaming, advanced=advanced, full_test=full_test, emergency=emergency, test_only=test_only, spoof=spoof, name=name, public_ip=ipv4(data["public_ip"]), bind_ip=ipv4(data.get("bind_ip", data["public_ip"])),
                inbound_port=ports[0], inbound_ports=ports, profiles=profiles,
                standby=standby, direction=direction, sni=sni, quality=quality)


def validate_spoof(value):
    if not isinstance(value, dict) or (value and set(value) != {"iran", "foreign"}):
        raise PronetError("Spoof requires both Iran and foreign source IPv4 addresses")
    return {role: ipv4(value[role]) for role in ("iran", "foreign")} if value else {}


def validate_profile(plan):
    if not isinstance(plan, dict):
        raise PronetError("Invalid profile plan")
    if type(plan.get('gaming',False)) is not bool:
        raise PronetError('Invalid gaming plan')
    if plan.get('gaming'):
        from .gaming import GAMING_PROFILES
        if plan.get('profile') not in GAMING_PROFILES:
            raise PronetError('Gaming cannot use a TCP-only carrier')
    identifier(plan["pair_id"])
    if plan.get("profile") not in PROFILES:
        raise PronetError("Unsupported profile")
    if plan.get("role") not in ("iran", "foreign"):
        raise PronetError("Invalid node role")
    for key in ("iran_ip", "foreign_ip", "bind_ip"):
        ipv4(plan[key])
    for key in ("gateway_bind_ip", "gateway_public_ip"):
        if key in plan: ipv4(plan[key])
    ports = [port(plan[k]) for k in ("control_port", "echo_port", "health_port", "data_port",
                                   "bridge_data_port", "bridge_health_port", "probe_front_port")]
    ports += inbound_ports(plan)
    if len(ports) != len(set(ports)):
        raise PronetError("Profile ports overlap")
    if not isinstance(plan.get("token"), str) or len(plan["token"]) != 64:
        raise PronetError("Invalid profile credential")
    try:
        bytes.fromhex(plan["token"])
        subnet = ipaddress.ip_network(plan["subnet"])
    except ValueError:
        raise PronetError("Invalid subnet or credential")
    if not subnet.is_private or subnet.version != 4 or subnet.prefixlen != 30:
        raise PronetError("Tunnel requires a private IPv4 /30")
    if plan.get("direction") not in ("iran-dials", "foreign-dials"):
        raise PronetError("Invalid direction")
    if plan["profile"] == "parsa-spoof":
        if not validate_spoof(plan.get("spoof", {})):
            raise PronetError("Spoof source addresses not configured; no packets sent")
        if set(plan["spoof"].values()) & {plan["iran_ip"], plan["foreign_ip"]}:
            raise PronetError("Spoof sources must differ from both real server addresses")
    return plan


def tunnel_ips(plan):
    net = ipaddress.ip_network(plan["subnet"])
    return str(net.network_address + 1), str(net.network_address + 2)


def iface(plan):
    # 15-char Linux limit; profile index is fixed and all IDs are validated.
    identifier(plan["pair_id"])
    return "pn" + plan["pair_id"][:10] + format(list(PROFILES).index(plan["profile"]), "x")


def ranking(results, standby=1, all_results=False):
    accepted = []
    for row in results:
        if row.get('gaming'):
            from .gaming import score
            value=score(row)
            if value is not None:
                tail=max(s['p95_ms'] for s in row['gaming_stages'].values())
                accepted.append(dict(row,score=round(100000/(1-value),3),p95_ms=round(tail,3)))
            continue
        # Absence of a measurement must never become a zero or a successful test.
        if not row.get("passed") or not row.get("echo_ms") or row.get("success_ratio") != 1:
            continue
        rates = [row.get("upload_mbps"), row.get("download_mbps")]
        samples = row["echo_ms"]
        if any(not isinstance(x, (int, float)) or not math.isfinite(x) or x <= 0 for x in rates):
            continue
        if any(not isinstance(x, (int, float)) or not math.isfinite(x) or x < 0 for x in samples):
            continue
        if not all(row.get(x) for x in ("half_close", "after_idle", "integrity")):
            continue
        median = statistics.median(samples)
        tail = sorted(samples)[max(0, math.ceil(len(samples) * .95) - 1)]
        # Geometric speed reward; penalize tail latency and jitter rather than
        # accepting an isolated fast burst as the stable winner.
        score = math.log1p(min(rates)) * 100 / (1 + tail / 200 + max(0, tail - median) / 100)
        accepted.append(dict(row, score=round(score, 3), p95_ms=round(tail, 3)))
    accepted.sort(key=lambda row: (-row["score"], row["profile"]))
    if all_results:
        return accepted
    if not accepted:
        return []
    winners = [accepted[0]]
    # Each standby comes from a transport family not used yet when a good
    # enough one exists, so one blocked protocol cannot take down every path.
    for _ in range(max(0, min(2, standby))):
        rest = [r for r in accepted if r not in winners]
        if not rest:
            break
        used = {PROFILES[r["profile"]]["family"] for r in winners}
        winners.append(next((r for r in rest if PROFILES[r["profile"]]["family"] not in used
                             and r["score"] >= accepted[0]["score"] * .5), rest[0]))
    return winners
