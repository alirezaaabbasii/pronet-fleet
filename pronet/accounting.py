"""Counter-only nftables accounting. Never flushes or changes a policy/NAT rule."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import pathlib
import shutil
import time

from .common import ROOT, PronetError, command, lock, read_json, utc, write_json


def public_interfaces():
    raw = json.loads(command(["ip", "-j", "-4", "address", "show"]).stdout)
    result = []
    for link in raw:
        # ip -j -4 address omits link_type on iproute2/Ubuntu 24.04.
        # Public IPv4 addresses may also live on VLAN/bond/PPP interfaces.
        if "LOOPBACK" in link.get("flags", []): continue
        ips = sorted({row["local"] for row in link.get("addr_info", []) if ipaddress.ip_address(row["local"]).is_global})
        if ips: result.append((link["ifname"], ips))
    return result


def counter_name(ip, direction):
    return "p_" + str(ipaddress.IPv4Address(ip)).replace(".", "_") + "_" + direction


def enable(node_id):
    from .common import identifier
    identifier(node_id)
    if not shutil.which("nft"): raise PronetError("nftables is unavailable; IP wire counters are UNKNOWN")
    table = "pronetf_" + node_id[:8]
    owner_path = ROOT / "counter-owner.json"
    with lock(ROOT / "counter-setup.lock"):
        previous = command(["nft", "-j", "list", "table", "netdev", table], check=False)
        owner = read_json(owner_path, {})
        if previous.returncode == 0 and owner.get("table") != table:
            raise PronetError("Counter table exists without an ownership record; it was not adopted")
        data = json.loads(previous.stdout)["nftables"] if previous.returncode == 0 else []
        chains = {row["chain"]["name"] for row in data if "chain" in row}
        counters = {row["counter"]["name"] for row in data if "counter" in row and "name" in row["counter"]}
        batch = [] if previous.returncode == 0 else ["add table netdev " + table]
        for interface, addresses in public_interfaces():
            suffix = hashlib.sha256(interface.encode()).hexdigest()[:8]
            for direction, hook, priority in (("in", "ingress", -500), ("out", "egress", 500)):
                chain = direction + "_" + suffix
                if chain not in chains:
                    batch.append(f'add chain netdev {table} {chain} {{ type filter hook {hook} device {json.dumps(interface)} priority {priority}; policy accept; }}')
                for address in addresses:
                    name = counter_name(address, direction)
                    if name in counters: continue
                    batch.append(f"add counter netdev {table} {name}")
                    field = "daddr" if direction == "in" else "saddr"
                    batch.append(f"add rule netdev {table} {chain} ip {field} {address} counter name {name}")
                    counters.add(name)
        if batch:
            text = "\n".join(batch) + "\n"
            command(["nft", "-c", "-f", "-"], input=text)
            if not owner:
                write_json(owner_path, {"table": table, "started_utc": utc()})
            command(["nft", "-f", "-"], input=text)
    return {"table": table, "interfaces": public_interfaces()}


def accumulate(previous, raw, boot_id, stamp):
    totals, rates = {}, {}
    reset = previous.get("boot_id") != boot_id
    elapsed = stamp - previous.get("stamp", stamp)
    for name, value in raw.items():
        before = previous.get("raw", {}).get(name)
        delta = value if before is None or reset or value < before else value - before
        totals[name] = previous.get("totals", {}).get(name, 0) + delta
        rates[name] = round(delta / elapsed, 1) if before is not None and not reset and value >= before and elapsed > .5 else None
    # Preserve retired-IP totals across temporary address removal.
    for name, value in previous.get("totals", {}).items(): totals.setdefault(name, value)
    return {"raw": raw, "totals": totals, "boot_id": boot_id, "stamp": stamp, "rates": rates,
            "since_utc": previous.get("since_utc", utc())}


_NAT_CACHE = {"stamp": 0.0, "value": []}
NAT_CACHE_SECONDS = 60


def nat_reservations():
    """Only NAT reservations are needed here. A full inventory() runs ss -p,
    iptables-save, nft -j and walks every /proc entry; doing that on every
    10 s heartbeat cost real CPU on busy gateways. NAT rules change rarely."""
    current = time.monotonic()
    if current - _NAT_CACHE["stamp"] >= NAT_CACHE_SECONDS or not _NAT_CACHE["stamp"]:
        from .runtime import inventory
        _NAT_CACHE["value"] = inventory()["nat_reserved"]
        _NAT_CACHE["stamp"] = current
    return _NAT_CACHE["value"]


def snapshot(identity):
    assigned = {}
    for path in (ROOT / "pairs").glob("*/selection.json"):
        if (path.parent / "stopped.json").exists(): continue
        selection = read_json(path)
        if not selection.get("profiles"): continue
        plan = read_json(path.parent / selection["profiles"][0] / "plan.json")
        if plan["role"] == "iran":
            assigned[plan.get("gateway_bind_ip", plan["bind_ip"])] = "ASSIGNED: " + path.parent.name[:8]
    legacy = read_json("/etc/pronet-monitor/config.json", {})
    for row in legacy.get("routes", []) + legacy.get("legacy", []):
        if row.get("public"): assigned.setdefault(row["public"], "LEGACY_REGISTERED")
    owner = read_json(ROOT / "counter-owner.json", {})
    table = owner.get("table", "pronet_monitor")
    counters = {}
    if shutil.which("nft"):
        result = command(["nft", "-j", "list", "table", "netdev", table], check=False)
        if result.returncode == 0:
            counters = {row["counter"]["name"]: row["counter"]["bytes"] for row in json.loads(result.stdout)["nftables"]
                        if "counter" in row and "name" in row["counter"]}
    boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if counters:
        with lock(ROOT / "counter-sample.lock"):
            previous = read_json(ROOT / "counter-ledger.json", {})
            if previous.get("table") != table: previous["raw"] = {}
            current = accumulate(previous, counters, boot_id, time.time())
            current["table"] = table
            write_json(ROOT / "counter-ledger.json", current)
    else:
        current = {"totals": {}, "rates": {}}
    info = {"nat_reserved": nat_reservations()}
    rows = []
    for _, addresses in public_interfaces():
        for address in addresses:
            role = assigned.get(address)
            if role is None and address == identity["bind_ip"]: role = "PRIMARY / CARRIER / SSH"
            if role is None:
                role = "UNMANAGED_NAT" if any(ipaddress.ip_address(address) in ipaddress.ip_network(row["destination"]) for row in info["nat_reserved"]) else "UNASSIGNED"
            names = [counter_name(address, value) for value in ("in", "out")]
            rates = [current["rates"].get(name) for name in names]
            activity = "UNKNOWN" if any(value is None for value in rates) else "ACTIVE" if sum(rates) else "IDLE"
            rows.append({"ip": address, "assignment": role, "activity": activity,
                         "rx_bytes": current["totals"].get(names[0]), "tx_bytes": current["totals"].get(names[1]),
                         "rx_Bps": rates[0], "tx_Bps": rates[1]})
    return {"ips": rows, "counter_source": table if counters else "UNAVAILABLE", "since_utc": current.get("since_utc"),
            "note": "Wire counters include SSH, carriers and scans. Durable sampled totals can miss traffic immediately before power loss; they are not a billing ledger."}
