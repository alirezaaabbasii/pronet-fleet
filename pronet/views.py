"""One summary model for the terminal status and the web dashboard.

Both views are read-only and are built from the overview the coordinator already
keeps; nothing here sends traffic through a tunnel or touches a server.
"""
from __future__ import annotations

import time

from .report import describe, ports_text


def human_bytes(value):
    if not isinstance(value, (int, float)):
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024 or unit == "TB":
            return ("%d %s" % (value, unit)) if unit == "B" else ("%.1f %s" % (value, unit))
        value /= 1024.0


def mbps(bytes_per_second):
    if not isinstance(bytes_per_second, (int, float)):
        return "-"
    return "%.1f" % (bytes_per_second * 8 / 1e6)


def ago(seconds):
    if not isinstance(seconds, (int, float)):
        return "never"
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "%ds ago" % seconds
    if seconds < 3600:
        return "%dm ago" % (seconds // 60)
    if seconds < 86400:
        return "%dh %dm ago" % (seconds // 3600, seconds % 3600 // 60)
    return "%dd ago" % (seconds // 86400)


def pct(value):
    return "%3d%%" % round(value) if isinstance(value, (int, float)) else "  ?%"


def servers(data):
    rows = []
    for node in data.get("nodes", []):
        resource = node.get("metrics", {}).get("resources", {})
        online = node.get("telemetry") == "CURRENT"
        rows.append({"id": node["id"], "name": node["info"].get("name", "?"), "role": node.get("role", "?"),
                     "ip": node["info"].get("public_ip", "?"), "online": online,
                     "seen": ago(node.get("age_seconds")), "cpu": resource.get("cpu_percent"),
                     "ram": resource.get("ram_percent"), "disk": resource.get("disk_percent"),
                     "ram_total_mb": resource.get("ram_total_mb"), "uptime": resource.get("uptime_seconds")})
    return rows


def tunnels(data, now=None):
    now = now or data.get("server_time") or time.time()
    nodes = {node["id"]: node for node in data.get("nodes", [])}
    rows = []
    for pair in data.get("pairs", []):
        if pair.get("state") in ("FAILED", "STOPPED"):
            continue
        request, result, runtime = pair.get("request", {}), pair.get("result", {}), pair.get("runtime", {})
        iran = nodes.get(pair.get("iran"), {})
        foreign = nodes.get(pair.get("foreign"), {})
        iran_on = iran.get("telemetry") == "CURRENT"
        foreign_on = foreign.get("telemetry") == "CURRENT"
        endpoint = result.get("endpoint") or "%s:%s" % (request.get("public_ip"), ports_text(request).replace(" ", ""))
        problems = []
        if pair.get("state") != "ACTIVE":
            status = "SETTING UP"
        elif not iran_on:
            status = "UNKNOWN"
            problems.append("Iran server is not reporting (offline, rebooting or out of traffic).")
        elif runtime.get("link") == "UP":
            status = "UP"
        else:
            status = "DOWN"
            problems.append("The active carrier did not answer the last health probe.")
        if pair.get("state") == "ACTIVE" and not foreign_on:
            problems.append("Foreign server is not reporting (offline, rebooting or out of traffic).")
        inbound = runtime.get("inbound", "UNKNOWN")
        if pair.get("state") == "ACTIVE" and inbound == "refused":
            states = runtime.get("inbound_ports") or {}
            closed = [p for p, state in states.items() if state == "refused"] if isinstance(states, dict) else []
            for number in closed or [ports_text(request)]:
                problems.append("Nothing listens on port %s on the foreign server: create the panel inbound (0.0.0.0:%s)."
                                % (number, number))
        if runtime.get("recovery_paused"):
            problems.append("Switching is paused; existing carriers stay running and monitored. A recovered primary or stable standby re-arms it when the switch budget permits.")
        active = runtime.get("active") or result.get("active")
        standby = []
        for name, health in (runtime.get("standby_health") or {}).items():
            if name == active or not isinstance(health, dict):
                continue
            ok = health.get("state") == "OK"
            warming = ok and "healthy_probes" in health and health["healthy_probes"] < 2
            standby.append({"name": name, "description": describe(name), "ok": ok,
                            "text": ("carrier OK; qualifying %s/2 probes" % health["healthy_probes"]) if warming
                            else ("carrier ready, rtt %s ms" % _num(health.get("rtt_ms"))) if ok
                            else "NOT answering (%s failed probes)" % health.get("failures", "?")})
            if not ok:
                problems.append("Standby %s is not answering; there is no working fallback right now." % name)
        traffic = runtime.get("traffic") or {}
        health = runtime.get("health") or {}
        switches = runtime.get("switches") or []
        rows.append({
            "id": pair["id"], "name": request.get("name", "?"), "state": pair.get("state"), "status": status,
            "endpoint": endpoint, "port": ports_text(request),
            "iran": iran.get("info", {}).get("name", "?"), "foreign": foreign.get("info", {}).get("name", "?"),
            "active": active, "active_description": describe(active) if active else "-",
            "rtt": runtime.get("rtt_ms") if status == "UP" else None,
            "standby": standby,
            "inbound": {"open": "listening", "refused": "NOT listening", "unconfirmed": "not confirmed"}.get(inbound, "unknown"),
            "inbound_ok": inbound == "open",
            "traffic": {"down_total": human_bytes(traffic.get("tx_bytes")), "up_total": human_bytes(traffic.get("rx_bytes")),
                        "down_now": mbps(traffic.get("tx_Bps")), "up_now": mbps(traffic.get("rx_Bps")),
                        "connections": traffic.get("connections_active"), "since": traffic.get("utc")},
            "failover": ("probe every %ss, failed-probe threshold ~%ss; policy=%s; carrier echo only"
                         % (health.get("probe_seconds", "?"), health.get("failover_seconds", "?"),
                            health.get("recovery_policy", "unknown (older agent)"))) if health else "-",
            "last_switch": ago(now - switches[-1]) if switches else "never",
            "events": runtime.get("events") or [],
            "problems": problems,
            "progress": result.get("progress"),
        })
    return rows


def _num(value):
    return "%d" % round(value) if isinstance(value, (int, float)) else "-"
