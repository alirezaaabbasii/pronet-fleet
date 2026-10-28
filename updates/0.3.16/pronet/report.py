"""Human-readable setup progress and final reports (plain English, terminal-safe)."""
from __future__ import annotations

import math
import time

from .model import PROFILES, ranking


def ports_text(request):
    """"2053" for one client port, "2053, 2083" for several."""
    return ", ".join(str(x) for x in request.get("inbound_ports") or [request.get("inbound_port")])

DESCRIPTIONS = {
    "paqet": "Independent Paqet: encrypted KCP over raw TCP",
    "backhaul-tcp": "Independent Backhaul reverse TCP (application encryption recommended)",
    "backhaul-tcpmux": "Independent Backhaul reverse TCP with multiplexing",
    "parsa-spoof": "Parsa spoofed TCP + WireGuard (requires configured source IPs and both-way egress)",
    "gre": "Native Linux GRE over IP protocol 47 (no BackPack)",
    "bp-l3-pck": "BackPack L3 over raw TCP (PCK)",
    "bp-l3-quic": "BackPack L3 over QUIC",
    "bp-l3-udp": "BackPack L3 over UDP",
    "bp-stealth": "BackPack reverse, stealth TCP",
    "bp-quic": "BackPack reverse over QUIC",
    "bp-kcp": "BackPack reverse over KCP/UDP",
    "bp-pck": "BackPack reverse over raw TCP (PCK)",
    "frp-tls": "FRP reverse tunnel over TLS/TCP",
    "frp-quic": "FRP reverse tunnel over QUIC",
    "chisel": "Chisel reverse over SSH/HTTP",
    "bp-direct-stealth": "BackPack direct, stealth TCP",
    "bp-l3-pck-reverse": "BackPack L3 raw TCP, foreign dials",
    "bp-l3-quic-reverse": "BackPack L3 QUIC, foreign dials",
    "bp-l3-udp-reverse": "BackPack L3 UDP, foreign dials",
    "bp-l3-pck-fec": "BackPack L3 raw TCP + FEC",
    "bp-l3-udp-fec": "BackPack L3 UDP + FEC",
    "bp-l3-sni": "BackPack L3, SNI-shaped TCP",
    "bp-l3-xdi": "BackPack L3 over ICMP (experimental)",
    "rathole-noise": "Rathole reverse, Noise-encrypted TCP",
    "wstunnel-wss": "wstunnel reverse over WebSocket/TLS",
    "wstunnel-h2": "wstunnel reverse over HTTP/2 TLS",
}
FAMILIES = {"tcp": "TCP", "udp": "UDP", "raw-tcp": "raw TCP", "icmp": "ICMP", "gre": "GRE", "spoof": "IP spoofing"}


def describe(profile):
    return DESCRIPTIONS.get(profile, profile)


def family(profile):
    return FAMILIES.get(PROFILES.get(profile, {}).get("family"), "?")


def duration(seconds):
    if seconds is None or not math.isfinite(seconds) or seconds < 0:
        return "?"
    seconds = int(round(seconds))
    return "%dm%02ds" % divmod(seconds, 60) if seconds >= 60 else "%ds" % seconds


def mbps(value):
    return "-" if not isinstance(value, (int, float)) else ("%.1f" % value)


def reason(row):
    """One short, user-facing reason for a failed carrier."""
    if row.get("passed"):
        return ""
    text = row.get("reason") or row.get("error") or ""
    if text:
        if "no end-to-end connectivity" in text or text == "unreachable":
            return "no connectivity (blocked or filtered on this route)"
        if "engine exited" in text:
            return "engine exited during start (see logs)"
        if "reverse direction" in text:
            return "works Iran->foreign only, reverse direction failed"
        return text[:110]
    if row.get("echo_ms") and row.get("success_ratio", 0) < 1:
        return "unstable (%d%% of probes answered)" % round(100 * row.get("success_ratio", 0))
    if not row.get("echo_ms"):
        return "no connectivity (blocked or filtered on this route)"
    if not row.get("half_close"):
        return "half-close not preserved"
    if not row.get("integrity"):
        return "data integrity check failed"
    if not row.get("after_idle"):
        return "connection dropped after idle"
    return "did not pass"


def _p95(samples):
    samples = [x for x in samples or [] if isinstance(x, (int, float))]
    if not samples:
        return None
    return sorted(samples)[max(0, math.ceil(len(samples) * .95) - 1)]


ACTIVE_STAGES = ("preparing", "starting", "connecting", "measuring", "reverse")
PHASE_LABELS = {"latency": "latency test", "upload": "upload test", "download": "download test",
                "idle": "idle check", "done": "finishing", "connected": "connected"}
SETUP_STAGES = {"PAIRED": (1, "Checking both servers"), "PREFLIGHT": (1, "Checking both servers"),
                "STAGED": (4, "Installing the selected carriers"), "VERIFYING": (4, "Verifying and opening the tunnel"),
                "ROLLING_BACK": (None, "Rolling back"), "STOPPING": (None, "Stopping")}


def _measure_fraction(row):
    """Real progress inside one benchmark: probes answered, bytes moved, idle seconds."""
    pct = (row.get("pct") or 0) / 100.0
    return {"latency": .3 * pct, "upload": .3 + .25 * pct, "download": .55 + .25 * pct,
            "idle": .8 + .2 * pct, "done": 1.0}.get(row.get("phase"), 0.0)


def carrier_progress(name, row, now, phase="screen"):
    """(percent, label) of one carrier in the live view."""
    stage = row.get("stage")
    if phase == "soak":
        if stage == "starting":
            return 3, "starting engines"
    elif stage == "preparing":
        return 4, "preparing engines"
    elif stage == "starting":
        return 10, "starting engines"
    elif stage == "connecting":
        if row.get("phase") == "connected":
            return 35, "connected"
        window = row.get("window") or 20
        waited = max(0.0, now - (row.get("since") or now))
        return 10 + int(25 * min(1.0, waited / window)), "connecting  %ds / %ds" % (min(waited, window), window)
    if stage in ("measuring", "reverse"):
        fraction = _measure_fraction(row)
        if row.get("phase") is None:
            label = "queued"
        elif row.get("phase") == "latency" and row.get("pct") == 100:
            label = "waiting for the speed-test slot"
        else:
            label = PHASE_LABELS.get(row.get("phase"), row.get("phase") or "")
        if phase == "soak":
            runs = row.get("runs") or 1
            done = (row.get("run") or 1) - 1
            if runs > 1:
                label += "  (run %d/%d)" % (done + 1, runs)
            return 5 + int(95 * (done + fraction) / runs), label
        l3 = PROFILES.get(name, {}).get("kind") == "l3"
        if stage == "reverse":
            return 93 + int(7 * fraction), "reverse direction " + label
        return 35 + int((58 if l3 else 65) * fraction), label
    return 0, stage or ""


def _summary_line(row):
    return "%5s / %-5s Mbps   p95 %s ms" % (mbps(row.get("upload_mbps")), mbps(row.get("download_mbps")),
                                            _fmt(_p95(row.get("echo_ms"))))


def progress_lines(pair, now=None, style=None):
    """Live view while a pair is being set up."""
    from .ui import Style, wrap
    style = style or Style()
    now = now or time.time()
    result = pair.get("result", {})
    state = pair.get("state", "?")
    request = pair.get("request", {})
    started = result.get("timing", {}).get("started")
    elapsed = duration(now - started) if started else "-"
    title = "%s  (%s)" % (request.get("name", "?"), pair.get("id", "")[:8])
    lines = ["  Tunnel " + style.paint(title, "1")]
    if state == "UNPAIRED":
        lines.append("  Waiting for the foreign server to join...")
        return lines
    live = result.get("live") or {}
    progress = result.get("progress", {})
    number, label = SETUP_STAGES.get(state, (None, state.lower()))
    if state == "TRIAL":
        if result.get("phase") == "longer-test":
            number, label = 3, "Longer test of the best carriers"
        else:
            number, label = 2, "Testing every carrier"
            if live.get("batch") and live.get("batches"):
                label += "  (group %d of %d)" % (live["batch"], live["batches"])
    lines.append("  " + style.paint(("Step %d/4  " % number if number else "") + label, "1;36")
                 + "   " + style.dim("elapsed " + elapsed))
    rows = result.get("results", [])
    if progress.get("total"):
        tested, total = progress.get("tested", 0), progress["total"]
        finished = sum(1 for r in (live.get("carriers") or {}).values() if r.get("stage") in ("passed", "failed"))
        if live.get("phase") == "screen":
            tested = max(tested, finished)
        lines.append("  [%s] %d/%d carriers tested, %d passed" % (
            style.bar(100 * tested / max(1, total), 30), tested, total, sum(1 for r in rows if r.get("passed"))))
    carriers = live.get("carriers") or {}
    order = live.get("order") or list(carriers)
    phase = live.get("phase", "screen")
    active = [name for name in order if carriers.get(name, {}).get("stage") in ACTIVE_STAGES]
    if active:
        lines += ["", style.section("NOW TESTING")]
        for name in active:
            pct, text = carrier_progress(name, carriers[name], now, phase)
            lines.append("    %-19s [%s] %3d%%  %s" % (name, style.bar(pct), pct, style.dim(text)))
    if phase == "soak" and carriers:
        done = [name for name in order if carriers.get(name, {}).get("stage") in ("qualified", "failed")]
        if done:
            lines += ["", style.section("LONGER TEST")]
            soaked = {row["profile"]: row.get("soak", {}) for row in rows if row.get("soak")}
            for name in done:
                soak = soaked.get(name, {})
                if carriers[name]["stage"] == "qualified":
                    lines.append("    %s %-17s %s" % (style.ok(""), name, _summary_line(soak)))
                else:
                    lines.append("    %s %-17s %s" % (style.bad(""), name, reason(soak) if soak else "did not pass"))
    passed = [row for row in rows if row.get("passed")]
    failed = [row for row in rows if not row.get("passed")]
    if passed or failed:
        lines += ["", style.section("RESULTS")]
        for row in passed:
            lines.append("    %s %-17s %s" % (style.ok(""), row["profile"], _summary_line(row)))
        groups = {}
        for row in failed:
            groups.setdefault(reason(row), []).append(row.get("profile", "?"))
        for text, names in sorted(groups.items(), key=lambda item: -len(item[1])):
            if len(names) <= 2:
                lines.append("    %s %-17s %s" % (style.bad(""), ", ".join(names), style.dim(text)))
            else:
                lines.append("    %s %d %s" % (style.bad(""), len(names), text))
                lines += ["      " + style.dim(line.strip()) for line in wrap(names, 6)]
    waiting = [name for name in order if carriers.get(name, {}).get("stage") == "waiting"]
    if waiting and phase == "screen":
        lines += ["", "  " + style.dim("Waiting: %d more carriers" % len(waiting))]
    activity = [text for key, text in sorted((live.get("now") or {}).items()) if isinstance(text, str) and text]
    if activity:
        # A moving mark shows the setup is alive even during long single steps.
        frames = ("\u280b", "\u2819", "\u2839", "\u2838", "\u283c", "\u2834", "\u2826", "\u2827", "\u2807", "\u280f") \
            if style.fancy else ("|", "/", "-", "\\")
        mark = style.paint(frames[int(now) % len(frames)], "1;36")
        lines.append("")
        lines += ["  %s %s" % (mark, style.paint("Now: " + text, "36")) for text in activity]
    return lines


def _fmt(value):
    return "-" if value is None else "%d" % round(value)


def blocked_patterns(rows, request=None):
    """Plain-language patterns behind failures, only when the data shows them."""
    request = request or {}
    def dial(name):
        spec = PROFILES.get(name, {})
        if spec.get("kind") == "reverse":
            return "foreign"
        if spec.get("kind") == "direct":
            return "iran"
        return "iran" if spec.get("direction", request.get("direction", "iran-dials")) == "iran-dials" else "foreign"
    blocked = lambda row: reason(row) == "no connectivity (blocked or filtered on this route)"
    udp = [r for r in rows if PROFILES.get(r.get("profile"), {}).get("family") in ("udp", "icmp")]
    tcp = [r for r in rows if PROFILES.get(r.get("profile"), {}).get("family") in ("tcp", "raw-tcp")]
    patterns, explained = [], set()
    if len(udp) >= 2 and not any(r.get("passed") for r in udp) and sum(1 for r in udp if blocked(r)) >= len(udp) - 1:
        patterns.append("UDP/QUIC does not get through on this route")
        explained.update(r["profile"] for r in udp)
    from_iran = [r for r in tcp if dial(r["profile"]) == "iran"]
    if (len(from_iran) >= 2 and all(blocked(r) for r in from_iran)
            and any(r.get("passed") for r in tcp if dial(r["profile"]) == "foreign")):
        patterns.append("connections started by Iran are blocked (filtering, or a firewall on the foreign server)")
        explained.update(r["profile"] for r in from_iran)
    return patterns, explained


def final_report(pair, nodes=None, style=None, details=False, dashboard=None):
    """Summary shown when setup finishes (success or failure)."""
    from .ui import Style, wrap
    style = style or Style()
    result = pair.get("result", {})
    request = pair.get("request", {})
    rows = result.get("results", [])
    timing = result.get("timing", {})
    took = duration(timing["finished"] - timing["started"]) if timing.get("finished") and timing.get("started") else "?"
    passed = [row for row in rows if row.get("passed")]
    failed = [row for row in rows if not row.get("passed")]
    port = ports_text(request)
    endpoint = result.get("endpoint") or "%s:%s" % (request.get("public_ip"), port.replace(" ", ""))
    name = request.get("name", "")
    tested = "%d tested in %s: %d passed, %d failed" % (len(rows), took, len(passed), len(failed))
    patterns, explained = blocked_patterns(rows, request)
    def failure_lines():
        out = []
        for text in patterns:
            main, _, note = text.partition(" (")
            out.append(style.field("Pattern", main))
            if note:
                out.append(" " * 18 + style.dim("(" + note))
        others = {}
        for row in failed:
            if row.get("profile") not in explained:
                others.setdefault(reason(row), []).append(row.get("profile", "?"))
        for text, names in sorted(others.items(), key=lambda item: -len(item[1])):
            if len(names) <= 2:
                out.append(style.field("Failed", "%s: %s" % (", ".join(names), text)))
            else:
                out.append(style.field("Failed", text + ":"))
                out += [" " * 18 + line.lstrip() for line in wrap(names, 18)]
        return out
    out = []
    if result.get("phase") == "emergency-tested":
        out += style.banner("EMERGENCY TEST COMPLETE", name)
        out += ["", style.field("Result", "passed" if result.get("test_passed") else "no emergency carrier qualified")]
        out += [style.field("Activation", "test only; no client gateway was activated"), "", style.section("TEST")]
        out += [style.field("Carriers", tested)]
        out += failure_lines()
        out += ["", "Emergency test resources were cleaned up on both servers."]
        if details: out += _details(rows, style)
        return out
    if pair.get("state") != "ACTIVE":
        out += style.banner("SETUP DID NOT COMPLETE", name)
        out += ["", style.field("Reason", result.get("error") or "state " + str(pair.get("state")), 2, 16)]
        out += ["", style.section("TEST"), style.field("Carriers", tested)]
        out += failure_lines()
        if result.get("failed_phase"):
            out.append(style.field("Stage", result["failed_phase"]))
        if result.get("cleanup_confirmed") is True:
            out += ["", "  Setup failed. Both servers were cleaned up."]
        else:
            out += ["", "  Setup failed. Cleanup is NOT confirmed; some services may remain."]
        for warning in result.get("warnings", []):
            out.append(style.field("Warning", warning))
        out += ["  Next: inspect the reason above and sudo pronet logs ID before creating a new tunnel."]
        if details:
            out += _details(rows, style)
        return out
    selected = result.get("selected", [])
    qualified = [row["soak"] for row in rows if row.get("soak", {}).get("passed")]
    scored = {row["profile"]: row for row in ranking(qualified, all_results=True)}
    out += style.banner("EMERGENCY TUNNEL READY" if request.get("emergency") else "TUNNEL READY", name)
    inbound = result.get("inbound") or pair.get("runtime", {}).get("inbound")
    out += ["", style.section("CONNECT"), style.field("Clients", endpoint)]
    if inbound == "open":
        out.append(style.field("Panel", "inbound on the foreign server, port %s: %s" % (port, style.ok("listening"))))
    else:
        out.append(style.field("Panel", style.warn("nothing listens on port %s on the foreign server" % port)))
    out += ["", style.section("CARRIERS")]
    if selected:
        primary = selected[0]
        row = scored.get(primary) or {}
        jitter = None
        if row.get("echo_ms"):
            jitter = max(0, (row.get("p95_ms") or 0) - sorted(row["echo_ms"])[len(row["echo_ms"]) // 2])
        figures = "%s up / %s down Mbps, %s ms" % (mbps(row.get("upload_mbps")), mbps(row.get("download_mbps")), _fmt(row.get("p95_ms")))
        if jitter is not None:
            figures += ", jitter %s ms" % _fmt(jitter)
        out.append(style.field("Primary", "%-19s %s" % (primary, figures)))
    if len(selected) > 1:
        used = {family(selected[0])}
        for number, standby in enumerate(selected[1:], 1):
            if family(standby) not in used:
                why = "%s family (primary is %s)" % (family(standby), family(selected[0]))
            else:
                why = "same family as another path (no other family qualified)"
            used.add(family(standby))
            out.append(style.field("Standby %d" % number if len(selected) > 2 else "Standby", "%-19s %s" % (standby, why)))
        seconds = (pair.get("runtime", {}).get("health") or {}).get("failover_seconds") or 120
        when = ("%d min" % (seconds // 60)) if seconds % 60 == 0 else duration(seconds)
        out.append(style.field("Failover", "automatic when the primary is down ~%s and the standby answers" % when))
    else:
        out.append(style.field("Standby", style.warn("none: only one carrier qualified, no automatic failover")))
    out += ["", style.section("TEST"), style.field("Carriers", tested)]
    if passed:
        ranked = sorted(passed, key=lambda r: -(scored.get(r["profile"], {}).get("score") or 0))
        names = [r["profile"] for r in ranked]
        out.append(style.field("Passed", ""))
        out[-1] += wrap(names, 18)[0].lstrip()
        out += [" " * 18 + line.lstrip() for line in wrap(names, 18)[1:]]
    out += failure_lines()
    rtt = _route_rtt(scored, selected)
    if rtt and rtt > 250:
        out += ["", "  " + style.warn("Route ~%d ms round trip: a foreign server closer to Iran will be faster." % rtt)]
    if inbound != "open":
        out += ["", style.section("TO DO"),
                "    1. In your panel create the inbound on the foreign node: listen 0.0.0.0, port %s." % port,
                "    2. Give clients address %s, port %s (keep UUID/path/SNI of that inbound)." % (request.get("public_ip"), port)]
    out += ["", style.section("MONITOR")]
    if dashboard:
        out.append(style.field("Dashboard", style.paint(dashboard, "1")))
        out.append(" " * 18 + style.dim("private link, read-only; the browser warns once (self-signed)"))
    out += [style.field("Status", "sudo pronet status"),
            style.field("Details", "sudo pronet report --details"),
            style.field("Tunnel ID", pair.get("id", ""))]
    if details:
        out += _details(rows, style)
    return out


def _details(rows, style):
    out = ["", style.section("ALL CARRIERS")]
    for row in rows:
        mark = style.ok("") if row.get("passed") else style.bad("")
        text = _summary_line(row) if row.get("passed") else reason(row)
        out.append("    %s %-19s %s" % (mark, row.get("profile", "?"), text))
        soak = row.get("soak")
        if soak:
            out.append("      %-19s longer test: %s" % ("", _summary_line(soak) if soak.get("passed") else reason(soak)))
    return out


def _route_rtt(scored, selected):
    for name in selected:
        row = scored.get(name)
        if row and row.get("echo_ms"):
            ordered = sorted(row["echo_ms"])
            return ordered[len(ordered) // 2]
    return None
