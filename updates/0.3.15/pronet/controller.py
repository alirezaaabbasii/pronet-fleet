"""Coordinates two outbound agents; never shells into servers or runs engines."""
from __future__ import annotations

import concurrent.futures
import contextlib
import ipaddress
import secrets
import threading
import time

from .common import PronetError, clean, inbound_ports, secret, utc
from .model import PROFILES, ranking


SCREEN_BATCH = 8          # the agent accepts at most 8 carriers per batch
SOAK_BATCH = 3
STANDBYS = 2              # warm standbys kept next to the primary (when available)
SECOND_STANDBY_MIN_MB = 1400
REACH_SECONDS = 20
RETEST_AFTER = 300             # every committed path down this long -> automatic re-test
NODE_SILENT = 120              # a server silent this long is reported (Telegram)
OVERVIEW_EVERY = 10            # seconds between health-driven controller passes
RETEST_BACKOFF = (3600, 7200, 14400, 21600)
REPLACE_COOLDOWN = 1800       # at most one standby replacement per pair per 30 minutes
UNSTABLE_MEMORY = 86400       # a carrier that proved unstable is not reused for a day


def dialer(plan):
    """Which server opens the carrier connection."""
    spec = PROFILES[plan["profile"]]
    if spec["kind"] == "reverse":
        return "foreign"
    if spec["kind"] == "direct":
        return "iran"
    return "iran" if plan.get("direction", "iran-dials") == "iran-dials" else "foreign"


def screen_batches(plans, size=SCREEN_BATCH):
    """Group carriers that tend to be blocked together into the same batch.

    A batch waits for its slowest member, and a filtered carrier always uses
    the whole reachability window. Keeping UDP/QUIC carriers and carriers that
    Iran dials apart from the usual TCP carriers dialed from abroad lets the
    batches that work finish without that wait. Every carrier is still tested.
    """
    def group(plan):
        if PROFILES[plan["profile"]]["family"] in ("udp", "icmp"):
            return 2
        return 0 if dialer(plan) == "foreign" else 1
    batches = []
    for key in (0, 1, 2):
        members = [plan for plan in plans if group(plan) == key]
        batches += [members[i:i + size] for i in range(0, len(members), size)]
    return batches


class Controller:
    reconnect_grace = 180      # seconds both servers report before an outage repair

    def __init__(self, store, stop_event=None):
        self.store = store
        self.stop = stop_event or threading.Event()
        self.running = set()
        self.busy_nodes = set()
        self.mutex = threading.Lock()
        self.guard = threading.RLock()   # result/live of a pair touched by pipelined stages

    def rpc(self, pair, node, op, payload, step, timeout=125, on_progress=None):
        if self.store.pair(pair["id"]).get("desired", "run") == "stop" and op != "cleanup":
            raise PronetError("Operator requested a stop; further setup operations were canceled")
        job = self.store.enqueue(pair["id"], node, op, payload, step)
        deadline = time.monotonic() + timeout
        seen, next_check = None, 0
        while time.monotonic() < deadline and not self.stop.is_set():
            result = self.store.job_result(job)
            if result is not None:
                if not result["ok"]:
                    raise PronetError(result.get("error", "Node operation failed"))
                return result.get("data", {})
            if on_progress and time.monotonic() >= next_check:
                next_check = time.monotonic() + .5
                with contextlib.suppress(Exception):
                    progress = self.store.job_progress(job)
                    if progress and progress != seen:
                        seen = progress
                        on_progress(progress)
            self.stop.wait(.2)
        raise PronetError("Node did not complete " + op + " within the bounded timeout")

    def both(self, pair, op, payloads, step, timeout=125):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = {role: pool.submit(self.rpc, pair, pair["iran" if role == "iran" else "foreign_node"],
                                        op, payloads[role], step + ":" + role, timeout)
                       for role in ("iran", "foreign")}
            results, errors = {}, []
            for role, future in futures.items():
                try:
                    results[role] = future.result()
                except Exception as error:
                    errors.append(role + ": " + clean(error))
            if errors:
                raise PronetError("; ".join(errors))
            return results

    def allocate(self, pair, inventories):
        request = pair["request"]
        used_ports = set(inventories["iran"]["ports"]) | set(inventories["foreign"]["ports"])
        used_ports.update(inventories["iran"]["ssh_ports"])
        used_ports.update(inventories["foreign"]["ssh_ports"])
        used_ports.update(inbound_ports(request))
        networks = []
        for info in inventories.values():
            for text in info["routes"] + info["reserved_subnets"]:
                try:
                    network = ipaddress.ip_network(text)
                    if network.prefixlen:
                        networks.append(network)
                except ValueError:
                    pass
        # Never allocate a fixed service port inside a node's ephemeral range:
        # outgoing connections (thousands of user sessions through the
        # gateway/bridge) borrow those ports, and a carrier or helper that
        # restarts later fails with EADDRINUSE on exactly the busiest servers.
        ephemeral = []
        for info in inventories.values():
            try:
                low, high = (int(x) for x in info.get("ephemeral_range", (32768, 60999)))
                if 1 <= low <= high <= 65535:
                    ephemeral.append((low, high))
            except (TypeError, ValueError):
                ephemeral.append((32768, 60999))
        def outside_ephemeral(value):
            return not any(low <= value <= high for low, high in ephemeral)
        def choose_port(control=False):
            common = [443, 8443, 9443, 22443] if control else []
            for value in common:
                if value not in used_ports:
                    used_ports.add(value)
                    return value
            for strict in (True, False):
                for _ in range(400):
                    value = 20000 + secrets.randbelow(45000)
                    if value not in used_ports and (not strict or outside_ephemeral(value)):
                        used_ports.add(value)
                        return value
            raise PronetError("Could not reserve a free port")
        def choose_subnet():
            for pool in ("10.244.0.0/16", "172.29.0.0/16", "192.168.240.0/20"):
                pool = ipaddress.ip_network(pool)
                for _ in range(128):
                    offset = secrets.randbelow(pool.num_addresses // 4) * 4
                    candidate = ipaddress.ip_network((int(pool.network_address) + offset, 30))
                    if not any(candidate.overlaps(existing) for existing in networks):
                        networks.append(candidate)
                        return str(candidate)
            raise PronetError("No collision-free tunnel subnet was found")
        plans = []
        for profile in request["profiles"]:
            if (PROFILES[profile]["kind"] == "l3" and PROFILES[profile]["engine"] not in ("native-gre", "parsa-spoof")
                    and not all(info["tun"] for info in inventories.values())):
                continue
            token, subnet = secret(), choose_subnet()
            plan = {"pair_id": pair["id"], "profile": profile, "token": token, "subnet": subnet,
                    "iran_ip": pair["iran_info"]["public_ip"], "foreign_ip": pair["foreign_info"]["public_ip"],
                    "control_port": choose_port(PROFILES[profile]["engine"] not in ("native-gre", "parsa-spoof")), "echo_port": choose_port(), "health_port": choose_port(),
                    "data_port": choose_port(), "inbound_port": request["inbound_port"],
                    "inbound_ports": inbound_ports(request),
                    "gateway_bind_ip": request["bind_ip"], "gateway_public_ip": request["public_ip"],
                    "bridge_data_port": choose_port(), "bridge_health_port": choose_port(), "probe_front_port": choose_port(),
                    "direction": PROFILES[profile].get("direction", request["direction"]), "sni": request.get("sni", ""),
                    "test_quality": request.get("quality", "balanced")}
            plan["spoof"] = request.get("spoof", {})
            plans.append(plan)
        if not plans:
            raise PronetError("No selected profile can run with these capabilities")
        return plans

    def live(self, pair, result, names=(), **fields):
        """Per-carrier live state for the progress view (display only)."""
        with self.guard:
            carriers = result.setdefault("live", {}).setdefault("carriers", {})
            now = time.time()
            for name in names:
                row = carriers.setdefault(name, {})
                if "stage" in fields and fields["stage"] != row.get("stage"):
                    row["since"] = now
                    row.pop("phase", None)
                    row.pop("pct", None)
                row.update(fields)
            with contextlib.suppress(Exception):
                self.store.set_live(pair["id"], result["live"])

    def live_progress(self, pair, result, stage):
        def apply(progress):
            with self.guard:
                carriers = result.setdefault("live", {}).setdefault("carriers", {})
                for name, row in progress.items():
                    if name in carriers and carriers[name].get("stage") == stage:
                        carriers[name].update(phase=row.get("phase"), pct=row.get("pct"))
                with contextlib.suppress(Exception):
                    self.store.set_live(pair["id"], result["live"])
        return apply

    def payloads(self, pair, plan):
        return {role: dict(plan, role=role, bind_ip=pair[role + "_info"]["bind_ip"]) for role in ("iran", "foreign")}

    def process(self, pair_id):
        pair = self.store.pair(pair_id)
        result = {"phase": "preflight", "results": [], "warnings": [], "timing": {"started": time.time()}}
        try:
            if pair["state"] != "PAIRED":
                raise PronetError("Hub restarted during setup; safely retire the interrupted setup and create a fresh pairing")
            result["live"] = {"phase": "preflight", "now": {"step": "checking both servers: version, ports, firewall"}}
            self.store.update_pair(pair_id, "PREFLIGHT", result)
            info = self.both(pair, "inventory", {"iran": {}, "foreign": {}}, "inventory")
            from . import __version__
            versions = {role: inventory.get("version", "older than 0.2.5") for role, inventory in info.items()}
            if any(version != __version__ for version in versions.values()):
                raise PronetError("Version mismatch (coordinator %s, iran %s, foreign %s). Run the installer on both servers, then create a new pairing."
                                  % (__version__, versions["iran"], versions["foreign"]))
            for role, inventory in info.items():
                if not inventory["systemd"] or not inventory["iptables"] or inventory["arch"] not in ("amd64", "arm64"):
                    raise PronetError(role + ": requires Linux amd64/arm64, systemd, and iptables tools")
                if inventory.get("unresolved_raw_engines"):
                    raise PronetError(role + ": an unmanaged raw tunnel has unknown ports; import or inspect it before installing new carriers")
                if inventory.get("firewall_readable") is False:
                    raise PronetError(role + ": firewall could not be inspected; setup stopped before changes")
            from .runtime import endpoint_occupied, endpoint_has_nat
            client_ports = inbound_ports(pair["request"])
            for number in client_ports:
                if endpoint_occupied(info["iran"], pair["request"]["bind_ip"], number):
                    raise PronetError("Iran public port %d is already occupied; no existing listener was stopped" % number)
            if pair["request"]["bind_ip"] not in info["iran"]["ips"]:
                raise PronetError("Iran gateway IP is not assigned to the host")
            for number in client_ports:
                if endpoint_has_nat(info["iran"], pair["request"]["bind_ip"], number):
                    raise PronetError("An existing DNAT/REDIRECT rule already owns public port %d; it was left unchanged" % number)
                if number in info["iran"]["ssh_ports"] + info["foreign"]["ssh_ports"]:
                    raise PronetError("The requested inbound port %d is used for SSH" % number)
            plans = self.allocate(pair, info)
            running = set()
            total = len(plans)
            batches = screen_batches(plans)
            # A second warm standby costs ~30 MB per server; keep one on small servers.
            small = any(isinstance(row.get("ram_total_mb"), int) and row["ram_total_mb"] < SECOND_STANDBY_MIN_MB
                        for row in info.values())
            standbys = (1 if small else STANDBYS) if pair["request"]["standby"] else 0
            result["progress"] = {"tested": 0, "total": total, "passed": 0}
            result["live"] = {"phase": "screen", "order": [plan["profile"] for batch in batches for plan in batch],
                              "batches": len(batches), "carriers": {}, "now": {}}
            for plan in plans:
                result["live"]["carriers"][plan["profile"]] = {"stage": "waiting"}
            self.store.update_pair(pair_id, "TRIAL", dict(result, phase="measuring"))
            self.screen_all(pair, plans, result, running)
            if self.stop.is_set():
                return
            screened = ranking(result["results"], all_results=True)
            # Qualify a sufficiently good different carrier family before a
            # second near-identical path; otherwise stopping after two passes
            # silently defeats ranking()'s standby diversity policy.
            preferred = ranking(result["results"], standbys)
            preferred_names = {row["profile"] for row in preferred}
            screened = preferred + [row for row in screened if row["profile"] not in preferred_names]
            qualified = []
            candidates = screened[:5]
            needed = 1 + standbys
            repetitions = 3 if pair["request"].get("quality") == "thorough" else 1
            result["live"] = {"phase": "soak", "order": [row["profile"] for row in candidates], "carriers": {}, "now": {}}
            for row in candidates:
                result["live"]["carriers"][row["profile"]] = {"stage": "waiting"}
            self.store.update_pair(pair_id, "TRIAL", dict(result, phase="longer-test"))
            index = 0
            while index < len(candidates) and len(qualified) < needed and not self.stop.is_set():
                chunk = candidates[index:index + SOAK_BATCH]
                label = "soak-batch:" + str(index)
                index += len(chunk)
                names = [row["profile"] for row in chunk]
                chunk_plans = {name: next(plan for plan in plans if plan["profile"] == name) for name in names}
                self.live(pair, result, names, stage="starting")
                self.note(pair, result, "measure", "longer test: starting %s" % ", ".join(names))
                try:
                    started = self.both(pair, "start_batch", {role: {"plans": [self.payloads(pair, chunk_plans[n])[role] for n in names]}
                                                              for role in ("iran", "foreign")}, label + ":start")
                except Exception as error:
                    started = {role: {"profiles": {n: {"error": clean(error)} for n in names}} for role in ("iran", "foreign")}
                running.update(names)
                observations = {name: [] for name in names}
                active = []
                for name in names:
                    replies = [started[role].get("profiles", {}).get(name, {}) for role in ("iran", "foreign")]
                    errors = [r.get("error") for r in replies if not isinstance(r, dict) or r.get("error") or not r.get("started")]
                    if errors:
                        observations[name].append({"profile": name, "passed": False, "echo_ms": [], "success_ratio": 0,
                                                   "error": errors[0] or "start failed", "stage": "start"})
                    else:
                        active.append(name)
                for repetition in range(repetitions):
                    if not active:
                        break
                    self.live(pair, result, active, stage="measuring", run=repetition + 1, runs=repetitions)
                    self.note(pair, result, "measure", "longer test: %d carriers, 4 MB each way (run %d of %d)"
                              % (len(active), repetition + 1, repetitions))
                    budget = 80 + REACH_SECONDS + 10
                    measured = self.rpc(pair, pair["iran"], "benchmark_batch",
                                        {"plans": [self.payloads(pair, dict(chunk_plans[n], long_test=True))["iran"] for n in active]},
                                        label + ":" + str(repetition), timeout=60 + budget * len(active),
                                        on_progress=self.live_progress(pair, result, "measuring")).get("profiles", {})
                    for name in active:
                        observations[name].append(measured.get(name) or {"profile": name, "passed": False, "echo_ms": [],
                                                                         "success_ratio": 0, "error": "no result", "stage": "soak"})
                    active = [name for name in active if observations[name][-1].get("passed")]
                for name in names:
                    rows = observations[name]
                    soaked = dict(rows[-1])
                    soaked["passed"] = len(rows) == repetitions and all(row.get("passed") for row in rows)
                    soaked["qualification_runs"] = len(rows)
                    if soaked["passed"]:
                        soaked["echo_ms"] = [sample for row in rows for sample in row["echo_ms"]]
                        soaked["upload_mbps"] = min(row["upload_mbps"] for row in rows)
                        soaked["download_mbps"] = min(row["download_mbps"] for row in rows)
                    soaked["observations"] = rows
                    for row in candidates:
                        if row["profile"] == name: row["soak"] = soaked
                    for row in result["results"]:
                        if row["profile"] == name: row["soak"] = soaked
                    if soaked["passed"]:
                        qualified.append(soaked)
                    self.live(pair, result, [name], stage="qualified" if soaked["passed"] else "failed")
                keep = {row["profile"] for row in ranking(qualified, standbys)}
                retire = sorted(running - keep)
                if retire:
                    self.note(pair, result, "measure", "longer test: removing carriers that were not selected")
                    self.both(pair, "retire_batch", {"iran": {"profiles": retire}, "foreign": {"profiles": retire}}, label + ":retire")
                    running.difference_update(retire)
                self.note(pair, result, "measure", None)
                self.store.update_pair(pair_id, "TRIAL", dict(result, phase="longer-test"))
            winners = ranking(qualified, standbys)
            if not winners:
                raise PronetError("No profile passed all integrity, idle, half-close and reachability tests. This is not proof that every possible network path is blocked.")
            selected = [row["profile"] for row in winners]
            result.update(phase="committing", selected=selected, active=selected[0])
            standby_text = (" and standby " + ", ".join(selected[1:])) if len(selected) > 1 else ""
            result["live"] = {"phase": "finish", "now": {"step": "installing primary %s%s on both servers" % (selected[0], standby_text)}}
            self.store.update_pair(pair_id, "STAGED", result)
            self.both(pair, "commit", {"iran": {"profiles": selected}, "foreign": {"profiles": selected}}, "commit")
            result["live"]["now"] = {"step": "verifying %s with a real transfer after installation" % selected[0]}
            self.store.update_pair(pair_id, "VERIFYING", dict(result, phase="verifying"))
            winner = next(plan for plan in plans if plan["profile"] == selected[0])
            proof = self.rpc(pair, pair["iran"], "benchmark", self.payloads(pair, winner)["iran"], "post-commit")
            if not proof.get("passed"):
                raise PronetError("Winner did not pass after permanent service activation")
            result["live"]["now"] = {"step": "opening client port(s) %s on Iran and checking the panel inbound"
                                             % ",".join(str(x) for x in client_ports)}
            self.store.update_pair(pair_id, "VERIFYING", dict(result, phase="activating"))
            active = self.both(pair, "activate", {"iran": {}, "foreign": {}}, "activate")
            result.pop("live", None)
            if active["foreign"].get("inbound") != "open":
                result["warnings"].append("Tunnel is active, but the foreign inbound port is not open. Install/configure the node before client use.")
            if active["iran"].get("tls") not in ("verified", "not-configured"):
                result["warnings"].append("TLS could not be verified with the configured SNI; inspect the foreign inbound and certificate.")
            result["warnings"].append("An authenticated WS/XHTTP client session through the public Iran address has not been tested automatically.")
            result["timing"]["finished"] = time.time()
            result["inbound"] = active["foreign"].get("inbound", "unknown")
            result.update(phase="complete", endpoint=f"{pair['request']['public_ip']}:" + ",".join(str(x) for x in client_ports))
            self.store.update_pair(pair_id, "ACTIVE", result)
        except Exception as error:
            result["timing"]["finished"] = time.time()
            result["failed_phase"] = result.get("phase", "unknown")
            result.update(phase="rollback", error=clean(error), cleanup_confirmed=False)
            self.store.update_pair(pair_id, "ROLLING_BACK", result)
            self.store.cancel_pending(pair_id)
            try:
                self.both(pair, "cleanup", {"iran": {}, "foreign": {}}, "rollback", timeout=125)
                result["cleanup_confirmed"] = True
            except Exception as cleanup_error:
                result["warnings"].append("Cleanup unconfirmed: " + clean(cleanup_error) + ". Temporary services expire; inspect committed services locally.")
            result["phase"] = "failed"
            self.store.update_pair(pair_id, "FAILED", result)

    def screen_batch(self, pair, batch, number, result, running):
        """Screen one group: start it, then measure what connected."""
        reachable = self.start_group(pair, batch, number, result, running)
        if reachable:
            self.measure_group(pair, reachable, number, result)

    def note(self, pair, result, lane, text):
        """One line per activity for the bottom of the live view."""
        with self.guard:
            now = result.setdefault("live", {}).setdefault("now", {})
            if text:
                now[lane] = text
            else:
                now.pop(lane, None)
            with contextlib.suppress(Exception):
                self.store.set_live(pair["id"], result["live"])

    def start_group(self, pair, batch, number, result, running):
        """Prepare, start and connect one group. Changes the hosts (one at a
        time on each agent) but never sends test traffic, so it can run while
        the previous group is being measured. Returns [(plan, reach)]."""
        label = "batch-" + str(number)
        names = [plan["profile"] for plan in batch]
        group = "group %d" % (number + 1)
        def failed(profile, reason, stage):
            with self.guard:
                result["results"].append({"profile": profile, "passed": False, "error": clean(reason), "stage": stage})
            self.live(pair, result, [profile], stage="failed")
        self.live(pair, result, names, stage="preparing")
        self.note(pair, result, "next", group + ": preparing engines on both servers")
        try:
            try:
                prepared = self.both(pair, "prepare_batch", {role: {"plans": [self.payloads(pair, plan)[role] for plan in batch]}
                                                             for role in ("iran", "foreign")}, label + ":prepare")
            except Exception as error:
                for name in names:
                    failed(name, error, "prepare")
                with self.guard:
                    running.update(names)
                return []
            startable = []
            for plan in batch:
                replies = [prepared[role].get("profiles", {}).get(plan["profile"], {}) for role in ("iran", "foreign")]
                errors = [r.get("error") for r in replies if not isinstance(r, dict) or r.get("error") or not r.get("prepared")]
                if errors:
                    failed(plan["profile"], errors[0] or "prepare failed", "prepare")
                    with self.guard:
                        running.add(plan["profile"])
                    continue
                for field in ("server_cert", "server_fingerprint", "server_noise_public_key"):
                    if field in replies[0]:
                        plan[field] = replies[0][field]
                if plan["profile"] == "parsa-spoof":
                    plan["wg_public_keys"] = {role: reply["wg_public_key"] for role, reply in zip(("iran", "foreign"), replies)}
                startable.append(plan)
            if not startable:
                return []
            self.live(pair, result, [plan["profile"] for plan in startable], stage="starting")
            self.note(pair, result, "next", group + ": starting engines")
            try:
                started = self.both(pair, "start_batch", {role: {"plans": [self.payloads(pair, plan)[role] for plan in startable]}
                                                          for role in ("iran", "foreign")}, label + ":start")
            except Exception as error:
                for plan in startable:
                    failed(plan["profile"], error, "start")
                with self.guard:
                    running.update(plan["profile"] for plan in startable)
                return []
            live = []
            for plan in startable:
                with self.guard:
                    running.add(plan["profile"])
                replies = [started[role].get("profiles", {}).get(plan["profile"], {}) for role in ("iran", "foreign")]
                errors = [r.get("error") for r in replies if not isinstance(r, dict) or r.get("error") or not r.get("started")]
                if errors:
                    failed(plan["profile"], errors[0] or "start failed", "start")
                else:
                    live.append(plan)
            if not live:
                return []
            self.live(pair, result, [plan["profile"] for plan in live], stage="connecting", window=REACH_SECONDS)
            self.note(pair, result, "next", group + ": waiting for connections (up to %d s)" % REACH_SECONDS)
            try:
                probe = self.rpc(pair, pair["iran"], "probe_batch", {"profiles": [plan["profile"] for plan in live],
                                                                      "seconds": REACH_SECONDS}, label + ":reach",
                                 timeout=REACH_SECONDS + 60, on_progress=self.live_progress(pair, result, "connecting"))
            except Exception as error:
                for plan in live:
                    failed(plan["profile"], error, "reach")
                return []
            reachable = []
            for plan in live:
                reach = probe.get("profiles", {}).get(plan["profile"], {})
                if not reach.get("reachable"):
                    failed(plan["profile"], reach.get("reason", "unreachable"), "reach")
                else:
                    reachable.append((plan, reach))
            # Connected carriers wait for the measurement lane.
            self.live(pair, result, [plan["profile"] for plan, _ in reachable], stage="measuring")
            return reachable
        finally:
            self.note(pair, result, "next", None)

    def measure_group(self, pair, reachable, number, result):
        """Measure one group's connected carriers in one job: transfers run
        strictly one at a time, so no number is shared between carriers."""
        label = "batch-" + str(number)
        group = "group %d" % (number + 1)
        def failed(profile, reason, stage):
            with self.guard:
                result["results"].append({"profile": profile, "passed": False, "error": clean(reason), "stage": stage})
            self.live(pair, result, [profile], stage="failed")
        l3 = {plan["profile"] for plan, _ in reachable if PROFILES[plan["profile"]]["kind"] == "l3"}
        self.note(pair, result, "measure", "%s: measuring %d carriers (speed tests one at a time)" % (group, len(reachable)))
        budget = 70 + REACH_SECONDS + 10
        try:
            try:
                measured = self.rpc(pair, pair["iran"], "benchmark_batch",
                                    {"plans": [self.payloads(pair, plan)["iran"] for plan, _ in reachable]},
                                    label + ":measure", timeout=60 + budget * len(reachable),
                                    on_progress=self.live_progress(pair, result, "measuring")).get("profiles", {})
            except Exception as error:
                for plan, _ in reachable:
                    failed(plan["profile"], error, "benchmark")
                return
            reverse_needed = [plan for plan, _ in reachable if plan["profile"] in l3 and measured.get(plan["profile"], {}).get("passed")]
            reverse = {}
            if reverse_needed:
                # L3 carriers must also work when the foreign server starts the flow.
                self.live(pair, result, [plan["profile"] for plan in reverse_needed], stage="reverse")
                self.note(pair, result, "measure", "%s: checking the foreign->Iran direction of %d L3 carriers" % (group, len(reverse_needed)))
                try:
                    reverse = self.rpc(pair, pair["foreign_node"], "benchmark_batch",
                                       {"plans": [self.payloads(pair, plan)["foreign"] for plan in reverse_needed]},
                                       label + ":reverse", timeout=60 + budget * len(reverse_needed),
                                       on_progress=self.live_progress(pair, result, "reverse")).get("profiles", {})
                except Exception as error:
                    reverse = {plan["profile"]: {"passed": False, "error": clean(error)} for plan in reverse_needed}
            for plan, reach in reachable:
                name = plan["profile"]
                row = measured.get(name)
                if not isinstance(row, dict):
                    failed(name, "benchmark result missing", "benchmark")
                    continue
                if name in l3 and row.get("passed"):
                    row["reverse_passed"] = bool(reverse.get(name, {}).get("passed"))
                    row["passed"] = row["reverse_passed"]
                    if not row["passed"]:
                        row["reason"] = "reverse direction (foreign to Iran) failed"
                row["reach_ms"] = reach.get("rtt_ms")
                with self.guard:
                    result["results"].append(row)
                self.live(pair, result, [name], stage="passed" if row.get("passed") else "failed")
        finally:
            self.note(pair, result, "measure", None)

    def screen_all(self, pair, plans, result, running):
        """Start/connect a group, measure it, then retire what is unnecessary.

        LinkLock is local to an agent. Starting the next group on the foreign
        agent during Iran's transfers bypassed that lock and contaminated the
        measurements. Keep host changes outside the measurement phase on BOTH
        ends; probes and idle waits inside a group still run concurrently.
        """
        batches = screen_batches(plans)
        result["live"]["batches"] = len(batches)
        measured = set()
        for index, batch in enumerate(batches):
            if self.stop.is_set():
                return
            reachable = self.start_group(pair, batch, index, result, running)
            with self.guard:
                result["live"]["batch"] = index + 1
            if reachable:
                self.measure_group(pair, reachable, index, result)
            measured.update(plan["profile"] for plan in batch)
            with self.guard:
                keep = {row["profile"] for row in ranking(result["results"], 2)}
                retire = sorted((running & measured) - keep)
            if retire:
                self.note(pair, result, "measure", "removing carriers that are not needed any more")
                self.both(pair, "retire_batch", {"iran": {"profiles": retire}, "foreign": {"profiles": retire}},
                          "retire-screen:" + str(index))
                with self.guard:
                    running.difference_update(retire)
                self.note(pair, result, "measure", None)
            with self.guard:
                result["progress"] = {"tested": len(result["results"]), "total": len(plans),
                                      "passed": sum(1 for row in result["results"] if row.get("passed"))}
                self.store.update_pair(pair["id"], "TRIAL", dict(result, phase="measuring"))

    def recover(self, pair_id, pause_id):
        pair = self.store.pair(pair_id)
        result = pair["result"]
        old = result.get("selected", [])
        now = time.time()
        starts = [stamp for stamp in result.get("recovery_starts", [])
                  if type(stamp) in (int, float) and now - 1800 <= stamp <= now]
        if starts:
            # Different pause IDs must not reset the cross-episode work budget.
            result["recovery"] = {"handled_pause_id": pause_id, "state": "cooldown",
                                  "attempted": [], "retry_after": starts[-1] + 1800}
            self.store.update_pair(pair_id, "ACTIVE", result)
            return
        result["recovery_starts"] = starts + [now]
        recovery = {"handled_pause_id": pause_id, "state": "trying", "attempted": []}
        result["recovery"] = recovery
        # Persist the episode before starting anything. A hub restart does not
        # turn one bounded recovery budget into an unlimited retry loop.
        self.store.update_pair(pair_id, "ACTIVE", result)

        prefix = "recovery:" + pause_id + ":"
        passed = ranking(result.get("results", []), all_results=True)
        profiles = [row["profile"] for row in passed if row["profile"] not in old]
        profiles += [profile for profile in old if profile not in profiles]
        for index, profile in enumerate(profiles[:3]):
            if self.stop.is_set(): return
            recovery["attempted"].append(profile)
            commit_attempted = False
            try:
                self.both(pair, "resume", {"iran": {"profile": profile}, "foreign": {"profile": profile}}, prefix + profile + ":resume")
                proof = self.rpc(pair, pair["iran"], "remeasure", {"profile": profile}, prefix + profile + ":measure")
                if not proof.get("passed"): raise PronetError("Recovery candidate did not pass a real transfer")
                selection = [profile] + [item for item in old if item != profile][:1]
                commit_attempted = True
                self.both(pair, "commit", {"iran": {"profiles": selection, "automatic": True},
                                          "foreign": {"profiles": selection, "automatic": True}}, prefix + profile + ":commit")
                self.both(pair, "activate", {"iran": {}, "foreign": {}}, prefix + profile + ":activate")
                recovery.update(state="recovered", active=profile)
                result.update(selected=selection, active=profile)
                self.store.update_pair(pair_id, "ACTIVE", result)
                return
            except Exception as error:
                recovery.setdefault("errors", []).append(profile + ": " + clean(error))
                if commit_attempted and old:
                    try:
                        for restore in old:
                            self.both(pair, "resume", {"iran": {"profile": restore}, "foreign": {"profile": restore}}, prefix + profile + ":restore:" + restore)
                        self.both(pair, "commit", {"iran": {"profiles": old}, "foreign": {"profiles": old}}, prefix + profile + ":restore-commit")
                        self.both(pair, "activate", {"iran": {}, "foreign": {}}, prefix + profile + ":restore-activate")
                    except Exception as restore_error:
                        recovery.setdefault("errors", []).append("Restore unconfirmed: " + clean(restore_error))
                        recovery["state"] = "restore-unconfirmed"
                        self.store.update_pair(pair_id, "ACTIVE", result)
                        return
                if profile not in old:
                    try:
                        self.both(pair, "retire", {"iran": {"profile": profile}, "foreign": {"profile": profile}}, prefix + profile + ":retire", timeout=70)
                    except Exception as retire_error:
                        recovery.setdefault("errors", []).append(clean(retire_error))
            self.store.update_pair(pair_id, "ACTIVE", result)
        recovery["state"] = "exhausted"
        self.store.update_pair(pair_id, "ACTIVE", result)

    def stop_pair(self, pair_id):
        pair = self.store.pair(pair_id)
        result = pair["result"]
        request_id = result.get("stop_request", "initial")
        try:
            if pair["foreign_node"] is None:
                result["phase"] = "stopped-before-pairing"
            else:
                self.both(pair, "cleanup", {"iran": {}, "foreign": {}}, "operator-stop:" + request_id, timeout=125)
                result["phase"] = "stopped-both-ends"
            self.store.update_pair(pair_id, "STOPPED", result)
        except Exception as error:
            result.update(phase="stop-unconfirmed", error=clean(error))
            self.store.update_pair(pair_id, "STOP_UNCONFIRMED", result)

    def launch(self, pair_id, recovery_pause=None, task=None):
        pair = self.store.pair(pair_id)
        members = {pair["iran"], pair["foreign_node"]}
        with self.mutex:
            if pair_id in self.running or len(self.running) >= 4 or self.busy_nodes & members:
                return
            self.running.add(pair_id)
            self.busy_nodes.update(members)
        def work():
            try:
                if self.store.pair(pair_id).get("desired") == "stop":
                    self.stop_pair(pair_id)
                elif task == "replace":
                    self.replace_standby(pair_id)
                elif task == "retest":
                    self.retest(pair_id)
                elif recovery_pause:
                    self.recover(pair_id, recovery_pause)
                else:
                    self.process(pair_id)
            finally:
                with self.mutex:
                    self.running.discard(pair_id)
                    self.busy_nodes.difference_update(members)
        threading.Thread(target=work, daemon=True, name="pair-" + pair_id[:8]).start()

    def run(self):
        # One unexpected error (a locked database, a malformed row) used to end
        # this thread silently: the HTTPS hub kept answering while no setup,
        # stop or recovery was ever processed again until a manual restart.
        next_full = 0.0
        while not self.stop.is_set():
            try:
                # New tunnels and stop requests are picked up within 2 s. The
                # health-driven part reads every node's telemetry, which only
                # changes with a heartbeat (10-15 s): it runs every 10 s.
                if time.monotonic() >= next_full:
                    self.cycle()
                    next_full = time.monotonic() + OVERVIEW_EVERY
                else:
                    self.cycle_queue()
            except Exception as error:
                import sys
                print("Pronet controller: cycle failed: " + clean(error), file=sys.stderr, flush=True)
                self.stop.wait(5)
                continue
            self.stop.wait(2)

    def cycle_queue(self):
        for pair_id in self.store.stopping():
            self.launch(pair_id)
        for pair_id in self.store.pending():
            self.launch(pair_id)

    def reporting_since(self, pair, current, now):
        """When both servers of a pair started reporting again (None while one
        is silent). A server back from a long outage first gets its carriers
        a few minutes to reconnect on their own: no re-test or exploration
        is started from the outage that just ended."""
        since = self.__dict__.setdefault("both_current_since", {})
        if pair["iran"] in current and pair["foreign"] in current:
            return since.setdefault(pair["id"], now)
        since.pop(pair["id"], None)
        return None

    def track_nodes(self, overview, current, now):
        """Notice when a server of an active tunnel stops reporting for 2+
        minutes, and when it is back (a short blip says nothing)."""
        state = self.__dict__.setdefault("node_state", {})
        for pair in overview["pairs"]:
            if pair.get("state") != "ACTIVE":
                continue
            for role in ("iran", "foreign"):
                node = pair.get(role)
                if not node:
                    continue
                key = (pair["id"], node)
                row = state.setdefault(key, {"up": node in current, "since": now, "told": False})
                up = node in current
                if up != row["up"]:
                    if up and row["told"]:
                        self.store.notice(pair["id"], "NODE_BACK",
                                          "%s:%d" % (role, max(1, (now - row["since"]) // 60)))
                    state[key] = row = {"up": up, "since": now, "told": False}
                elif not up and not row["told"] and now - row["since"] >= NODE_SILENT:
                    row["told"] = True
                    self.store.notice(pair["id"], "NODE_STALE", role)

    def cycle(self):
        self.cycle_queue()
        overview = self.store.overview()
        current = {node["id"] for node in overview["nodes"] if node["telemetry"] == "CURRENT"}
        now = time.time()
        with contextlib.suppress(Exception):
            self.track_nodes(overview, current, now)
        for pair in overview["pairs"]:
            runtime = pair.get("runtime", {})
            since = self.reporting_since(pair, current, now)
            settled = since is not None and now - since >= self.reconnect_grace
            if (pair["state"] == "ACTIVE" and pair["iran"] in current and pair["foreign"] in current
                    and not runtime.get("remote_stopped")):
                task = self.maintenance_task(pair, runtime, now, since)
                if task:
                    self.launch(pair["id"], task=task)
                    continue
            pause = runtime.get("pause_id")
            recovery = pair["result"].get("recovery", {})
            handled = recovery.get("handled_pause_id")
            # An explore episode refused for its cooldown is retried when the
            # cooldown ends, not forgotten for as long as the pause lasts.
            cooled = recovery.get("state") == "cooldown" and time.time() >= (recovery.get("retry_after") or 0)
            if (settled and pair["state"] == "ACTIVE" and pair["iran"] in current and pair["foreign"] in current
                    and runtime.get("recovery_paused") and runtime.get("link") == "UNCONFIRMED"
                    and not runtime.get("remote_stopped") and pause and (pause != handled or cooled)):
                policy = runtime.get("health", {}).get("recovery_policy", "stable")
                if policy != "explore":
                    # Keep both committed paths running and probing. A short
                    # common outage must not trigger a whole-family replacement.
                    # overview() deliberately omits internal state. Never write
                    # that public projection back over the full pair record.
                    result = self.store.pair(pair["id"])["result"]
                    held = result.get("recovery_hold", {})
                    if held.get("pause_id") != pause:
                        result["recovery_hold"] = {"pause_id": pause, "policy": "stable",
                                                   "state": "awaiting-operator", "utc": utc()}
                        self.store.update_pair(pair["id"], "ACTIVE", result)
                    continue
                health = runtime.get("health", {})
                if health.get("switches_30m", 0) >= 3:
                    # Exploration must obey the same switch budget as the
                    # watchdog. It remains eligible when the window expires.
                    continue
                self.launch(pair["id"], pause)

    # ------------------------------------------------------------ maintenance

    def maintenance_task(self, pair, runtime, now=None, reporting_since=None):
        """Decide a background repair for an active tunnel (or None).

        retest:  every committed path has been down for RETEST_AFTER while
                 both servers still report to the coordinator (so the problem
                 is the carriers, not a server or its uplink).
        replace: the primary is healthy and a standby keeps dropping; it is
                 swapped for the next carrier that passed the setup test.
        """
        now = now or time.time()
        down = runtime.get("all_down_since")
        health = runtime.get("standby_health") or {}
        unstable = [name for name, row in health.items() if isinstance(row, dict) and row.get("unstable")]
        if type(down) in (int, float) and reporting_since:
            down = max(down, reporting_since)   # the outage counts from when both report again
        wants_retest = type(down) in (int, float) and now - down >= RETEST_AFTER
        wants_replace = (runtime.get("link") == "UP" and not runtime.get("active_unstable") and bool(unstable))
        if not (wants_retest or wants_replace):
            return None
        result = self.store.pair(pair["id"])["result"]
        maint = result.get("maintenance") or {}
        if wants_retest and now >= (maint.get("next_retest_at") or 0):
            return "retest"
        if wants_replace and now >= (maint.get("next_replace_at") or 0) and self.reserve(result, runtime, now):
            return "replace"
        return None

    def reserve(self, result, runtime, now=None):
        """Carriers that passed this pair's setup test, best first, which are
        not committed now and did not prove unstable recently."""
        now = now or time.time()
        seen = (result.get("maintenance") or {}).get("unstable_seen") or {}
        current = set(runtime.get("profiles") or []) | set(result.get("selected") or [])
        return [row["profile"] for row in ranking(result.get("results", []), all_results=True)
                if row["profile"] not in current and now - (seen.get(row["profile"]) or 0) > UNSTABLE_MEMORY]

    def runtime_of(self, pair_id):
        return next((p.get("runtime", {}) for p in self.store.overview()["pairs"] if p["id"] == pair_id), {})

    def try_candidates(self, pair, names, prefix, long_test):
        """Start carriers from their stored plans on both servers, then check
        reachability and measure them. Returns ({name: row}, started)."""
        rows, started = {}, []
        replies = self.both(pair, "resume_batch", {"iran": {"profiles": names}, "foreign": {"profiles": names}}, prefix + ":resume")
        for name in names:
            errors = [replies[role].get("profiles", {}).get(name, {}).get("error") for role in ("iran", "foreign")]
            if any(errors) or not all(replies[role].get("profiles", {}).get(name, {}).get("started") for role in ("iran", "foreign")):
                rows[name] = {"profile": name, "passed": False, "error": next((e for e in errors if e), "start failed")}
            else:
                started.append(name)
        if not started:
            return rows, names
        probe = self.rpc(pair, pair["iran"], "probe_batch", {"profiles": started, "seconds": REACH_SECONDS},
                         prefix + ":reach", timeout=REACH_SECONDS + 60).get("profiles", {})
        reachable = [name for name in started if probe.get(name, {}).get("reachable")]
        for name in started:
            if name not in reachable:
                rows[name] = {"profile": name, "passed": False, "error": probe.get(name, {}).get("reason", "unreachable")}
        if reachable:
            budget = (80 if long_test else 70) + REACH_SECONDS + 10
            measured = self.rpc(pair, pair["iran"], "benchmark_batch", {"profiles": reachable, "long_test": long_test},
                                prefix + ":measure", timeout=60 + budget * len(reachable)).get("profiles", {})
            l3 = [name for name in reachable if PROFILES[name]["kind"] == "l3" and measured.get(name, {}).get("passed")]
            reverse = {}
            if l3:
                reverse = self.rpc(pair, pair["foreign_node"], "benchmark_batch", {"profiles": l3, "long_test": False},
                                   prefix + ":reverse", timeout=60 + budget * len(l3)).get("profiles", {})
            for name in reachable:
                row = measured.get(name) or {"profile": name, "passed": False, "error": "no result"}
                if name in l3:
                    row["passed"] = bool(reverse.get(name, {}).get("passed"))
                    if not row["passed"]:
                        row["reason"] = "reverse direction (foreign to Iran) failed"
                rows[name] = row
        return rows, names

    def maintenance_event(self, pair_id, kind, detail):
        with contextlib.suppress(Exception):
            self.store.add_event(pair_id, kind, detail)

    def replace_standby(self, pair_id):
        """Swap an unstable standby for the next qualified carrier while the
        primary keeps serving users (it is never restarted or switched)."""
        pair = self.store.pair(pair_id)
        result = pair["result"]
        now = time.time()
        maint = result.setdefault("maintenance", {})
        maint["next_replace_at"] = now + REPLACE_COOLDOWN
        maint["state"] = "replacing-standby"
        self.store.update_pair(pair_id, "ACTIVE", result)   # persisted first: a restart cannot loop
        runtime = self.runtime_of(pair_id)
        active = runtime.get("active")
        health = runtime.get("standby_health") or {}
        unstable = [name for name, row in health.items() if isinstance(row, dict) and row.get("unstable")]
        profiles = runtime.get("profiles") or result.get("selected") or []
        if not active or not unstable or runtime.get("link") != "UP":
            maint["state"] = "idle"
            self.store.update_pair(pair_id, "ACTIVE", result)
            return
        seen = maint.setdefault("unstable_seen", {})
        for name in unstable:
            seen[name] = now
        keep = [active] + [name for name in profiles if name != active and name not in unstable]
        token = "%d" % now
        outcome = "no qualified carrier was available"
        for candidate in self.reserve(result, runtime, now)[:2]:
            prefix = "replace:%s:%s" % (token, candidate)
            try:
                rows, _ = self.try_candidates(pair, [candidate], prefix, long_test=True)
                if rows.get(candidate, {}).get("passed"):
                    selection = (keep + [candidate])[:3]
                    self.both(pair, "commit", {role: {"profiles": selection, "automatic": True, "expect_active": active}
                                               for role in ("iran", "foreign")}, prefix + ":commit")
                    result["selected"] = selection
                    outcome = "replaced %s with %s" % (", ".join(unstable), candidate)
                    self.maintenance_event(pair_id, "STANDBY_REPLACED", outcome)
                    break
                self.both(pair, "retire_batch", {"iran": {"profiles": [candidate]}, "foreign": {"profiles": [candidate]}},
                          prefix + ":retire", timeout=70)
                seen[candidate] = now
            except Exception as error:
                outcome = "replacement stopped: " + clean(error)
                with contextlib.suppress(Exception):
                    self.both(pair, "retire_batch", {"iran": {"profiles": [candidate]}, "foreign": {"profiles": [candidate]}},
                              prefix + ":retire-after-error", timeout=70)
                break
        maint.update(state="idle", last_replace={"utc": utc(), "result": outcome})
        self.store.update_pair(pair_id, "ACTIVE", result)

    def retest(self, pair_id):
        """Every committed carrier has been down for minutes while both
        servers are online: test the carriers again and install the best.

        Bounded: one run per pair, then 1 h, 2 h, 4 h, 6 h before the next if
        nothing works. Client address and ports do not change. Aborted if a
        committed path comes back before the new selection is installed.
        """
        from . import __version__
        pair = self.store.pair(pair_id)
        result = pair["result"]
        now = time.time()
        maint = result.setdefault("maintenance", {})
        failures = maint.get("retest_failures", 0)
        maint["next_retest_at"] = now + RETEST_BACKOFF[min(failures, len(RETEST_BACKOFF) - 1)]
        maint["state"] = "retesting"
        self.store.update_pair(pair_id, "ACTIVE", result)   # persisted first: a restart cannot loop
        self.maintenance_event(pair_id, "RETEST_STARTED", "every committed path down for %d+ minutes" % (RETEST_AFTER // 60))
        token = "%d" % now
        started = []
        outcome, installed = "no carrier passed", None
        try:
            info = self.both(pair, "inventory", {"iran": {}, "foreign": {}}, "retest:%s:inventory" % token)
            versions = {role: row.get("version") for role, row in info.items()}
            if any(version != __version__ for version in versions.values()):
                raise PronetError("versions differ (coordinator %s, iran %s, foreign %s); run the installer on both servers"
                                  % (__version__, versions["iran"], versions["foreign"]))
            runtime = self.runtime_of(pair_id)
            current = set(runtime.get("profiles") or result.get("selected") or [])
            tested = [row["profile"] for row in result.get("results", []) if row.get("profile") in PROFILES]
            passed_before = [row["profile"] for row in ranking(result.get("results", []), all_results=True)]
            order = passed_before + [name for name in tested if name not in passed_before]
            candidates = [name for name in order if name not in current]
            plans = [{"profile": name, "direction": PROFILES[name].get("direction", pair["request"].get("direction", "iran-dials"))}
                     for name in candidates]
            # Carriers that worked before are tried first, in their own groups.
            worked = [plan for plan in plans if plan["profile"] in passed_before]
            groups = ([worked[i:i + SCREEN_BATCH] for i in range(0, len(worked), SCREEN_BATCH)]
                      + screen_batches([plan for plan in plans if plan["profile"] not in passed_before]))
            rows = {}
            for number, group in enumerate(groups):
                names = [plan["profile"] for plan in group]
                if self.stop.is_set():
                    return
                found, tried = self.try_candidates(pair, names, "retest:%s:g%d" % (token, number), long_test=False)
                started += tried
                rows.update(found)
                if sum(1 for row in rows.values() if row.get("passed")) >= 1 + STANDBYS:
                    break   # enough working carriers: users are waiting
            passed = ranking(list(rows.values()), all_results=True)
            if passed:
                finalists = [row["profile"] for row in passed[:1 + STANDBYS]]
                long_rows, _ = self.try_candidates(pair, finalists, "retest:%s:long" % token, long_test=True)
                winners = [row["profile"] for row in ranking([r for r in long_rows.values() if r.get("passed")], STANDBYS)]
                if winners and self.runtime_of(pair_id).get("all_down_since") is None:
                    outcome = "a committed path came back during the re-test; nothing was changed"
                    winners = []
                if winners:
                    self.both(pair, "commit", {role: {"profiles": winners, "automatic": True, "rescue": True}
                                               for role in ("iran", "foreign")}, "retest:%s:commit" % token)
                    self.both(pair, "activate", {"iran": {}, "foreign": {}}, "retest:%s:activate" % token)
                    installed = winners
                    result.update(selected=winners, active=winners[0])
                    outcome = "installed %s" % ", ".join(winners)
        except Exception as error:
            outcome = "re-test stopped: " + clean(error)
        finally:
            leftover = sorted(set(started) - set(installed or []))
            if leftover and not installed:
                with contextlib.suppress(Exception):
                    for start in range(0, len(leftover), 8):
                        self.both(pair, "retire_batch", {"iran": {"profiles": leftover[start:start + 8]},
                                                         "foreign": {"profiles": leftover[start:start + 8]}},
                                  "retest:%s:retire:%d" % (token, start), timeout=70)
        if installed:
            maint["retest_failures"] = 0
            maint["next_retest_at"] = time.time() + RETEST_AFTER
        else:
            maint["retest_failures"] = failures + 1
        maint.update(state="idle", last_retest={"utc": utc(), "result": outcome})
        self.maintenance_event(pair_id, "RETEST_FINISHED", outcome)
        self.store.update_pair(pair_id, "ACTIVE", result)
