from __future__ import annotations

import contextlib
import threading
import time

from .common import ROOT, PronetError, canonical, clean, digest, event, identifier, lock, read_json, write_json
from .hub import Client
from .runtime import Runtime, resources


JOB_POLL = 0.5
IDLE_POLL = 5
BUSY_WINDOW = 180
JOB_RETENTION = 14 * 86400
JOB_WAIT = 8                 # seconds the hub may hold a job poll open
PROGRESS_OPS = {"probe_batch", "benchmark_batch"}
# Read-only network measurements. They run in their own lane, next to (not
# instead of) the operations that change the host, which stay one at a time.
MEASURE_OPS = {"probe_batch", "benchmark_batch", "benchmark"}
MEASURE_SLOTS = 2


class ProgressReporter:
    """Sends a running test job's per-carrier progress to the hub.

    Bounded: at most one small request per interval and only when something
    changed, only for test jobs, and it stops for good if the hub does not
    support it. Progress is display data; a failure here never fails a job.
    """
    def __init__(self, client, job, interval):
        self.client, self.job, self.interval = client, job, interval
        self.state, self.sent = {}, None
        self.lock = threading.Lock()
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True, name="progress")

    def update(self, values):
        with self.lock:
            for name, row in values.items():
                if isinstance(name, str) and isinstance(row, dict):
                    self.state[name] = {"phase": str(row.get("phase", ""))[:20], "pct": int(row.get("pct", 0))}

    def run(self):
        while not self.done.wait(self.interval):
            with self.lock:
                snapshot = {name: dict(row) for name, row in self.state.items()}
            if snapshot == self.sent:
                continue
            try:
                self.client.call("/v1/progress", {"job_id": self.job["id"], "lease_proof": self.job["lease_proof"],
                                                  "progress": snapshot}, timeout=5)
                self.sent = snapshot
            except PronetError:
                return

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.done.set()
        self.thread.join(6)


class Agent:
    lanes = True            # cleared when the hub does not support job lanes

    def __init__(self, config, runtime=None, client=None):
        self.config = config
        self.runtime = runtime or Runtime(config)
        self.client = client or Client(config["hub_url"], config["node_id"] + ":" + config["node_secret"], config.get("ca_file"))
        self.stop = threading.Event()
        self.measure_jobs = threading.BoundedSemaphore(MEASURE_SLOTS)

    def execute_job(self, job):
        identifier(job["id"])
        identifier(job["pair_id"])
        # Measurements change nothing on the host: they do not take the host
        # operation lock, so a test can run while the next carriers start.
        guard = contextlib.nullcontext() if job["op"] in MEASURE_OPS else lock(ROOT / "host-operation.lock")
        with guard:
            return self._execute_job(job)

    def _execute_job(self, job):
        fingerprint = digest(canonical({key: job[key] for key in ("op", "payload", "pair_id")}).decode())
        path = ROOT / "jobs" / (job["id"] + ".json")
        if path:
            cached = read_json(path, {})
            if cached:
                if cached.get("fingerprint") != fingerprint:
                    raise PronetError("Job ID reused with different content")
                if "result" in cached:
                    return cached["result"]
            write_json(path, {"fingerprint": fingerprint, "started": time.time()})
            reporter = None
            if job["op"] in PROGRESS_OPS and job.get("lease_proof"):
                local = self.config.get("role") == "iran"
                reporter = ProgressReporter(self.client, job, 1 if local else 2)
            try:
                if reporter and getattr(self.runtime, "accepts_progress", False):
                    with reporter:
                        result = {"ok": True, "data": self.runtime.execute(job, progress=reporter.update)}
                else:
                    result = {"ok": True, "data": self.runtime.execute(job)}
            except Exception as error:
                result = {"ok": False, "error": clean(error)}
                event(ROOT / "agent-events.jsonl", "JOB_FAILED", job["op"] + ": " + clean(error))
            write_json(path, {"fingerprint": fingerprint, "result": result, "completed": time.time()})
            return result

    def heartbeat(self):
        while not self.stop.is_set():
            try:
                metrics = {"resources": resources(), "pairs": []}
                try:
                    from .accounting import snapshot
                    metrics["ip_traffic"] = snapshot(self.config)
                except Exception as error:
                    metrics["ip_traffic"] = {"error": clean(error)}
                paths = sorted((ROOT / "pairs").glob("*/selection.json"),
                               key=lambda path: ((path.parent / "stopped.json").exists(), path.parent.name))
                metrics["pairs_truncated"] = len(paths) > 100
                metrics["pairs_total"] = len(paths)
                for path in paths[:100]:
                    try:
                        metrics["pairs"].append(self.runtime.status(path.parent.name))
                    except Exception as error:
                        metrics["pairs"].append({"id": path.parent.name, "error": clean(error)})
                self.client.call("/v1/heartbeat", metrics)
            except Exception as error:
                event(ROOT / "agent-events.jsonl", "HUB_UNAVAILABLE", error)
            self.stop.wait(10)

    def watch(self):
        while not self.stop.is_set():
            try:
                with lock(ROOT / "host-operation.lock", blocking=False):
                    self.runtime.watchdog()
            except BlockingIOError:
                pass
            except Exception as error:
                event(ROOT / "agent-events.jsonl", "WATCHDOG_ERROR", error)
            # Probe interval and failover threshold: sudo pronet probe-interval / failover-delay.
            from .runtime import probe_seconds
            self.stop.wait(probe_seconds())

    def prune_jobs(self, now=None):
        """Bound the local idempotency cache; completed records are only needed
        while the hub can still replay the same lease (minutes, not weeks)."""
        now = now or time.time()
        removed = 0
        for path in (ROOT / "jobs").glob("*.json"):
            try:
                record = read_json(path, {})
                if "result" in record and now - record.get("completed", now) > JOB_RETENTION:
                    path.unlink()
                    removed += 1
            except (OSError, ValueError):
                continue
        return removed

    def claim(self, lane):
        """Long-poll the hub for a job of one lane (or any job on an older hub)."""
        path = "/v1/jobs?wait=%d" % JOB_WAIT
        if self.lanes:
            path += "&lane=" + lane
        try:
            return self.client.call(path, timeout=JOB_WAIT + 10).get("job")
        except PronetError as error:
            if self.lanes and ("Unknown API endpoint" in str(error) or "Invalid request" in str(error)):
                self.lanes = False  # older hub: a single lane for every job
                return None
            raise

    def busy(self):
        return time.monotonic() - getattr(self, "last_job", -BUSY_WINDOW * 2) < BUSY_WINDOW

    def measure_loop(self):
        """Second lane: read-only measurements, at most MEASURE_SLOTS at once.
        Active only around setup or repair work: an idle tunnel costs no extra
        connections (the main loop's slow poll picks up the first job)."""
        while not self.stop.is_set():
            if not self.lanes:
                return
            if not self.busy():
                self.stop.wait(1)
                continue
            if not self.measure_jobs.acquire(timeout=1):
                continue
            try:
                job = self.claim("measure")
            except Exception as error:
                self.measure_jobs.release()
                event(ROOT / "agent-events.jsonl", "CONTROL_RETRY", error)
                self.stop.wait(5)
                continue
            if not job:
                self.measure_jobs.release()
                continue
            self.last_job = time.monotonic()
            threading.Thread(target=self.run_measure, args=(job,), daemon=True, name="measure").start()

    def run_measure(self, job):
        try:
            result = self.execute_job(job)
            for attempt in range(3):
                try:
                    self.client.call("/v1/result", {"job_id": job["id"], "lease_proof": job["lease_proof"], "result": result})
                    return
                except PronetError as error:
                    if "superseded" in str(error) or "cannot be overwritten" in str(error):
                        return
                    # The local job record keeps the result: a later lease of
                    # the same job replays it instead of measuring again.
                    self.stop.wait(3)
        except Exception as error:
            event(ROOT / "agent-events.jsonl", "CONTROL_RETRY", error)
        finally:
            self.measure_jobs.release()

    def run(self):
        workers = [threading.Thread(target=self.heartbeat, daemon=True, name="heartbeat"),
                   threading.Thread(target=self.watch, daemon=True, name="watchdog"),
                   threading.Thread(target=self.measure_loop, daemon=True, name="measure-lane")]
        for worker in workers: worker.start()
        try:
            self.job_loop()
        finally:
            self.stop.set()
            for worker in workers: worker.join(5)

    def job_loop(self):
        # A result not acknowledged before a network interruption is persisted
        # and retried before claiming another job. A completed operation is not
        # re-executed just because its HTTP response was lost.
        pending_path = ROOT / "pending-result.json"
        next_prune = 0
        # Poll fast only around active setup work. An idle agent polling every
        # 0.5 s meant two HTTPS handshakes per second from the foreign server
        # to Iran, forever, for nothing.
        self.last_job = time.monotonic()
        long_poll = True
        while not self.stop.is_set():
            try:
                if time.monotonic() >= next_prune:
                    next_prune = time.monotonic() + 3600
                    with lock(ROOT / "host-operation.lock", blocking=False):
                        self.prune_jobs()
            except (BlockingIOError, OSError):
                pass
            try:
                pending = read_json(pending_path, {})
                if not pending:
                    busy = self.busy()
                    if busy and long_poll:
                        # The hub answers as soon as a job is queued: no polling
                        # gap between setup steps (each costs a TLS handshake
                        # across the Iran<->foreign route).
                        try:
                            job = self.claim("main")
                        except PronetError as error:
                            if "Unknown API endpoint" not in str(error) and "Invalid request" not in str(error):
                                raise
                            long_poll = False  # older hub
                            continue
                    else:
                        job = self.client.call("/v1/jobs").get("job")
                    if not job:
                        if not (busy and long_poll):
                            self.stop.wait(JOB_POLL if busy else IDLE_POLL)
                        continue
                    self.last_job = time.monotonic()
                    result = self.execute_job(job)
                    pending = {"job_id": job["id"], "lease_proof": job["lease_proof"], "result": result}
                    write_json(pending_path, pending)
                try:
                    self.client.call("/v1/result", pending)
                except PronetError as error:
                    if "superseded" not in str(error) and "cannot be overwritten" not in str(error):
                        raise
                    # A new lease will replay the local cached result with its
                    # fresh proof. Keep the completed local job record.
                pending_path.unlink(missing_ok=True)
            except Exception as error:
                event(ROOT / "agent-events.jsonl", "CONTROL_RETRY", error)
                self.stop.wait(5)
