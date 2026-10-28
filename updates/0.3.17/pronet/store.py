"""Transactional pairing and leased, idempotent node operations."""
from __future__ import annotations

import contextlib
import hmac
import json
import pathlib
import secrets
import sqlite3
import threading
import time

from .common import PronetError, canonical, digest, identifier, inbound_ports, secret
from .model import validate_request

OPERATIONS = {"inventory", "prepare", "start", "benchmark", "commit", "activate", "cleanup", "retire", "resume", "remeasure", "status",
              "prepare_batch", "start_batch", "probe_batch", "retire_batch", "benchmark_batch", "resume_batch", "switch"}
MEASURE_OPS = {"probe_batch", "benchmark_batch", "benchmark"}   # same set as agent.MEASURE_OPS
PAIR_CODE_SECONDS = 600
TERMINAL = {"ACTIVE", "FAILED", "STOPPED"}


class Connection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


class Store:
    def __init__(self, path, enrollment_key, admin_key, clock=time.time):
        self.path = str(path)
        self.enrollment_hash, self.admin_hash = digest(enrollment_key), digest(admin_key)
        self.clock = clock
        # Wakes held job polls when a job is queued or released.
        self.jobs_changed = threading.Condition()
        self.jobs_version = 0
        pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS nodes (
              id TEXT PRIMARY KEY, credential TEXT NOT NULL, role TEXT NOT NULL,
              info TEXT NOT NULL, last REAL NOT NULL, metrics TEXT NOT NULL DEFAULT '{}');
            CREATE TABLE IF NOT EXISTS pairs (
              id TEXT PRIMARY KEY, code TEXT NOT NULL, iran TEXT NOT NULL, foreign_node TEXT,
              expires REAL NOT NULL, state TEXT NOT NULL, request TEXT NOT NULL,
              result TEXT NOT NULL DEFAULT '{}', updated REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS failures (
              node TEXT PRIMARY KEY, window REAL NOT NULL, count INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS jobs (
              id TEXT PRIMARY KEY, pair_id TEXT NOT NULL, node TEXT NOT NULL,
              op TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL,
              lease REAL NOT NULL DEFAULT 0, tries INTEGER NOT NULL DEFAULT 0,
              result TEXT, created REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS jobs_node ON jobs(node,state);
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT, pair_id TEXT, at REAL, kind TEXT, detail TEXT);
            CREATE TABLE IF NOT EXISTS notices (
              id INTEGER PRIMARY KEY AUTOINCREMENT, pair_id TEXT NOT NULL, at REAL NOT NULL,
              body TEXT NOT NULL, sent INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS notice_marks (pair_id TEXT PRIMARY KEY, seen TEXT NOT NULL);
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(pairs)")}
            if "desired" not in columns:
                db.execute("ALTER TABLE pairs ADD COLUMN desired TEXT NOT NULL DEFAULT 'run'")
        pathlib.Path(path).chmod(0o600)
        try:
            from .learning import CarrierMemory
            self.learning = CarrierMemory(pathlib.Path(path).with_name('carrier-memory.sqlite3'), clock)
        except (sqlite3.Error, OSError):
            self.learning = None

    def connect(self):
        db = sqlite3.connect(self.path, timeout=15, factory=Connection)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=15000")
        return db

    @contextlib.contextmanager
    def transaction(self):
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def admin(self, token):
        return isinstance(token, str) and hmac.compare_digest(digest(token), self.admin_hash)

    def enroll(self, enrollment_key, info):
        if not isinstance(enrollment_key, str) or not hmac.compare_digest(digest(enrollment_key), self.enrollment_hash):
            raise PronetError("Enrollment refused")
        if not isinstance(info, dict) or set(info) != {"role", "public_ip", "bind_ip", "name"}:
            raise PronetError("Invalid node identity")
        from .common import ipv4
        if info["role"] not in ("iran", "foreign"):
            raise PronetError("Choose Iran or Foreign")
        info["public_ip"], info["bind_ip"] = ipv4(info["public_ip"]), ipv4(info["bind_ip"])
        if not isinstance(info["name"], str) or not 1 <= len(info["name"]) <= 60 or any(ord(c) < 32 for c in info["name"]):
            raise PronetError("Invalid node name")
        node_id, credential = secrets.token_hex(12), secret()
        with self.transaction() as db:
            if db.execute("SELECT count(*) FROM nodes").fetchone()[0] >= 2000:
                raise PronetError("Node limit reached")
            db.execute("INSERT INTO nodes(id,credential,role,info,last) VALUES(?,?,?,?,?)",
                       (node_id, digest(credential), info["role"], canonical(info).decode(), self.clock()))
        return {"node_id": node_id, "node_secret": credential}

    def authenticate(self, token):
        try:
            node_id, credential = token.split(":", 1)
            identifier(node_id)
        except (ValueError, AttributeError, PronetError):
            raise PronetError("Authentication refused")
        with self.connect() as db:
            node = db.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        if node is None or not hmac.compare_digest(digest(credential), node["credential"]):
            raise PronetError("Authentication refused")
        return dict(node)

    def heartbeat(self, node, metrics):
        if not isinstance(metrics, dict) or len(canonical(metrics)) > 131072:
            raise PronetError("Invalid metrics")
        if not isinstance(metrics.get("resources", {}), dict):
            raise PronetError("Invalid resource metrics")
        pairs = metrics.get("pairs", [])
        if not isinstance(pairs, list) or len(pairs) > 100:
            raise PronetError("Invalid pair metrics")
        for pair in pairs:
            if not isinstance(pair, dict): raise PronetError("Invalid pair metrics")
            identifier(pair.get("id"))
            for key in ("selection", "profiles", "active", "traffic"):
                if not isinstance(pair.get(key, {}), dict): raise PronetError("Invalid pair metrics")
        traffic = metrics.get("ip_traffic", {})
        if not isinstance(traffic, dict) or not isinstance(traffic.get("ips", []), list) or len(traffic.get("ips", [])) > 512:
            raise PronetError("Invalid IP metrics")
        for row in traffic.get("ips", []):
            if not isinstance(row, dict) or not all(key in row for key in ("ip", "assignment", "activity")):
                raise PronetError("Invalid IP metrics")
        acks = metrics.pop("notices_ack", [])
        wants = metrics.pop("notify", False) is True
        if not isinstance(acks, list) or len(acks) > 50 or any(type(a) is not int for a in acks):
            raise PronetError("Invalid notice acknowledgement")
        with self.transaction() as db:
            db.execute("UPDATE nodes SET last=?,metrics=? WHERE id=?",
                       (self.clock(), canonical(metrics).decode(), node["id"]))
            if node["role"] == "iran":
                self.collect_notices(db, node, pairs)
            reply = {"ok": True}
            if node["role"] == "foreign":
                if acks:
                    marks = ",".join("?" * len(acks))
                    db.execute("UPDATE notices SET sent=1 WHERE id IN (%s) AND pair_id IN "
                               "(SELECT id FROM pairs WHERE foreign_node=?)" % marks, acks + [node["id"]])
                if wants:
                    rows = db.execute("SELECT notices.id,notices.body FROM notices JOIN pairs ON pairs.id=notices.pair_id "
                                      "WHERE pairs.foreign_node=? AND notices.sent=0 ORDER BY notices.id LIMIT 10",
                                      (node["id"],)).fetchall()
                    reply["notices"] = [dict(json.loads(row["body"]), id=row["id"]) for row in rows]
        return reply

    # ----------------------------------------------------------- notices
    def collect_notices(self, db, node, pairs):
        """Turn new tunnel events from an Iran heartbeat into Telegram notices.
        Each event is noticed once (its digest is remembered); the first
        heartbeat of a pair only records what already happened."""
        from .notify import NOTIFY_KINDS
        for pair in pairs:
            events = pair.get("events")
            if not isinstance(events, list) or not events:
                continue
            row = db.execute("SELECT request FROM pairs WHERE id=? AND iran=?", (pair["id"], node["id"])).fetchone()
            if row is None:
                continue
            mark = db.execute("SELECT seen FROM notice_marks WHERE pair_id=?", (pair["id"],)).fetchone()
            seen = json.loads(mark["seen"]) if mark else None
            digests = []
            for item in events[-20:]:
                if not isinstance(item, dict):
                    continue
                key = digest(canonical({k: str(item.get(k, "")) for k in ("utc", "event", "detail")}).decode())[:16]
                digests.append(key)
                if seen is not None and key not in seen and item.get("event") in NOTIFY_KINDS:
                    self.queue_notice(db, pair["id"], json.loads(row["request"]).get("name"),
                                      item.get("event"), item.get("detail", ""), item.get("utc"))
            keep = ((seen or []) + [d for d in digests if d not in (seen or [])])[-60:]
            db.execute("INSERT INTO notice_marks(pair_id,seen) VALUES(?,?) ON CONFLICT(pair_id) DO UPDATE SET seen=excluded.seen",
                       (pair["id"], json.dumps(keep)))

    def queue_notice(self, db, pair_id, name, kind, detail, at=None):
        body = {"kind": str(kind)[:40], "pair": str(name or pair_id[:8])[:40], "detail": str(detail)[:200],
                "utc": at if isinstance(at, str) else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.clock()))}
        db.execute("INSERT INTO notices(pair_id,at,body) VALUES(?,?,?)", (pair_id, self.clock(), canonical(body).decode()))
        # Bounded: two days, 300 rows.
        db.execute("DELETE FROM notices WHERE at<? OR id <= (SELECT MAX(id) FROM notices) - 300", (self.clock() - 172800,))

    def notice(self, pair_id, kind, detail):
        with self.transaction() as db:
            row = db.execute("SELECT request FROM pairs WHERE id=?", (identifier(pair_id),)).fetchone()
            if row is not None:
                self.queue_notice(db, pair_id, json.loads(row["request"]).get("name"), kind, detail)

    def create_pair(self, node, request):
        if node["role"] != "iran":
            raise PronetError("Only Iran can create a pair")
        request = validate_request(request)
        # The carrier identity remains fixed at enrollment. A separate gateway
        # address is allowed for a multi-IP Iran; the local agent must verify
        # its assignment before any listener is created.
        current = self.clock()
        with self.transaction() as db:
            db.execute("UPDATE pairs SET state='FAILED',result=? WHERE state='UNPAIRED' AND expires<?",
                       ('{"error":"Pairing code expired"}', current))
            pending = db.execute("SELECT count(*) FROM pairs WHERE state='UNPAIRED'").fetchone()[0]
            if pending >= 100:
                raise PronetError("Too many pending pairs")
            existing = db.execute("SELECT request FROM pairs WHERE iran=? AND state NOT IN ('FAILED','STOPPED')", (node["id"],)).fetchall()
            for row in existing:
                other = json.loads(row[0])
                if other["bind_ip"] == request["bind_ip"] and set(inbound_ports(other)) & set(inbound_ports(request)):
                    raise PronetError("This endpoint is already reserved by a pair")
            occupied = {row[0] for row in db.execute("SELECT code FROM pairs WHERE state='UNPAIRED'")}
            for _ in range(100):
                code = f"{secrets.randbelow(10000):04d}"
                if code not in occupied:
                    break
            else:
                raise PronetError("Could not allocate pairing code")
            pair_id = secrets.token_hex(12)
            db.execute("INSERT INTO pairs(id,code,iran,expires,state,request,updated) VALUES(?,?,?,?,?,?,?)",
                       (pair_id, code, node["id"], current + PAIR_CODE_SECONDS, "UNPAIRED", canonical(request).decode(), current))
        return {"pair_id": pair_id, "code": code, "expires_in": PAIR_CODE_SECONDS}

    def join_pair(self, node, code):
        if node["role"] != "foreign":
            raise PronetError("Only Foreign can join")
        if not isinstance(code, str) or len(code) != 4 or not code.isascii() or not code.isdigit():
            raise PronetError("Enter the four digits exactly")
        current = self.clock()
        failed = False
        pair_id = None
        with self.transaction() as db:
            record = db.execute("SELECT * FROM failures WHERE node=?", (node["id"],)).fetchone()
            count = record["count"] if record and current - record["window"] < 300 else 0
            if count >= 5:
                raise PronetError("Too many pairing attempts; wait five minutes")
            row = db.execute("SELECT * FROM pairs WHERE code=? AND state='UNPAIRED' AND expires>=?", (code, current)).fetchone()
            if row is None:
                window = record["window"] if count else current
                db.execute("INSERT OR REPLACE INTO failures VALUES(?,?,?)", (node["id"], window, count + 1))
                failed = True  # Commit attempts even though the response is an error.
            else:
                if row["iran"] == node["id"]:
                    raise PronetError("A node cannot pair with itself")
                active = db.execute("SELECT count(*) FROM pairs WHERE foreign_node=? AND state NOT IN ('FAILED','STOPPED')", (node["id"],)).fetchone()[0]
                if active:
                    raise PronetError("This foreign node already belongs to a pair; use a separate node configuration")
                db.execute("UPDATE pairs SET foreign_node=?,state='PAIRED',updated=? WHERE id=? AND state='UNPAIRED'",
                           (node["id"], current, row["id"]))
                pair_id = row["id"]
        if failed:
            raise PronetError("Code not available or expired")
        return {"pair_id": pair_id, "state": "PAIRED"}

    def pair(self, pair_id):
        identifier(pair_id)
        with self.connect() as db:
            row = db.execute("SELECT * FROM pairs WHERE id=?", (pair_id,)).fetchone()
            if row is None:
                raise PronetError("Unknown pair")
            result = dict(row)
            for name in ("request", "result"):
                result[name] = json.loads(result[name])
            for role, column in (("iran_info", "iran"), ("foreign_info", "foreign_node")):
                node = db.execute("SELECT info FROM nodes WHERE id=?", (result[column],)).fetchone()
                result[role] = json.loads(node[0]) if node else None
            return result

    def add_event(self, pair_id, kind, detail):
        from .notify import NOTIFY_KINDS
        with self.transaction() as db:
            db.execute("INSERT INTO events(pair_id,at,kind,detail) VALUES(?,?,?,?)",
                       (identifier(pair_id), self.clock(), str(kind)[:40], canonical({"detail": str(detail)[:300]}).decode()))
            row = db.execute("SELECT request FROM pairs WHERE id=?", (pair_id,)).fetchone()
            if row is not None and kind in NOTIFY_KINDS:
                self.queue_notice(db, pair_id, json.loads(row["request"]).get("name"), kind, detail)

    def update_pair(self, pair_id, state, result):
        with self.transaction() as db:
            current = db.execute("SELECT desired,result FROM pairs WHERE id=?", (identifier(pair_id),)).fetchone()
            if current and current["desired"] == "stop" and state not in ("STOPPED", "STOP_UNCONFIRMED"):
                result = dict(result, phase="operator-stop")
                previous = json.loads(current["result"])
                if "stop_request" in previous:
                    result["stop_request"] = previous["stop_request"]
                state = "STOPPING"
            db.execute("UPDATE pairs SET state=?,result=?,updated=? WHERE id=?",
                       (state, canonical(result).decode(), self.clock(), identifier(pair_id)))
            db.execute("INSERT INTO events(pair_id,at,kind,detail) VALUES(?,?,?,?)",
                       (pair_id, self.clock(), state, canonical({k: v for k, v in result.items() if k in ('error','phase','active','warnings')}).decode()))
            db.execute("DELETE FROM events WHERE id < (SELECT coalesce(max(id),0)-10000 FROM events)")

    def pending(self):
        with self.connect() as db:
            return [row[0] for row in db.execute("SELECT id FROM pairs WHERE desired='run' AND state IN ('PAIRED','PREFLIGHT','TRIAL','STAGED','VERIFYING','ROLLING_BACK')")]

    def stopping(self):
        with self.connect() as db:
            return [row[0] for row in db.execute("SELECT id FROM pairs WHERE desired='stop' AND state NOT IN ('STOPPED','STOP_UNCONFIRMED')")]

    def advanced_pair(self, node, pair_id, spoof=None):
        from .model import PROFILES, validate_spoof
        pair_id = identifier(pair_id)
        sources = validate_spoof(spoof or {})
        with self.transaction() as db:
            old = db.execute('SELECT * FROM pairs WHERE id=?',(pair_id,)).fetchone()
            if not old or node['role'] != 'iran' or old['iran'] != node['id']:
                raise PronetError('Only the owner Iran node may request an advanced test')
            previous = json.loads(old['result'])
            if (old['state'] != 'FAILED' or old['desired'] != 'run' or not previous.get('cleanup_confirmed')
                    or not previous.get('advanced_available') or not old['foreign_node']):
                raise PronetError('Advanced retry requires a failed ordinary qualification with confirmed cleanup')
            request = json.loads(old['request'])
            request.update(advanced=True, full_test=True, emergency=False, test_only=False, spoof=sources,
                           profiles=[name for name,spec in PROFILES.items() if not spec.get('emergency') or sources])
            request = validate_request(request)
            # Reuse only the already paired peer, never an arbitrary foreign ID.
            busy = db.execute("SELECT request FROM pairs WHERE id!=? AND state NOT IN ('FAILED','STOPPED') AND (iran=? OR foreign_node=?)",
                              (pair_id,node['id'],old['foreign_node'])).fetchall()
            for other in busy:
                data = json.loads(other['request'])
                if data.get('bind_ip') == request['bind_ip'] and set(inbound_ports(data)) & set(inbound_ports(request)):
                    raise PronetError('This client endpoint is now reserved by another pairing')
            foreign_busy = db.execute("SELECT 1 FROM pairs WHERE foreign_node=? AND state NOT IN ('FAILED','STOPPED')",(old['foreign_node'],)).fetchone()
            if foreign_busy: raise PronetError('The foreign node now belongs to another pairing')
            new_id=secrets.token_hex(12)
            db.execute("INSERT INTO pairs(id,code,iran,foreign_node,expires,state,request,result,updated) VALUES(?,?,?,?,?,'PAIRED',?,'{}',?)",
                       (new_id,'',node['id'],old['foreign_node'],0,canonical(request).decode(),self.clock()))
        return {'pair_id':new_id,'state':'PAIRED','advanced':True}

    def request_stop(self, node, pair_id):
        pair = self.pair(pair_id)
        if node["id"] not in (pair["iran"], pair["foreign_node"]):
            raise PronetError("This node does not own the pair")
        if pair["state"] == "STOPPED": return {"state": "STOPPED", "pair_id": pair_id}
        result = pair["result"]
        result["stop_request"] = secrets.token_hex(12)
        result["phase"] = "operator-stop"
        with self.transaction() as db:
            db.execute("UPDATE pairs SET desired='stop',state='STOPPING',result=?,updated=? WHERE id=?",
                       (canonical(result).decode(), self.clock(), pair_id))
        self.cancel_pending(pair_id)
        return {"state": "STOPPING", "pair_id": pair_id}

    def enqueue(self, pair_id, node_id, op, payload, step):
        if op not in OPERATIONS:
            raise PronetError("Operation not allowed")
        pair = self.pair(pair_id)
        if node_id not in (pair["iran"], pair["foreign_node"]):
            raise PronetError("Node is not a member of the pair")
        job_id = digest(pair_id + ":" + step)[:24]
        encoded = canonical(payload).decode()
        with self.transaction() as db:
            desired = db.execute("SELECT desired FROM pairs WHERE id=?", (pair_id,)).fetchone()[0]
            if desired == "stop" and op != "cleanup":
                raise PronetError("Operator requested a stop")
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row:
                if (row["op"], row["payload"], row["node"]) != (op, encoded, node_id):
                    raise PronetError("Idempotency key was reused for a different operation")
            else:
                db.execute("INSERT INTO jobs(id,pair_id,node,op,payload,state,created) VALUES(?,?,?,?,?,'queued',?)",
                           (job_id, pair_id, node_id, op, encoded, self.clock()))
        self.notify_jobs()
        return job_id

    def job_signal(self):
        with self.jobs_changed:
            return self.jobs_version

    def notify_jobs(self):
        with self.jobs_changed:
            self.jobs_version += 1
            self.jobs_changed.notify_all()

    def wait_jobs(self, seen, timeout):
        with self.jobs_changed:
            self.jobs_changed.wait_for(lambda: self.jobs_version != seen, timeout)

    def claim(self, node, lane=None):
        current = self.clock()
        lane_filter, values = "", [node["id"], current]
        if lane in ("main", "measure"):
            marks = ",".join("?" * len(MEASURE_OPS))
            lane_filter = " AND jobs.op %s IN (%s)" % ("" if lane == "measure" else "NOT", marks)
            values += sorted(MEASURE_OPS)
        with self.transaction() as db:
            rows = db.execute("SELECT jobs.* FROM jobs JOIN pairs ON pairs.id=jobs.pair_id WHERE node=? AND (jobs.state='queued' OR (jobs.state='leased' AND lease<?)) AND (pairs.state NOT IN ('FAILED','STOPPED') OR jobs.op='cleanup') AND (pairs.desired='run' OR jobs.op='cleanup')" + lane_filter + " ORDER BY created LIMIT 1",
                              values).fetchall()
            if not rows:
                return None
            row = rows[0]
            if row["tries"] >= 3:
                db.execute("UPDATE jobs SET state='done',result=? WHERE id=?", ('{"ok":false,"error":"Job lease retry budget exhausted"}', row["id"]))
                return None
            # Nodes execute at most one job; a random lease proof rejects a
            # delayed result from a superseded worker.
            proof = secret()
            lease = current + 180
            db.execute("UPDATE jobs SET state='leased',lease=?,tries=tries+1,result=? WHERE id=?",
                       (lease, canonical({"lease_proof": proof}).decode(), row["id"]))
            return {"id": row["id"], "pair_id": row["pair_id"], "op": row["op"],
                    "payload": json.loads(row["payload"]), "lease_proof": proof, "lease_until": lease}

    def finish(self, node, job_id, proof, result):
        identifier(job_id)
        if not isinstance(result, dict) or type(result.get("ok")) is not bool or len(canonical(result)) > 131072:
            raise PronetError("Invalid job result")
        with self.transaction() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=? AND node=?", (job_id, node["id"])).fetchone()
            if row is None:
                raise PronetError("Job not assigned to this node")
            previous = json.loads(row["result"] or "{}")
            if row["state"] == "done":
                if previous == result:
                    return {"ok": True}
                raise PronetError("Completed job cannot be overwritten")
            if not isinstance(proof, str) or not hmac.compare_digest(previous.get("lease_proof", ""), proof):
                raise PronetError("Job lease was superseded")
            db.execute("UPDATE jobs SET state='done',result=? WHERE id=?", (canonical(result).decode(), job_id))
        return {"ok": True}

    def job_progress_set(self, node, job_id, proof, progress):
        """Display-only progress of a leased job (agent -> hub)."""
        identifier(job_id)
        if (not isinstance(progress, dict) or len(progress) > 16
                or any(not isinstance(k, str) or len(k) > 64 or not isinstance(v, dict) for k, v in progress.items())):
            raise PronetError("Invalid job progress")
        clean_progress = {}
        for name, row in progress.items():
            pct = row.get("pct", 0)
            clean_progress[name] = {"phase": str(row.get("phase", ""))[:20],
                                    "pct": max(0, min(100, pct)) if type(pct) is int else 0}
        with self.transaction() as db:
            row = db.execute("SELECT state,result FROM jobs WHERE id=? AND node=?", (job_id, node["id"])).fetchone()
            if row is None or row["state"] != "leased":
                return {"ok": False}
            previous = json.loads(row["result"] or "{}")
            if not isinstance(proof, str) or not hmac.compare_digest(previous.get("lease_proof", ""), proof):
                raise PronetError("Job lease was superseded")
            previous["progress"] = clean_progress
            # A grouped transfer can take longer than the initial 180 s lease.
            # Only its current proof may extend it; a stale worker cannot keep
            # a superseded lease alive.
            db.execute("UPDATE jobs SET result=?,lease=? WHERE id=? AND state='leased'",
                       (canonical(previous).decode(), self.clock() + 180, job_id))
        return {"ok": True}

    def job_progress(self, job_id):
        with self.connect() as db:
            row = db.execute("SELECT state,result FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row or row["state"] != "leased":
            return None
        value = json.loads(row["result"] or "{}").get("progress")
        return value if isinstance(value, dict) else None

    def set_live(self, pair_id, live):
        """Update only the live test view of a pair: no state change, no event row."""
        with self.transaction() as db:
            row = db.execute("SELECT state,desired,result FROM pairs WHERE id=?", (identifier(pair_id),)).fetchone()
            if row is None or row["desired"] == "stop" or row["state"] in TERMINAL:
                return
            result = json.loads(row["result"])
            result["live"] = live
            db.execute("UPDATE pairs SET result=? WHERE id=?", (canonical(result).decode(), pair_id))

    def request_switch(self, pair_id):
        """Dashboard: ask the Iran agent to move new connections back to the
        main carrier. Returns the job id (its result says what happened)."""
        pair = self.pair(identifier(pair_id))
        if pair.get("state") != "ACTIVE" or pair.get("desired", "run") != "run":
            raise PronetError("This tunnel is not active")
        return self.enqueue(pair_id, pair["iran"], "switch", {"profile": None}, "switch-" + secrets.token_hex(8))

    def job_result(self, job_id):
        with self.connect() as db:
            row = db.execute("SELECT state,result FROM jobs WHERE id=?", (job_id,)).fetchone()
        return json.loads(row["result"]) if row and row["state"] == "done" else None

    def cancel_pending(self, pair_id):
        with self.connect() as db:
            db.execute("UPDATE jobs SET state='done',result=? WHERE pair_id=? AND state='queued' AND op!='cleanup'",
                       ('{"ok":false,"error":"Setup canceled"}', identifier(pair_id)))

    def overview(self, node=None):
        current = self.clock()
        with self.connect() as db:
            allowed_nodes = None
            if node:
                allowed_nodes = {node["id"]}
                for row in db.execute("SELECT iran,foreign_node FROM pairs WHERE iran=? OR foreign_node=?", (node["id"], node["id"])):
                    allowed_nodes.update(x for x in row if x)
            nodes = []
            for row in db.execute("SELECT id,role,info,last,metrics FROM nodes"):
                if allowed_nodes is not None and row["id"] not in allowed_nodes:
                    continue
                nodes.append({"id": row["id"], "role": row["role"], "info": json.loads(row["info"]),
                              "age_seconds": max(0, round(current - row["last"])),
                              "telemetry": "CURRENT" if current - row["last"] < 45 else "STALE",
                              "metrics": json.loads(row["metrics"])})
            pairs = []
            for row in db.execute("SELECT * FROM pairs ORDER BY updated DESC"):
                if node and node["id"] not in (row["iran"], row["foreign_node"]):
                    continue
                result = json.loads(row["result"])
                safe = {k: v for k, v in result.items() if k in ("phase", "error", "warnings", "results", "selected", "active", "endpoint", "recovery", "progress", "timing", "inbound", "live", "maintenance", "failed_phase", "cleanup_confirmed", "test_passed", "cleaned", "emergency", "learning", "advanced_available", "advanced_skipped")}
                pairs.append({"id": row["id"], "iran": row["iran"], "foreign": row["foreign_node"],
                              "state": row["state"], "request": json.loads(row["request"]), "result": safe,
                              "updated": row["updated"]})
            by_id = {item["id"]: item for item in nodes}
            for pair in pairs:
                own = by_id.get(pair["iran"], {})
                remote = by_id.get(pair["foreign"], {})
                observed = next((item for item in own.get("metrics", {}).get("pairs", []) if item.get("id") == pair["id"]), {})
                other = next((item for item in remote.get("metrics", {}).get("pairs", []) if item.get("id") == pair["id"]), {})
                selected = observed.get("selection", {})
                state = "UNKNOWN"
                if own.get("telemetry") == "CURRENT":
                    if observed.get("state") == "STOPPED": state = "STOPPED"
                    elif selected.get("last_probe") == "OK": state = "UP"
                    elif selected.get("last_probe"): state = "UNCONFIRMED"
                pair["runtime"] = {"link": state, "active": selected.get("active"),
                                   "active_uptime": selected.get("active_uptime") if type(selected.get("active_uptime")) in (int, float) else None,
                                   "profiles": [x for x in selected.get("profiles", []) if isinstance(x, str)][:3]
                                   if isinstance(selected.get("profiles", []), list) else [],
                                   "active_unstable": bool(selected.get("active_unstable")) if own.get("telemetry") == "CURRENT" else False,
                                   "active_episodes": selected.get("active_episodes", 0) if isinstance(selected.get("active_episodes", 0), int) else 0,
                                   "all_down_since": selected.get("all_down_since") if own.get("telemetry") == "CURRENT"
                                   and type(selected.get("all_down_since")) in (int, float) else None,
                                   "pause_reason": selected.get("pause_reason") if isinstance(selected.get("pause_reason"), str) else None,
                                   "recovery_paused": selected.get("auto_paused", False),
                                   "pause_id": selected.get("pause_id"), "remote_stopped": other.get("state") == "STOPPED",
                                   "rtt_ms": selected.get("rtt_ms") if state == "UP" else None,
                                   "inbound": other.get("inbound", "UNKNOWN") if remote.get("telemetry") == "CURRENT" else "UNKNOWN",
                                   "inbound_ports": other.get("inbound_ports", {}) if remote.get("telemetry") == "CURRENT" and isinstance(other.get("inbound_ports", {}), dict) else {},
                                   "standby_health": selected.get("standby_health", {}) if own.get("telemetry") == "CURRENT" and isinstance(selected.get("standby_health", {}), dict) else {},
                                   "traffic": observed.get("traffic", {}) if isinstance(observed.get("traffic", {}), dict) else {},
                                   "switches": [x for x in selected.get("switches", []) if isinstance(x, (int, float))][-3:]
                                   if isinstance(selected.get("switches", []), list) else [],
                                   "health": observed.get("health", {}) if isinstance(observed.get("health", {}), dict) else {},
                                   "events": [x for x in observed.get("events", []) if isinstance(x, dict)][-6:]
                                   if isinstance(observed.get("events", []), list) else [],
                                   "engines": {name: bool(row.get("engine_active")) for name, row in observed.get("profiles", {}).items()
                                               if isinstance(row, dict)} if isinstance(observed.get("profiles", {}), dict) else {},
                                   "remote_engines": {name: bool(row.get("engine_active")) for name, row in other.get("profiles", {}).items()
                                                      if isinstance(row, dict)} if remote.get("telemetry") == "CURRENT" and isinstance(other.get("profiles", {}), dict) else {}}
        return {"nodes": nodes, "pairs": pairs, "server_time": current}
