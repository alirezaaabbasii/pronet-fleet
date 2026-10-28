"""Bounded local aggregate statistics; never runs probes or sends telemetry.

At most one independent observation per route/profile/6-hour window. Repeating
the same setup does not manufacture evidence. Fleet retirement needs evidence
from many routes AND days; no fixed handful of failed packets can retire a path.
Retired adapters remain available only to explicitly requested full/advanced tests.
"""
from __future__ import annotations

import functools
import hashlib
import json
import math
import pathlib
import sqlite3
import time

from .common import APP, PronetError
from .model import PROFILES

MAX_ROWS = 2048
MAX_RUNS = 256
MAX_PAGES = 512                 # 2 MiB, separate from the coordinator job database
WINDOW = 6 * 3600
STALE = 90 * 86400
MASK = (1 << 62) - 1


@functools.lru_cache(maxsize=64)
def fingerprint(profile):
    spec = PROFILES[profile]
    assets = json.loads((APP / 'assets.lock.json').read_text())
    engine = assets.get(spec['engine'], {'version':'native-1'})
    adapter = 'carrier_engines.py' if spec['engine'] in ('paqet','backhaul','parsa-spoof') else 'native_gre.py' if spec['engine']=='native-gre' else 'engines.py'
    adapter_hash=hashlib.sha256((APP/'pronet'/adapter).read_bytes()).hexdigest()
    qualifier_hash=hashlib.sha256((APP/'pronet'/'wire.py').read_bytes()).hexdigest()
    data = [spec, engine.get('version'), engine.get('assets'), adapter_hash, qualifier_hash, 'qualification-v1']
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]


def route_key(pair):
    iran = pair.get('iran_info', {}).get('public_ip', pair['request'].get('public_ip'))
    foreign = pair.get('foreign_info', {}).get('public_ip')
    if not iran or not foreign:
        raise PronetError('Learning route identity is incomplete')
    value = [iran, foreign, pair['request'].get('direction','iran-dials'), pair['request'].get('sni','')]
    return hashlib.sha256(json.dumps(value).encode()).hexdigest()[:32]


def upper_bound(n, success):
    if not n: return 1.0
    z = 1.96
    p = success / n
    return (p + z*z/(2*n) + z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))) / (1+z*z/n)


def retired(row, global_scope=False):
    if not row: return False
    # Bit collisions undercount distinct routes; they never create evidence.
    enough_days = int(row['days']).bit_count() >= 7
    if global_scope:
        return (row['n'] >= 40 and int(row['routes']).bit_count() >= 8 and enough_days
                and upper_bound(row['n'], row['success']) < .10)
    return row['n'] >= 24 and enough_days and upper_bound(row['n'], row['success']) < .20


def observation(row):
    if row.get('stage') in ('prepare','start'):
        return None
    from .model import ranking
    if ranking([row]):
        # A failing soak must not be learned as a successful stable path.
        if isinstance(row.get('soak'), dict) and not row['soak'].get('passed'):
            return False
        return True
    text = str(row.get('error') or row.get('reason') or '').lower()
    technical = ('engine exited','service','version','missing','unavailable','permission','occupied','ownership','timeout waiting for job')
    if any(word in text for word in technical): return None
    if row.get('stage') == 'reach' and any(x in text for x in ('connect','unreach','filtered','blocked')):
        return False
    if row.get('echo_ms') and isinstance(row.get('success_ratio'), (int,float)):
        return False
    return None


class CarrierMemory:
    def __init__(self, path, clock=time.time):
        self.path = pathlib.Path(path)
        self.clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as db:
            db.executescript('''
                PRAGMA journal_mode=DELETE;
                CREATE TABLE IF NOT EXISTS stats (
                  route TEXT, profile TEXT, version TEXT, n INTEGER, success INTEGER,
                  first REAL, last REAL, last_success REAL, rate REAL, latency REAL,
                  day INTEGER, days INTEGER, routes INTEGER, bucket INTEGER, bucket_ok INTEGER,
                  PRIMARY KEY(route,profile,version));
                CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, at REAL);
            ''')
        self.path.chmod(0o600)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=3)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA busy_timeout=3000')
        db.execute('PRAGMA page_size=4096')
        db.execute('PRAGMA max_page_count=' + str(MAX_PAGES))
        return _Closing(db)

    def plan(self, pair, names, force=False):
        if force: return {'profiles':list(names),'skipped':[], 'preferred':[], 'bypassed':True}
        route = route_key(pair)
        now = self.clock()
        selected, skipped, priorities, preferred = [], [], {}, []
        with self.connect() as db:
            rows = {(r['route'],r['profile'],r['version']):dict(r) for r in db.execute(
                'SELECT * FROM stats WHERE route IN (?,?)',(route,'*'))}
        for name in names:
            version = fingerprint(name)
            own, fleet = rows.get((route,name,version)),rows.get(('*',name,version))
            if own and own['last'] < now-STALE and not retired(own): own=None
            if fleet and fleet['last'] < now-STALE and not retired(fleet, True): fleet=None
            local_bad = retired(own)
            fleet_bad = retired(fleet, True) and not (own and own['last_success'] >= now-30*86400)
            if local_bad or fleet_bad:
                row = own if local_bad else fleet
                skipped.append({'profile':name, 'reason':'low measured qualification success on this route' if local_bad else 'low measured qualification success across fleet routes',
                                'observations':row['n'],'successes':row['success'],
                                'success_upper_bound':round(upper_bound(row['n'],row['success']),3)})
                continue
            selected.append(name)
            best = own if own and own['success'] else fleet
            if best and best['success']:
                rate = max(0,min(best['rate'],10000))
                priorities[name] = (2 if own and own['success'] else 1, best['success']/max(1,best['n']), math.log1p(rate)/(1+best['latency']/200))
                preferred.append(name)
        preferred.sort(key=lambda n:priorities[n], reverse=True)
        selected = preferred + [n for n in selected if n not in preferred]
        return {'profiles':selected,'preferred':preferred,'skipped':skipped,'bypassed':False}

    def record(self, pair, rows, healthy=True):
        if not healthy or pair['request'].get('emergency'):
            return
        values = [(r,observation(r)) for r in rows if r.get('profile') in PROFILES and not PROFILES[r['profile']].get('emergency')]
        # An entirely dead route is not evidence against every individual engine.
        if not any(ok is True for _,ok in values): return
        route = route_key(pair)
        now = self.clock()
        day,bucket = int(now//86400),int(now//WINDOW)
        bit = 1 << (int(hashlib.sha256(route.encode()).hexdigest()[:8],16)%62)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM runs WHERE id=?',(pair['id'],)).fetchone(): return
            versions=sorted({fingerprint(name) for name,spec in PROFILES.items() if not spec.get('emergency')})
            db.execute('DELETE FROM stats WHERE version NOT IN ('+','.join('?' for _ in versions)+')',versions)
            db.execute('DELETE FROM stats WHERE route!=? AND last<? AND (n<24 OR success>n*.25)',('*',now-STALE))
            db.execute('DELETE FROM stats WHERE rowid IN (SELECT rowid FROM stats WHERE route!=? ORDER BY last ASC LIMIT max(0,(SELECT count(*) FROM stats)-?))',('*',MAX_ROWS-2*len(PROFILES)))
            for row,ok in values:
                if ok is None: continue
                name=row['profile']; version=fingerprint(name)
                own=db.execute('SELECT * FROM stats WHERE route=? AND profile=? AND version=?',(route,name,version)).fetchone()
                own=dict(own) if own else None
                fresh = not own or own['bucket'] != bucket
                upgrade = not fresh and ok and not own['bucket_ok']
                if not fresh and not upgrade and not (ok and pair["request"].get("advanced")): continue
                dn,ds = int(fresh),int(ok and (fresh or upgrade))
                rate = min(row.get('upload_mbps') or 0,row.get('download_mbps') or 0)
                latency = sum(row.get('echo_ms') or [0])/len(row.get('echo_ms') or [0])
                if not math.isfinite(rate) or not math.isfinite(latency): continue
                for scope in (route,'*'):
                    previous=db.execute('SELECT * FROM stats WHERE route=? AND profile=? AND version=?',(scope,name,version)).fetchone()
                    old=dict(previous) if previous else dict(n=0,success=0,first=now,last_success=0,rate=0,latency=0,day=day,days=0,routes=0,bucket=-1,bucket_ok=0)
                    delta=max(0,min(62,day-old['day']))
                    days=((int(old['days']) << delta)&MASK)|1
                    n,s=old['n']+dn,old['success']+ds
                    if n>4096: n=max(1,n//2);s=min(n,s//2)
                    # A deliberate advanced success requalifies this route;
                    # fleet evidence is retained for other routes.
                    if scope==route and ok and pair['request'].get('advanced'):
                        n,s,days=1,1,1
                    ew_rate=(old['rate']*.8+rate*.2) if old['rate'] else rate
                    ew_latency=(old['latency']*.8+latency*.2) if old['latency'] else latency
                    db.execute('INSERT OR REPLACE INTO stats VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                        (scope,name,version,n,s,old['first'],now,now if ok else old['last_success'],
                         ew_rate if ok else old['rate'],ew_latency if ok else old['latency'],day,days,
                         (int(old['routes'])|bit)&MASK,bucket,int(ok or (not fresh and old['bucket_ok']))))
            db.execute('INSERT INTO runs VALUES(?,?)',(pair['id'],now))
            db.execute('DELETE FROM runs WHERE rowid IN (SELECT rowid FROM runs ORDER BY at DESC LIMIT -1 OFFSET ?)',(MAX_RUNS,))

    def summary(self):
        with self.connect() as db:
            rows=[dict(r) for r in db.execute('SELECT profile,version,n,success,last,last_success,rate,latency,days,routes FROM stats WHERE route=?',('*',))]
            count=db.execute('SELECT count(*) FROM stats').fetchone()[0]
        rows=[row for row in rows if row['profile'] in PROFILES and row['version']==fingerprint(row['profile'])]
        for row in rows:
            row['retired']=retired(row,True)
            row['routes_observed_at_least']=int(row.pop('routes')).bit_count()
            row['days_observed']=int(row.pop('days')).bit_count()
        return {'records':count,'bytes':self.path.stat().st_size,'max_bytes':MAX_PAGES*4096,'profiles':rows,
                'scope':'this coordinator only; no external telemetry','background_probes':False}

    def clear(self):
        with self.connect() as db:
            db.execute('DELETE FROM stats');db.execute('DELETE FROM runs')
            db.commit();db.execute('VACUUM')


class _Closing:
    def __init__(self, db): self.db=db
    def __enter__(self): return self.db
    def __exit__(self, kind, value, traceback):
        try:
            if kind is None: self.db.commit()
            else: self.db.rollback()
        finally: self.db.close()
