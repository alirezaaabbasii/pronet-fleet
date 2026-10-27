"""Opt-in activation of a verified, versioned offline management bundle.

Changes owned unit references, not live engine versions or pair identities.
"""
from __future__ import annotations

import pathlib
import re
import time

from .common import ROOT, CONFIG, PronetError, atomic_write, command, lock, read_json, write_json

MAIN_PATTERN = re.compile(r"/opt/pronet-fleet/[0-9]+\.[0-9]+\.[0-9]+/main\.py")
OWNER_PATTERN = re.compile(r"# Pronet Fleet owner=(hub|agent|counters|[a-f0-9]{24})\n")
UNIT_DIRECTORY = pathlib.Path('/etc/systemd/system')


def migrated_unit(text, main_file):
    if not OWNER_PATTERN.match(text): raise PronetError("Refusing unit outside Pronet Fleet ownership")
    if not MAIN_PATTERN.search(text): return None
    updated = MAIN_PATTERN.sub(lambda _: str(main_file), text)
    # Repair early preview unit files as part of this migration.
    updated = re.sub(r'^WorkingDirectory="(/[^"\n]+)"$', r'WorkingDirectory=\1', updated, flags=re.M)
    return hardened_unit(updated)


def hardened_unit(text):
    """0.2.4 restart/capacity policy for PERMANENT owned services.

    Temporary trial units (RuntimeMaxSec) and the oneshot counter unit are left
    exactly as they are. Only these known lines are rewritten.
    """
    if "RuntimeMaxSec=" in text or "Type=oneshot" in text:
        return text
    replacements = (("StartLimitIntervalSec=600\nStartLimitBurst=5\n", "StartLimitIntervalSec=0\n"),
                    ("Restart=on-failure\n", "Restart=always\n"),
                    ("LimitNOFILE=32768\n", "LimitNOFILE=65536\n"),
                    ("TasksMax=128\n", "TasksMax=512\n"),
                    ("MemoryMax=384M\n", "MemoryMax=1G\n"))
    for old, new in replacements:
        text = text.replace(old, new)
    return text


def activate(main_file, previous_wrapper, wrapper):
    config = read_json(CONFIG / 'hub/hub.json', {})
    if config and pathlib.Path(config['database']).exists():
        import sqlite3
        with sqlite3.connect(config['database']) as db:
            pending = db.execute("SELECT count(*) FROM pairs WHERE state IN ('PAIRED','PREFLIGHT','TRIAL','STAGED','VERIFYING','ROLLING_BACK','STOPPING')").fetchone()[0]
        if pending: raise PronetError("Setup is in progress; activate the update after it completes")
    try:
        with lock(ROOT / 'host-operation.lock', blocking=False):
            return activate_locked(main_file, previous_wrapper, wrapper)
    except BaseException as error:
        if previous_wrapper: atomic_write(wrapper, previous_wrapper, 0o755)
        if isinstance(error, BlockingIOError):
            raise PronetError("A node operation is running; retry activation after it completes")
        raise


def raise_gateway_limits():
    """Gateways created by <=0.2.3 stored connection_limit=1024. The 0.2.4
    gateway reloads this file live, so the new limit applies without a restart."""
    from .wire import DEFAULT_CONNECTION_LIMIT
    raised = []
    for path in sorted((ROOT / 'pairs').glob('*/gateway.json')):
        try:
            config = read_json(path)
            if config.get('connection_limit') == 1024:
                config['connection_limit'] = DEFAULT_CONNECTION_LIMIT
                write_json(path, config)
                raised.append(path.parent.name)
        except (OSError, ValueError, PronetError):
            continue
    return raised


def activate_locked(main_file, previous_wrapper, wrapper):
    directory = UNIT_DIRECTORY
    stamp = str(time.time_ns())
    backup = ROOT / 'upgrade-backups' / stamp
    backup.mkdir(parents=True, mode=0o700)
    changed, restarted = [], []
    for unit in sorted(directory.glob('pronetf-*.service')):
        if unit.is_symlink(): raise PronetError("Owned service path is a symlink")
        text = unit.read_text()
        if not OWNER_PATTERN.match(text): continue
        migrated = migrated_unit(text, main_file)
        if migrated is None or migrated == text: continue
        atomic_write(backup / unit.name, text)
        changed.append((unit, text, migrated))
    atomic_write(backup / 'pronet-wrapper', previous_wrapper or b'')
    # Validate the entire staged set before changing any active unit.
    for unit, _, migrated in changed:
        staged = backup / 'staged' / unit.name
        atomic_write(staged, migrated, 0o644)
        command(['systemd-analyze', 'verify', str(staged)])
    try:
        for unit, _, migrated in changed: atomic_write(unit, migrated, 0o644)
        command(['systemctl', 'daemon-reload'])
        for name in ('pronetf-hub.service', 'pronetf-agent.service'):
            if not any(unit.name == name for unit, _, _ in changed): continue
            active = command(['systemctl', 'is-active', name], check=False).stdout.strip()
            if active in ('active', 'activating', 'failed'):
                command(['systemctl', 'reset-failed', name], check=False)
                restarted.append(name)
                command(['systemctl', 'restart', name])
                time.sleep(.7)
                if command(['systemctl', 'is-active', name], check=False).stdout.strip() != 'active':
                    raise PronetError("Updated service did not remain active: " + name)
        raised = raise_gateway_limits()
        write_json(backup / 'result.json', {'state': 'ACTIVATED', 'main': str(main_file), 'gateway_limits_raised': raised,
                   'units': [unit.name for unit, _, _ in changed], 'restarted': restarted})
    except BaseException:
        for unit, previous, _ in changed: atomic_write(unit, previous, 0o644)
        if previous_wrapper: atomic_write(wrapper, previous_wrapper, 0o755)
        command(['systemctl', 'daemon-reload'], check=False)
        for name in restarted: command(['systemctl', 'restart', name], check=False)
        write_json(backup / 'result.json', {'state': 'ROLLED_BACK', 'main': str(main_file)})
        raise
    return {'backup': str(backup), 'updated_units': len(changed), 'restarted': restarted,
            'engines': 'Existing running engines retain their pinned versions; use a newly tested pair to change a carrier build.'}
