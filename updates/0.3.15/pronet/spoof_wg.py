"""Pair-owned WireGuard over Parsa's single UDP pipe.

Only TCP spoof carriers are enabled: upstream ICMP modes change a global sysctl.
WireGuard supplies authenticated encryption, replay protection and isolation.
No address scanning, forwarding sysctl, default route or shared WG config changes.
"""
from __future__ import annotations

import base64
import contextlib
import json
import pathlib
import shutil
import subprocess
import threading

from .common import ROOT, PronetError, atomic_write, command, lock, read_json, write_json
from .model import iface, tunnel_ips, validate_profile


def requirements():
    if not shutil.which('wg'):
        raise PronetError('Spoof needs wireguard-tools (wg); install the prerequisite on both servers')
    if not shutil.which('ip'):
        raise PronetError('Spoof needs Linux iproute2')


def checked_key(value):
    try:
        if not isinstance(value, str) or len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError()
    except ValueError:
        raise PronetError('Invalid WireGuard public key')
    return value


def public_key(directory):
    requirements()
    path = pathlib.Path(directory) / 'wg.key'
    if not path.exists():
        atomic_write(path, command(['wg', 'genkey']).stdout.strip() + '\n')
    if path.is_symlink():
        raise PronetError('Refusing WireGuard key symlink')
    return checked_key(command(['wg', 'pubkey'], input=path.read_text()).stdout.strip())


def expected(plan):
    validate_profile(plan)
    if plan['profile'] != 'parsa-spoof':
        raise PronetError('WireGuard helper only accepts the Parsa spoof profile')
    return {'name': iface(plan), 'owner': 'pronetf:' + plan['pair_id'] + ':parsa-spoof:engine'}


def lookup(name):
    rows = json.loads(command(['ip', '-j', '-d', 'link', 'show']).stdout)
    return next((row for row in rows if row.get('ifname') == name), None)


def record_path(item):
    return ROOT / 'spoof-ownership' / (item['name'] + '.json')


def owned(row, item):
    record = read_json(record_path(item), {})
    if (row.get('linkinfo', {}).get('info_kind') != 'wireguard'
            or record.get('expected') != item or record.get('ifindex') != row.get('ifindex')
            or row.get('ifalias') not in (item['owner'], '' if record.get('phase') == 'creating' else None)):
        raise PronetError('Spoof interface ownership changed; leaving interface untouched')


def down(plan):
    item = expected(plan)
    with lock(ROOT / 'spoof-operation.lock'):
        row = lookup(item['name'])
        if row is not None:
            owned(row, item)
            command(['ip', 'link', 'delete', 'dev', item['name']])
        record_path(item).unlink(missing_ok=True)


def up(plan, directory):
    requirements()
    item = expected(plan)
    role = plan['role']
    peer_role = 'foreign' if role == 'iran' else 'iran'
    keys = plan.get('wg_public_keys', {})
    peer_key = checked_key(keys.get(peer_role))
    if public_key(directory) != checked_key(keys.get(role)):
        raise PronetError('WireGuard identity changed after preparation')
    own, peer = tunnel_ips(plan) if role == 'iran' else tuple(reversed(tunnel_ips(plan)))
    text = ('[Interface]\nPrivateKey = ' + (directory / 'wg.key').read_text().strip()
            + '\nListenPort = ' + str(plan['data_port']) + '\n[Peer]\nPublicKey = ' + peer_key
            + '\nAllowedIPs = ' + peer + '/32\n')
    if role == 'iran':
        text += 'Endpoint = 127.0.0.1:' + str(plan['health_port']) + '\nPersistentKeepalive = 15\n'
    config = directory / 'wireguard.conf'
    atomic_write(config, text)
    with lock(ROOT / 'spoof-operation.lock'):
        row = lookup(item['name'])
        if row is None:
            write_json(record_path(item), {'expected': item, 'phase': 'creating'})
            command(['ip', 'link', 'add', 'dev', item['name'], 'type', 'wireguard'])
            row = lookup(item['name'])
            if row is None: raise PronetError('WireGuard interface did not appear')
            write_json(record_path(item), {'expected': item, 'phase': 'creating', 'ifindex': row['ifindex']})
            command(['ip', 'link', 'set', 'dev', item['name'], 'alias', item['owner']])
            row = lookup(item['name'])
        owned(row, item)
        command(['wg', 'setconf', item['name'], str(config)])
        command(['ip', '-4', 'address', 'replace', own + '/30', 'dev', item['name']])
        command(['ip', 'link', 'set', 'dev', item['name'], 'mtu', '1200', 'up'])
        write_json(record_path(item), {'expected': item, 'phase': 'active', 'ifindex': row['ifindex']})


def run(plan, directory, stop=None):
    stop = stop or threading.Event()
    recipe = read_json(directory / 'launch.json')
    args = recipe['command']
    binary = pathlib.Path(args[0]).resolve()
    if not binary.is_relative_to((ROOT / 'engines').resolve()):
        raise PronetError('Spoof executable is outside managed storage')
    process = None
    try:
        # Start the relay first, then WG starts sending its handshakes to it.
        process = subprocess.Popen(args)
        up(plan, directory)
        while not stop.wait(.5):
            if process.poll() is not None:
                raise PronetError('Spoof relay exited; refusing to leave a false healthy interface')
            owned(lookup(iface(plan)) or {}, expected(plan))
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        down(plan)
