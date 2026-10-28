"""Native Linux GRE (IP protocol 47), independent of BackPack.

Only an interface with this pair's alias AND matching GRE endpoints/key may be
reused or removed. No default routes, forwarding policy or global sysctls change.
GRE keys distinguish tunnels; they are not encryption or authentication.
"""
from __future__ import annotations

import ipaddress
import json
import shutil
import threading

from .common import ROOT, PronetError, command, lock, read_json, write_json
from .model import iface, tunnel_ips, validate_profile

MTU = 1280


def parameters(plan):
    validate_profile(plan)
    if plan['profile'] != 'gre':
        raise PronetError('Native GRE requires the gre profile')
    iran = plan['role'] == 'iran'
    local, peer = tunnel_ips(plan) if iran else tuple(reversed(tunnel_ips(plan)))
    return {'name': iface(plan), 'owner': 'pronetf:' + plan['pair_id'] + ':gre:engine',
            'local': plan['bind_ip'], 'remote': plan['foreign_ip'] if iran else plan['iran_ip'],
            # Allocated subnets are collision-checked across all managed pairs.
            'key': int(ipaddress.ip_network(plan['subnet']).network_address),
            'address': local + '/30', 'peer': peer, 'mtu': MTU}


def links():
    rows = json.loads(command(['ip', '-j', '-d', 'link', 'show']).stdout)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise PronetError('Cannot inspect GRE interface ownership')
    return rows


def lookup(name):
    return next((row for row in links() if row.get('ifname') == name), None)


def _key(value):
    if type(value) is int:
        return value
    if isinstance(value, str):
        return int(ipaddress.IPv4Address(value)) if '.' in value else int(value, 0)
    raise ValueError('missing GRE key')


def ownership_path(expected):
    return ROOT / 'gre-ownership' / (expected['name'] + '.json')


def assert_owned(row, expected, pending=False):
    info = row.get('linkinfo') or {}
    data = info.get('info_data') or {}
    try:
        tagged = row.get('ifalias') == expected['owner']
        if pending and row.get('ifalias') in (None, ''):
            record = read_json(ownership_path(expected), {})
            tagged = (record.get('expected') == expected and record.get('phase') == 'creating'
                      and ('ifindex' not in record or record['ifindex'] == row.get('ifindex')))
        matches = (row.get('ifname') == expected['name'] and tagged
                   and info.get('info_kind') == 'gre' and data.get('local') == expected['local']
                   and data.get('remote') == expected['remote'] and _key(data.get('ikey')) == expected['key']
                   and _key(data.get('okey')) == expected['key'])
    except (ValueError, TypeError):
        matches = False
    if not matches:
        raise PronetError('GRE interface ownership or endpoints changed; refusing modification: ' + expected['name'])


def _check_routes(plan, expected):
    subnet = ipaddress.ip_network(plan['subnet'])
    routes = json.loads(command(['ip', '-j', '-4', 'route', 'show', 'table', 'all']).stdout)
    for route in routes:
        if route.get('dev') == expected['name'] or route.get('dst') in (None, 'default'):
            continue
        try:
            other = ipaddress.ip_network(route['dst'], strict=False)
        except ValueError:
            continue
        if subnet.overlaps(other):
            raise PronetError('GRE subnet overlaps an existing route; existing route left unchanged')


def _down(expected):
    row = lookup(expected['name'])
    if row is not None:
        assert_owned(row, expected, pending=True)
        command(['ip', 'link', 'delete', 'dev', expected['name']])
    ownership_path(expected).unlink(missing_ok=True)


def up(plan):
    expected = parameters(plan)
    with lock(ROOT / 'gre-operation.lock'):
        current = lookup(expected['name'])
        if current is not None:
            assert_owned(current, expected, pending=True)
        _check_routes(plan, expected)
        created = False
        try:
            if current is None:
                # Some kernels ignore IFLA_IFALIAS on NEWLINK. Record the
                # creation intent first; only this exact pending identity can
                # be recovered if the helper dies before SETLINK tags it.
                write_json(ownership_path(expected), {'expected': expected, 'phase': 'creating'})
                command(['ip', 'link', 'add', 'name', expected['name'], 'alias', expected['owner'],
                         'mtu', str(MTU), 'type', 'gre', 'local', expected['local'], 'remote', expected['remote'],
                         'key', str(expected['key']), 'ttl', '64'])
                created = True
            row = lookup(expected['name']) or {}
            assert_owned(row, expected, pending=True)
            if row.get('ifalias') != expected['owner']:
                write_json(ownership_path(expected), {'expected': expected, 'phase': 'creating', 'ifindex': row['ifindex']})
                command(['ip', 'link', 'set', 'dev', expected['name'], 'alias', expected['owner']])
            write_json(ownership_path(expected), {'expected': expected, 'phase': 'active', 'ifindex': row.get('ifindex')})
            command(['ip', '-4', 'address', 'replace', expected['address'], 'dev', expected['name']])
            if plan.get('gaming'):
                command(['ip','link','set','dev',expected['name'],'txqueuelen','64'])
                if shutil.which('tc'):
                    command(['tc','qdisc','replace','dev',expected['name'],'root','fq_codel'],check=False)
            command(['ip', 'link', 'set', 'dev', expected['name'], 'mtu', str(MTU), 'up'])
            assert_owned(lookup(expected['name']) or {}, expected)
        except BaseException:
            if created:
                _down(expected)
            elif current is None:
                ownership_path(expected).unlink(missing_ok=True)
            raise
    return {'interface': expected['name'], 'outer_protocol': 47, 'mtu': MTU}


def down(plan):
    expected = parameters(plan)
    with lock(ROOT / 'gre-operation.lock'):
        _down(expected)


def run(plan, stop=None):
    stop = stop or threading.Event()
    try:
        up(plan)
        while not stop.wait(5):
            expected = parameters(plan)
            assert_owned(lookup(expected['name']) or {}, expected)
    finally:
        down(plan)
