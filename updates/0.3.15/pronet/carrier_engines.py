"""Independent, version-pinned packet and reverse engines.

Non-L3 engines carry the existing authenticated FIN/ACK bridge. That bridge
preserves application half-close even when upstream closes both TCP directions.
No upstream installer or global tuning command is executed.
"""
from __future__ import annotations

import json
import re
import socket
import time

from .common import PronetError, atomic_write, command
from .model import PROFILES


def route(peer, local, port):
    rows = json.loads(command(['ip', '-j', '-4', 'route', 'get', peer, 'from', local]).stdout)
    if not rows or not isinstance(rows[0].get('dev'), str):
        raise PronetError('Paqet: peer route has no usable network interface')
    row = rows[0]
    device, hop = row['dev'], row.get('gateway', peer)
    # Resolve the actual next hop without changing any routes or neighbour data.
    for attempt in range(6):
        neighbours = json.loads(command(['ip', '-j', '-4', 'neigh', 'show', 'to', hop, 'dev', device]).stdout)
        for neighbour in neighbours:
            mac = neighbour.get('lladdr', '')
            if re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac):
                return device, mac
        if attempt < 5:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind((local, 0))
                sock.sendto(b'', (peer, port))
            time.sleep(.2)
    raise PronetError('Paqet: next-hop MAC unavailable; no network settings changed')


def render(plan, directory, binaries):
    from .engines import toml_table
    engine = PROFILES[plan['profile']]['engine']
    iran = plan['role'] == 'iran'
    mappings = [(plan['health_port'], plan['bridge_health_port']),
                (plan['data_port'], plan['bridge_data_port'])]
    if engine == 'backhaul':
        values = dict(transport=PROFILES[plan['profile']]['carrier'], token=plan['token'],
                      nodelay=True, keepalive_period=30, log_level='warn', web_port=0,
                      sniffer=False, pprof=False, skip_optz=True, accept_udp=False)
        if iran:
            values.update(bind_addr=f"{plan['bind_ip']}:{plan['control_port']}", heartbeat=15,
                          ports=[f'127.0.0.1:{src}=127.0.0.1:{dst}' for src, dst in mappings])
        else:
            values.update(remote_addr=f"{plan['iran_ip']}:{plan['control_port']}",
                          retry_interval=3, dial_timeout=8, connection_pool=4)
        path = directory / 'engine.toml'
        atomic_write(path, toml_table('server' if iran else 'client', values))
        return dict(command=[binaries[engine], '-c', str(path)], validate=None, environment={})
    if engine == 'paqet':
        peer = plan['foreign_ip'] if iran else plan['iran_ip']
        device, mac = route(peer, plan['bind_ip'], plan['control_port'])
        config = dict(role='client' if iran else 'server', log={'level': 'warn'},
                      network={'interface': device, 'ipv4': {'addr': f"{plan['bind_ip']}:{plan['control_port']}",
                               'router_mac': mac}, 'tcp': {'local_flag': ['PA'], 'remote_flag': ['PA']}},
                      transport={'protocol': 'kcp', 'conn': 1, 'kcp': {'block': 'aes', 'key': plan['token'],
                                 'mode': 'normal', 'mtu': 1200}})
        if iran:
            config['server'] = {'addr': f"{peer}:{plan['control_port']}"}
            config['forward'] = [{'listen': f'127.0.0.1:{src}', 'target': f'127.0.0.1:{dst}', 'protocol': 'tcp'}
                                 for src, dst in mappings]
        else:
            config['listen'] = {'addr': f"{plan['bind_ip']}:{plan['control_port']}"}
        path = directory / 'engine.yaml'
        # JSON is a strict YAML subset. No optional YAML dependency is needed.
        atomic_write(path, json.dumps(config, indent=2) + '\n')
        return dict(command=[binaries[engine], 'run', '-c', str(path)], validate=None, environment={})
    if engine == 'parsa-spoof':
        config = dict(mode='local' if iran else 'remote', spoof_ip=plan['spoof'][plan['role']],
                      peer_spoof_ip=plan['spoof']['foreign' if iran else 'iran'],
                      spoof_port=plan['control_port'], send_transport='tcp', recv_transport='tcp')
        if iran:
            config.update(listen=f"127.0.0.1:{plan['health_port']}", remote=plan['foreign_ip'],
                          remote_port=plan['control_port'], recv_port=plan['control_port'])
        else:
            config.update(listen_port=plan['control_port'], forward=f"127.0.0.1:{plan['data_port']}",
                          client_ip=plan['iran_ip'], client_port=plan['control_port'])
        path = directory / 'spoof.json'
        atomic_write(path, json.dumps(config, indent=2) + '\n')
        return dict(command=[binaries[engine], 'run', '-c', str(path)], validate=None, environment={})
    raise PronetError('Unsupported independent engine')


def packet_rules(plan):
    """Table/chain/rule tuples; each match belongs to one pair and raw port."""
    iran = plan['role'] == 'iran'
    peer = plan['foreign_ip'] if iran else plan['iran_ip']
    local = plan['bind_ip']
    tag = 'pronetf:' + plan['pair_id'] + ':' + plan['profile'] + ':engine'
    port = str(plan['control_port'])
    if plan['profile'] == 'paqet':
        inbound = ['-s', peer, '-d', local, '-p', 'tcp', '--sport', port, '--dport', port]
        outbound = ['-s', local, '-d', peer, '-p', 'tcp', '--sport', port, '--dport', port]
        rules = [('raw', 'PREROUTING', inbound, 'NOTRACK'), ('raw', 'OUTPUT', outbound, 'NOTRACK'),
                 ('mangle', 'OUTPUT', outbound + ['--tcp-flags', 'RST', 'RST'], 'DROP')]
    elif plan['profile'] == 'parsa-spoof':
        forged = plan['spoof']['foreign' if iran else 'iran']
        # Kernel replies go to the forged source; suppress only this tunnel's
        # RST/SYN-ACK. Raw payload packets are emitted with the local spoof IP.
        reply = ['-s', local, '-d', forged, '-p', 'tcp', '--sport', port, '--dport', port]
        rules = [('mangle', 'OUTPUT', reply + ['--tcp-flags', 'RST', 'RST'], 'DROP'),
                 ('mangle', 'OUTPUT', reply + ['--tcp-flags', 'SYN,ACK', 'SYN,ACK'], 'DROP'),
                 ('filter', 'INPUT', ['!', '-i', 'lo', '-p', 'udp', '--dport', str(plan['data_port'])], 'DROP')]
    else:
        return []
    return [(table, chain, match + ['-m', 'comment', '--comment', tag, '-j', target])
            for table, chain, match, target in rules]


def packet_firewall(plan, action):
    for table, chain, rule in packet_rules(plan):
        prefix = ['iptables', '-w', '5', '-t', table]
        exists = command(prefix + ['-C', chain] + rule, check=False).returncode == 0
        if action == 'up' and not exists:
            command(prefix + ['-I', chain, '1'] + rule)
        elif action == 'down' and exists:
            command(prefix + ['-D', chain] + rule)
