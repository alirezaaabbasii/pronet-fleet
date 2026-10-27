#!/usr/bin/env python3
"""Read-only local diagnostics. Optional bounded carrier transfers, no repair."""
import argparse
import datetime
import json
import pathlib
import re
import subprocess
import sys
import time

# Importing the installed wire helpers must not write bytecode into /opt.
sys.dont_write_bytecode = True

STATE = pathlib.Path('/var/lib/pronet-fleet')
CONFIG = pathlib.Path('/etc/pronet-fleet')
VERSION = re.compile(r'/opt/pronet-fleet/(\d+\.\d+\.\d+)/main\.py')


def read(path):
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def pick(value, keys):
    return {k: value[k] for k in keys if k in value}


def source_path():
    try:
        match = VERSION.search(pathlib.Path('/usr/local/bin/pronet').read_text())
        if match:
            return pathlib.Path('/opt/pronet-fleet') / match[1]
    except OSError:
        pass
    return None


def services(pair_id):
    names = {'pronetf-agent.service', 'pronetf-hub.service'}
    names.update(p.name for p in pathlib.Path('/etc/systemd/system').glob('pronetf-' + pair_id + '-*.service'))
    rows = {}
    for name in sorted(names):
        try:
            result = subprocess.run(['systemctl', 'show', name,
                '--property=LoadState,ActiveState,SubState,NRestarts,MemoryCurrent,CPUUsageNSec,ExecStart,ExecMainPID'],
                capture_output=True, text=True, timeout=3)
            props = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            row = pick(props, ('LoadState', 'ActiveState', 'SubState', 'NRestarts', 'MemoryCurrent', 'CPUUsageNSec'))
            # Full ExecStart may contain secrets. Only emit a matched code version.
            match = VERSION.search(props.get('ExecStart', ''))
            row['unit_code_version'] = match[1] if match else None
            row['running_code_version'] = None
            pid = props.get('ExecMainPID', '')
            if pid.isdigit() and int(pid) > 0:
                try:
                    match = VERSION.search((pathlib.Path('/proc') / pid / 'cmdline').read_bytes().decode(errors='replace'))
                    row['running_code_version'] = match[1] if match else None
                except OSError:
                    pass
            rows[name] = row
        except (OSError, subprocess.TimeoutExpired):
            rows[name] = {'available': False}
    return rows


def host_metrics():
    row = {}
    try:
        row['loadavg'] = pathlib.Path('/proc/loadavg').read_text().split()[:3]
        row['uptime_seconds'] = float(pathlib.Path('/proc/uptime').read_text().split()[0])
        mem = dict(line.split(':', 1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
        row['memory_kib'] = {k: int(mem[k].split()[0]) for k in ('MemTotal', 'MemAvailable') if k in mem}
    except (OSError, ValueError, IndexError):
        pass
    try:
        lines = pathlib.Path('/proc/net/snmp').read_text().splitlines()
        for i, line in enumerate(lines[:-1]):
            if line.startswith('Tcp:') and 'RetransSegs' in line:
                tcp = dict(zip(line.split()[1:], lines[i+1].split()[1:]))
                row['tcp'] = {k: int(tcp[k]) for k in ('RetransSegs', 'OutSegs', 'InSegs', 'EstabResets', 'CurrEstab') if k in tcp}
        vm = dict(line.split() for line in pathlib.Path('/proc/vmstat').read_text().splitlines())
        row['oom_kills_since_boot'] = int(vm.get('oom_kill', 0))
    except (OSError, ValueError):
        pass
    interfaces = {}
    for directory in pathlib.Path('/sys/class/net').glob('*'):
        try:
            interfaces[directory.name] = {k: int((directory / 'statistics' / k).read_text())
                for k in ('rx_bytes', 'tx_bytes', 'rx_dropped', 'tx_dropped', 'rx_errors', 'tx_errors')}
        except (OSError, ValueError):
            continue
    row['interfaces'] = interfaces
    return row


def snapshot(pair_id, state=STATE, config=CONFIG):
    directory = state / 'pairs' / pair_id
    selection = read(directory / 'selection.json')
    node = read(config / 'node.json')
    gateway = read(directory / 'gateway.json')
    selected = pick(selection, ('active', 'profiles', 'failures', 'last_probe', 'rtt_ms',
        'auto_paused', 'pause_id', 'pause_reason', 'healthy_probes', 'switches', 'utc'))
    selected['standby_health'] = {name: pick(row, ('state', 'failures', 'healthy_probes', 'rtt_ms', 'utc'))
        for name, row in selection.get('standby_health', {}).items() if isinstance(row, dict)}
    root = source_path()
    return {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'pair': pair_id,
        'node': pick(node, ('name', 'role', 'public_ip')),
        'wrapper_code_version': root.name if root else None,
        'settings': pick(read(config / 'settings.json'), ('probe_seconds', 'failover_seconds', 'recovery_policy')),
        'selection_exists': (directory / 'selection.json').is_file(), 'selection': selected,
        'gateway': pick(gateway, ('active_backend', 'mode', 'port', 'ports', 'connection_limit')),
        'traffic': pick(read(directory / 'traffic.json'), ('rx_bytes', 'tx_bytes', 'rx_Bps', 'tx_Bps',
            'connections_total', 'connections_active', 'connection_failures', 'rejected_limit', 'utc')),
        'services': services(pair_id), 'host': host_metrics()}


def probe_paths(pair_id, state=STATE, config=CONFIG):
    if read(config / 'node.json').get('role') != 'iran':
        return {'skipped': 'carrier transfer measurements run on Iran only'}
    source = source_path()
    if not source:
        return {'skipped': 'installed wrapper version could not be identified'}
    sys.path.insert(0, str(source))
    from pronet import engines
    from pronet.model import validate_profile
    from pronet.wire import benchmark
    directory = state / 'pairs' / pair_id
    profiles = read(directory / 'selection.json').get('profiles', [])
    rows = {}
    for name in profiles[:2]:
        if not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', name):
            continue
        try:
            plan = validate_profile(read(directory / name / 'plan.json'))
            result = benchmark(engines.probe_address(plan), plan['token'],
                rounds=1, size=65536, idle=0, timeout=4, budget=12)
            rows[name] = pick(result, ('passed', 'echo_ms', 'upload_mbps', 'download_mbps',
                'integrity', 'half_close', 'seconds', 'payload_bytes', 'success_ratio'))
        except Exception as error:
            # Never serialize exception messages: they can contain credentials.
            rows[name] = {'error_type': type(error).__name__}
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pair', required=True)
    parser.add_argument('--samples', type=int, default=12)
    parser.add_argument('--interval', type=int, default=30)
    parser.add_argument('--probe-data', action='store_true', help='Send up to 64 KiB each way per committed carrier/sample (Iran only)')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-f0-9]{24}', args.pair): parser.error('invalid pair ID')
    if not 1 <= args.samples <= 120: parser.error('samples must be 1..120')
    if not 5 <= args.interval <= 300: parser.error('interval must be 5..300 seconds')
    print(json.dumps({'diagnostic': 'pronet-read-only-0.3.6', 'carrier_transfer_enabled': args.probe_data,
        'scope': 'carrier and gateway; does not authenticate a real WS/XHTTP/VLESS client',
        'no_service_or_configuration_changes': True}), flush=True)
    for index in range(args.samples):
        started = time.monotonic()
        row = snapshot(args.pair)
        if args.probe_data: row['carrier_transfer'] = probe_paths(args.pair)
        print(json.dumps(row, sort_keys=True), flush=True)
        if index + 1 < args.samples:
            time.sleep(max(0, args.interval - (time.monotonic() - started)))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
