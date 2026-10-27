#!/usr/bin/env python3
"""Explicit fault injection for an authorized dedicated Iran test node only.

Requires a completed pair, a disposable Xray fixture, and root. Restores the hub
and deliberately stopped engine in finally. Never reboots or touches SSH/panels.
"""
import argparse
import contextlib
import json
import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import sys
import time


def command(args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=40)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pair', required=True)
    parser.add_argument('--app-root', type=pathlib.Path, required=True)
    parser.add_argument('--harness', type=pathlib.Path, required=True)
    parser.add_argument('--work', type=pathlib.Path, required=True)
    parser.add_argument('--archive', type=pathlib.Path, required=True)
    parser.add_argument('--gateway', required=True)
    parser.add_argument('--mode', choices=['ws', 'xhttp'], default='ws')
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch('[a-f0-9]{24}', args.pair): raise ValueError('Explicit root test pair required')
    sys.path.insert(0, str(args.app_root))
    from pronet.common import ROOT, CONFIG, read_json, write_json
    from pronet.runtime import unit_name
    if read_json(CONFIG/'node.json')['role'] != 'iran': raise ValueError('Run on the dedicated Iran node')
    with sqlite3.connect('file:'+str(ROOT/'hub/hub.sqlite3')+'?mode=ro', uri=True) as db:
        if db.execute('SELECT state FROM pairs WHERE id=?', (args.pair,)).fetchone() != ('ACTIVE',):
            raise ValueError('Pair must be ACTIVE before fault injection')
    directory = ROOT/'pairs'/args.pair
    selection = read_json(directory/'selection.json')
    active = selection['active']
    if len(selection['profiles']) != 2: raise ValueError('This test requires a warm standby')
    unit = unit_name(args.pair, active, 'engine', 'iran')
    report = {'passed': False, 'initial_active': active, 'profiles': selection['profiles'], 'phases': {}}
    hub_stopped = engine_stopped = False
    def client_once(label, timeout=150):
        result = subprocess.run([sys.executable, str(args.harness), 'client', '--mode', args.mode,
                   '--work', str(args.work), '--archive', str(args.archive), '--gateway-ip', args.gateway,
                   '--app-root', str(args.app_root), '--idle', '2'], capture_output=True, text=True, timeout=timeout)
        parsed = json.loads(result.stdout)
        report['phases'][label] = parsed
        print(label, parsed.get('passed'), flush=True)
        if result.returncode or not parsed.get('passed'): raise RuntimeError('Application failed in phase: '+label)
    def client(label, recover=False):
        start=time.monotonic(); end=start+(65 if recover else 150); attempts=0
        while time.monotonic()<end:
            attempts+=1
            try:
                client_once(label, timeout=max(1,end-time.monotonic()))
                report['phases'][label]['recovery_attempts']=attempts
                report['phases'][label]['observed_seconds']=round(time.monotonic()-start,2)
                return
            except (RuntimeError,subprocess.TimeoutExpired):
                if not recover or time.monotonic()>=end: raise
                time.sleep(2)
        raise RuntimeError('Recovery deadline exhausted: '+label)
    try:
        client('baseline')
        pid = command(['systemctl','show',unit,'-p','MainPID','--value']).stdout.strip()
        command(['systemctl','kill','--kill-whom=main','--signal=SIGKILL',unit])
        end = time.monotonic()+45
        while time.monotonic()<end:
            current = command(['systemctl','show',unit,'-p','MainPID','--value']).stdout.strip()
            if current not in ('0', pid) and command(['systemctl','is-active',unit],check=False).returncode == 0: break
            time.sleep(1)
        else: raise RuntimeError('Engine did not restart with a new PID')
        report['engine_restart'] = {'new_pid_observed':True}
        client('after_engine_crash', recover=True)
        hub_stopped=True; command(['systemctl','stop','pronetf-hub.service'])
        client('with_hub_stopped')
        command(['systemctl','start','pronetf-hub.service']); hub_stopped=False
        engine_stopped=True; command(['systemctl','stop',unit])
        start = time.monotonic(); end = start+100
        while time.monotonic()<end:
            selected = read_json(directory/'selection.json')
            if selected['active'] != active: break
            time.sleep(2)
        else: raise RuntimeError('Warm standby did not take over')
        report['failover']={'from':active,'to':selected['active'],'seconds':round(time.monotonic()-start,1)}
        client('after_warm_standby_failover')
        report['passed']=True
    except BaseException as error:
        report['error']=type(error).__name__+': '+str(error)[:300]
    finally:
        if engine_stopped:
            command(['systemctl','reset-failed',unit],check=False)
            report['engine_restored']=command(['systemctl','start',unit],check=False).returncode==0
        if hub_stopped: report['hub_restored']=command(['systemctl','start','pronetf-hub.service'],check=False).returncode==0
        report['hub_active']=command(['systemctl','is-active','pronetf-hub.service'],check=False).returncode==0
        report['final_active']=read_json(directory/'selection.json')['active']
        report['passed']=report['passed'] and report['hub_active'] and report.get('engine_restored',True)
        write_json(args.work/'faults-report.json',report)
        print(json.dumps(report,indent=2),flush=True)
    return 0 if report['passed'] else 1

if __name__=='__main__': sys.exit(main())
