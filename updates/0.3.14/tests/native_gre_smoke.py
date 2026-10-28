#!/usr/bin/env python3
"""Privileged Linux GRE test, restricted to fresh disposable network namespaces."""
import argparse
import json
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile
import time

APP=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(APP))
from pronet import native_gre
from pronet.common import PronetError
from pronet.model import tunnel_ips
from pronet.wire import ProbeServer, benchmark, echo


def run(args,**kw):
    return subprocess.run(list(map(str,args)),capture_output=True,text=True,check=True,timeout=30,**kw)


def child(mode,path):
    plan=json.loads(pathlib.Path(path).read_text())
    if mode=='up': native_gre.up(plan)
    elif mode=='down': native_gre.down(plan)
    elif mode=='serve':
        with ProbeServer(('0.0.0.0',plan['echo_port']),plan['token']) as server:
            server.serve_forever()
    elif mode in ('check','blocked'):
        target=tunnel_ips(plan)[1 if plan['role']=='iran' else 0]
        if mode=='blocked':
            try: echo((target,plan['echo_port']),plan['token'],.5)
            except (OSError,PronetError): return
            raise RuntimeError('GRE unexpectedly worked with outer protocol 47 blocked')
        result=benchmark((target,plan['echo_port']),plan['token'],rounds=3,size=262144,idle=.3,budget=12)
        if not result['passed']: raise RuntimeError('native GRE transfer/integrity/half-close/idle failed: '+json.dumps(result))


def main():
    if sys.platform!='linux' or os.geteuid()!=0:
        raise RuntimeError('Requires root on a disposable Linux test host')
    token=secrets.token_hex(4);pair=secrets.token_hex(12)
    namespaces={role:'pngre-'+token+'-'+role for role in ('i','f')}
    created=[];workers=[];logs=[];report={'passed':False}
    with tempfile.TemporaryDirectory(prefix='pronet-gre-test-') as tmp:
        root=pathlib.Path(tmp)
        plans={}
        for short,role,number in [('i','iran',1),('f','foreign',2)]:
            p=dict(pair_id=pair,profile='gre',role=role,token='b'*64,subnet='10.244.251.0/30',
                   iran_ip='198.18.0.1',foreign_ip='198.18.0.2',bind_ip='198.18.0.%d'%number,
                   control_port=24443,echo_port=24444,health_port=24445,data_port=24446,inbound_port=2053,
                   bridge_health_port=24447,bridge_data_port=24448,probe_front_port=24449,direction='iran-dials')
            plans[short]=p;(root/(short+'.json')).write_text(json.dumps(p))
        def env(short): return dict(os.environ,PRONET_STATE=str(root/short))
        def ns(short,args): return ['ip','netns','exec',namespaces[short]]+list(map(str,args))
        def invoke(short,mode): return run(ns(short,[sys.executable,__file__,'--child',mode,'--plan',root/(short+'.json')]),env=env(short))
        try:
            for short in namespaces:
                run(['ip','netns','add',namespaces[short]]);created.append(short)
                run(['ip','-n',namespaces[short],'link','set','lo','up'])
            left,right='pgi'+token,'pgf'+token
            run(['ip','link','add',left,'type','veth','peer','name',right])
            for short,device,number in [('i',left,1),('f',right,2)]:
                run(['ip','link','set',device,'netns',namespaces[short]])
                run(['ip','-n',namespaces[short],'link','set',device,'name','eth0'])
                run(['ip','-n',namespaces[short],'address','add','198.18.0.%d/30'%number,'dev','eth0'])
                run(['ip','-n',namespaces[short],'link','set','eth0','up'])
            name=native_gre.parameters(plans['i'])['name']
            run(['ip','-n',namespaces['i'],'link','add',name,'alias','external-test-owner','type','dummy'])
            try: invoke('i','up')
            except subprocess.CalledProcessError: pass
            else: raise RuntimeError('An unowned interface was adopted')
            row=json.loads(run(['ip','-n',namespaces['i'],'-j','-d','link','show','dev',name]).stdout)[0]
            assert row['ifalias']=='external-test-owner' and row['linkinfo']['info_kind']=='dummy'
            run(['ip','-n',namespaces['i'],'link','delete',name]);report['unowned_interface_preserved']=True
            for short in namespaces:
                invoke(short,'up');invoke(short,'up')
                log=open(root/(short+'.log'),'w');logs.append(log)
                workers.append(subprocess.Popen(ns(short,[sys.executable,__file__,'--child','serve','--plan',root/(short+'.json')]),
                                                env=env(short),stdout=log,stderr=log))
            deadline=time.monotonic()+10
            while True:
                try: invoke('i','check');break
                except subprocess.CalledProcessError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.2)
            invoke('f','check');report['bidirectional_integrity_half_close_idle']=True
            rule=['OUTPUT','-p','47','-d','198.18.0.2','-j','DROP']
            run(ns('i',['iptables','-I']+rule))
            invoke('i','blocked');report['outer_protocol_47_verified']=True
            run(ns('i',['iptables','-D']+rule));invoke('i','check')
            for short in namespaces:
                invoke(short,'down');invoke(short,'down')
                rows=json.loads(run(['ip','-n',namespaces[short],'-j','link','show']).stdout)
                assert all(row['ifname']!=name for row in rows)
            report['idempotent_owned_cleanup']=True;report['passed']=True
        finally:
            for p in workers:
                if p.poll() is None:
                    p.terminate();p.wait(timeout=5)
            for short in reversed(created): run(['ip','netns','delete',namespaces[short]])
            for log in logs: log.close()
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--child',choices=['up','down','serve','check','blocked']);parser.add_argument('--plan')
    args=parser.parse_args()
    if args.child: child(args.child,args.plan)
    else: main()
