import contextlib
import io
import pathlib
import tempfile
import unittest
from unittest import mock

from pronet import cli, learning, model
from pronet.common import PronetError
from pronet.controller import Controller
import test_core
from test_core import setup_request


def pair(number, route=0, advanced=False):
    return {'id':format(number,'024x'),'request':{'public_ip':'192.0.2.1','direction':'iran-dials','advanced':advanced},
            'iran_info':{'public_ip':'192.0.2.1'},'foreign_info':{'public_ip':'192.0.2.'+str(route+2)}}


def good(name='frp-tls'):
    return dict(profile=name,passed=True,success_ratio=1,echo_ms=[20,30],upload_mbps=10,
                download_mbps=12,half_close=True,integrity=True,after_idle=True)


def bad(name='bp-quic'):
    return dict(profile=name,passed=False,stage='reach',error='no connectivity (blocked or filtered on this route)')


class MemoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.now=[100*86400.]
        self.memory=learning.CarrierMemory(pathlib.Path(self.temp.name)/'memory.sqlite3',lambda:self.now[0])

    def train(self):
        for day in range(7):
            self.now[0]=(100+day)*86400.
            for route in range(8): self.memory.record(pair(day*8+route+1,route),[good(),bad()])

    def test_handful_of_failures_cannot_retire_a_carrier(self):
        for day in range(5):
            self.now[0]=(100+day)*86400.
            self.memory.record(pair(day+1,day),[good(),bad()])
        plan=self.memory.plan(pair(100,30),['bp-quic','frp-tls'])
        self.assertEqual(plan['skipped'],[])

    def test_same_window_repetition_does_not_manufacture_independent_evidence(self):
        for i in range(50): self.memory.record(pair(i+1),[good(),bad()])
        summary={r['profile']:r for r in self.memory.summary()['profiles']}
        self.assertEqual(summary['bp-quic']['n'],1)
        self.assertFalse(summary['bp-quic']['retired'])

    def test_many_routes_and_days_can_retire_but_full_test_bypasses_it(self):
        self.train()
        plan=self.memory.plan(pair(100,30),['bp-quic','frp-tls'])
        self.assertEqual(plan['profiles'],['frp-tls'])
        self.assertEqual(plan['skipped'][0]['profile'],'bp-quic')
        self.assertEqual(self.memory.plan(pair(100,30),['bp-quic','frp-tls'],True)['profiles'],['bp-quic','frp-tls'])

    def test_route_success_protects_that_route_from_a_fleet_prior(self):
        self.train()
        self.now[0]+=learning.WINDOW
        self.memory.record(pair(200,30),[good('bp-quic')])
        self.assertIn('bp-quic',self.memory.plan(pair(201,30),['bp-quic'])['profiles'])
        self.assertNotIn('bp-quic',self.memory.plan(pair(201,31),['bp-quic'])['profiles'])

    def test_advanced_success_requalifies_a_locally_retired_profile(self):
        for i in range(28):
            self.now[0]=(100+i//4)*86400+(i%4)*learning.WINDOW
            self.memory.record(pair(i+1),[good(),bad()])
        self.assertEqual(self.memory.plan(pair(101),['bp-quic'])['profiles'],[])
        self.memory.record(pair(200,advanced=True),[good('bp-quic')])
        self.assertEqual(self.memory.plan(pair(201),['bp-quic'])['profiles'],['bp-quic'])

    def test_software_errors_and_total_route_outage_do_not_become_negative_evidence(self):
        self.memory.record(pair(1),[good(),dict(bad(),stage='prepare',error='binary missing')])
        self.assertNotIn('bp-quic',[r['profile'] for r in self.memory.summary()['profiles']])
        self.memory.record(pair(2),[bad(),bad('paqet')])
        self.assertNotIn('paqet',[r['profile'] for r in self.memory.summary()['profiles']])
        self.memory.record(pair(3),[good(),bad()],healthy=False)
        self.assertNotIn('bp-quic',[r['profile'] for r in self.memory.summary()['profiles']])

    def test_emergency_carriers_are_never_learned_into_ordinary_statistics(self):
        self.memory.record(pair(1),[good(),good('parsa-spoof')])
        self.assertNotIn('parsa-spoof',[r['profile'] for r in self.memory.summary()['profiles']])

    def test_duplicate_run_version_change_and_clear(self):
        self.train()
        count=self.memory.summary()['profiles'][0]['n']
        self.memory.record(pair(56,7),[good(),bad()])
        self.assertEqual(self.memory.summary()['profiles'][0]['n'],count)
        with mock.patch.object(learning,'fingerprint',return_value='new-engine-build'):
            self.assertEqual(self.memory.plan(pair(100,30),['bp-quic'])['profiles'],['bp-quic'])
        self.memory.clear()
        self.assertEqual(self.memory.summary()['records'],0)

    def test_bounded_summary_file_and_no_raw_ip_or_event_log_in_summary(self):
        with mock.patch.object(learning,'MAX_ROWS',64),mock.patch.object(learning,'MAX_RUNS',16):
            for i in range(100): self.memory.record(pair(i+1,i%80),[good(),bad()])
        data=self.memory.summary()
        self.assertLessEqual(data['records'],64)
        self.assertLessEqual(data['bytes'],2*1024*1024)
        self.assertNotIn('192.0.2.',str(data))
        self.assertFalse(data['background_probes'])
        self.assertEqual(self.memory.path.stat().st_mode & 0o777,0o600)

    def test_engine_upgrades_do_not_accumulate_obsolete_global_statistics(self):
        for i in range(20):
            with mock.patch.object(learning,'fingerprint',return_value='engine-'+str(i)):
                self.memory.record(pair(i+1),[good(),bad()])
                self.assertLessEqual(self.memory.summary()['records'],4)

    def test_known_good_carriers_start_first_without_dropping_transport_families(self):
        plans=[{'profile':'frp-tls'},{'profile':'bp-quic'},{'profile':'paqet'}]
        controller=Controller(mock.Mock())
        batches=controller.batches(plans,['bp-quic'])
        self.assertEqual(batches[0][0]['profile'],'bp-quic')
        self.assertEqual(sorted(p['profile'] for b in batches for p in b),sorted(p['profile'] for p in plans))


class AdvancedTests(unittest.TestCase):
    setUp=test_core.StoreTests.setUp
    tearDown=test_core.StoreTests.tearDown
    node=test_core.StoreTests.node
    # StoreTests supplies authenticated nodes and a real isolated database.
    def failed_pair(self):
        created=self.store.create_pair(self.iran,setup_request())
        self.store.join_pair(self.foreign,created['code'])
        self.store.update_pair(created['pair_id'],'FAILED',{'advanced_available':True,'cleanup_confirmed':True,'results':[]})
        return created['pair_id']

    def test_explicit_advanced_retry_reuses_only_the_previous_foreign_peer(self):
        old=self.failed_pair()
        new=self.store.advanced_pair(self.iran,old,{'iran':'192.0.2.40','foreign':'192.0.2.41'})
        result=self.store.pair(new['pair_id'])
        self.assertNotEqual(old,new['pair_id'])
        self.assertEqual(result['foreign_node'],self.foreign['id'])
        self.assertTrue(result['request']['advanced'])
        self.assertTrue(result['request']['full_test'])
        self.assertEqual(set(result['request']['profiles']),set(model.PROFILES))

    def test_no_spoof_sources_skip_only_emergency_not_retired_or_experimental_normal(self):
        new=self.store.advanced_pair(self.iran,self.failed_pair())
        names=self.store.pair(new['pair_id'])['request']['profiles']
        self.assertEqual(set(names),set(model.NORMAL_PROFILES))
        self.assertIn('bp-l3-xdi',names)

    def test_advanced_retry_requires_failed_qualification_confirmed_cleanup_and_ownership(self):
        old=self.failed_pair()
        with self.assertRaises(PronetError): self.store.advanced_pair(self.foreign,old)
        self.store.update_pair(old,'ACTIVE',{'advanced_available':True,'cleanup_confirmed':True})
        with self.assertRaises(PronetError): self.store.advanced_pair(self.iran,old)
        self.store.update_pair(old,'FAILED',{'advanced_available':True,'cleanup_confirmed':False})
        with self.assertRaises(PronetError): self.store.advanced_pair(self.iran,old)


class PromptTests(unittest.TestCase):
    def test_no_advanced_work_without_explicit_one(self):
        pair={'id':'a'*24,'result':{'advanced_available':True,'cleanup_confirmed':True}}
        with mock.patch.object(cli.sys.stdin,'isatty',return_value=True),mock.patch.object(cli,'ask',return_value='0'), \
             mock.patch.object(cli,'advanced_test') as start,contextlib.redirect_stdout(io.StringIO()):
            cli.offer_advanced(pair)
            start.assert_not_called()
        with mock.patch.object(cli.sys.stdin,'isatty',return_value=True),mock.patch.object(cli,'ask',return_value='1'), \
             mock.patch.object(cli,'advanced_test') as start,contextlib.redirect_stdout(io.StringIO()):
            cli.offer_advanced(pair)
            start.assert_called_once_with(pair['id'])

    def test_noninteractive_failure_prints_manual_command_without_starting(self):
        with mock.patch.object(cli.sys.stdin,'isatty',return_value=False),mock.patch.object(cli,'advanced_test') as start, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            cli.offer_advanced({'id':'a'*24,'result':{'advanced_available':True,'cleanup_confirmed':True}})
            start.assert_not_called()
            self.assertIn('sudo pronet advanced',out.getvalue())
