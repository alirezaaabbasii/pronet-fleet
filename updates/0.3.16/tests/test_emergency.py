import contextlib
import io
import unittest
from unittest import mock

from pronet import cli, model
from pronet.common import PronetError
from pronet.controller import Controller
from pronet.report import final_report


class EmergencyTests(unittest.TestCase):
    def request(self, **kwargs):
        return dict(name='manual-test', public_ip='192.0.2.1', inbound_port=2053, **kwargs)

    def passed(self, profile):
        return dict(profile=profile, passed=True, success_ratio=1, echo_ms=[1,2],
                    upload_mbps=10, download_mbps=10, half_close=True, integrity=True, after_idle=True)

    def test_default_and_all_normal_lists_exclude_emergency(self):
        self.assertNotIn('parsa-spoof', model.DEFAULT_PROFILES)
        self.assertNotIn('parsa-spoof', model.NORMAL_PROFILES)
        self.assertEqual(model.EMERGENCY_PROFILES,['parsa-spoof'])
        for name in ('paqet','backhaul-tcp','backhaul-tcpmux'):
            self.assertIn(name, model.DEFAULT_PROFILES)
        self.assertNotIn('parsa-spoof',model.validate_request(self.request())['profiles'])

    def test_manual_emergency_request_is_separate_and_cannot_mix(self):
        data=model.validate_request(self.request(emergency=True,test_only=True))
        self.assertEqual(data['profiles'],['parsa-spoof'])
        self.assertTrue(data['test_only'])
        for kwargs in ({'profiles':['parsa-spoof']},
                       {'emergency':True,'profiles':['parsa-spoof','frp-tls']},
                       {'emergency':True,'profiles':['frp-tls']},
                       {'test_only':True}, {'emergency':'true'}):
            with self.assertRaises(PronetError): model.validate_request(self.request(**kwargs))

    def test_old_successful_spoof_result_is_not_an_automatic_reserve(self):
        controller=Controller(mock.Mock())
        result={'results':[self.passed('parsa-spoof'),self.passed('paqet')]}
        self.assertEqual(controller.reserve(result,{},now=100000),['paqet'])

    def test_emergency_pair_never_starts_automatic_retesting_or_exploration(self):
        store=mock.Mock()
        pair={'id':'a'*24,'request':{'emergency':True},'result':{}}
        store.pair.return_value=pair
        controller=Controller(store)
        runtime={'all_down_since':1,'profiles':['parsa-spoof']}
        self.assertIsNone(controller.maintenance_task(pair,runtime,now=10000,reporting_since=1))
        controller.retest(pair['id'])
        controller.replace_standby(pair['id'])
        controller.recover(pair['id'],'pause')
        store.update_pair.assert_not_called()
        store.enqueue.assert_not_called()

    def test_legacy_normal_recovery_never_retests_previously_passed_spoof(self):
        store=mock.Mock()
        pair={'id':'a'*24,'iran':'b'*24,'foreign_node':'c'*24,'result':{
            'selected':[], 'results':[self.passed('parsa-spoof'),self.passed('paqet')]}}
        store.pair.return_value=pair
        controller=Controller(store)
        controller.both=mock.Mock(return_value={})
        controller.rpc=mock.Mock(return_value={'passed':False})
        controller.recover(pair['id'],'pause')
        self.assertEqual(controller.rpc.call_count,1)
        self.assertEqual(controller.rpc.call_args.args[3]['profile'],'paqet')
        self.assertEqual(pair['result']['recovery']['attempted'],['paqet'])

    def test_emergency_menu_back_does_not_start_or_modify_anything(self):
        with mock.patch.object(cli,'root_linux'),mock.patch.object(cli,'node_config',return_value={'role':'iran'}), \
                mock.patch.object(cli,'ask',return_value='0'),mock.patch.object(cli,'new_tunnel') as start, \
                contextlib.redirect_stdout(io.StringIO()):
            cli.emergency_menu()
            start.assert_not_called()

    def test_menu_test_only_uses_only_emergency_and_no_standby(self):
        with mock.patch.object(cli,'root_linux'),mock.patch.object(cli,'node_config',return_value={'role':'iran'}), \
                mock.patch.object(cli,'ask',side_effect=['1','192.0.2.3','192.0.2.4','2053']), \
                mock.patch.object(cli,'new_tunnel') as start,contextlib.redirect_stdout(io.StringIO()):
            cli.emergency_menu()
            self.assertTrue(start.call_args.kwargs['test_only'])
            self.assertTrue(start.call_args.kwargs['emergency'])
            self.assertEqual(start.call_args.kwargs['profiles'],['parsa-spoof'])
            self.assertFalse(start.call_args.kwargs['standby'])

    def test_report_distinguishes_test_completion_from_activation_and_failure(self):
        pair={'state':'STOPPED','request':self.request(emergency=True),'result':{
            'phase':'emergency-tested','test_passed':True,'cleaned':True,'results':[self.passed('parsa-spoof')]}}
        text='\n'.join(final_report(pair,details=True))
        self.assertIn('EMERGENCY TEST COMPLETE',text)
        self.assertIn('no client gateway',text)
        self.assertNotIn('SETUP DID NOT COMPLETE',text)
        self.assertNotIn('TUNNEL READY',text)


if __name__=='__main__': unittest.main()
