"""Removing one pair must preserve the app and other tunnels, and confirm cleanup."""
import pathlib
import tempfile
import unittest
from unittest import mock

from pronet import cli
from pronet.common import PronetError


def pair(identity, state='ACTIVE', cleaned=False):
    return {'id':identity,'iran':'iran','foreign':'foreign','state':state,
            'request':{'name':'Tunnel '+identity[:4],'public_ip':'192.0.2.1','inbound_port':2053},
            'result':{'cleanup_confirmed':cleaned}}


class RemoveMenuTests(unittest.TestCase):
    def setUp(self):
        self.client=mock.Mock();self.calls=[]
        self.temp=tempfile.TemporaryDirectory();self.join=pathlib.Path(self.temp.name)/'pending-join.json'
    def tearDown(self):self.temp.cleanup()
    def run_remove(self, snapshots, answer='y', pair_id=None, **kwargs):
        views=iter(snapshots)
        def call(path, body=None):
            self.calls.append((path,body))
            if path=='/v1/overview':
                value=next(views)
                if isinstance(value,BaseException): raise value
                return {'pairs':value,'nodes':[]}
            if path=='/v1/stop':return {'state':'STOPPING'}
            raise AssertionError(path)
        self.client.call.side_effect=call
        with mock.patch.object(cli,'root_linux'),mock.patch.object(cli,'node_client',return_value=self.client), \
                mock.patch.object(cli,'say') as say,mock.patch('builtins.input',side_effect=answer if isinstance(answer,list) else [answer]), \
                mock.patch.object(cli.time,'sleep'),mock.patch.object(cli,'JOIN_FILE',self.join):
            result=cli.remove_tunnel(pair_id,**kwargs)
        self.output='\n'.join(str(c.args[0]) for c in say.call_args_list)
        return result
    def test_select_exact_pair_then_wait_for_confirmed_cleanup(self):
        a,b='a'*24,'b'*24
        cli.write_json(self.join,{'pair_id':b,'lines':['secret command']})
        result=self.run_remove([[pair(a),pair(b)],[pair(a),pair(b,'STOPPING')],[pair(a),pair(b,'STOPPED')]],answer=['2','y'])
        self.assertEqual(result['state'],'STOPPED')
        self.assertEqual([body for path,body in self.calls if path=='/v1/stop'],[{'pair_id':b}])
        self.assertFalse(self.join.exists())
        self.assertIn('removed from both servers',self.output)
    def test_declining_confirmation_does_not_change_anything(self):
        self.assertIsNone(self.run_remove([[pair('a'*24)]],answer='n'))
        self.assertFalse(any(path=='/v1/stop' for path,_ in self.calls))
    def test_unconfirmed_cleanup_is_not_reported_as_removed(self):
        result=self.run_remove([[pair('a'*24)],[pair('a'*24,'STOP_UNCONFIRMED')]])
        self.assertEqual(result['state'],'STOP_UNCONFIRMED')
        self.assertNotIn('Tunnel removed from both servers',self.output)
        self.assertIn('not confirmed',self.output)
    def test_deadline_reports_pending_not_success_and_keeps_join_receipt(self):
        cli.write_json(self.join,{'pair_id':'a'*24})
        result=self.run_remove([[pair('a'*24)]],timeout=0)
        self.assertEqual(result['state'],'STOPPING')
        self.assertIn('pending',self.output)
        self.assertTrue(self.join.exists())
    def test_leaving_wait_does_not_claim_services_keep_running(self):
        result=self.run_remove([[pair('a'*24)],KeyboardInterrupt()])
        self.assertEqual(result['state'],'STOPPING')
        self.assertIn('continues in the background',self.output)
        self.assertNotIn('services keep running',self.output)
    def test_removing_one_tunnel_keeps_another_pending_join_command(self):
        cli.write_json(self.join,{'pair_id':'b'*24,'lines':['keep this command']})
        self.run_remove([[pair('a'*24)],[pair('a'*24,'STOPPED')]])
        self.assertEqual(cli.read_json(self.join)['pair_id'],'b'*24)

    def test_completed_failed_attempt_is_not_offered_as_an_active_tunnel(self):
        result=self.run_remove([[pair('a'*24,'FAILED',True)]])
        self.assertIsNone(result)
        self.assertFalse(any(path=='/v1/stop' for path,_ in self.calls))
    def test_explicit_other_or_ambiguous_prefix_is_rejected_without_mutation(self):
        for identity in ('b'*24,'a'*4):
            with self.assertRaises(PronetError):
                self.run_remove([[pair('a'*24)]],pair_id=identity,confirm=False)
            self.assertFalse(any(path=='/v1/stop' for path,_ in self.calls))
    def test_foreign_and_iran_menus_offer_tunnel_removal(self):
        for role,choice in (('iran','8'),('foreign','4')):
            with mock.patch.object(cli,'menu_header'),mock.patch.object(cli,'CONFIG',pathlib.Path(self.temp.name)), \
                    mock.patch.object(cli,'node_config',return_value={'role':role}), \
                    mock.patch.object(cli,'ask',return_value=choice),mock.patch.object(cli,'say'), \
                    mock.patch.object(cli,'remove_tunnel') as remove:
                (pathlib.Path(self.temp.name)/'node.json').touch()
                cli._wizard_once()
            remove.assert_called_once_with()


class JoinDiagnosisTests(unittest.TestCase):
    def test_tls_timeout_reports_tcp_was_connected(self):
        sock=mock.MagicMock()
        context=mock.Mock();context.wrap_socket.side_effect=TimeoutError('handshake timed out')
        with mock.patch.object(cli.ssl,'create_default_context',return_value=context), \
                mock.patch.object(cli.socket,'create_connection',return_value=sock):
            with self.assertRaisesRegex(PronetError,'TCP connected.*TLS'):
                cli.fetch_pinned_ca('https://192.0.2.1:9443','a'*64)
    def test_tcp_timeout_is_distinguished_from_tls_failure(self):
        with mock.patch.object(cli.socket,'create_connection',side_effect=TimeoutError('connect timed out')):
            with self.assertRaisesRegex(PronetError,'TCP connection'):
                cli.fetch_pinned_ca('https://192.0.2.1:9443','a'*64)


if __name__=='__main__':unittest.main()
