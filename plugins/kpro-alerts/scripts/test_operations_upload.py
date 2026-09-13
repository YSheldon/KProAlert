import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from kpro_alert_bridge import Store
from operations import Operations,evidence,status
from operations_upload import upload, reconcile


class OperationsUploadTests(unittest.TestCase):
    def test_missing_remote_record_identity_never_acknowledges(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, ops = Path(tmp)/'events.db',Path(tmp)/'ops.db'
            cli=Path(tmp)/'cli.exe';cli.touch()
            with Store(source) as store:
                store.ingest('dev','session',dict(eventType=7,operation=2,sequence=1))
                uid=store.db.execute('SELECT id FROM events').fetchone()[0]
            captured=evidence(source,uid)
            with Operations(ops,source) as journal:
                journal.assess(uid,captured['evidenceSha256'],'unknown',10,['insufficient_evidence'],['investigate'],'model','a'*32)
            expected={}
            def runner(command, **kwargs):
                if '+record-upsert' in command:
                    expected.update(json.loads(command[command.index('--json')+1]))
                    return SimpleNamespace(stdout=json.dumps({'ok':True,'data':{'record_id':'recTest'}}))
                return SimpleNamespace(stdout=json.dumps({'ok':True,'data':{'record':{'fields':expected}}}))
            result=upload(ops,source,str(cli),'baseTest','tblTest',apply=True,runner=runner)
            self.assertEqual(result['uploaded'],0)
            self.assertEqual(status(ops)['deliveryStates'],{'pending':1})

    def test_preview_does_not_initialize_missing_journal_or_call_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            ops = Path(tmp) / 'missing.db'
            result = upload(ops, Path(tmp)/'missing-source.db', None, 'baseTest', 'tblTest',
                            runner=lambda *a, **kw: self.fail('Preview must not call CLI'))
            self.assertEqual(result['records'], [])
            self.assertFalse(result['applied'])
            self.assertFalse(ops.exists())

    def test_exact_readback_then_ack_and_uncertain_send_is_not_repeated(self):
        for fail_readback in (False,True):
            with self.subTest(fail=fail_readback), tempfile.TemporaryDirectory() as tmp:
                source, ops = Path(tmp)/'events.db',Path(tmp)/'ops.db'
                cli=Path(tmp)/'cli.exe';cli.touch()
                with Store(source) as store:
                    store.ingest('dev','session',dict(eventType=7,operation=2,sequence=1))
                    uid=store.db.execute('SELECT id FROM events').fetchone()[0]
                captured=evidence(source,uid)
                with Operations(ops,source) as journal:
                    journal.assess(uid,captured['evidenceSha256'],'unknown',10,['insufficient_evidence'],['investigate'],'model','a'*32)
                calls=[]
                expected={}
                def runner(command,**kwargs):
                    calls.append(command)
                    if '+record-upsert' in command:
                        expected.update(json.loads(command[command.index('--json')+1]))
                        return SimpleNamespace(stdout=json.dumps({'ok':True,'data':{'record_id':'recTest'}}))
                    fields={**expected}
                    if fail_readback:fields['证据摘要']='tampered'
                    return SimpleNamespace(stdout=json.dumps({'ok':True,'data':{'record':{'record_id':'recTest','fields':fields}}}))
                result=upload(ops,source,str(cli),'baseTest','tblTest',apply=True,runner=runner)
                self.assertEqual(result['uploaded'],0 if fail_readback else 1)
                self.assertEqual(result['uncertain'],1 if fail_readback else 0)
                self.assertEqual(len(calls),4 if fail_readback else 2)
                upload(ops,source,str(cli),'baseTest','tblTest',apply=True,runner=runner)
                self.assertEqual(len(calls),4 if fail_readback else 2)
                self.assertEqual(status(ops)['deliveryStates'],{'pending' if fail_readback else 'acknowledged':1})
                if fail_readback:
                    record_id = result['records'][0]
                    def read_only_runner(command, **kwargs):
                        self.assertIn('+record-get', command)
                        return SimpleNamespace(stdout=json.dumps({'ok':True,'data':{'record':{
                            'record_id':'recTest','fields':expected}}}))
                    with self.assertRaises(ValueError):
                        reconcile(ops,source,str(cli),'wrongBase','tblTest',record_id,'recTest',runner=read_only_runner)
                    receipt = reconcile(ops,source,str(cli),'baseTest','tblTest',record_id,'recTest',runner=read_only_runner)
                    self.assertTrue(receipt['reconciled'])
                    self.assertFalse(receipt['resent'])
                    self.assertEqual(status(ops)['deliveryStates'],{'acknowledged':1})
