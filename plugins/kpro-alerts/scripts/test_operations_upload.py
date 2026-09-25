import json
import sqlite3
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from kpro_alert_bridge import Store
from operations import Operations,digest,evidence,status
from operations_upload import fields, upload, reconcile


class OperationsUploadTests(unittest.TestCase):
    def test_reconcile_cli_documents_exact_remote_id_discovery(self):
        root=Path(__file__).resolve().parents[3]
        result=subprocess.run(
            [sys.executable,str(root/'falconpro.py'),
             'operations','reconcile','--help'],
            capture_output=True,text=True,encoding='utf-8',timeout=30,check=False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('if omitted',result.stdout)
        self.assertIn('exact',result.stdout)
        self.assertIn('local Analysis ID',result.stdout)

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
                    db=sqlite3.connect(ops)
                    try:
                        state,remote_id,destination=db.execute(
                            'SELECT state,record_id,destination FROM ops_outbox WHERE id=?',
                            (expected['分析ID'],)).fetchone()
                    finally:
                        db.close()
                    self.assertEqual((state,remote_id,destination),(
                        'pending','recTest',digest({'base':'baseTest','table':'tblTest'})))
                    fields={**expected}
                    if fail_readback:fields['证据摘要']='tampered'
                    return SimpleNamespace(stdout=json.dumps({'ok':True,'data':{'record':{'record_id':'recTest','fields':fields}}}))
                result=upload(ops,source,str(cli),'baseTest','tblTest',apply=True,runner=runner)
                self.assertEqual(result['uploaded'],0 if fail_readback else 1)
                self.assertEqual(result['uncertain'],1 if fail_readback else 0)
                self.assertEqual(len(calls),4 if fail_readback else 2)
                if fail_readback:
                    db=sqlite3.connect(ops)
                    try:
                        state,remote_id,destination=db.execute(
                            'SELECT state,record_id,destination FROM ops_outbox WHERE id=?',
                            (result['records'][0],)).fetchone()
                    finally:
                        db.close()
                    self.assertEqual(state,'pending')
                    self.assertEqual(remote_id,'recTest')
                    self.assertEqual(destination,digest({'base':'baseTest','table':'tblTest'}))
                    self.assertEqual(result['failures'][0].get('remoteRecordId'),'recTest')
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
                    with self.assertRaisesRegex(ValueError,'persisted receipt'):
                        reconcile(ops,source,str(cli),'baseTest','tblTest',record_id,'recOther',runner=read_only_runner)
                    receipt = reconcile(ops,source,str(cli),'baseTest','tblTest',record_id,None,runner=read_only_runner)
                    self.assertTrue(receipt['reconciled'])
                    self.assertFalse(receipt['resent'])
                    self.assertEqual(status(ops)['deliveryStates'],{'acknowledged':1})

    def test_reconcile_discovers_unique_remote_record_without_resending(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,ops=Path(tmp)/'events.db',Path(tmp)/'ops.db'
            cli=Path(tmp)/'cli.exe';cli.touch()
            with Store(source) as store:
                store.ingest('dev','session',dict(eventType=7,operation=2,sequence=1))
                uid=store.db.execute('SELECT id FROM events').fetchone()[0]
            captured=evidence(source,uid)
            with Operations(ops,source) as journal:
                record=journal.assess(uid,captured['evidenceSha256'],'unknown',10,
                    ['insufficient_evidence'],['investigate'],'model','b'*32)
                destination=digest({'base':'baseTest','table':'tblTest'})
                journal.reserve(record['recordId'],destination)
            expected=fields(record)
            calls=[]
            def runner(command,**kwargs):
                calls.append(command)
                self.assertNotIn('+record-upsert',command)
                if '+record-list' in command:
                    query=json.loads(command[command.index('--filter-json')+1])
                    self.assertEqual(query,{'logic':'and','conditions':[
                        ['分析ID','==',record['recordId']]]})
                    return SimpleNamespace(stdout=json.dumps({'ok':True,'data':{
                        'fields':['分析ID'],'data':[[record['recordId']]],
                        'record_id_list':['recRecovered'],'has_more':False}}))
                self.assertIn('+record-get',command)
                return SimpleNamespace(stdout=json.dumps({'ok':True,'data':{'record':{
                    'record_id':'recRecovered','fields':expected}}}))
            receipt=reconcile(ops,source,str(cli),'baseTest','tblTest',record['recordId'],None,runner=runner)
            self.assertTrue(receipt['reconciled'])
            self.assertFalse(receipt['resent'])
            self.assertEqual(receipt['remoteRecordId'],'recRecovered')
            self.assertEqual(['+record-list' if '+record-list' in c else '+record-get'
                              for c in calls],['+record-list','+record-get'])
            self.assertEqual(status(ops)['deliveryStates'],{'acknowledged':1})

    def test_reconcile_rejects_duplicate_remote_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,ops=Path(tmp)/'events.db',Path(tmp)/'ops.db'
            cli=Path(tmp)/'cli.exe';cli.touch()
            with Store(source) as store:
                store.ingest('dev','session',dict(eventType=7,operation=2,sequence=1))
                uid=store.db.execute('SELECT id FROM events').fetchone()[0]
            captured=evidence(source,uid)
            with Operations(ops,source) as journal:
                record=journal.assess(uid,captured['evidenceSha256'],'unknown',10,
                    ['insufficient_evidence'],['investigate'],'model','c'*32)
                journal.reserve(record['recordId'],digest({'base':'baseTest','table':'tblTest'}))
            calls=[]
            def runner(command,**kwargs):
                calls.append(command)
                return SimpleNamespace(stdout=json.dumps({'ok':True,'data':{
                    'fields':['分析ID'],'data':[[record['recordId']],[record['recordId']]],
                    'record_id_list':['recOne','recTwo'],'has_more':False}}))
            with self.assertRaisesRegex(ValueError,'(?i)ambiguous'):
                reconcile(ops,source,str(cli),'baseTest','tblTest',record['recordId'],None,runner=runner)
            self.assertEqual(len(calls),1)
            self.assertIn('+record-list',calls[0])
            self.assertEqual(status(ops)['deliveryStates'],{'pending':1})

    def test_reconcile_no_remote_match_stays_pending_without_post(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,ops=Path(tmp)/'events.db',Path(tmp)/'ops.db'
            cli=Path(tmp)/'cli.exe';cli.touch()
            with Store(source) as store:
                store.ingest('dev','session',dict(eventType=7,operation=2,sequence=1))
                uid=store.db.execute('SELECT id FROM events').fetchone()[0]
            captured=evidence(source,uid)
            with Operations(ops,source) as journal:
                record=journal.assess(uid,captured['evidenceSha256'],'unknown',10,
                    ['insufficient_evidence'],['investigate'],'model','d'*32)
                journal.reserve(record['recordId'],digest({'base':'baseTest','table':'tblTest'}))
            calls=[]
            def runner(command,**kwargs):
                calls.append(command)
                self.assertNotIn('+record-upsert',command)
                self.assertIn('+record-list',command)
                return SimpleNamespace(stdout=json.dumps({'ok':True,'data':{
                    'fields':['分析ID'],'data':[],'record_id_list':[],'has_more':False}}))
            with self.assertRaisesRegex(ValueError,'No matching remote record'):
                reconcile(ops,source,str(cli),'baseTest','tblTest',record['recordId'],None,runner=runner)
            self.assertEqual(len(calls),1)
            self.assertEqual(status(ops)['deliveryStates'],{'pending':1})
