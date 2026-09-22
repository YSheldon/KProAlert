import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from kpro_alert_bridge import Store, ingest_document
from operations import Operations, events
from operations_upload import upload
from test_native_actions import receipt_fixture


class NativeResultDeliveryTests(unittest.TestCase):
    def test_legacy_event_remains_analysis_only_for_collection_and_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            source,database=Path(tmp)/'events.db',Path(tmp)/'operations.db'
            with Store(source) as store:
                store.ingest('e'*64,'session',dict(eventType=7,operation=2,sequence=1,policyVersion=12,
                    processId=42,processCreateTime=987))
            event=events(source)['events'][0]
            with Operations(database,source,'codex') as journal:
                decision=journal.assess(event['eventId'],event['evidenceSha256'],'suspicious',75,
                    ['bulk_overwrite'],['switch_to_enforce'],'test','1'*32)
                request=journal.propose(decision['recordId'],'switch_to_enforce','2'*32)
                receipt=receipt_fixture(request)
                with patch('native_actions.read_result',return_value=receipt) as native:
                    with self.assertRaisesRegex(ValueError,'Historical event'):
                        journal.collect_native_result(request['recordId'],'entry.exe','a'*64,'e'*64)
                    native.assert_not_called()
            with patch.dict('os.environ',{'KPRO_NATIVE_ENTRY':'entry.exe','KPRO_NATIVE_ENTRY_SHA256':'a'*64,'KPRO_ENDPOINT_DEVICE_ID':'e'*64}), patch('native_actions._invoke',return_value=receipt) as invoke:
                from native_actions import verify_delivery
                with self.assertRaisesRegex(ValueError,'Historical event'):
                    verify_delivery(dict(request=request,nativeReceipt=receipt),source)
                invoke.assert_not_called()

    def test_native_receipt_is_read_not_supplied_and_rechecked_before_upload(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, database = Path(tmp)/'events.db', Path(tmp)/'operations.db'
            with Store(source) as store:
                ingest_document(store,'e'*64,dict(session='session',batchId='1',dropped=0,
                    records=[dict(eventType=7,operation=2,sequence=1,policyVersion=12,processId=42,processCreateTime=987)],
                    nativeSources=[dict(schema='FalconProCollectorSource/v1',batchSha256='b'*64,recordIndex=0)]))
            event=events(source)['events'][0]
            with Operations(database,source,'codex') as journal:
                decision=journal.assess(event['eventId'],event['evidenceSha256'],'suspicious',75,
                    ['bulk_overwrite'],['switch_to_enforce'],'test','1'*32)
                request=journal.propose(decision['recordId'],'switch_to_enforce','2'*32)
                receipt=receipt_fixture(request)
                with patch('native_actions.read_result',return_value=receipt) as native:
                    record=journal.collect_native_result(request['recordId'],'entry.exe','a'*64,'e'*64)
                    self.assertEqual(record['nativeReceipt'],receipt)
                    self.assertEqual(record['executionState'],'executed_verified')
                    again=journal.collect_native_result(request['recordId'],'entry.exe','a'*64,'e'*64)
                    self.assertEqual(record['recordId'],again['recordId'])
                    self.assertEqual(native.call_count,2)
                # Exclude the already-tested analysis/request uploads from this lane.
                for item in (decision,request):
                    journal.reserve(item['recordId'],'f'*64)
                    journal.ack(item['recordId'],'f'*64,'recPrior')
            with Operations(database,source,'workbuddy') as journal, patch('native_actions.read_result',return_value=receipt):
                other=journal.collect_native_result(request['recordId'],'entry.exe','a'*64,'e'*64)
                self.assertEqual(other['recordId'],record['recordId'])
                self.assertEqual(journal.status()['records'],3)
            calls=[]
            def runner(*args,**kwargs):
                calls.append(args)
                raise AssertionError('Unverified receipt must not leave this endpoint')
            with patch('native_actions.verify_delivery',side_effect=ValueError('native unavailable')):
                result=upload(database,source,'entry.exe','baseTest','tblTest',apply=True,runner=runner)
            self.assertEqual(calls,[])
            self.assertEqual(result['uploaded'],0)
            self.assertEqual(result['blocked'],1)
            with Operations(database,source) as journal:
                self.assertEqual(journal.status()['deliveryStates'],{'acknowledged':2,'new':1})
            from types import SimpleNamespace
            cli=Path(tmp)/'cli.exe';cli.touch()
            expected={}
            def deliver(command,**kwargs):
                if '+record-upsert' in command:
                    expected.update(json.loads(command[command.index('--json')+1]))
                    return SimpleNamespace(stdout=json.dumps({'ok':True,'data':{'record_id':'recNative'}}))
                return SimpleNamespace(stdout=json.dumps({'ok':True,'data':{'record':{'record_id':'recNative','fields':expected}}}))
            with patch('native_actions.verify_delivery') as verify:
                result=upload(database,source,str(cli),'baseTest','tblTest',apply=True,runner=deliver)
                verify.assert_called_once_with(record,source)
            self.assertEqual(result['readBack'],1)
            self.assertEqual(result['uncertain'],0)
            self.assertEqual(expected['执行状态'],'executed_verified')
            self.assertEqual(expected['分析结论'],'executed_verified')
            with Operations(database,source) as journal:
                self.assertEqual(journal.status()['deliveryStates'],{'acknowledged':3})
            import sqlite3
            with sqlite3.connect(source) as db:
                raw=json.loads(db.execute('SELECT raw FROM events').fetchone()[0]);raw.pop('_nativeSource')
                db.execute('UPDATE events SET raw=?',(json.dumps(raw),))
            db.close()
            with Operations(database,source) as journal, patch('native_actions.read_result',return_value=receipt):
                with self.assertRaises(ValueError):
                    journal.collect_native_result(request['recordId'],'entry.exe','a'*64,'e'*64)
            with patch.dict('os.environ',{'KPRO_NATIVE_ENTRY':'entry.exe','KPRO_NATIVE_ENTRY_SHA256':'a'*64,'KPRO_ENDPOINT_DEVICE_ID':'e'*64}), patch('native_actions._invoke',return_value=receipt):
                from native_actions import verify_delivery
                with self.assertRaises(ValueError):verify_delivery(record,source)


if __name__=='__main__':unittest.main()
