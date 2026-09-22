import copy
from pathlib import Path
import tempfile
import unittest
from kpro_alert_bridge import Store, ingest_document
from operations import events
from spool import validate_safe_batch

class NativeProvenanceTests(unittest.TestCase):
    def batch(self):
        return dict(schema='KProSafeEventBatch/v1',redacted=True,session='native-session',batchId='1',dropped=0,
            records=[dict(eventType=7,operation=2,sequence=1,policyVersion=12,processId=42,processCreateTime=987)],
            nativeSources=[dict(schema='FalconProCollectorSource/v1',batchSha256='a'*64,recordIndex=2)])

    def test_retains_original_index_as_untrusted_native_locator(self):
        validate_safe_batch(self.batch())
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'events.db'
            with Store(path) as store:
                self.assertEqual(ingest_document(store,'b'*64,self.batch()),1)
            event=events(path)['events'][0]
            self.assertEqual(event['nativeSource'],self.batch()['nativeSources'][0])
            self.assertEqual(event['sourceAttestation'],'not_verified_by_native_broker')

    def test_rejects_misaligned_and_extra_fields_without_partial_ingest(self):
        for mutate in [lambda b:b.update(nativeSources=[]),
                       lambda b:b['nativeSources'][0].update(recordIndex=True),
                       lambda b:b['nativeSources'][0].update(path='PRIVATE')]:
            with tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'events.db';batch=self.batch();mutate(batch)
                with Store(path) as store:
                    with self.assertRaises(ValueError):ingest_document(store,'b'*64,batch)
                    self.assertEqual(store.health()['storedEvents'],0)

    def test_legacy_batch_does_not_invent_native_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'events.db';batch=self.batch();batch.pop('nativeSources')
            with Store(path) as store:ingest_document(store,'b'*64,batch)
            self.assertNotIn('nativeSource',events(path)['events'][0])

if __name__=='__main__':unittest.main()
