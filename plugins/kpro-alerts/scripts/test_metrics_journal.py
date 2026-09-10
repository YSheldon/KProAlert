import tempfile
import unittest
import json
from pathlib import Path
from metrics_journal import Journal


class MetricsJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.j=Journal(Path(self.temp.name)/'metrics.db')

    def tearDown(self):
        self.j.close()
        self.temp.cleanup()

    def record(self):
        return self.j.record(kind='install_success',version='1.2.0.267',architecture='x64',
                             os_family='windows11',state='unknown',day=100)

    def test_no_consent_no_collection(self):
        self.assertIsNone(self.record())
        self.assertEqual(self.j.prepare(),[])

    def test_disable_forgets_pending_data_and_identity(self):
        self.j.enable()
        first=self.record()['installationId']
        self.j.disable()
        self.assertEqual(self.j.prepare(),[])
        self.j.enable()
        self.assertNotEqual(first,self.record()['installationId'])

    def test_uncertain_never_automatically_retried(self):
        self.j.enable()
        event=self.record()
        self.assertEqual(len(self.j.prepare()),1)
        self.assertEqual(self.j.prepare(),[])
        self.j.uncertain(event['eventId'])
        self.assertEqual(self.j.prepare(),[])
        self.j.ack(event['eventId'],'rec123456')
        self.assertEqual(self.j.status()['acknowledged'],1)

    def test_ack_requires_prepared_and_receipt(self):
        self.j.enable()
        event=self.record()
        with self.assertRaises(ValueError):
            self.j.ack(event['eventId'],'rec123')
        self.j.prepare()
        with self.assertRaises(ValueError):
            self.j.ack(event['eventId'],'fake success')

    def test_daily_status_is_coalesced(self):
        self.j.enable()
        kw=dict(kind='status',version='1.2.0.267',architecture='x64',os_family='windows11',state='unknown',day=100)
        first=self.j.record(**kw)
        second=self.j.record(**kw)
        self.assertEqual(first['eventId'],second['eventId'])
        self.assertEqual(len(self.j.prepare()),1)

    def test_poisoned_payload_is_not_exported_or_consumed(self):
        self.j.enable()
        event=self.record()
        with self.j.db:
            self.j.db.execute('UPDATE metrics_events SET payload=?',(json.dumps({**event,'path':'private'}),))
        with self.assertRaises(ValueError):
            self.j.prepare()
        self.assertEqual(self.j.status()['pending'],1)

    def test_recovery_is_read_only_and_paginated(self):
        self.j.enable()
        for day in range(100,160):
            self.j.record(kind='status',version='1.2.0.267',architecture='x64',os_family='windows11',day=day)
        batch=self.j.prepare()
        self.j.prepare()
        first=self.j.status(limit=50)
        second=self.j.status(limit=50,after=first['nextCursor'])
        self.assertEqual(len(first['unconfirmedEventIds']),50)
        self.assertEqual(len(second['unconfirmedEventIds']),10)
        recovered=self.j.recover(batch[0]['eventId'])
        self.assertEqual(recovered['event'],batch[0])
        self.assertTrue(recovered['manualReconciliationRequired'])
        self.assertEqual(self.j.prepare(),[])

    def test_row_identity_mismatch_fails_closed(self):
        self.j.enable()
        event=self.record()
        with self.j.db:
            self.j.db.execute('UPDATE metrics_events SET payload=?',(json.dumps({**event,'eventId':'0'*32}),))
        with self.assertRaises(ValueError):
            self.j.prepare()


if __name__=='__main__':
    unittest.main()
