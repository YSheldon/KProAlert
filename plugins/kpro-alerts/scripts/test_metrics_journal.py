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

    def test_same_observation_is_not_recorded_again_on_another_day(self):
        self.j.enable()
        args=dict(kind='upgrade_success',version='0.3.0.2',architecture='x64',
                  os_family='windows11',observation_key='a'*64)
        first=self.j.record(**args,day=100)
        second=self.j.record(**args,day=101)
        self.assertEqual(first,second)
        self.assertEqual(len(self.j.preview()),1)

    def test_observation_reuse_with_changed_facts_is_rejected(self):
        self.j.enable()
        args=dict(kind='upgrade_success',architecture='x64',os_family='windows11',
                  observation_key='b'*64,day=100)
        self.j.record(**args,version='0.3.0.2')
        with self.assertRaises(ValueError):
            self.j.record(**args,version='0.3.0.3')
        self.assertEqual(len(self.j.preview()),1)

    def test_observation_key_is_local_only_and_requires_consent(self):
        args=dict(kind='upgrade_success',version='0.3.0.2',architecture='x64',
                  os_family='windows11',observation_key='c'*64,day=100)
        self.assertIsNone(self.j.record(**args))
        self.j.enable()
        event=self.j.record(**args)
        self.assertNotIn('observation_key',event)
        self.assertNotIn('c'*64,json.dumps(self.j.preview()))
        with self.assertRaises(ValueError):
            self.j.record(**{**args,'observation_key':'private/device/path'})

    def test_acknowledged_observation_is_not_requeued(self):
        self.j.enable()
        args=dict(kind='upgrade_success',version='0.3.0.2',architecture='x64',
                  os_family='windows11',observation_key='d'*64,day=100)
        event=self.j.record(**args)
        self.j.prepare()
        self.j.ack(event['eventId'],'recAcknowledged')
        self.assertEqual(event,self.j.record(**{**args,'day':101}))
        self.assertEqual(self.j.preview(),[])
        self.assertEqual(self.j.status()['acknowledged'],1)

    def test_concurrent_observation_import_is_atomic(self):
        from concurrent.futures import ThreadPoolExecutor
        self.j.enable()
        def observe(day):
            with Journal(Path(self.temp.name)/'metrics.db') as journal:
                return journal.record(kind='upgrade_success',version='0.3.0.2',
                    architecture='x64',os_family='windows11',observation_key='e'*64,day=day)
        with ThreadPoolExecutor(max_workers=4) as workers:
            results=list(workers.map(observe,range(100,104)))
        self.assertEqual(len({item['eventId'] for item in results}),1)
        self.assertEqual(len(self.j.preview()),1)

    def test_observation_kind_conflict_is_not_another_install(self):
        self.j.enable()
        args=dict(kind='upgrade_success',version='0.3.0.2',architecture='x64',
                  os_family='windows11',observation_key='f'*64,day=100)
        self.j.record(**args)
        with self.assertRaises(ValueError):
            self.j.record(**{**args,'kind':'install_success'})
        self.assertEqual(self.j.preview()[0]['kind'],'upgrade_success')

    def test_uncertain_observation_is_not_requeued(self):
        self.j.enable()
        args=dict(kind='upgrade_success',version='0.3.0.2',architecture='x64',
                  os_family='windows11',observation_key='1'*64,day=100)
        event=self.j.record(**args)
        self.j.prepare()
        self.j.uncertain(event['eventId'])
        self.assertEqual(event,self.j.record(**{**args,'day':101}))
        self.assertEqual(self.j.preview(),[])
        self.assertEqual(self.j.status()['uncertain'],1)

    def test_observation_namespace_changes_after_new_consent_identity(self):
        args=dict(kind='upgrade_success',version='0.3.0.2',architecture='x64',
                  os_family='windows11',observation_key='2'*64,day=100)
        self.j.enable()
        first=self.j.record(**args)
        first_key=self.j.db.execute('SELECT dedupe FROM metrics_events').fetchone()[0]
        self.j.disable()
        self.j.enable()
        second=self.j.record(**args)
        second_key=self.j.db.execute('SELECT dedupe FROM metrics_events').fetchone()[0]
        self.assertNotEqual(first['installationId'],second['installationId'])
        self.assertNotEqual(first_key,second_key)


if __name__=='__main__':
    unittest.main()
