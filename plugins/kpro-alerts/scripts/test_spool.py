import json
from pathlib import Path
import tempfile
import unittest
from kpro_alert_bridge import Store
from spool import consume


class SpoolTests(unittest.TestCase):
    def test_raw_or_string_fields_never_imported_or_archived(self):
        for extra in ({}, {'schema':'KProSafeEventBatch/v1','redacted':True}):
            with tempfile.TemporaryDirectory() as d:
                root=Path(d); queue=root/'spool'; queue.mkdir()
                doc=dict(session='test',dropped=0,records=[dict(eventType=7,operation=8,sequence=1,path='private')],**extra)
                (queue/'raw.json').write_text(json.dumps(doc))
                with Store(root/'events.db') as store:
                    result=consume(store,queue,'host',archive=True)
                    self.assertEqual(result['failedFiles'],1)
                    self.assertEqual(store.health()['storedEvents'],0)
                    self.assertTrue((queue/'raw.json').exists())

    def test_archive_after_commit_and_ignore_temporary(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            queue = root / 'spool'
            queue.mkdir()
            doc = dict(schema='KProSafeEventBatch/v1',redacted=True,session='test', batchId='b1', dropped=2,projectionDropped=3,
                       records=[dict(eventType=7, operation=8, sequence=1)])
            (queue/'one.json').write_text(json.dumps(doc))
            (queue/'two.json.tmp').write_text('unfinished')
            with Store(root/'events.db') as s:
                result = consume(s, queue, 'host', archive=True)
                self.assertEqual(result['importedFiles'], 1)
                self.assertFalse((queue/'one.json').exists())
                self.assertEqual(len(list((queue/'archive').glob('*.json'))), 1)
                self.assertEqual(consume(s, queue, 'host', archive=True)['importedFiles'], 0)
                self.assertEqual(s.health()['reportedDropped'], 5)

    def test_invalid_file_retained_and_valid_file_processed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            queue = root/'spool'
            queue.mkdir()
            (queue/'bad.json').write_text('oops')
            (queue/'ok.json').write_text(json.dumps(dict(schema='KProSafeEventBatch/v1',redacted=True,session='t', batchId='b', dropped=0, records=[])))
            with Store(root/'events.db') as s:
                result = consume(s, queue, 'host', archive=True)
                self.assertEqual(result['failedFiles'], 1)
                self.assertEqual(result['importedFiles'], 1)
                self.assertTrue((queue/'bad.json').exists())

    def test_disk_capacity_failure_does_not_archive(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            queue = root/'spool'
            queue.mkdir()
            (queue/'batch.json').write_text(json.dumps(dict(schema='KProSafeEventBatch/v1',redacted=True,session='t', dropped=0, records=[
                dict(eventType=7, operation=8, sequence=i) for i in (1,2)])))
            with Store(root/'events.db', max_events=1) as s:
                result = consume(s, queue, 'host', archive=True)
                self.assertEqual(result['failedFiles'], 1)
                self.assertTrue((queue/'batch.json').exists())
                self.assertEqual(s.health()['storedEvents'], 0)


if __name__ == '__main__':
    unittest.main()
