import json
from pathlib import Path
import tempfile
import unittest
from kpro_alert_bridge import Store
from spool import consume


class SpoolTests(unittest.TestCase):
    def test_archive_after_commit_and_ignore_temporary(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            queue = root / 'spool'
            queue.mkdir()
            doc = dict(session='test', batchId='b1', dropped=2,
                       records=[dict(eventType=7, operation=8, sequence=1)])
            (queue/'one.json').write_text(json.dumps(doc))
            (queue/'two.json.tmp').write_text('unfinished')
            with Store(root/'events.db') as s:
                result = consume(s, queue, 'host', archive=True)
                self.assertEqual(result['importedFiles'], 1)
                self.assertFalse((queue/'one.json').exists())
                self.assertEqual(len(list((queue/'archive').glob('*.json'))), 1)
                self.assertEqual(consume(s, queue, 'host', archive=True)['importedFiles'], 0)
                self.assertEqual(s.health()['reportedDropped'], 2)

    def test_invalid_file_retained_and_valid_file_processed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            queue = root/'spool'
            queue.mkdir()
            (queue/'bad.json').write_text('oops')
            (queue/'ok.json').write_text(json.dumps(dict(session='t', batchId='b', dropped=0, records=[])))
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
            (queue/'batch.json').write_text(json.dumps(dict(session='t', dropped=0, records=[
                dict(eventType=7, operation=8, sequence=i) for i in (1,2)])))
            with Store(root/'events.db', max_events=1) as s:
                result = consume(s, queue, 'host', archive=True)
                self.assertEqual(result['failedFiles'], 1)
                self.assertTrue((queue/'batch.json').exists())
                self.assertEqual(s.health()['storedEvents'], 0)


if __name__ == '__main__':
    unittest.main()
