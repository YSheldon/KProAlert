import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from metrics_journal import Journal
from metrics_upload import upload


class MetricsUploadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / 'metrics.db'
        with Journal(self.db) as journal:
            journal.enable()
            journal.record(kind='install_success', version='1.2.0.300',
                           architecture='x64', os_family='windows11')
        self.cli = Path(self.tmp.name) / 'lark-cli.exe'
        self.cli.write_text('fixture')

    def test_preview_does_not_call_cli(self):
        def forbidden(*args, **kwargs):
            self.fail('preview must not send')
        result = upload(self.db, self.cli, 'base', 'table', runner=forbidden)
        self.assertFalse(result['applied'])
        self.assertEqual(result['prepared'], 1)

    def test_apply_acknowledges_verified_receipt(self):
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(stdout=json.dumps({'ok': True, 'data': {'record_id': 'rec123'}}))
        result = upload(self.db, self.cli, 'base', 'table', apply=True, runner=runner)
        self.assertEqual(result['uploaded'], 1)
        self.assertEqual(result['uncertain'], 0)
        self.assertIn('install_success', json.dumps(calls))
        with Journal(self.db) as journal:
            self.assertEqual(journal.status()['acknowledged'], 1)

    def test_uncertain_write_is_not_retried(self):
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            raise TimeoutError('fixture timeout')
        result = upload(self.db, self.cli, 'base', 'table', apply=True, runner=runner)
        self.assertEqual(result['uncertain'], 1)
        self.assertEqual(len(calls), 1)
        with Journal(self.db) as journal:
            self.assertEqual(journal.status()['uncertain'], 1)


if __name__ == '__main__':
    unittest.main()
