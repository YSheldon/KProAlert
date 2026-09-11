import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from metrics_journal import Journal
from metrics_upload import fields, upload


class MetricsUploadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / 'metrics.db'
        with Journal(self.db) as journal:
            journal.enable()
            self.event = journal.record(kind='install_success', version='1.2.0.300',
                                        architecture='x64', os_family='windows11')
        self.cli = Path(self.tmp.name) / 'lark-cli.exe'
        self.cli.write_text('fixture')

    def readback(self, event, record_id='rec123'):
        payload = fields(event)
        return {
            'ok': True,
            'data': {
                'fields': list(payload.keys()),
                'data': [list(payload.values())],
                'has_more': False,
                'record_id_list': [record_id],
            },
        }

    def test_preview_does_not_call_cli(self):
        def forbidden(*args, **kwargs):
            self.fail('preview must not send')
        result = upload(self.db, self.cli, 'base', 'table', runner=forbidden)
        self.assertFalse(result['applied'])
        self.assertEqual(result['prepared'], 1)

    def test_preview_is_repeatable_and_keeps_event_pending(self):
        first = upload(self.db, self.cli, 'base', 'table', runner=lambda *args, **kwargs: self.fail('preview must not send'))
        second = upload(self.db, self.cli, 'base', 'table', runner=lambda *args, **kwargs: self.fail('preview must not send'))
        self.assertEqual(first['events'], second['events'])
        self.assertEqual(first['prepared'], 1)
        self.assertEqual(second['prepared'], 1)
        with Journal(self.db) as journal:
            self.assertEqual(journal.status()['pending'], 1)
            self.assertEqual(journal.status()['prepared'], 0)

    def test_preview_then_apply_uploads_the_same_pending_event(self):
        preview = upload(self.db, self.cli, 'base', 'table', runner=lambda *args, **kwargs: self.fail('preview must not send'))
        calls = []
        event = self.event

        def runner(command, **kwargs):
            calls.append(command)
            if '+record-upsert' in command:
                return SimpleNamespace(stdout=json.dumps({'ok': True, 'data': {
                    'created': True, 'record_id_list': ['rec123']}}))
            return SimpleNamespace(stdout=json.dumps(self.readback(event)))

        result = upload(self.db, self.cli, 'base', 'table', apply=True, runner=runner)
        self.assertEqual(preview['events'][0]['eventId'], event['eventId'])
        self.assertEqual(result['uploaded'], 1)
        self.assertEqual(result['uncertain'], 0)
        self.assertEqual(len(calls), 2)
        self.assertIn('+record-get', calls[1])
        with Journal(self.db) as journal:
            self.assertEqual(journal.status()['acknowledged'], 1)

    def test_apply_acknowledges_verified_receipt(self):
        calls = []
        event = self.event
        def runner(command, **kwargs):
            calls.append(command)
            if '+record-upsert' in command:
                return SimpleNamespace(stdout=json.dumps({'ok': True, 'data': {
                    'created': True, 'record_id_list': ['rec123']}}))
            return SimpleNamespace(stdout=json.dumps(self.readback(event)))
        result = upload(self.db, self.cli, 'base', 'table', apply=True, runner=runner)
        self.assertEqual(result['uploaded'], 1)
        self.assertEqual(result['uncertain'], 0)
        self.assertIn('install_success', json.dumps(calls))
        self.assertIn('--record-id', calls[1])
        self.assertEqual(calls[1][calls[1].index('--record-id') + 1], 'rec123')
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
        repeated = upload(self.db, self.cli, 'base', 'table', apply=True, runner=runner)
        self.assertEqual(repeated['prepared'], 0)
        self.assertEqual(repeated['uploaded'], 0)
        self.assertEqual(repeated['uncertain'], 0)
        self.assertEqual(len(calls), 1)
        with Journal(self.db) as journal:
            self.assertEqual(journal.status()['uncertain'], 1)

    def test_write_receipt_without_matching_readback_is_uncertain(self):
        calls = []
        event = self.event

        def runner(command, **kwargs):
            calls.append(command)
            if '+record-upsert' in command:
                return SimpleNamespace(stdout=json.dumps({'ok': True, 'data': {
                    'created': True, 'record_id_list': ['rec123']}}))
            wrong = self.readback(event, 'rec999')
            return SimpleNamespace(stdout=json.dumps(wrong))

        result = upload(self.db, self.cli, 'base', 'table', apply=True, runner=runner)
        self.assertEqual(result['uploaded'], 0)
        self.assertEqual(result['uncertain'], 1)
        self.assertEqual(len(calls), 2)
        with Journal(self.db) as journal:
            self.assertEqual(journal.status()['uncertain'], 1)

    def test_invalid_cli_does_not_reserve_event(self):
        missing = Path(self.tmp.name) / 'missing-lark-cli.exe'
        with self.assertRaises(ValueError):
            upload(self.db, missing, 'base', 'table', apply=True)
        with Journal(self.db) as journal:
            self.assertEqual(journal.status()['pending'], 1)
            self.assertEqual(journal.status()['prepared'], 0)


if __name__ == '__main__':
    unittest.main()
