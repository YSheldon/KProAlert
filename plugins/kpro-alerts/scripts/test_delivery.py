import json
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import tempfile
from pathlib import Path
from kpro_alert_bridge import feishu_sender, Store


class DeliveryTests(unittest.TestCase):
    def test_bounded_publication_resumes_without_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory)/'events.db') as store:
                for number in range(3):
                    store.ingest('device','session',dict(sequence=number,eventType=number,operation=2))
                calls = []
                def send(alert, record):
                    calls.append(alert['alertId'])
                    return 'rec' + str(len(calls))
                self.assertTrue(store.sync(send, max_deliveries=1))
                self.assertEqual(len(calls), 1)
                self.assertTrue(store.sync(send, max_deliveries=1))
                self.assertFalse(store.sync(send, max_deliveries=1))
                self.assertFalse(store.sync(send, max_deliveries=1))
                self.assertEqual(len(set(calls)), 3)

    def test_cli_1094_receipt(self):
        alert = dict(alertId='a'*64, deviceId='TEST', sessionId='TEST',
                     eventType=7, operation=8, eventCount=1,
                     firstReceived='2026-09-08T00:00:00Z', lastReceived='2026-09-08T00:00:00Z')
        reply = {'ok': True, 'data': {'created': True,
                 'record': {'record_id_list': ['recTest123']}}}
        with patch('kpro_alert_bridge.subprocess.run', return_value=SimpleNamespace(stdout=json.dumps(reply))):
            self.assertEqual(feishu_sender('cli', 'base', 'table')(alert, None), 'recTest123')


if __name__ == '__main__':
    unittest.main()
