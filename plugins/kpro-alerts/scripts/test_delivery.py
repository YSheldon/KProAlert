import json
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from kpro_alert_bridge import feishu_sender


class DeliveryTests(unittest.TestCase):
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
