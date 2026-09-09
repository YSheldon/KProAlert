import json
import os
import tempfile
from pathlib import Path
import unittest
from collector_health import read_health


class HealthTests(unittest.TestCase):
    def test_old_receipt_is_not_fresh(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'health.json'
            p.write_text(json.dumps(dict(schema='KProCollectorHealth/v1', pid=1, tick=1,
                status=0, pendingEvents=0, collectorDropped=2, writtenBatches=5, stopped=False)))
            os.utime(p, (0, 0))
            result = read_health(p)
            self.assertFalse(result['receiptFresh'])
            self.assertEqual(result['protectionStatus'], 'not_probed')
            self.assertEqual(result['collectorDropped'], 2)

    def test_malformed_receipt_is_not_success(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'health.json'
            p.write_text('{}')
            with self.assertRaises(ValueError):
                read_health(p)


if __name__ == '__main__':
    unittest.main()
