import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from delivery_worker import validate_config, run_once, run_worker, WorkerLock


class WorkerTests(unittest.TestCase):
    def fixture(self, root):
        spool = root / 'spool'
        spool.mkdir()
        return dict(schema='KProDelivery/v1', database=str(root/'events.db'),
                    spool=str(spool), device='test-host', interval=10,
                    health=str(root/'delivery-health.json'), publish=False)

    def test_rejects_unknown_config_and_partial_cloud(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self.fixture(Path(d))
            self.assertEqual(validate_config(cfg)['interval'], 10)
            for delta in ({'shellCommand': 'anything'}, {'interval': 1},
                          {'publish': True}, {'database': 'relative.db'},
                          {'health': str(Path(d)/'events.db-wal')},
                          {'health': str(Path(d)/'events.db-shm')},
                          {'health': str(Path(d)/'delivery.json')},
                          {'spool': str(Path(d))}):
                with self.assertRaises(ValueError):
                    validate_config(dict(cfg, **delta))

    def test_committed_batch_archived_restart_no_duplicate(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = self.fixture(root)
            (root/'spool/batch.json').write_text(json.dumps(dict(
                session='s', dropped=0, records=[dict(eventType=0, operation=2, sequence=1)])))
            first = run_once(validate_config(cfg))
            self.assertEqual(first['health']['storedEvents'], 1)
            self.assertEqual(first['importedEvents'], 1)
            self.assertEqual(run_once(validate_config(cfg))['importedEvents'], 0)
            self.assertEqual(len(list((root/'spool/archive').glob('*.json'))), 1)

    def test_loop_persists_bounded_health_and_honors_limit(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = self.fixture(root)
            self.assertEqual(run_worker(cfg, max_cycles=2, sleep=lambda _: None), 0)
            receipt = json.loads((root/'delivery-health.json').read_text())
            self.assertEqual(receipt['schema'], 'KProDeliveryHealth/v1')
            self.assertEqual(receipt['cycle'], 2)
            self.assertEqual(receipt['status'], 'ready')
            self.assertLess((root/'delivery-health.json').stat().st_size, 8192)
            self.assertNotIn(str(root), json.dumps(receipt))

    def test_second_worker_cannot_claim_same_database(self):
        with tempfile.TemporaryDirectory() as d:
            lock = Path(d)/'delivery.lock'
            with WorkerLock(lock):
                with self.assertRaises(RuntimeError):
                    with WorkerLock(lock):
                        pass
            with WorkerLock(lock):
                pass

    def test_failed_import_is_visible_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = self.fixture(root)
            (root/'spool/bad.json').write_text('bad')
            self.assertEqual(run_worker(cfg, max_cycles=1), 1)
            receipt = json.loads((root/'delivery-health.json').read_text())
            self.assertEqual(receipt['status'], 'attention_required')
            self.assertTrue((root/'spool/bad.json').exists())

    def test_idle_does_not_repeatedly_parse_export(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = self.fixture(root)
            cfg.update(publish=True, cli=str(root/'lark.exe'), base='base', table='table')
            (root/'lark.exe').touch()
            with patch('delivery_worker.Store.sync') as sync:
                sync.return_value = False
                run_worker(cfg, max_cycles=3, sleep=lambda _: None)
                self.assertEqual(sync.call_count, 1)
                self.assertEqual(sync.call_args.kwargs['max_deliveries'], 1)


if __name__ == '__main__':
    unittest.main()
