import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from kpro_alert_bridge import Store, ingest_document


def event(sequence=1):
    return dict(eventType=7, operation=8, sequence=sequence,
                processId=42, processCreateTime=123)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'events.db'

    def tearDown(self):
        self.temp.cleanup()

    def test_batch_is_atomic(self):
        with Store(self.path) as s:
            with self.assertRaises(ValueError):
                ingest_document(s, 'host', dict(session='boot', dropped=0,
                    records=[event(), dict(eventType=99, operation=8, sequence=2)]))
            self.assertEqual(len(s.export()), 0)

    def test_empty_batch_idempotent_and_loss_visible(self):
        with Store(self.path) as s:
            batch = dict(session='boot', batchId='b1', dropped=3, records=[])
            ingest_document(s, 'host', batch)
            ingest_document(s, 'host', batch)
            self.assertEqual(s.health()['reportedDropped'], 3)
            batch['batchId'] = 'b2'
            ingest_document(s, 'host', batch)
            self.assertEqual(s.health()['reportedDropped'], 6)

    def test_capacity_rejects_without_partial_batch(self):
        with Store(self.path, max_events=1) as s:
            with self.assertRaises(RuntimeError):
                ingest_document(s, 'host', dict(session='boot', dropped=0,
                    records=[event(1), event(2)]))
            self.assertEqual(s.health()['storedEvents'], 0)

    def test_restart_dedup_and_ack(self):
        sender = Mock(return_value='rec123')
        with Store(self.path) as s:
            self.assertTrue(s.ingest('host', 'boot', event()))
            s.sync(sender)
        with Store(self.path) as s:
            self.assertFalse(s.ingest('host', 'boot', event()))
            s.sync(sender)
        self.assertEqual(sender.call_count, 1)

    def test_uncertain_send_survives_restart(self):
        sender = Mock(side_effect=TimeoutError())
        with Store(self.path) as s:
            s.ingest('host', 'boot', event())
            with self.assertRaises(TimeoutError):
                s.sync(sender)
        with Store(self.path) as s:
            with self.assertRaises(RuntimeError):
                s.sync(sender)
            self.assertEqual(s.health()['uncertainDeliveries'], 1)
        self.assertEqual(sender.call_count, 1)

    def test_same_sequence_modified_payload_is_error(self):
        with Store(self.path) as s:
            s.ingest('host', 'boot', event())
            changed = event()
            changed['operation'] = 16
            with self.assertRaises(ValueError):
                s.ingest('host', 'boot', changed)


if __name__ == '__main__':
    unittest.main()
