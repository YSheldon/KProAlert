import json
import os
import tempfile
from pathlib import Path
import unittest
from collector_health import read_health


class HealthTests(unittest.TestCase):
    @staticmethod
    def native():
        return dict(phase=2, status=0, generation='4', indexInitialized=True,
                    indexMissing=0, indexInvalid=0, producerBudget=0, childPending=True,
                    completedPasses=1, examinedThisPass=3, deferredThisPass=2,
                    copiesThisPass=3, replicasThisPass=2, terminalAcceptedThisPass=1,
                    unresolvedReferencesThisPass=1, retirementEnabled=False,
                    notificationDeliveryVerified=False)

    def read_native(self, native):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'health.json'
            path.write_text(json.dumps(dict(schema='KProCollectorHealth/v1', pid=1, tick=1,
                status=0, pendingEvents=0, collectorDropped=0, writtenBatches=5,
                stopped=False, nativeRetention=native)), encoding='utf-8')
            return read_health(path)

    def test_native_health_is_diagnostic_not_receipt_authority(self):
        source = self.native()
        source['path'] = 'private marker not exported'
        source['instructions'] = 'do not execute this field'
        result = self.read_native(source)
        native = result['nativeRetention']
        self.assertEqual(native['phaseName'], 'consumer_running')
        self.assertEqual(native['unresolvedReferencesThisPass'], 1)
        self.assertEqual(native['verificationProvenance'], 'unverified_local_health_metadata')
        self.assertNotIn('path', native)
        self.assertNotIn('instructions', native)
        self.assertNotIn('notificationDeliveryVerified', native)
        self.assertFalse(native['reportedNotificationDeliveryVerified'])
        self.assertFalse(native['reportedRetirementEnabled'])
        self.assertEqual(result['protectionStatus'], 'not_probed')

    def test_native_health_rejects_invalid_known_values(self):
        for field, value in [('phase', True), ('phase', 5), ('status', 1 << 31),
                             ('copiesThisPass', -1), ('completedPasses', 1 << 64),
                             ('generation', '04'), ('generation', '0'),
                             ('childPending', 1), ('producerBudget', 6)]:
            with self.subTest(field=field, value=value):
                source = self.native()
                source[field] = value
                with self.assertRaises(ValueError):
                    self.read_native(source)
        source = self.native()
        del source['indexInitialized']
        with self.assertRaises(ValueError):
            self.read_native(source)

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

    def test_clock_diagnostic_is_optional_and_not_verification_authority(self):
        source = self.native()
        source.update(clockStatus=0, clockVerified=True, clockRolledBack=True,
                      clockHighWaterUtcSeconds=1790000120)
        result = self.read_native(source)['nativeRetention']
        self.assertTrue(result.get('reportedClockVerified'))
        self.assertTrue(result.get('clockRolledBack'))
        self.assertEqual(result.get('clockHighWaterUtcSeconds'), 1790000120)
        self.assertNotIn('clockVerified', result)
        self.assertEqual(result['verificationProvenance'], 'unverified_local_health_metadata')

    def test_partial_or_invalid_clock_diagnostic_is_rejected(self):
        base = self.native()
        base.update(clockStatus=0, clockVerified=True, clockRolledBack=False,
                    clockHighWaterUtcSeconds=1790000120)
        for field, value in [('clockStatus', True), ('clockStatus', 1 << 31),
                             ('clockVerified', 1), ('clockRolledBack', 'false'),
                             ('clockHighWaterUtcSeconds', True),
                             ('clockHighWaterUtcSeconds', -1),
                             ('clockHighWaterUtcSeconds', 253402300800)]:
            with self.subTest(field=field):
                source = dict(base)
                source[field] = value
                with self.assertRaises(ValueError):
                    self.read_native(source)
        del base['clockStatus']
        with self.assertRaises(ValueError):
            self.read_native(base)

    def test_malformed_receipt_is_not_success(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'health.json'
            p.write_text('{}')
            with self.assertRaises(ValueError):
                read_health(p)


if __name__ == '__main__':
    unittest.main()
