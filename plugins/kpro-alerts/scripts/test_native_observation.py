import json
import tempfile
import time
import unittest
from pathlib import Path

from install_metrics import summarize
from metrics_journal import Journal
from native_observation import collect_native_observation, validate_native_observation


def today():
    return int(time.time() // 86400)


class NativeObservationTests(unittest.TestCase):
    def observation(self, *, observation_id='a' * 64, operation='install',
                    os_family='windows11', day=None, test_only=False):
        return {
            'schema': 'FalconProNativeObservation/v1',
            'observationId': observation_id,
            'operation': operation,
            'phase': 'complete',
            'version': '0.3.0.2',
            'architecture': 'x64',
            'osFamily': os_family,
            'day': today() if day is None else day,
            'testOnly': test_only,
            'protectionVerified': False,
        }

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / 'metrics.db'
        self.addCleanup(self.temp.cleanup)

    def test_native_observation_has_exact_ten_publicly_safe_fields(self):
        result = validate_native_observation(self.observation(), today=today())
        self.assertEqual(set(result), {
            'schema', 'observationId', 'operation', 'phase', 'version',
            'architecture', 'osFamily', 'day', 'testOnly', 'protectionVerified',
        })
        self.assertNotIn('deviceId', result)
        self.assertNotIn('sid', result)
        self.assertNotIn('path', result)

    def test_native_observation_rejects_unknown_or_confidence_fields(self):
        for key, value in (
                ('deviceId', 'private'), ('sid', 'private'), ('path', 'private'),
                ('unexpected', True), ('protectionVerified', True)):
            candidate = {**self.observation(), key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_native_observation(candidate, today=today())

    def test_native_observation_rejects_future_day_and_null_os(self):
        with self.assertRaises(ValueError):
            validate_native_observation(self.observation(day=today() + 1), today=today())
        with self.assertRaises(ValueError):
            validate_native_observation(self.observation(os_family=None), today=today())

    def test_windows8_is_distinct_supported_os_family(self):
        result = validate_native_observation(
            self.observation(os_family='windows8'), today=today())
        self.assertEqual(result['osFamily'], 'windows8')

    def test_no_opt_in_does_not_call_reader_or_collect(self):
        calls = []

        def forbidden_reader():
            calls.append(True)
            raise AssertionError('reader must not run without opt-in')

        result = collect_native_observation(self.database, forbidden_reader)
        self.assertIsNone(result)
        self.assertEqual(calls, [])
        self.assertFalse(self.database.exists())
        with Journal(self.database) as journal:
            self.assertFalse(journal.status()['enabled'])

    def test_reader_must_be_callable_and_return_an_observation_object(self):
        with self.assertRaises(ValueError):
            collect_native_observation(self.database, json.dumps(self.observation()))
        with Journal(self.database) as journal:
            journal.enable()
        with self.assertRaises(ValueError):
            collect_native_observation(self.database, lambda: json.dumps(self.observation()))

    def test_opted_in_observation_maps_to_install_success_without_raw_identity(self):
        with Journal(self.database) as journal:
            journal.enable()
        event = collect_native_observation(self.database, self.observation)
        self.assertEqual(event['kind'], 'install_success')
        self.assertEqual(event['state'], 'unknown')
        self.assertEqual(event['version'], '0.3.0.2')
        self.assertEqual(event['osFamily'], 'windows11')
        self.assertFalse(event['simulated'])
        self.assertNotIn('observationId', event)
        self.assertNotIn('deviceId', event)
        self.assertNotIn('path', event)

    def test_upgrade_maps_and_reuses_one_observation_id_across_days(self):
        with Journal(self.database) as journal:
            journal.enable()
        first = collect_native_observation(
            self.database, lambda: self.observation(operation='upgrade', day=today()))
        second = collect_native_observation(
            self.database, lambda: self.observation(operation='upgrade', day=today()))
        self.assertEqual(first, second)
        self.assertEqual(first['kind'], 'upgrade_success')
        with Journal(self.database) as journal:
            self.assertEqual(len(journal.preview()), 1)

    def test_test_only_observation_requires_simulation_and_is_not_production_metric(self):
        with Journal(self.database) as journal:
            journal.enable(simulated=True)
        event = collect_native_observation(
            self.database, lambda: self.observation(test_only=True))
        self.assertTrue(event['simulated'])
        self.assertEqual(summarize([event], today=today())['successfulInstallations'], 0)

        other_database = Path(self.temp.name) / 'production' / 'metrics.db'
        other_database.parent.mkdir()
        with Journal(other_database) as journal:
            journal.enable(simulated=False)
        with self.assertRaises(ValueError):
            collect_native_observation(
                other_database, lambda: self.observation(test_only=True))

    def test_initial_consent_identity_is_rechecked_inside_record_transaction(self):
        with Journal(self.database) as journal:
            journal.enable()

        def reader():
            with Journal(self.database) as changed:
                changed.disable()
                changed.enable()
            return self.observation()

        with self.assertRaisesRegex(ValueError, 'consent changed'):
            collect_native_observation(self.database, reader)
        with Journal(self.database) as journal:
            self.assertEqual(journal.preview(), [])

    def test_initial_simulation_mode_is_rechecked_inside_record_transaction(self):
        with Journal(self.database) as journal:
            journal.enable(simulated=False)

        def reader():
            with Journal(self.database) as changed:
                with changed.db:
                    changed.db.execute(
                        "UPDATE metrics_meta SET value='1' WHERE key='simulated'")
            return self.observation()

        with self.assertRaisesRegex(ValueError, 'simulation mode changed'):
            collect_native_observation(self.database, reader)
        with Journal(self.database) as journal:
            self.assertEqual(journal.preview(), [])


if __name__ == '__main__':
    unittest.main()
