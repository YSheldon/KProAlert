import unittest
import json
import sys
import subprocess
import time
from types import SimpleNamespace
from unittest.mock import patch
from source_egress import project, read


class ProjectionTests(unittest.TestCase):
    def test_timeout_does_not_wait_for_inherited_stdout(self):
        from source_egress import _bounded_cli
        code = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(1.5)"])'
        start = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            _bounded_cli([sys.executable, '-c', code], timeout=0.2, max_bytes=128)
        self.assertLess(time.monotonic() - start, 1.0)

    def test_cli_output_is_bounded_before_capture(self):
        import source_egress
        bounded = getattr(source_egress, '_bounded_cli', None)
        self.assertTrue(callable(bounded), 'CLI must cap output during capture')
        with self.assertRaisesRegex(ValueError, 'output exceeds'):
            bounded([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(b"x"*4096)'], max_bytes=128)

    def test_cli_timeout_and_success(self):
        import source_egress
        bounded = getattr(source_egress, '_bounded_cli', None)
        self.assertTrue(callable(bounded), 'CLI needs bounded output and deadline')
        result = bounded([sys.executable, '-c', 'print("ok")'], max_bytes=128)
        self.assertEqual(result.stdout.strip(), 'ok')
        with self.assertRaises(subprocess.TimeoutExpired):
            bounded([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=0.2, max_bytes=128)

    def record(self):
        return dict(schema='FalconProSourceEgressObservation/v1', recordId='a'*64,
                    workspaceId='b'*64, source='zcode_checkpoints', kind='package_observed',
                    evidenceLevel='filesystem_observation', observedAtUnixMs=1,
                    simulated=True, historical=False, networkUploadConfirmed=False,
                    coverageStatus='bounded_observation', encryptedSizeBytes=830)

    def test_valid(self):
        self.assertEqual(project(self.record()), self.record())

    def test_invalid_boundaries(self):
        for key, value in [('networkUploadConfirmed', True), ('simulated', 1),
                           ('observedAtUnixMs', True), ('encryptedSizeBytes', -1),
                           ('evidenceLevel', 'application_claim'), ('path', 'private'),
                           ('recordId', 'x'*64), ('historical', True)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                record = self.record(); record[key] = value; project(record)

    def test_gap(self):
        record = self.record(); record.pop('encryptedSizeBytes')
        record.update(kind='observer_coverage_gap', evidenceLevel='coverage_gap', coverageStatus='gap')
        self.assertEqual(project(record), record)

    def test_acceptance_claim(self):
        record = self.record(); record.pop('encryptedSizeBytes')
        record.update(kind='application_acceptance_claim', evidenceLevel='application_claim', extraMetadataChanged=True)
        self.assertEqual(project(record), record)
        record['extraMetadataChanged'] = 'true'
        with self.assertRaises(ValueError): project(record)

    def test_table_read_and_binding(self):
        record = self.record()
        envelope = dict(ok=True, data=dict(fields=['recordId', 'observationJson', 'simulated'],
                        data=[[record['recordId'], json.dumps(record), True]], has_more=False))
        def runner(*args, **kwargs):
            return SimpleNamespace(returncode=0, stdout=json.dumps(envelope))
        with patch('source_egress._resolve_cli', return_value='lark-cli'):
            result = read('cli', 'base', 'table', runner=runner)
            self.assertEqual(result['records'], [record])
            self.assertFalse(result['actionExecutionAvailable'])
            self.assertIsNone(result['nextOffset'])
            envelope['data']['has_more'] = True
            result = read('cli', 'base', 'table', offset=10, runner=runner)
            self.assertEqual(result['nextOffset'], 11)
            with self.assertRaises(ValueError): read('cli', 'base', 'table', offset=True, runner=runner)
            envelope['data']['data'][0][0] = 'c'*64
            with self.assertRaises(ValueError): read('cli', 'base', 'table', runner=runner)

    def test_non_object_response(self):
        with patch('source_egress._resolve_cli', return_value='lark-cli'):
            with self.assertRaises(ValueError):
                read('cli', 'base', 'table', runner=lambda *a, **k: SimpleNamespace(returncode=0, stdout='[]'))


if __name__ == '__main__': unittest.main()
