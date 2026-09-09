import hashlib
import tempfile
from pathlib import Path
import unittest
from release_manifest import validate


class ManifestTests(unittest.TestCase):
    def test_missing_signing_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                validate({'schema': 'KProAlertRelease/v1'}, Path(d), 'x64')

    def test_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                validate(dict(schema='KProAlertRelease/v1', architecture='x64',
                    version='0.2.0', releaseStatus='verified', files=[dict(name='../bad.exe', sha256='a'*64)]), Path(d), 'x64')

    def test_complete_hashed_package(self):
        names = ('KProSvc.exe', 'KProProtect.dll', 'KProFilter.sys', 'DrvCfg2.dat', 'default-policy.hex')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            files = []
            for n in names:
                (root/n).write_bytes(b'test')
                files.append(dict(name=n, sha256=hashlib.sha256(b'test').hexdigest(), size=4))
            manifest = dict(schema='KProAlertRelease/v1', architecture='x64', version='0.2.0',
                releaseStatus='verified', files=files, gates={
                    'serviceF1ArtifactProduct': True, 'driverMicrosoftProduct': True,
                    'dllProduct': True, 'policySignature': True, 'endToEnd': True})
            self.assertEqual(validate(manifest, root, 'x64')['fileCount'], 5)
            (root/'KProFilter.sys').write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                validate(manifest, root, 'x64')


if __name__ == '__main__':
    unittest.main()
