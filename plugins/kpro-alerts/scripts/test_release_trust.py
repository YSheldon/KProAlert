from pathlib import Path
import subprocess
import sys
import unittest


class ReleaseTrustTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'win32', 'Windows Authenticode contracts')
    def test_publisher_and_timestamp_gates(self):
        result = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                                 '-File', str(Path(__file__).with_name('test_release_trust.ps1'))],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_installer_uses_snapshot_trust(self):
        source = (Path(__file__).resolve().parents[3]/'Install-KProAlert.ps1').read_text(encoding='utf-8-sig')
        self.assertTrue('Assert-KProReleaseAttestation -Bytes $attestationBytes' in source,
                        'Installer must authenticate the same in-memory snapshot it parses.')


if __name__ == '__main__':
    unittest.main()
