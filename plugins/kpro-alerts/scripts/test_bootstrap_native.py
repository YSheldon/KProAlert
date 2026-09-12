import os
from pathlib import Path
import subprocess
import unittest


@unittest.skipUnless(os.name == 'nt', 'Windows PowerShell contract')
class NativeBootstrapTests(unittest.TestCase):
    def test_download_and_package_boundaries(self):
        result = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned',
                                 '-File', str(Path(__file__).with_suffix('.ps1'))],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
