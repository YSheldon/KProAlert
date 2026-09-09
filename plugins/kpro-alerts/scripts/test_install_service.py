"""Installer contract checks; Windows test mocks SCM, never creates a service."""
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]


class ServiceInstallTests(unittest.TestCase):
    def test_no_native_sc_create_quoting(self):
        source = (ROOT / 'Install-KProAlert.ps1').read_text(encoding='utf-8-sig')
        self.assertNotIn("@('create','KProSvc'", source)
        self.assertIn('New-KProProtectionService $serviceExe', source)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows PowerShell contract')
    def test_quoted_path_and_readback(self):
        result = subprocess.run(
            ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
             str(pathlib.Path(__file__).with_name('test_install_service.ps1'))],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
