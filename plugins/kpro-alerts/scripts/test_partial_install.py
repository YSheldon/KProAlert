import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]


class PartialInstallTests(unittest.TestCase):
    def test_marker_precedes_payload_copy_and_transaction_is_forwarded(self):
        installer = (ROOT / 'Install-KProAlert.ps1').read_text(encoding='utf-8-sig')
        self.assertLess(installer.index('Write-KProInstallRootMarker $destination'),
                        installer.index('Copy-Item -LiteralPath (Join-Path $source $entry.name)'))
        for name in ('Install-FalconPro.ps1', 'Invoke-FalconProLifecycle.ps1'):
            self.assertIn('LifecycleTransactionId', (ROOT / name).read_text(encoding='utf-8-sig'))
        lifecycle = (ROOT / 'Invoke-FalconProLifecycle.ps1').read_text(encoding='utf-8-sig')
        self.assertIn('Archive-PartialInstallation', lifecycle)
        self.assertIn('partial_archive_pending', lifecycle)
        self.assertIn('function Assert-PartialRuntimeAbsent', lifecycle)
        self.assertIn('System32\\fltmc.exe', lifecycle)
        self.assertIn('Win32_Process -Filter', lifecycle)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows PowerShell filesystem contract')
    def test_prefix_and_archive_contract(self):
        result = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned',
                                 '-File', str(pathlib.Path(__file__).with_suffix('.ps1'))],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows PowerShell route contract')
    def test_public_recovery_routes(self):
        result = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned',
                                 '-File', str(pathlib.Path(__file__).with_name('test_recovery_routes.ps1'))],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows PowerShell service recovery contract')
    def test_service_recovery_binding(self):
        result = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned',
                                 '-File', str(pathlib.Path(__file__).with_name('test_service_recovery.ps1'))],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
