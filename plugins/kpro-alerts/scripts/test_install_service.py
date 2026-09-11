"""Installer contract checks; Windows test mocks SCM, never creates a service."""
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]


class ServiceInstallTests(unittest.TestCase):
    def test_windows_contract_runs_in_ci(self):
        workflow = (ROOT/'.github/workflows/test.yml').read_text()
        self.assertIn('windows-latest', workflow)

    def test_candidate_requires_explicit_validation_switch(self):
        source = (ROOT / 'Install-KProAlert.ps1').read_text(encoding='utf-8-sig')
        self.assertIn('[switch]$ValidateCandidate', source)
        self.assertIn("$candidate = $ValidateCandidate -and $manifest.releaseStatus -eq 'candidate'", source)
        self.assertIn("if ($candidate -and $gate -eq 'endToEnd') { continue }", source)

    def test_no_native_sc_create_quoting(self):
        source = (ROOT / 'Install-KProAlert.ps1').read_text(encoding='utf-8-sig')
        self.assertNotIn("@('create','KProSvc'", source)
        self.assertIn('New-KProProtectionService $serviceExe', source)

    def test_install_root_owner_and_readback_precede_payload_copy(self):
        source = (ROOT / 'Install-KProAlert.ps1').read_text(encoding='utf-8-sig')
        start = source.index('$acl = New-Object Security.AccessControl.DirectorySecurity')
        end = source.index('foreach ($entry in $manifest.files)', start)
        block = source[start:end]
        self.assertIn("$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))", block)
        self.assertLess(block.index('$acl.SetOwner('), block.index('Set-Acl -LiteralPath $destination'))
        self.assertLess(block.index('Set-Acl -LiteralPath $destination'),
                        block.index('Assert-KProInstallRootAcl (Get-Acl -LiteralPath $destination) $DeliveryUserSid'))

    @unittest.skipUnless(sys.platform == 'win32', 'Windows PowerShell contract')
    def test_quoted_path_and_readback(self):
        result = subprocess.run(
            ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
             str(pathlib.Path(__file__).with_name('test_install_service.ps1'))],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
