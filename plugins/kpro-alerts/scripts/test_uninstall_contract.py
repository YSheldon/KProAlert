from pathlib import Path
import unittest


class UninstallTests(unittest.TestCase):
    def test_product_authorization_precedes_service_removal(self):
        source = (Path(__file__).resolve().parents[3]/'Uninstall-KProAlert.ps1').read_text()
        self.assertLess(source.index('--uninstall'), source.index("@('delete','KProSvc')"))
        for text in ('ManifestSha256', 'Unexpected service path', 'success',
                     'KProFilter', 'Move-Item -LiteralPath', 'SupportsShouldProcess'):
            self.assertIn(text, source)
        self.assertNotIn('fltmc unload', source)
        self.assertNotIn('Remove-Item', source)

    def test_trust_module_is_read_locked_until_import(self):
        source = (Path(__file__).resolve().parents[3]/'Uninstall-KProAlert.ps1').read_text()
        self.assertIn('function Read-LockedInput', source)
        self.assertIn('$moduleBytes = Read-LockedInput $module 1048576', source)
        self.assertLess(source.index('$moduleBytes = Read-LockedInput $module 1048576'),
                        source.index('Import-Module $module -Force'))
        self.assertIn('foreach($handle in $inputHandles)', source)
        self.assertNotIn('Get-FileHash -LiteralPath $module', source)

    def test_residual_checks_cover_both_driver_image_paths(self):
        root = Path(__file__).resolve().parents[3]
        uninstall = (root/'Uninstall-KProAlert.ps1').read_text()
        endpoint = (root/'plugins/kpro-alerts/scripts/EndpointFacts.ps1').read_text()
        for source in (uninstall, endpoint):
            self.assertIn('KProFilter.sys', source)
            self.assertIn('KProFilterArm.sys', source)
            self.assertIn('$driverPaths', source)
        self.assertIn('[IO.Path]::GetFullPath', uninstall)


if __name__ == '__main__':
    unittest.main()
