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


if __name__ == '__main__':
    unittest.main()
