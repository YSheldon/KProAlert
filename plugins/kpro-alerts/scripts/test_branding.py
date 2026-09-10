"""Product display names must not change compatibility identifiers."""
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class BrandingTests(unittest.TestCase):
    def test_plugin_display_and_identity(self):
        plugin = json.loads((ROOT / 'plugins/kpro-alerts/.codex-plugin/plugin.json').read_text())
        self.assertEqual(plugin['name'], 'kpro-alerts')
        self.assertEqual(plugin['interface']['displayName'], 'FalconPro')
        for key in ('shortDescription', 'longDescription', 'defaultPrompt'):
            self.assertIn('FalconPro', plugin['interface'][key])
            self.assertNotIn('Kpro', plugin['interface'][key])
        market = json.loads((ROOT / '.agents/plugins/marketplace.json').read_text())
        self.assertEqual(market['interface']['displayName'], 'FalconPro')
        self.assertEqual(market['plugins'][0]['name'], 'kpro-alerts')

    def test_install_display_preserves_service_id(self):
        source = (ROOT / 'Install-KProAlert.ps1').read_text()
        self.assertIn("-DisplayName 'FalconPro Protection'", source)
        self.assertIn('New-Service -Name KProSvc', source)

    def test_mcp_display_and_readme(self):
        source = (ROOT / 'plugins/kpro-alerts/scripts/mcp_server.py').read_text()
        self.assertIn("FastMCP('FalconPro')", source)
        self.assertTrue((ROOT / 'README.md').read_text().startswith('# FalconPro\n'))


if __name__ == '__main__':
    unittest.main()
