"""Keep all assistant entry instructions on the same native install contract."""
from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[3]


class NativeInstallGuideTests(unittest.TestCase):
    def test_shared_native_guide_is_present_and_release_gated(self):
        guide = ROOT / 'NATIVE-INSTALL.md'
        self.assertTrue(guide.is_file(), 'Native endpoint guide is missing')
        text = guide.read_text(encoding='utf-8')
        for value in ('FalconProSetup.exe', 'FalconProSetup32.exe',
                      'FalconProSetupArm.exe', 'FalconProRelease.exe',
                      'releases/latest', 'stable_release_required',
                      'Win7 SP1', 'Grok Bot', 'Codex', 'Cursor', 'WorkBuddy'):
            self.assertIn(value, text)
        self.assertIn('Do not publish or request a device test permit', text)

    def test_client_entry_documents_link_the_native_guide(self):
        for name in ('README.md', 'START-HERE.md', 'INSTALL.md',
                     'ASSISTANT-SETUP.md', 'GROK-BOT.md', 'LIFECYCLE.md',
                     'LOCAL-ENDPOINT.md', 'BOOTSTRAP-UPGRADE.md', 'RELEASE-CONTRACT.md'):
            with self.subTest(name=name):
                self.assertTrue('NATIVE-INSTALL.md' in (ROOT/name).read_text(encoding='utf-8'), name)
        skill = ROOT/'plugins/kpro-alerts/skills/kpro-alerts/SKILL.md'
        self.assertIn('NATIVE-INSTALL.md', skill.read_text(encoding='utf-8'))

    def test_native_source_is_not_in_public_tree(self):
        self.assertFalse((ROOT/'native').exists())

    def test_bot_and_local_flow_do_not_default_to_script_installation(self):
        rules = json.loads((ROOT/'FalconPro.bot-template.json').read_text(encoding='utf-8'))['rules']
        joined = '\n'.join(rules)
        self.assertTrue('NATIVE-INSTALL.md' in joined)
        self.assertFalse('falconpro.py upgrade' in joined)
        self.assertFalse('falconpro.py status and install' in joined)
        local = (ROOT/'LOCAL-ENDPOINT.md').read_text(encoding='utf-8')
        self.assertFalse('`falconpro.py install' in local)
        self.assertFalse('.\\Install-FalconPro.ps1 -ExpectedDeviceId' in local)
        metrics = (ROOT/'INSTALL-METRICS.md').read_text(encoding='utf-8')
        self.assertTrue('native Rust entry does not accept --metrics-database' in metrics)


if __name__ == '__main__':
    unittest.main()
