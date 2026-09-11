import tempfile
import unittest
from pathlib import Path
from setup_config import build_config, save_config


class SetupTests(unittest.TestCase):
    def test_explicit_onboarding_config_has_no_fake_source(self):
        with self.assertRaises(ValueError):build_config()
        self.assertEqual(build_config(onboarding_only=True)['mcpServers']['kpro-alerts']['env'],{})
        with self.assertRaises(ValueError):build_config(cli='lark.exe',onboarding_only=True)
        with self.assertRaises(ValueError):build_config(database='events.db',onboarding_only=True)

    def test_collector_health_is_explicit(self):
        config=build_config(database='events.db',collector_health='collector-health.json')
        self.assertTrue(Path(config['mcpServers']['kpro-alerts']['env']['KPRO_COLLECTOR_HEALTH']).is_absolute())

    def test_config_uses_absolute_paths(self):
        config = build_config(database='events.db')
        server = config['mcpServers']['kpro-alerts']
        self.assertTrue(Path(server['command']).is_absolute())
        self.assertTrue(Path(server['args'][0]).is_absolute())
        self.assertTrue(Path(server['env']['KPRO_ALERT_DATABASE']).is_absolute())

    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / 'config.json'
            save_config(target, {'a': 1})
            with self.assertRaises(FileExistsError):
                save_config(target, {'a': 2})
            self.assertIn('1', target.read_text())

    def test_incomplete_feishu_rejected(self):
        with self.assertRaises(ValueError):
            build_config(cli='lark.exe')


if __name__ == '__main__':
    unittest.main()
