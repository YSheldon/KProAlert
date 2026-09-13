import json
import tempfile
from pathlib import Path
import unittest
from zcode_setup import configure


class ZCodeSetupTests(unittest.TestCase):
    server = {'command': 'python', 'args': ['mcp_server.py'], 'env': {}}

    def test_native_merge_and_idempotency(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.zcode/cli').mkdir(parents=True)
            path = root / '.zcode/cli/config.json'
            path.write_text(json.dumps({'theme': 'dark', 'mcp': {'servers': {'existing': {}}}}))
            self.assertEqual(configure(self.server, user_root=root, project_root=root)['registration'], 'configured')
            content = path.read_bytes()
            self.assertEqual(configure(self.server, user_root=root, project_root=root)['registration'], 'unchanged')
            self.assertEqual(content, path.read_bytes())
            self.assertEqual(json.loads(content)['theme'], 'dark')
            self.assertIn('existing', json.loads(content)['mcp']['servers'])

    def test_workspace_disable_is_not_overridden(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.zcode').mkdir()
            (root / '.zcode/config.json').write_text(json.dumps({'mcp': {'servers': {'kpro-alerts': {**self.server, 'enable': False}}}}))
            with self.assertRaises(ValueError):
                configure(self.server, user_root=root, project_root=root)
            self.assertFalse((root / '.zcode/cli/config.json').exists())

    def test_compatibility_servers_cannot_be_silently_hidden(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / 'project'; project.mkdir()
            (root / '.agents').mkdir()
            path = root / '.agents/mcp.json'
            path.write_text('{"mcpServers":{"existing":{"command":"other"}}}')
            original = path.read_bytes()
            with self.assertRaises(ValueError):
                configure(self.server, user_root=root, project_root=project)
            self.assertEqual(original, path.read_bytes())
            self.assertFalse((root / '.zcode/cli/config.json').exists())
