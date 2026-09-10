import json
from pathlib import Path
import tempfile
import unittest
from cursor_setup import configure


SERVER = dict(command='python', args=['mcp_server.py'], env={})


class CursorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / '.cursor').mkdir()
        self.path = self.root / '.cursor/mcp.json'
        self.kw = dict(config_path=self.path, project_root=self.root)

    def test_merges_preserves_and_is_idempotent(self):
        old = dict(mcpServers={'other': dict(command='other')}, preference=17)
        self.path.write_text(json.dumps(old))
        self.assertEqual(configure(SERVER, **self.kw)['registration'], 'configured')
        merged = json.loads(self.path.read_text())
        self.assertEqual(merged['mcpServers']['other'], old['mcpServers']['other'])
        self.assertEqual(merged['preference'], 17)
        self.assertEqual(configure(SERVER, **self.kw)['registration'], 'unchanged')
        self.assertEqual(len(list(self.path.parent.glob('*.bak'))), 1)

    def test_conflict_and_duplicate_keys_do_not_mutate(self):
        for text in ('{"mcpServers":{"kpro-alerts":{"command":"other"}}}',
                     '{"mcpServers":{},"mcpServers":{}}'):
            self.path.write_text(text)
            with self.assertRaises(ValueError):
                configure(SERVER, **self.kw)
            self.assertEqual(self.path.read_text(), text)

    def test_project_override_prevents_global_change(self):
        project = self.root / 'project'
        (project / '.cursor').mkdir(parents=True)
        (project / '.cursor/mcp.json').write_text('{"mcpServers":{"kpro-alerts":{"command":"other"}}}')
        with self.assertRaises(ValueError):
            configure(SERVER, config_path=self.path, project_root=project)
        self.assertFalse(self.path.exists())

    def test_live_lock_is_not_stolen(self):
        lock = self.path.with_name('mcp.json.falconpro.lock')
        lock.write_text('1234')
        with self.assertRaises(FileExistsError):
            configure(SERVER, **self.kw)
        self.assertEqual(lock.read_text(), '1234')


if __name__ == '__main__':
    unittest.main()
