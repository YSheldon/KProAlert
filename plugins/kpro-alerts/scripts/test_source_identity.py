"""Exercise the actual source-hash expression without starting an MCP server."""
import ast
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch


class SourceIdentityTests(unittest.TestCase):
    def fingerprint(self, changed=None):
        source = Path(__file__).with_name('mcp_server.py')
        tree = ast.parse(source.read_text(encoding='utf-8'))
        expressions = [node for node in tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == '_source_hash'
                               for target in node.targets)]
        self.assertTrue(expressions)
        program = compile(ast.Module(body=expressions, type_ignores=[]), str(source), 'exec')
        original = Path.read_bytes

        def capture(path):
            data = original(path)
            return data + b'\n# changed test candidate\n' if path.name == changed else data

        namespace = dict(Path=Path, hashlib=hashlib, __file__=str(source))
        with patch.object(Path, 'read_bytes', capture):
            exec(program, namespace)
        return namespace['_source_hash']

    def test_replica_validator_and_store_changes_alter_running_code_identity(self):
        baseline = self.fingerprint()
        for name in ('safe_replica.py', 'kpro_alert_bridge.py'):
            with self.subTest(dependency=name):
                self.assertNotEqual(self.fingerprint(name), baseline)


if __name__ == '__main__':
    unittest.main()
