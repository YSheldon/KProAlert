import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from assistant_setup import make_plan, register, equivalent


class AssistantSetupTests(unittest.TestCase):
    def test_cursor_handoff_does_not_invoke_cli_or_write_settings(self):
        plan=make_plan('cursor',database='events.db')
        def forbidden(*args,**kwargs):
            self.fail('Cursor handoff must not invoke a fabricated CLI')
        result=register(plan,forbidden)
        self.assertEqual(result['registration'],'host_tool_required')
        self.assertEqual(result['configuration']['mcpServers']['kpro-alerts'],plan['server'])
        self.assertTrue(result['preserveExistingServers'])
        self.assertFalse(result['clientRuntimeVerified'])
        self.assertFalse(result['protectionInstalled'])

    def plan(self, root, client='codex'):
        cli = root/'client.exe'
        cli.touch()
        return make_plan(client, database=str(root/'events.db'), client_command=[str(cli)])

    def test_plan_has_no_protection_side_effect(self):
        with tempfile.TemporaryDirectory() as d:
            plan=self.plan(Path(d))
            self.assertFalse(plan['installsDriver'])
            self.assertFalse(plan['registersBackgroundTask'])
            self.assertTrue(Path(plan['server']['command']).is_absolute())

    def test_existing_foreign_connector_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            plan=self.plan(Path(d))
            calls=[]
            def runner(args, **kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=0,stdout='{"transport":{"command":"other","args":[],"env":{}}}')
            with self.assertRaises(RuntimeError): register(plan, runner)
            self.assertEqual(len(calls),1)

    def test_codex_create_and_readback(self):
        with tempfile.TemporaryDirectory() as d:
            plan=self.plan(Path(d))
            import json
            replies=[SimpleNamespace(returncode=1,stdout='',stderr="No MCP server named 'kpro-alerts' found."),
                     SimpleNamespace(returncode=0,stdout='Added'),
                     SimpleNamespace(returncode=0,stdout=json.dumps({'transport':plan['server']}))]
            calls=[]
            def runner(args, **kwargs): calls.append(args); return replies.pop(0)
            self.assertEqual(register(plan,runner)['registration'],'configured')
            self.assertIn('add',calls[1])
            self.assertFalse(replies)

    def test_arbitrary_get_failure_does_not_authorize_write(self):
        with tempfile.TemporaryDirectory() as d:
            plan=self.plan(Path(d))
            with self.assertRaises(RuntimeError):
                register(plan,lambda *a,**k: SimpleNamespace(returncode=1,stdout='',stderr='Permission denied'))

    def test_malformed_success_is_not_absence(self):
        with tempfile.TemporaryDirectory() as d:
            plan=self.plan(Path(d))
            calls=[]
            def runner(*args,**kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=0,stdout='{}')
            with self.assertRaises(RuntimeError):
                register(plan,runner)
            self.assertEqual(len(calls),1)

    def test_grok_requires_host_registration_tool(self):
        with tempfile.TemporaryDirectory() as d:
            plan=make_plan('grok',database=str(Path(d)/'events.db'))
            result=register(plan,lambda *a,**k: self.fail('Must not invent a Grok CLI'))
            self.assertEqual(result['registration'],'host_tool_required')
            self.assertEqual(result['hostTool'],'AddMcpServer')

    def test_existing_equivalent_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            plan=self.plan(Path(d))
            self.assertTrue(equivalent(plan['server'],plan['server']))


if __name__=='__main__': unittest.main()
