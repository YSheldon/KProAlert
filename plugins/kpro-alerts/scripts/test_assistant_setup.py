import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from assistant_setup import make_plan, register, migrate, equivalent


class AssistantSetupTests(unittest.TestCase):
    def test_native_binding_is_forwarded_without_approval_or_registration(self):
        with tempfile.TemporaryDirectory() as d:
            cli=Path(d)/'client.exe';cli.touch()
            for client in ('codex','cursor','grok','workbuddy'):
                plan=make_plan(client,database='events.db',operations_database='ops.db',
                    endpoint_device_id='a'*64,client_command=[str(cli)],
                    native_entry=r'C:\FalconProSetup.exe',native_entry_sha256='b'*64)
                self.assertEqual(plan['server']['env']['KPRO_NATIVE_ENTRY_SHA256'],'b'*64)
                self.assertEqual(plan['server']['env']['KPRO_ASSISTANT_CLIENT'],client)
                self.assertFalse(plan['automaticRemediation'])
                self.assertFalse(plan['installsDriver'])
            self.assertEqual(list(Path(d).iterdir()),[cli])

    def test_first_setup_needs_no_database_or_cloud_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            cli=Path(d)/'client.exe';cli.touch()
            for client in ('codex','cursor','grok','workbuddy'):
                plan=make_plan(client,client_command=[str(cli)])
                self.assertTrue(plan['onboardingOnly'])
                self.assertFalse(plan['dataSourcesConfigured'])
                self.assertEqual(plan['server']['env'],{})
                self.assertFalse(plan['installsDriver'])
                self.assertFalse(plan['registersBackgroundTask'])
            self.assertEqual(list(Path(d).iterdir()),[cli])

    def test_onboarding_cannot_reset_existing_sources(self):
        with tempfile.TemporaryDirectory() as d:
            cli=Path(d)/'client.exe';cli.touch()
            plan=make_plan('codex',client_command=[str(cli)])
            import json
            existing={**plan['server'],'env':{'KPRO_ALERT_DATABASE':'existing.db'}}
            calls=[]
            def runner(*args,**kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=0,stdout=json.dumps({'transport':existing}))
            with self.assertRaises(RuntimeError):register(plan,runner)
            self.assertEqual(len(calls),1)

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

    def test_migration_preserves_existing_environment_and_reads_back(self):
        with tempfile.TemporaryDirectory() as d:
            plan=self.plan(Path(d))
            old=dict(command='old-python',args=['old-server.py'],env={'KPRO_FEISHU_BASE':'base','KPRO_FEISHU_TABLE':'table'})
            expected={**plan['server'], 'env': old['env']}
            replies=[
                SimpleNamespace(returncode=0,stdout=__import__('json').dumps({'transport':old}),stderr=''),
                SimpleNamespace(returncode=0,stdout='removed',stderr=''),
                SimpleNamespace(returncode=0,stdout='added',stderr=''),
                SimpleNamespace(returncode=0,stdout=__import__('json').dumps({'transport':expected}),stderr=''),
            ]
            calls=[]
            def runner(args, **kwargs):
                calls.append(args); return replies.pop(0)
            result=migrate(plan,runner)
            self.assertEqual(result['registration'],'migrated')
            self.assertTrue(result['preservedExistingEnvironment'])
            self.assertIn('remove',calls[1])
            self.assertIn('add',calls[2])
            self.assertFalse(replies)

    def test_migration_refuses_disabled_or_readback_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            plan=self.plan(Path(d))
            disabled=SimpleNamespace(returncode=0,stdout='{"enabled":false,"transport":{}}',stderr='')
            with self.assertRaises(RuntimeError):
                migrate(plan,lambda *a,**k: disabled)
            old=dict(command='old',args=[],env={})
            replies=[SimpleNamespace(returncode=0,stdout=__import__('json').dumps({'transport':old}),stderr=''),
                     SimpleNamespace(returncode=0,stdout='',stderr=''),
                     SimpleNamespace(returncode=0,stdout='',stderr=''),
                     SimpleNamespace(returncode=0,stdout=__import__('json').dumps({'transport':old}),stderr='')]
            with self.assertRaises(RuntimeError):
                migrate(plan,lambda *a,**k: replies.pop(0))

    def test_workbuddy_file_migration_preserves_type_and_environment(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            cli=root/'client.exe';cli.touch()
            config=root/'mcp.json'
            config.write_text(__import__('json').dumps({'mcpServers': {'kpro-alerts': {
                'type':'stdio','command':'old-python','args':['old.py'],
                'env':{'KPRO_ALERT_DATABASE':'old.db'},'disabled':False}}}))
            plan=make_plan('workbuddy',client_command=[str(cli)],workbuddy_config=str(root))
            result=migrate(plan)
            observed=__import__('json').loads(config.read_text())['mcpServers']['kpro-alerts']
            self.assertEqual(result['registration'],'migrated')
            self.assertEqual(observed['type'],'stdio')
            self.assertEqual(observed['env'],{'KPRO_ALERT_DATABASE':'old.db'})
            self.assertTrue(list(root.glob('mcp.json.falconpro-*.bak')))


if __name__=='__main__': unittest.main()
