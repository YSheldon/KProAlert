import tempfile
import unittest
import subprocess
import sys
import json
from pathlib import Path
from setup_config import build_config, save_config


class SetupTests(unittest.TestCase):
    def test_shared_entry_exports_cloud_reader_without_registering(self):
        with tempfile.TemporaryDirectory() as d:
            cli=Path(d)/'lark.exe';cli.touch()
            result=subprocess.run([sys.executable,str(Path(__file__).resolve().parents[3]/'falconpro.py'),
                'setup','--client','grok','--cli',str(cli),'--base','base123','--operations-table','tblOps'],
                capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            plan=json.loads(result.stdout)
            self.assertEqual(plan['server']['env']['KPRO_FEISHU_OPERATIONS_TABLE'],'tblOps')
            self.assertFalse(plan['installsDriver'])
            self.assertEqual(list(Path(d).iterdir()),[cli])

    def test_operations_cloud_source_requires_explicit_complete_binding(self):
        with tempfile.TemporaryDirectory() as d:
            cli=Path(d)/'lark.exe'
            cli.touch()
            config=build_config(cli=str(cli),base='base123',operations_table='tblOps')
            env=config['mcpServers']['kpro-alerts']['env']
            self.assertEqual(env['KPRO_FEISHU_OPERATIONS_TABLE'],'tblOps')
            self.assertNotIn('KPRO_FEISHU_TABLE',env)
            self.assertNotIn('KPRO_NATIVE_ENTRY',env)
            for kwargs in ({'operations_table':'tblOps'},
                           {'cli':str(cli),'operations_table':'tblOps'},
                           {'cli':str(cli),'base':'base123','operations_table':'bad table'}):
                with self.assertRaises(ValueError):build_config(**kwargs)

    def test_native_binding_requires_complete_local_sources_and_does_not_enable_execution(self):
        config=build_config(database='events.db',operations_database='ops.db',endpoint_device_id='a'*64,
            native_entry=r'C:\Program Files\FalconPro\FalconProSetup.exe',native_entry_sha256='b'*64)
        env=config['mcpServers']['kpro-alerts']['env']
        self.assertEqual(env['KPRO_NATIVE_ENTRY_SHA256'],'b'*64)
        self.assertNotIn('KPRO_AUTO_APPROVE',env)
        for kwargs in ({'native_entry':'x.exe'},{'native_entry_sha256':'b'*64},
                       {'native_entry':r'C:\FalconProSetup.exe','native_entry_sha256':'b'*64}):
            with self.assertRaises(ValueError):build_config(database='events.db',**kwargs)

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
