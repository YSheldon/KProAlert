import unittest
from unittest.mock import Mock
from types import SimpleNamespace
import json
from pathlib import Path
from endpoint import classify, probe


DEVICE = 'a' * 64


def facts(**updates):
    value = dict(schema='FalconProEndpointFacts/v1', deviceId=DEVICE,
                 supported=True, service='absent', driver='absent',
                 conflicts=False, residualFiles=False)
    value.update(updates)
    return value


class EndpointTests(unittest.TestCase):
    def test_unbound_never_means_absent(self):
        result = classify(facts(), '')
        self.assertEqual(result['state'], 'target_unbound')
        self.assertFalse(result['installEligible'])

    def test_wrong_host_is_not_target(self):
        self.assertEqual(classify(facts(), 'b'*64)['state'], 'target_mismatch')

    def test_absence_requires_every_check(self):
        result = classify(facts(), DEVICE)
        self.assertEqual(result['state'], 'not_installed')
        self.assertTrue(result['installEligible'])
        self.assertFalse(result['automaticInstallAuthorized'])
        for change in ({'residualFiles': True}, {'conflicts': True},
                       {'service': 'unknown'}, {'driver': 'unknown'}):
            self.assertFalse(classify(facts(**change), DEVICE)['installEligible'])

    def test_running_does_not_prove_policy(self):
        result = classify(facts(service='running', driver='running'), DEVICE)
        self.assertEqual(result['state'], 'running_policy_unverified')
        self.assertFalse(result['protectionVerified'])

    def test_partial_and_stopped_never_reinstall(self):
        for service, driver in [('running','absent'), ('stopped','stopped')]:
            result = classify(facts(service=service, driver=driver), DEVICE)
            self.assertFalse(result['installEligible'])
            self.assertIn(result['state'], ('partial_install','installed_not_running'))

    def test_invalid_receipt_fails_closed(self):
        for change in ({'supported':1}, {'deviceId':'wrong'}, {'service':'Running'},
                       {'schema':'other'}, {'residualFiles':None}):
            self.assertEqual(classify(facts(**change), DEVICE)['state'], 'unknown')

    def test_unsupported_never_install(self):
        self.assertEqual(classify(facts(supported=False), DEVICE)['state'], 'unsupported')

    def test_cloud_does_not_launch_windows_command(self):
        runner=Mock()
        result=probe(DEVICE, platform='posix', runner=runner)
        self.assertEqual(result['state'], 'local_channel_required')
        runner.assert_not_called()

    def test_probe_timeout_and_bad_json(self):
        for runner in (Mock(side_effect=OSError('private details')),
                       Mock(return_value=SimpleNamespace(returncode=1,stdout='private details')),
                       Mock(return_value=SimpleNamespace(returncode=0,stdout='bad json'))):
            result=probe(DEVICE, platform='nt', runner=runner)
            self.assertEqual(result['state'], 'unknown')
            self.assertNotIn('private details', str(result))

    def test_probe_fixed_file_no_shell(self):
        runner=Mock(return_value=SimpleNamespace(returncode=0,stdout=json.dumps(facts())))
        self.assertTrue(probe(DEVICE, platform='nt', runner=runner)['installEligible'])
        args, kwargs=runner.call_args
        self.assertIn('-File', args[0])
        self.assertNotIn('-Command', args[0])
        self.assertFalse(kwargs.get('shell',False))
        self.assertLessEqual(kwargs['timeout'],30)

    def test_binding_configuration(self):
        from setup_config import build_config
        cfg=build_config(endpoint_device_id=DEVICE)
        self.assertEqual(cfg['mcpServers']['kpro-alerts']['env']['KPRO_ENDPOINT_DEVICE_ID'],DEVICE)
        with self.assertRaises(ValueError):
            build_config(endpoint_device_id='cloud')

    def test_registration_rejects_unrequested_sources(self):
        from assistant_setup import equivalent
        desired=dict(command='python',args=['server.py'],env={'KPRO_ENDPOINT_DEVICE_ID':DEVICE})
        actual={**desired,'env':{**desired['env'],'KPRO_ALERT_DATABASE':'unrequested.db'}}
        self.assertFalse(equivalent(actual,desired))
        self.assertTrue(equivalent(desired,desired))

    def test_install_wrapper_gate_order(self):
        root=Path(__file__).resolve().parents[3]
        source=(root/'Install-FalconPro.ps1').read_text()
        self.assertLess(source.index('Assert-TargetAbsent'),source.index('$installArgs ='))
        self.assertIn('$ApproveInstallation',source)
        self.assertIn('$PSCmdlet.ShouldProcess',source)
        self.assertNotIn('-ValidateCandidate',source)
        self.assertNotIn('ExecutionPolicy Bypass',source)
        self.assertIn('ExpectedDeviceId',source)
        self.assertLess(source.index('Assert-SourceFiles'),source.index('function Assert-TargetAbsent'))
        self.assertIn('SourceManifestSha256',source)
        self.assertIn('ComputeHash($manifestBytes)',source)
        self.assertIn('UTF8.GetString($manifestBytes)',source)
        self.assertNotIn('Get-Content -LiteralPath $manifestPath',source)

    def test_source_manifest_covers_all_helpers(self):
        from build_onboarding_manifest import build, NAMES
        import hashlib
        root=Path(__file__).resolve().parents[3]
        result=build(root)
        self.assertEqual(len(result['files']),4)
        self.assertEqual({entry['name'] for entry in result['files']},set(NAMES))
        for entry in result['files']:
            self.assertEqual(entry['sha256'],hashlib.sha256((root/entry['name']).read_bytes()).hexdigest())


if __name__=='__main__':
    unittest.main()
