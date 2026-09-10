import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from lifecycle import plan, apply, validate_sources, SOURCES
from install_metrics import make_event, summarize
from test_release_download import descriptor


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.release=self.root/'release'
        self.device='d'*64

    def download(self, destination, verify):
        root=Path(destination)
        (root/'package').mkdir(parents=True)
        (root/'onboarding').mkdir()
        names=('KProSvc.exe','KProProtect.dll','KProFilter.sys','DrvCfg2.dat','default-policy.hex')
        files=[]
        for name in names:
            data=('fixture-'+name).encode()
            (root/'package'/name).write_bytes(data)
            files.append(dict(name=name,size=len(data),sha256=hashlib.sha256(data).hexdigest()))
        from release_manifest import GATES
        self.manifest=dict(schema='KProAlertRelease/v1',releaseStatus='verified',platform='windows11-x64',
                           architecture='x64',version='1.2.0.300',files=files,gates={key:True for key in GATES})
        encoded=json.dumps(self.manifest).encode()
        (root/'package/release-manifest.json').write_bytes(encoded)
        entries=[]
        for name in SOURCES:
            path=root/'onboarding'/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(b'test-only source')
            entries.append(dict(name=name,sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        source=json.dumps(dict(schema='FalconProOnboardingSource/v2',files=entries)).encode()
        (root/'onboarding/onboarding-source.json').write_bytes(source)
        (root/'FalconPro-release.ps1').write_bytes(b'test-only descriptor')
        self.descriptor=descriptor()
        self.descriptor.update(packageManifestSha256=hashlib.sha256(encoded).hexdigest(),
                               sourceManifestSha256=hashlib.sha256(source).hexdigest())
        return self.descriptor

    def plan(self, operation='install'):
        state='not_installed' if operation=='install' else 'running_policy_unverified'
        return plan(operation,self.release,self.device,endpoint_probe=lambda _:dict(state=state),
                    download=self.download,sid_reader=lambda:'S-1-5-21-1-2-3-1001')

    def invoke(self, value, **kwargs):
        options=dict(approval=True,platform='nt',verifier=lambda _:self.descriptor,
                     endpoint_probe=lambda _:dict(state='not_installed'),executor=Mock(return_value=dict(state='complete')))
        options.update(kwargs)
        return apply(value,**options)

    def test_cloud_unbound_and_partial_do_not_download(self):
        for state in ('local_channel_required','target_unbound','target_mismatch','partial_install','unknown'):
            download=Mock()
            result=plan('install',self.release,self.device,endpoint_probe=lambda _:dict(state=state),download=download)
            self.assertEqual(result['state'],state)
            download.assert_not_called()

    def test_no_consent_and_cloud_never_invoke_native(self):
        value=self.plan()
        runner=Mock()
        for options in (dict(approval=False),dict(platform='posix')):
            with self.assertRaises(ValueError):self.invoke(value,executor=runner,**options)
        runner.assert_not_called()

    def test_modified_sources_or_policy_block_before_native(self):
        value=self.plan()
        native=Mock()
        path=self.release/'package/default-policy.hex'
        original=path.read_bytes()
        path.write_bytes(b'new unsigned policy')
        with self.assertRaises(ValueError):self.invoke(value,executor=native)
        path.write_bytes(original)
        (self.release/'onboarding/Install-KProAlert.ps1').write_bytes(b'changed')
        with self.assertRaises(ValueError):self.invoke(value,executor=native)
        native.assert_not_called()

    def test_signature_and_stable_gate_fail_before_native(self):
        value=self.plan()
        native=Mock()
        with self.assertRaises(ValueError):self.invoke(value,executor=native,verifier=Mock(side_effect=ValueError('untrusted')))
        bad={**self.descriptor,'releaseStatus':'candidate'}
        with self.assertRaises(ValueError):self.invoke(value,executor=native,verifier=lambda _:bad)
        native.assert_not_called()

    def test_reboot_pending_is_not_counted_success(self):
        value=self.plan()
        metrics=Mock()
        self.invoke(value,executor=Mock(return_value=dict(state='awaiting_reboot')),metrics=metrics)
        self.assertEqual([call.kwargs['kind'] for call in metrics.record.call_args_list],['install_started'])

    def test_resume_only_counts_verified_completion(self):
        value=self.plan('upgrade')
        metrics=Mock()
        self.invoke(value,mode='resume',endpoint_probe=lambda _:dict(state='running_policy_unverified'),metrics=metrics)
        self.assertEqual([call.kwargs['kind'] for call in metrics.record.call_args_list],['upgrade_success'])

    def test_native_timeout_does_not_invent_failure_or_replay(self):
        import subprocess
        value=self.plan()
        native=Mock(side_effect=subprocess.TimeoutExpired('native',600))
        metrics=Mock()
        result=self.invoke(value,executor=native,metrics=metrics)
        self.assertTrue(result['outcomeUncertain'])
        self.assertFalse(result['automaticRetry'])
        self.assertEqual(native.call_count,1)
        self.assertEqual(metrics.record.call_count,1)

    def test_upgrades_do_not_inflate_installations(self):
        def event(kind,identity):
            return make_event(consent=True,installation_id='a'*32,event_id=identity*32,day=100,
                              kind=kind,version='1.2.0.300',architecture='x64',os_family='windows11')
        result=summarize([event('install_success','b'),event('upgrade_started','c'),event('upgrade_success','d')],today=100)
        self.assertEqual(result['successfulInstallations'],1)
        self.assertEqual(result['reportedUpgradeSuccesses'],1)
        self.assertEqual(result['activeInstallations7d'],1)


if __name__=='__main__':unittest.main()
