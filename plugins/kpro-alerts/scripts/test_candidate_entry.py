import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import os
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('candidate_builder', ROOT / 'tools/build_candidate_permit.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class CandidateEntryTests(unittest.TestCase):
    def fixture(self, root):
        for name in (*builder.NAMES, 'Invoke-FalconProCandidateValidation.ps1'):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'unit fixture, not signed or executable')
        package = root / 'package'
        package.mkdir()
        files = []
        for name in ('KProSvc.exe','KProProtect.dll','KProFilter.sys','DrvCfg2.dat','default-policy.hex'):
            (package/name).write_bytes(b'fixture')
            files.append(dict(name=name, sha256=builder.digest(b'fixture'), size=7))
        manifest = dict(schema='KProAlertRelease/v1', platform='windows11-x64', architecture='x64',
                        releaseStatus='candidate', files=files,
                        gates=dict(serviceF1ArtifactProduct=True,driverMicrosoftProduct=True,dllProduct=True,
                                   policySignature=True,endToEnd=False,privateRawEventSpool=True))
        (package/'release-manifest.json').write_text(json.dumps(manifest))
        (package/'release-attestation.ps1').write_bytes(b'fixture attestation; signing enforced only by native admission')
        return package, manifest

    def test_binds_all_files_and_source_without_promoting(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);package,_=self.fixture(root)
            source, raw=builder.build(root,[package],'a'*64,'b'*32,'x64','install')
            permit=json.loads(base64.b64decode(raw.decode().split('FALCONPRO-CANDIDATE-JSON: ')[1]))
            self.assertEqual(permit['sourceManifestSha256'],builder.digest(source))
            self.assertEqual(len(permit['packages'][0]['files']),5)
            self.assertEqual(len(json.loads(source)['files']),8)
            self.assertNotIn('verified',raw.decode())

    def test_rejects_tamper_and_missing_old_upgrade(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);package,_=self.fixture(root)
            with self.assertRaises(ValueError):builder.build(root,[package],'a'*64,'b'*32,'x64','upgrade')
            (package/'DrvCfg2.dat').write_bytes(b'changed')
            with self.assertRaises(ValueError):builder.build(root,[package],'a'*64,'b'*32,'x64','install')

    def test_certificate_only_target_binds_eight_files_and_base_previous(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);target,manifest=self.fixture(root)
            extras=('FalconPplBootstrap.exe','FalconElamControl.dll','FalconElam.sys')
            for name in extras:
                (target/name).write_bytes(b'fixture')
                manifest['files'].append(dict(name=name,sha256=builder.digest(b'fixture'),size=7))
            manifest['serviceProtection']='certificate-only'
            (target/'release-manifest.json').write_text(json.dumps(manifest))
            previous=root/'previous';previous.mkdir()
            files=[]
            for name in ('KProSvc.exe','KProProtect.dll','KProFilter.sys','DrvCfg2.dat','default-policy.hex'):
                (previous/name).write_bytes(b'fixture')
                files.append(dict(name=name,sha256=builder.digest(b'fixture'),size=7))
            old=dict(schema='KProAlertRelease/v1',platform='windows11-x64',architecture='x64',releaseStatus='verified',
                     files=files,gates=dict(serviceF1ArtifactProduct=True,driverMicrosoftProduct=True,dllProduct=True,
                     policySignature=True,endToEnd=True,privateRawEventSpool=True))
            (previous/'release-manifest.json').write_text(json.dumps(old))
            (previous/'release-attestation.ps1').write_bytes(b'previous attestation')
            source,raw=builder.build(root,[target,previous],'a'*64,'b'*32,'x64','upgrade')
            permit=json.loads(base64.b64decode(raw.decode().split('FALCONPRO-CANDIDATE-JSON: ')[1]))
            self.assertEqual(len(permit['packages']),2)
            self.assertEqual(len(permit['packages'][0]['files']),8)
            self.assertEqual(len(permit['packages'][1]['files']),5)
            (target/'FalconElam.sys').unlink()
            with self.assertRaises(ValueError):builder.build(root,[target,previous],'a'*64,'b'*32,'x64','upgrade')

    def test_no_unsigned_policy_gate_exception(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);package,manifest=self.fixture(root)
            manifest['gates']['policySignature']=False
            (package/'release-manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):builder.build(root,[package],'a'*64,'b'*32,'x64','install')

    def test_missing_attestation_is_a_candidate_error(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);package,_=self.fixture(root)
            (package/'release-attestation.ps1').unlink()
            with self.assertRaisesRegex(ValueError, 'Candidate attestation missing'):
                builder.build(root,[package],'a'*64,'b'*32,'x64','install')

    def test_native_entry_explicit_and_results_separate(self):
        entry=(ROOT/'Invoke-FalconProCandidateValidation.ps1').read_text()
        self.assertIn('if(-not $ApproveCandidateValidation)',entry)
        self.assertLess(entry.index('Get-KProCandidatePermit $'),entry.index("& (Join-Path $PSScriptRoot 'Invoke-FalconProLifecycle.ps1')"))
        lifecycle=(ROOT/'Invoke-FalconProLifecycle.ps1').read_text()
        for token in ('FalconProCandidateLifecycleResult/v1','validation_complete','candidatePermitSha256',
                      'Assert-KProCandidatePackage','@candidateInstallArgs'):
            self.assertIn(token,lifecycle)
        public=(ROOT/'Install-FalconPro.ps1').read_text()
        self.assertNotIn('CandidatePermitPath',public)
        self.assertIn('$plan.candidateValidation -ne $false',public)

    def test_trusted_launcher_verifies_before_executing_candidate(self):
        import candidate_validation
        code=candidate_validation.VERIFIER
        self.assertLess(code.index('Get-KProCandidatePermit '),code.index('& (Join-Path $a.SourceRoot'))
        self.assertIn('[IO.File]::Open',code)
        self.assertIn('FileShare',code)
        self.assertNotIn('Bypass',code)

    def test_mixed_plan_and_result_identities_rejected(self):
        from candidate_validation import validate_result
        options=dict(Apply=False, Mode='install')
        plan=dict(mode='candidate-validation-plan',validationOnly=True,operation='install')
        self.assertEqual(validate_result(plan,options),plan)
        for bad in (dict(plan,schema='wrong'),dict(plan,schema='FalconProCandidateLifecycleResult/v1'),
                    dict(schema='FalconProCandidateLifecycleResult/v1',mode='wrong',validationOnly=True)):
            with self.assertRaises(ValueError):validate_result(bad,options)
        with self.assertRaises(ValueError):validate_result(plan,dict(options,Apply=True))

    @unittest.skipUnless(os.name=='nt', 'Windows candidate pre-execution signature gate')
    def test_unsigned_candidate_never_executes_its_first_line(self):
        import candidate_validation
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            marker=root/'must-not-exist.txt'
            entry=root/'Invoke-FalconProCandidateValidation.ps1'
            entry.write_text("[IO.File]::WriteAllText('"+str(marker).replace("'","''")+"','executed')")
            permit=root/'candidate-permit.ps1'
            permit.write_bytes(b'# FALCONPRO-CANDIDATE-JSON: e30=')
            options=dict(SourceRoot=str(root),CandidatePermitPath=str(permit),CandidatePermitSha256=builder.digest(permit.read_bytes()),
                         ExpectedDeviceId='a'*64,TransactionId='b'*32,ExpectedArchitecture='x64',SourceManifestSha256='c'*64,
                         ManifestSha256='d'*64,Mode='install',PackageRoot=str(root),DeliveryUserSid='S-1-5-21-1-2-3-1001',Apply=False)
            original=candidate_validation.subprocess.run
            results=[]
            def observe(*args,**kwargs):
                result=original(*args,**kwargs);results.append(result);return result
            with patch.object(candidate_validation.subprocess,'run',side_effect=observe):
                with self.assertRaises(ValueError):candidate_validation.run(options,approval=True)
            self.assertEqual(len(results),1)
            self.assertIn(b'A valid Authenticode signature',results[0].stderr)
            self.assertFalse(marker.exists())


if __name__=='__main__':unittest.main()
