import base64
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from native_upgrade import query_snapshot, _query_snapshot_impl


class NativeSnapshotTests(unittest.TestCase):
    def invoke(self, **changes):
        with tempfile.TemporaryDirectory() as folder:
            helper=Path(folder)/'Invoke-PolicySnapshot.ps1'
            helper.write_bytes(b'test fixture, never executed')
            body={'schema':'FalconProNativeSnapshot/v1','servicePid':42,
                  'manifestSha256':'c'*64,'exitCode':0,
                  'stdoutBase64':base64.b64encode(b'captured service output').decode()}
            runner=Mock(return_value=SimpleNamespace(returncode=0,stdout=json.dumps(body).encode(),stderr=b''))
            parser=Mock(return_value={'digestSha256':'d'*64})
            args=dict(device_id='a'*64,transaction_id='b'*64,manifest_sha256='c'*64,
                      helper_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(),platform='nt',
                      helper_path=helper,runner=runner,parser=parser,
                      endpoint_probe=lambda _: {'state':'running_policy_unverified'},
                      resolver=lambda _: 'trusted-powershell.exe')
            args.update(changes)
            result=_query_snapshot_impl(**args)
            return result,runner,parser

    def test_capture_calls_only_snapshot(self):
        result,runner,parser=self.invoke()
        self.assertEqual(result['digestSha256'],'d'*64)
        self.assertIn('-TransactionId',runner.call_args.args[0])
        self.assertNotIn('-Apply',runner.call_args.args[0])
        self.assertEqual(parser.call_args.args[0],b'captured service output')
        self.assertEqual(parser.call_args.kwargs['service_pid'],42)

    def test_rejects_cloud_and_unbound_target(self):
        for change in ({'platform':'posix'}, {'device_id':''},
                       {'endpoint_probe':lambda _: {'state':'target_mismatch'}}):
            with self.assertRaises(ValueError):self.invoke(**change)

    def test_helper_tamper_denied(self):
        with self.assertRaises(ValueError):self.invoke(helper_sha256='0'*64)

    def test_failed_native_process_denied(self):
        bad=Mock(return_value=SimpleNamespace(returncode=1,stdout=b'{}',stderr=b'sensitive error'))
        with self.assertRaises(ValueError):self.invoke(runner=bad)

    def test_no_duplicate_native_fields(self):
        bad=Mock(return_value=SimpleNamespace(returncode=0,
            stdout=b'{"schema":"bad","schema":"FalconProNativeSnapshot/v1"}',stderr=b''))
        with self.assertRaises(ValueError):self.invoke(runner=bad)

    def test_restore_passes_expected_digest(self):
        _,runner,parser=self.invoke(expected_digest='e'*64)
        self.assertIn('-ExpectedDigest',runner.call_args.args[0])
        self.assertEqual(parser.call_args.kwargs['expected_digest'],'e'*64)

    def test_helper_is_read_only_and_dependency_bound(self):
        root=Path(__file__).resolve().parents[3]
        script=Path(__file__).with_name('Invoke-PolicySnapshot.ps1').read_text()
        digest=hashlib.sha256((root/'tools/KProReleaseTrust.psm1').read_bytes()).hexdigest()
        self.assertIn(digest,script)
        for forbidden in ('--uninstall','SetPolicy','New-Service','Stop-Service','-ExecutionPolicy Bypass'):
            self.assertNotIn(forbidden,script)
        for gate in ('Assert-ProtectedPath','FileShare]::Read','Get-AuthenticodeSignature','endToEnd',
                     'DiscretionaryAclPresent','AreAccessRulesProtected','protectedAnchor','NativeProgramFiles',
                     'Assert-ProgramFilesAcl'):
            self.assertIn(gate,script)

    def test_production_api_has_no_dependency_overrides(self):
        import inspect
        self.assertEqual(set(inspect.signature(query_snapshot).parameters),
                         {'device_id','transaction_id','manifest_sha256','helper_sha256','expected_digest'})

if __name__=='__main__':unittest.main()
