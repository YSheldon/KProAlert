import json
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import contextmanager
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch
import native_receipt_reader as native


class NativeReceiptReaderTests(unittest.TestCase):
    def test_invalid_identifiers_and_paths_are_rejected_before_execution(self):
        for path,sha,device,tx in [
            ('C:\\x\\FalconProSetup.exe','bad','a'*64,'b'*32),
            ('C:\\x\\FalconProSetup.exe','c'*64,'bad','b'*32),
            ('C:\\x\\FalconProSetup.exe','c'*64,'a'*64,'../tx'),
            ('\\\\host\\share\\FalconProSetup.exe','c'*64,'a'*64,'b'*32),
            ('C:\\x\\other.exe','c'*64,'a'*64,'b'*32),
        ]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                native.read_receipt(path,sha,device,tx,runner=lambda *a,**k:self.fail('must not execute'))

    def test_native_output_is_required(self):
        with patch.object(native,'_locked_entry'),patch.object(native,'_verify_publisher'),self.assertRaises(ValueError):
            native.read_receipt('C:\\x\\FalconProSetup.exe','c'*64,'a'*64,'b'*32,
                                runner=lambda *a,**k:CompletedProcess([],0,b'{}',b''))

    def test_transport_exceptions_do_not_expose_local_binding(self):
        private_args=['C:\\private\\FalconProSetup.exe','receipt','--device','a'*64,'--transaction','b'*32]
        for error in [TimeoutExpired(private_args,60),
                      OSError(5,'denied','C:\\private\\FalconProSetup.exe')]:
            with self.subTest(error=type(error).__name__), \
                 patch.object(native,'_locked_entry'),patch.object(native,'_verify_publisher'), \
                 self.assertRaises(ValueError) as caught:
                def fail(*args,**kwargs):
                    raise error
                native.read_receipt(private_args[0],'c'*64,'a'*64,'b'*32,runner=fail)
            self.assertEqual(str(caught.exception),'Native receipt transport failed')
        with patch.object(native,'_locked_entry',side_effect=OSError('C:\\private\\entry')), \
             self.assertRaisesRegex(ValueError,'^Native receipt transport failed$'):
            native.read_receipt(private_args[0],'c'*64,'a'*64,'b'*32)

    def test_publisher_launch_failure_is_sanitized(self):
        with patch.object(native,'_locked_entry'), \
             patch.object(native,'_verify_publisher',side_effect=TimeoutExpired('private-command',60)), \
             self.assertRaisesRegex(ValueError,'^Native receipt transport failed$'):
            native.read_receipt('C:\\private\\FalconProSetup.exe','c'*64,'a'*64,'b'*32)

    def test_verified_fixed_readonly_invocation_stays_pinned(self):
        events=[]
        @contextmanager
        def guard(*args):
            events.append('pin')
            yield
            events.append('unpin')
        def run(args,**kwargs):
            events.append('run')
            self.assertEqual(args[1:],['receipt','--device','a'*64,'--transaction','b'*32])
            self.assertEqual(kwargs['timeout'],60)
            value=dict(schema='FalconProNativeObservation/v1',observationId='d'*64,
                operation='upgrade',phase='complete',version='0.3.0.2',architecture='x64',
                osFamily='windows11',day=100,testOnly=True,protectionVerified=False)
            return CompletedProcess(args,0,json.dumps(value).encode(),b'')
        with patch.object(native,'_locked_entry',guard),patch.object(native,'_verify_publisher',lambda p:events.append('verify')):
            result=native.read_receipt('C:\\x\\FalconProSetup.exe','c'*64,'a'*64,'b'*32,runner=run)
        self.assertEqual(events,['pin','verify','run','unpin'])
        self.assertEqual(result['schema'],'FalconProNativeObservation/v1')

    def test_duplicate_oversized_and_failed_results_are_rejected(self):
        for code,data in [(0,b'{"schema":"a","schema":"FalconProNativeObservation/v1"}'),
                          (0,b' '*8193),(2,b'{}')]:
            with patch.object(native,'_locked_entry'),patch.object(native,'_verify_publisher'),self.assertRaises(ValueError):
                native.read_receipt('C:\\x\\FalconProSetup.exe','c'*64,'a'*64,'b'*32,
                    runner=lambda *a,**k:CompletedProcess([],code,data,b''))

    @unittest.skipUnless(os.name=='nt','Windows file sharing contract')
    def test_actual_file_guard_blocks_writer_and_rejects_drift(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'FalconProSetup.exe'
            path.write_bytes(b'bounded fixture')
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            with native._locked_entry(str(path),digest):
                with self.assertRaises(OSError):
                    with path.open('wb') as stream:
                        stream.write(b'changed')
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                with native._locked_entry(str(path),digest):
                    self.fail('drift accepted')

    def test_error_projection_does_not_include_private_payload(self):
        for error in ['receipt_not_complete','C:\\private\\customer.json']:
            with patch.object(native,'_locked_entry'),patch.object(native,'_verify_publisher'):
                with self.assertRaises(ValueError) as caught:
                    native.read_receipt('C:\\x\\FalconProSetup.exe','c'*64,'a'*64,'b'*32,
                        runner=lambda *a,**k:CompletedProcess([],2,json.dumps({'error':error}).encode(),b''))
                self.assertNotIn('private',str(caught.exception))

    def test_publisher_probe_uses_child_system_module_path(self):
        with patch.object(native,'native_tool',return_value='powershell.exe'),patch.object(native,'_locked_entry'), \
             patch.object(native.subprocess,'run',return_value=CompletedProcess([],0,b'verified',b'')) as run:
            native._verify_publisher('C:\\x\\FalconProSetup.exe')
        command=run.call_args.args[0][-1]
        self.assertIn("$env:PSModulePath=Join-Path $PSHOME 'Modules'",command)
        self.assertLess(command.index('$env:PSModulePath'),command.index('Import-Module'))
        self.assertNotIn('Bypass',run.call_args.args[0])

    def test_publisher_module_is_hash_pinned_during_import(self):
        events=[]
        @contextmanager
        def guard(path,digest):
            self.assertEqual(Path(path).name,'KProReleaseTrust.psm1')
            self.assertEqual(digest,'e425929f633ce478e9459a794abdcae4098dc200cda8c1d1d872a45feb05a27a')
            events.append('pin')
            yield
            events.append('unpin')
        def run(*args,**kwargs):
            events.append('import')
            return CompletedProcess([],0,b'verified',b'')
        with patch.object(native,'_locked_entry',guard),patch.object(native.subprocess,'run',side_effect=run), \
             patch.object(native,'native_tool',return_value='powershell.exe'):
            native._verify_publisher('C:\\x\\FalconProSetup.exe')
        self.assertEqual(events,['pin','import','unpin'])
        with patch.object(native,'_locked_entry',side_effect=ValueError('module hash mismatch')), \
             patch.object(native.subprocess,'run') as process,self.assertRaises(ValueError):
            native._verify_publisher('C:\\x\\FalconProSetup.exe')
        process.assert_not_called()

    def test_actual_channel_is_rejected_outside_windows(self):
        with patch.object(native.os,'name','posix'), \
             self.assertRaisesRegex(ValueError,'Authorized local Windows channel required'):
            with native._locked_entry('C:\\x\\FalconProSetup.exe','a'*64):
                self.fail('Non-Windows channel accepted')


if __name__=='__main__':
    unittest.main()
