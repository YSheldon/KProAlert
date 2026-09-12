"""No desktop interaction: native UAC outcomes are supplied by a bounded fake."""
import contextlib
import ctypes
import os
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

from elevation import run_elevated, _ShellExecuteInfo, _WindowsShell


class FakeShell:
    def __init__(self, *, success=True, handle=17, error=0, wait=0, code=0):
        self.launch = Mock(return_value=(success, handle, error))
        self.wait = Mock(return_value=wait)
        self.exit_code = Mock(return_value=code)
        self.close = Mock()
        self.finish = Mock()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.finish()


class ElevationTests(unittest.TestCase):
    def run_case(self, api):
        return run_elevated(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                            ['-NoProfile', '-File', r'C:\Program Files\FalconPro\entry.ps1'], api=api)

    def test_cancel_is_not_unknown_or_a_started_child(self):
        api = FakeShell(success=False, handle=None, error=1223)
        self.assertEqual(self.run_case(api), {'cancelled': True, 'started': False, 'exitCode': None})
        api.wait.assert_not_called()
        api.close.assert_not_called()
        api.finish.assert_called_once()

    def test_access_denied_is_not_cancel(self):
        api = FakeShell(success=False, handle=None, error=5)
        with self.assertRaises(OSError):
            self.run_case(api)
        api.wait.assert_not_called()
        api.finish.assert_called_once()

    def test_cancel_with_a_process_handle_is_not_a_safe_noop(self):
        api = FakeShell(success=False, error=1223)
        with self.assertRaises(OSError):
            self.run_case(api)
        api.close.assert_called_once_with(17)

    def test_child_exit_1223_is_not_uac_cancel(self):
        result = self.run_case(FakeShell(code=1223))
        self.assertFalse(result['cancelled'])
        self.assertTrue(result['started'])
        self.assertEqual(result['exitCode'], 1223)

    def test_native_abi_size(self):
        self.assertEqual(ctypes.sizeof(_ShellExecuteInfo), 112 if ctypes.sizeof(ctypes.c_void_p) == 8 else 60)

    @unittest.skipUnless(os.name == 'nt', 'Loads Windows system DLLs; never launches a process')
    def test_native_flags_and_raw_cancellation_error(self):
        api = _WindowsShell()
        def cancelled(pointer):
            info = pointer._obj
            self.assertEqual(info.cbSize, ctypes.sizeof(_ShellExecuteInfo))
            self.assertEqual(info.fMask, 0x140)
            self.assertEqual(info.lpVerb, 'runas')
            self.assertEqual(info.lpParameters, '-NoProfile')
            ctypes.set_last_error(1223)
            return 0
        api.shell = type('ShellStub', (), {'ShellExecuteExW': staticmethod(cancelled)})()
        self.assertEqual(api.launch(r'C:\Windows\powershell.exe', '-NoProfile'), (False, None, 1223))

    @unittest.skipUnless(os.name == 'nt', 'Loads Windows system DLLs; never launches a process')
    def test_com_reference_is_balanced_only_when_owned(self):
        api = _WindowsShell()
        for hr in (0, 1, -2147417850):
            api.ole = Mock()
            api.ole.CoInitializeEx.return_value = hr
            if hr < 0:
                with self.assertRaises(OSError):
                    with api:
                        self.fail('Incompatible COM apartment accepted')
                api.ole.CoUninitialize.assert_not_called()
            else:
                with api:
                    pass
                api.ole.CoUninitialize.assert_called_once()

    def test_completion_quotes_the_script_and_closes_handle(self):
        api = FakeShell()
        self.assertEqual(self.run_case(api), {'cancelled': False, 'started': True, 'exitCode': 0})
        self.assertIn('"C:\\Program Files\\FalconPro\\entry.ps1"', api.launch.call_args.args[1])
        api.wait.assert_called_once_with(17, 600000)
        api.close.assert_called_once_with(17)
        api.finish.assert_called_once()

    def test_timeout_is_unknown_not_cancelled_and_never_terminates_child(self):
        api = FakeShell(wait=258)
        self.assertEqual(self.run_case(api), {'cancelled': False, 'started': True, 'exitCode': None})
        api.exit_code.assert_not_called()
        api.close.assert_called_once_with(17)

    def test_missing_process_handle_is_unknown(self):
        api = FakeShell(handle=None)
        self.assertIsNone(self.run_case(api)['exitCode'])
        api.wait.assert_not_called()

    def test_wait_and_exit_query_errors_close_handle(self):
        for method in ('wait', 'exit_code'):
            api = FakeShell()
            getattr(api, method).side_effect = OSError('native error')
            with self.assertRaises(OSError):
                self.run_case(api)
            api.close.assert_called_once_with(17)
            api.finish.assert_called_once()

    def test_unexpected_wait_result_is_not_success(self):
        api = FakeShell(wait=0xffffffff)
        with self.assertRaises(OSError):
            self.run_case(api)
        api.close.assert_called_once_with(17)

    def test_invalid_arguments_never_launch(self):
        for executable, arguments in [('powershell.exe', []), ('C:\\a.exe', ['x\0y'])]:
            api = FakeShell()
            with self.assertRaises(ValueError):
                run_elevated(executable, arguments, api=api)
            api.launch.assert_not_called()

    def test_lifecycle_cancel_does_not_read_registry_or_old_receipt(self):
        from lifecycle import native_execute
        value = dict(releaseRoot=str(Path('release').absolute()), deviceId='d'*64, transactionId='a'*32,
                     manifestSha256='b'*64, sourceManifestSha256='c'*64,
                     deliveryUserSid='S-1-5-21-1-2-3-1001', architecture='x64')
        outcome = {'cancelled': True, 'started': False, 'exitCode': None}
        with patch('lifecycle.native_tool', return_value='C:\\Windows\\powershell.exe'), \
             patch('lifecycle.lock_entry', return_value=contextlib.nullcontext()), \
             patch('lifecycle.verify_entry') as verify, patch('lifecycle.run_elevated', return_value=outcome), \
             patch('lifecycle.read_json') as read:
            result = native_execute(value, 'install')
        verify.assert_called_once()
        read.assert_not_called()
        self.assertEqual(result['state'], 'elevation_cancelled')
        self.assertFalse(result['operationStarted'])
        self.assertFalse(result['outcomeUncertain'])
        self.assertFalse(result['automaticRetry'])


if __name__ == '__main__':
    unittest.main()
