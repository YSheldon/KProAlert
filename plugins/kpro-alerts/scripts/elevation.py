"""Native UAC launch with an explicit, non-retriable user-cancel outcome."""
import ctypes
import ntpath
import os
import subprocess


class _ShellExecuteInfo(ctypes.Structure):
    _fields_ = [('cbSize', ctypes.c_uint32), ('fMask', ctypes.c_uint32),
                ('hwnd', ctypes.c_void_p), ('lpVerb', ctypes.c_wchar_p),
                ('lpFile', ctypes.c_wchar_p), ('lpParameters', ctypes.c_wchar_p),
                ('lpDirectory', ctypes.c_wchar_p), ('nShow', ctypes.c_int),
                ('hInstApp', ctypes.c_void_p), ('lpIDList', ctypes.c_void_p),
                ('lpClass', ctypes.c_wchar_p), ('hkeyClass', ctypes.c_void_p),
                ('dwHotKey', ctypes.c_uint32), ('hIcon', ctypes.c_void_p),
                ('hProcess', ctypes.c_void_p)]


class _WindowsShell:
    def __init__(self):
        if os.name != 'nt':
            raise ValueError('UAC requires the local Windows host')
        self.kernel = ctypes.WinDLL('kernel32.dll', use_last_error=True)
        self.kernel.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        self.kernel.GetSystemDirectoryW.restype = ctypes.c_uint32
        directory = ctypes.create_unicode_buffer(32768)
        length = self.kernel.GetSystemDirectoryW(directory, len(directory))
        if not 0 < length < len(directory):
            raise ctypes.WinError(ctypes.get_last_error())
        self.shell = ctypes.WinDLL(ntpath.join(directory.value, 'shell32.dll'), use_last_error=True)
        self.ole = ctypes.WinDLL(ntpath.join(directory.value, 'ole32.dll'), use_last_error=True)
        self.shell.ShellExecuteExW.argtypes = [ctypes.POINTER(_ShellExecuteInfo)]
        self.shell.ShellExecuteExW.restype = ctypes.c_int
        self.kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.kernel.WaitForSingleObject.restype = ctypes.c_uint32
        self.kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        self.kernel.GetExitCodeProcess.restype = ctypes.c_int
        self.kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel.CloseHandle.restype = ctypes.c_int
        self.ole.CoInitializeEx.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.ole.CoInitializeEx.restype = ctypes.c_int32
        self.ole.CoUninitialize.argtypes = []
        self.ole.CoUninitialize.restype = None

    def __enter__(self):
        # Own one COM reference; never change another component's apartment.
        hr = self.ole.CoInitializeEx(None, 0x2 | 0x4)
        if hr not in (0, 1):
            raise OSError(hr, 'Cannot initialize the UAC shell apartment')
        return self

    def __exit__(self, *args):
        self.ole.CoUninitialize()

    def launch(self, executable, arguments):
        info = _ShellExecuteInfo()
        info.cbSize = ctypes.sizeof(info)
        info.fMask = 0x40 | 0x100  # NOCLOSEPROCESS | NOASYNC; no security bypass flags.
        info.lpVerb = 'runas'
        info.lpFile = executable
        info.lpParameters = arguments
        info.nShow = 0
        ctypes.set_last_error(0)
        success = bool(self.shell.ShellExecuteExW(ctypes.byref(info)))
        return success, info.hProcess, 0 if success else ctypes.get_last_error()

    def wait(self, handle, milliseconds):
        result = self.kernel.WaitForSingleObject(handle, milliseconds)
        if result == 0xffffffff:
            raise ctypes.WinError(ctypes.get_last_error())
        return result

    def exit_code(self, handle):
        result = ctypes.c_uint32()
        if not self.kernel.GetExitCodeProcess(handle, ctypes.byref(result)):
            raise ctypes.WinError(ctypes.get_last_error())
        return result.value

    def close(self, handle):
        if not self.kernel.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())


def run_elevated(executable, arguments, timeout_ms=600000, *, api=None):
    if (not isinstance(executable, str) or not ntpath.isabs(executable) or '\0' in executable or
            not isinstance(arguments, (list, tuple)) or
            any(not isinstance(item, str) or '\0' in item for item in arguments) or
            type(timeout_ms) is not int or not 0 < timeout_ms <= 600000):
        raise ValueError('Invalid native elevation arguments')
    with (api if api is not None else _WindowsShell()) as shell:
        success, handle, error = shell.launch(executable, subprocess.list2cmdline(arguments))
        try:
            if not success:
                if error == 1223 and not handle:
                    return dict(cancelled=True, started=False, exitCode=None)
                raise OSError(error, 'Native elevation failed')
            if not handle:
                return dict(cancelled=False, started=True, exitCode=None)
            waited = shell.wait(handle, timeout_ms)
            if waited == 258:
                # A timed-out installer may still be working: do not kill or replay it.
                return dict(cancelled=False, started=True, exitCode=None)
            if waited != 0:
                raise OSError(waited, 'Unexpected native wait result')
            return dict(cancelled=False, started=True, exitCode=shell.exit_code(handle))
        finally:
            if handle:
                shell.close(handle)
