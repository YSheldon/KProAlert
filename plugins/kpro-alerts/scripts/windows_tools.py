"""Resolve fixed system tools through Windows APIs, not caller environment variables."""
import os
import sys
from pathlib import Path


def native_tool(name):
    if name not in ('WindowsPowerShell/v1.0/powershell.exe','whoami.exe'):
        raise ValueError('Unsupported native tool')
    if os.name!='nt':raise ValueError('Native Windows channel required')
    import ctypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetSystemWindowsDirectoryW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint]
    kernel.GetSystemWindowsDirectoryW.restype=ctypes.c_uint
    root=ctypes.create_unicode_buffer(32768)
    size=kernel.GetSystemWindowsDirectoryW(root,len(root))
    if not 0<size<len(root):raise ValueError('System Windows directory unavailable')
    info=ctypes.create_string_buffer(64)
    kernel.GetNativeSystemInfo.argtypes=[ctypes.c_void_p]
    kernel.GetNativeSystemInfo.restype=None
    kernel.GetNativeSystemInfo(info)
    native_arch=int.from_bytes(info.raw[:2],'little')
    system='Sysnative' if sys.maxsize<=2**32 and native_arch in (9,12) else 'System32'
    return str(Path(root.value)/system/name)
