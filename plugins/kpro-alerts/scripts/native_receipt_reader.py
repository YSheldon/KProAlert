"""Verified, read-only native receipt invocation on an authorized local Windows host."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
from windows_tools import native_tool

NAMES={'falconprosetup.exe','falconprosetup32.exe','falconprosetuparm.exe'}
TRUST_SHA256='d106f5681c7041f68478163f8d7f324d226530e3052b3e68cc58d88758fd786f'


def _request(entry,entry_sha256,device,transaction):
    for value,length in ((entry_sha256,64),(device,64),(transaction,32)):
        if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{'+str(length)+'}',value):
            raise ValueError('Explicit native entry/device/transaction binding required')
    if not isinstance(entry,str) or len(entry)>32760 or any(ord(c)<32 for c in entry):
        raise ValueError('Invalid native executable path')
    path=PureWindowsPath(entry)
    if not path.is_absolute() or not re.fullmatch('[A-Za-z]:',path.drive) or path.name.lower() not in NAMES:
        raise ValueError('Known local native executable required')
    for part in entry.replace('/','\\').split('\\')[1:]:
        if part in ('.','..') or ':' in part or part.endswith((' ','.')):
            raise ValueError('Ambiguous native executable path')
    return str(path)


@contextmanager
def _locked_entry(entry,expected):
    if os.name!='nt':
        raise ValueError('Authorized local Windows channel required')
    import ctypes
    from ctypes import wintypes
    class FileInfo(ctypes.Structure):
        _fields_=[('attributes',wintypes.DWORD),('created',wintypes.FILETIME),
            ('accessed',wintypes.FILETIME),('written',wintypes.FILETIME),
            ('volume',wintypes.DWORD),('sizeHigh',wintypes.DWORD),('sizeLow',wintypes.DWORD),
            ('links',wintypes.DWORD),('indexHigh',wintypes.DWORD),('indexLow',wintypes.DWORD)]
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=(wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,
                                wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE)
    kernel.CreateFileW.restype=wintypes.HANDLE
    kernel.GetFileInformationByHandle.argtypes=(wintypes.HANDLE,ctypes.POINTER(FileInfo))
    kernel.GetFileInformationByHandle.restype=wintypes.BOOL
    kernel.CloseHandle.argtypes=(wintypes.HANDLE,)
    handles=[]
    path=Path(entry)
    try:
        paths=list(reversed(path.parents))+[path]
        for index,item in enumerate(paths):
            directory=index<len(paths)-1
            handle=kernel.CreateFileW(str(item),0x80 if directory else 0x80000000,1,None,3,
                                     0x00200000|(0x02000000 if directory else 0),None)
            if handle==ctypes.c_void_p(-1).value:
                raise ValueError('Native entry could not be pinned')
            handles.append(handle)
            info=FileInfo()
            if not kernel.GetFileInformationByHandle(handle,ctypes.byref(info)):
                raise ValueError('Native file information unavailable')
            if info.attributes&0x400 or bool(info.attributes&0x10)!=directory:
                raise ValueError('Reparse or unexpected native file type')
            if not directory and not 0<(info.sizeHigh<<32|info.sizeLow)<=64*1024*1024:
                raise ValueError('Native entry size rejected')
        with path.open('rb') as stream:
            data=stream.read(64*1024*1024+1)
        if len(data)>64*1024*1024 or hashlib.sha256(data).hexdigest()!=expected:
            raise ValueError('Native entry hash differs from the admitted release')
        yield
    finally:
        for handle in reversed(handles):
            kernel.CloseHandle(handle)


def _verify_publisher(entry):
    module=Path(__file__).resolve().parents[3]/'tools/KProReleaseTrust.psm1'
    quote=lambda value: "'"+str(value).replace("'","''")+"'"
    command=("$ErrorActionPreference='Stop'; $env:PSModulePath=Join-Path $PSHOME 'Modules'; $module=Import-Module "+quote(module)+
             " -PassThru; $signature=Get-AuthenticodeSignature -LiteralPath "+quote(entry)+
             "; $null=& $module {param($signature) Assert-KProReleasePublisher -Signature $signature} $signature; Write-Output 'verified'")
    with _locked_entry(str(module),TRUST_SHA256):
        result=subprocess.run([native_tool('WindowsPowerShell/v1.0/powershell.exe'),'-NoProfile',
            '-NonInteractive','-ExecutionPolicy','RemoteSigned','-Command',command],
            capture_output=True,timeout=60)
    if result.returncode or result.stdout.strip()!=b'verified':
        raise ValueError('Native publisher verification failed')


def _unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError('Duplicate native observation field')
        result[key]=value
    return result


def _read_receipt(entry, entry_sha256, device, transaction, *, runner=None):
    entry=_request(entry,entry_sha256,device,transaction)
    runner=runner or subprocess.run
    with _locked_entry(entry,entry_sha256):
        _verify_publisher(entry)
        result=runner([entry,'receipt','--device',device,'--transaction',transaction],
                      capture_output=True,timeout=60)
    if not isinstance(result.stdout,bytes) or len(result.stdout)>8192 or result.stderr:
        raise ValueError('Native receipt verification did not complete')
    value=json.loads(result.stdout.decode('utf-8'),object_pairs_hook=_unique)
    if result.returncode:
        code=value.get('error') if isinstance(value,dict) else None
        if isinstance(code,str) and re.fullmatch('[a-z0-9_]{1,80}',code):
            raise ValueError('Native receipt rejected: '+code)
        raise ValueError('Native receipt verification did not complete')
    if not isinstance(value,dict) or value.get('schema')!='FalconProNativeObservation/v1':
        raise ValueError('Native observation unavailable')
    from native_observation import validate_native_observation
    return validate_native_observation(value)


def read_receipt(entry, entry_sha256, device, transaction, *, runner=None):
    """Expected SHA comes from the admitted signed release, not a receipt file."""
    try:
        return _read_receipt(entry,entry_sha256,device,transaction,runner=runner)
    except (OSError,subprocess.SubprocessError,UnicodeError,json.JSONDecodeError):
        # Transport exception text can contain the local device binding or path.
        raise ValueError('Native receipt transport failed') from None
