"""Common local lifecycle: signed download, explicit elevation, native result readback."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import time

from bootstrap import delivery_sid, verify_descriptor
from endpoint import probe
from release_download import acquire, validate_descriptor, version_tuple
from release_manifest import validate
from spool import checked
from windows_tools import native_tool
from release_platforms import layout


SOURCES = ('Install-FalconPro.ps1', 'Install-KProAlert.ps1',
           'Invoke-FalconProLifecycle.ps1', 'Uninstall-KProAlert.ps1',
           'plugins/kpro-alerts/scripts/EndpointFacts.ps1',
           'plugins/kpro-alerts/scripts/Invoke-PolicySnapshot.ps1',
           'tools/KProReleaseTrust.psm1')


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON field')
        value[key] = item
    return value


def read_json(path, maximum=65536):
    checked(path)
    with Path(path).open('rb') as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError('JSON exceeds size limit')
    return json.loads(data.decode('utf-8-sig'), object_pairs_hook=unique)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else hashlib.sha256(stream.read()).hexdigest()


def validate_sources(root, expected):
    root = Path(root)
    path = root / 'onboarding-source.json'
    value = read_json(path, 16384)
    if sha(path) != expected or value.get('schema') != 'FalconProOnboardingSource/v2':
        raise ValueError('Signed lifecycle source manifest required')
    entries = value.get('files')
    if not isinstance(entries, list) or len(entries) != len(SOURCES):
        raise ValueError('Unexpected onboarding file set')
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'name', 'sha256'}:
            raise ValueError('Invalid source record')
        name = entry['name']
        if name not in SOURCES or name in seen:
            raise ValueError('Unexpected or duplicate source name')
        seen.add(name)
        source = root / name
        checked(source)
        if not source.is_file() or source.stat().st_size > 1048576 or sha(source) != entry['sha256']:
            raise ValueError('Onboarding source mismatch')


def plan(operation, destination, device_id, *, endpoint_probe=probe, download=acquire, sid_reader=delivery_sid):
    if operation not in ('install', 'upgrade'):
        raise ValueError('Unsupported lifecycle operation')
    state = endpoint_probe(device_id)
    required = 'not_installed' if operation == 'install' else 'running_policy_unverified'
    if state.get('state') != required:
        return dict(state=state.get('state', 'unknown'), installPerformed=False,
                    nextStep='Bind the actual Windows endpoint or diagnose existing protection')
    architecture = state.get('architecture')
    target = layout(architecture)
    descriptor = download(destination, verify_descriptor, platform=target['platform'])
    root = Path(destination).resolve(strict=True)
    manifest = read_json(root / 'package/release-manifest.json')
    if sha(root / 'package/release-manifest.json') != descriptor['packageManifestSha256']:
        raise ValueError('Package manifest differs from signed descriptor')
    validate(manifest, root / 'package', architecture)
    if descriptor['platform'] != target['platform']:
        raise ValueError('Release/endpoint architecture mismatch')
    if version_tuple(manifest['version']) != version_tuple(descriptor['version']):
        raise ValueError('Release version mismatch')
    validate_sources(root / 'onboarding', descriptor['sourceManifestSha256'])
    return dict(schema='FalconProLifecyclePlan/v2', operation=operation, deviceId=device_id,
                architecture=architecture,
                transactionId=secrets.token_hex(16), releaseRoot=str(root),
                version=manifest['version'], manifestSha256=descriptor['packageManifestSha256'],
                sourceManifestSha256=descriptor['sourceManifestSha256'], deliveryUserSid=sid_reader(),
                requiresApproval=True, installPerformed=False)


def checked_plan(value):
    keys={'schema','operation','deviceId','transactionId','releaseRoot','version',
          'manifestSha256','sourceManifestSha256','deliveryUserSid','requiresApproval','installPerformed'}
    if not isinstance(value,dict):
        raise ValueError('Invalid lifecycle plan')
    if value.get('schema')=='FalconProLifecyclePlan/v1' and set(value)==keys:
        value={**value,'schema':'FalconProLifecyclePlan/v2','architecture':'x64'}
    if set(value)!=keys|{'architecture'} or value['schema']!='FalconProLifecyclePlan/v2':
        raise ValueError('Invalid lifecycle plan')
    layout(value['architecture'])
    if value['operation'] not in ('install','upgrade') or value['requiresApproval'] is not True or value['installPerformed'] is not False:
        raise ValueError('Invalid lifecycle intent')
    for name,length in (('deviceId',64),('transactionId',32),('manifestSha256',64),('sourceManifestSha256',64)):
        if not isinstance(value[name],str) or not re.fullmatch('[a-f0-9]{'+str(length)+'}',value[name]):
            raise ValueError('Invalid lifecycle identity')
    version_tuple(value['version'])
    if not isinstance(value['deliveryUserSid'],str) or not re.fullmatch('S-1-5-21-[0-9-]{1,100}',value['deliveryUserSid']):
        raise ValueError('Invalid local delivery SID')
    if not isinstance(value['releaseRoot'],str) or not Path(value['releaseRoot']).is_absolute():
        raise ValueError('Absolute admitted release path required')
    return value


def ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


@contextmanager
def lock_entry(path):
    # Keep the signed entry immutable between validation and the UAC child open.
    import ctypes
    from ctypes import wintypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=(wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,
                                wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE)
    kernel.CreateFileW.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=(wintypes.HANDLE,)
    handle=kernel.CreateFileW(str(path),0x80000000,1,None,3,0x80,None)
    if handle==ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(),'Cannot pin native entry')
    try:
        yield
    finally:
        kernel.CloseHandle(handle)


def verify_entry(path):
    module=Path(__file__).resolve().parents[3]/'tools/KProReleaseTrust.psm1'
    code=("$ErrorActionPreference='Stop'; Import-Module "+ps_quote(module)+
          "; $null=Assert-KProReleaseAttestation -Bytes ([IO.File]::ReadAllBytes("+
          ps_quote(path)+")); Write-Output 'verified'")
    result=subprocess.run([native_tool('WindowsPowerShell/v1.0/powershell.exe'),
                           '-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned',
                           '-Command',code],capture_output=True,timeout=60)
    if result.returncode!=0 or result.stdout.strip()!=b'verified':
        raise ValueError('Native lifecycle entry requires an approved publisher signature')


def native_execute(value, mode):
    executable=native_tool('WindowsPowerShell/v1.0/powershell.exe')
    root=Path(value['releaseRoot'])
    entry=root/'onboarding/Invoke-FalconProLifecycle.ps1'
    args=['-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(entry),'-Mode',mode,
          '-ExpectedDeviceId',value['deviceId'],'-TransactionId',value['transactionId'],
          '-SourceManifestSha256',value['sourceManifestSha256'],'-ManifestSha256',value['manifestSha256'],
          '-PackageRoot',str(root/'package'),'-DeliveryUserSid',value['deliveryUserSid'],'-Approve','-Apply']
    args+=['-ExpectedArchitecture',value['architecture']]
    code=("$ErrorActionPreference='Stop'; $child=Start-Process -FilePath "+ps_quote(executable)+
          " -Verb RunAs -WindowStyle Hidden -PassThru -Wait -ArgumentList "+
          ps_quote(subprocess.list2cmdline(args))+"; exit $child.ExitCode")
    with lock_entry(entry):
        verify_entry(entry)
        result=subprocess.run([executable,'-NoProfile','-NonInteractive','-Command',code],
                              capture_output=True,timeout=600)
    # The source/receipt roots are fixed by the native OS, never a remote payload.
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion',
                       0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as key:
        program_files=Path(winreg.QueryValueEx(key,'ProgramFilesDir')[0])
    path=program_files/'FalconProTransactions'/value['transactionId']/'result.json'
    if result.returncode!=0:
        return dict(state='attention_required',nativeExitCode=result.returncode,
                    transactionId=value['transactionId'],automaticRetry=False,
                    installPerformed=False,outcomeUncertain=True)
    reply=read_json(path,16384)
    for name in ('deviceId','transactionId','manifestSha256','sourceManifestSha256','deliveryUserSid','version','architecture'):
        if reply.get(name)!=value[name]:
            raise ValueError('Native lifecycle result binding failed')
    if reply.get('schema')!='FalconProLifecycleResult/v1' or reply.get('phase') not in (
            'awaiting_reboot','complete','recovery_awaiting_reboot','rolled_back','cancelled_no_change'):
        raise ValueError('Native lifecycle outcome is incomplete')
    return dict(state=reply['phase'],transactionId=value['transactionId'],
                version=reply.get('installedVersion',reply['version']),
                installPerformed=reply['phase']!='cancelled_no_change',
                rebootRequired=reply['phase'].endswith('awaiting_reboot'),
                userDataPreserved=True,automaticRetry=False)


def apply(value, *, approval=False, mode=None, platform=None, verifier=verify_descriptor,
          executor=native_execute, endpoint_probe=probe, metrics=None):
    value=checked_plan(value)
    if approval is not True:
        raise ValueError('Explicit local-device and release approval required')
    if (platform or os.name)!='nt':
        raise ValueError('Run on the bound Windows PC, not a cloud bot')
    selected=mode or value['operation']
    if selected not in (value['operation'],'resume','rollback'):
        raise ValueError('Operation changed after planning')
    state=endpoint_probe(value['deviceId'])
    allowed={'install':{'not_installed'},'upgrade':{'running_policy_unverified'},
             'resume':{'running_policy_unverified'},'rollback':{'running_policy_unverified','not_installed'}}
    if state.get('state') not in allowed[selected]:
        raise ValueError('Endpoint changed; do not reinstall or replay a partial operation')
    if state.get('architecture')!=value['architecture']:
        raise ValueError('Endpoint architecture differs from the approved plan')
    root=Path(value['releaseRoot'])
    checked(root)
    signed=(root/'FalconPro-release.ps1').read_bytes()
    if len(signed)>65536:
        raise ValueError('Descriptor exceeds size budget')
    descriptor=validate_descriptor(verifier(signed))
    if descriptor['platform']!=layout(value['architecture'])['platform']:
        raise ValueError('Signed release architecture differs from the approved plan')
    for key in ('version','sourceManifestSha256'):
        if descriptor[key]!=value[key]:raise ValueError('Release differs from approved plan')
    if descriptor['packageManifestSha256']!=value['manifestSha256']:
        raise ValueError('Package differs from approved plan')
    validate_sources(root/'onboarding',value['sourceManifestSha256'])
    if sha(root/'package/release-manifest.json')!=value['manifestSha256']:
        raise ValueError('Package manifest changed')
    validate(read_json(root/'package/release-manifest.json'),root/'package',value['architecture'])
    def record(kind):
        if metrics is None:return
        try:metrics.record(kind=kind,version=value['version'],architecture=value['architecture'],os_family='windows11')
        except (OSError,ValueError,RuntimeError,sqlite3.Error):pass
    if selected in ('install','upgrade'):record(selected+'_started')
    try:
        result=executor(value,selected)
    except (OSError,ValueError,subprocess.SubprocessError):
        # No failure/success count when an elevated outcome may be unknown.
        return dict(state='attention_required',outcomeUncertain=True,automaticRetry=False,
                    transactionId=value['transactionId'])
    if result.get('state')=='complete':record(value['operation']+'_success')
    return result
