"""Read-only native policy proof; never executes upgrade steps or trusts imported receipts."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from endpoint import probe
from spool import checked
from windows_tools import native_tool


def _unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate native response field')
        result[key]=value
    return result


def _hex(value):
    if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{64}',value):
        raise ValueError('Missing or invalid trusted upgrade binding')


def query_snapshot(device_id,transaction_id,manifest_sha256,helper_sha256,expected_digest=None):
    """Capture native proof using only fixed production dependencies.

    Digests are supplied by the admitted release coordinator. This SDK function
    is not an authentication service for arbitrary Python callers; executing
    untrusted Python in the same process is outside its trust model.
    """
    return _query_snapshot_impl(device_id,transaction_id,manifest_sha256,helper_sha256,expected_digest)


def _query_snapshot_impl(device_id,transaction_id,manifest_sha256,helper_sha256,expected_digest=None,
                   *,platform=None,helper_path=None,runner=None,parser=None,
                   endpoint_probe=probe,resolver=native_tool):
    """Private test seam. Hashes come from admitted signed distributions, not alert/AI fields.

    This function captures fresh subprocess stdout; it has no API for importing a
    prior receipt. Call before uninstall and after restore with the same digest.
    No mutation is enabled by a successful snapshot alone.
    """
    if (platform or os.name)!='nt':raise ValueError('Bound local Windows channel required')
    for value in (device_id,transaction_id,manifest_sha256,helper_sha256):_hex(value)
    if expected_digest is not None:_hex(expected_digest)
    state=endpoint_probe(device_id)
    if state.get('state')!='running_policy_unverified':
        raise ValueError('Installed endpoint is not eligible; retain existing protection')
    helper=Path(helper_path) if helper_path is not None else Path(__file__).with_name('Invoke-PolicySnapshot.ps1')
    checked(helper)
    with helper.open('rb') as stream:source=stream.read(65537)
    if len(source)>65536 or hashlib.sha256(source).hexdigest()!=helper_sha256:
        raise ValueError('Native helper is not the admitted source')
    command=[str(resolver('WindowsPowerShell/v1.0/powershell.exe')),'-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned',
             '-File',str(helper),'-ExpectedDeviceId',device_id,'-TransactionId',transaction_id,
             '-ManifestSha256',manifest_sha256]
    if expected_digest is not None:command+=['-ExpectedDigest',expected_digest]
    started=time.time()
    try:
        result=(runner or subprocess.run)(command,capture_output=True,timeout=90)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise ValueError('Native policy proof unavailable; no upgrade authorized') from exc
    if result.returncode!=0 or not isinstance(result.stdout,bytes) or len(result.stdout)>16384:
        raise ValueError('Native policy proof failed')
    try:
        native=json.loads(result.stdout.decode('utf-8-sig'),object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number')))
    except (UnicodeError,ValueError) as exc:raise ValueError('Invalid native response') from exc
    fields={'schema','servicePid','manifestSha256','exitCode','stdoutBase64'}
    if not isinstance(native,dict) or set(native)!=fields or native['schema']!='FalconProNativeSnapshot/v1':
        raise ValueError('Unsupported native response')
    if (native['manifestSha256']!=manifest_sha256 or type(native['servicePid']) is not int or
        not 0<native['servicePid']<=0xffffffff or type(native['exitCode']) is not int or
        native['exitCode']!=0 or not isinstance(native['stdoutBase64'],str)):
        raise ValueError('Native response binding failed')
    try:raw=base64.b64decode(native['stdoutBase64'],validate=True)
    except ValueError as exc:raise ValueError('Invalid native response encoding') from exc
    if parser is None:
        from policy_snapshot import parse_snapshot
        parser=parse_snapshot
    return parser(raw,exit_code=native['exitCode'],transaction_id=transaction_id,
                  device_id=device_id,service_pid=native['servicePid'],expected_digest=expected_digest,
                  started_at=started,now=time.time())
