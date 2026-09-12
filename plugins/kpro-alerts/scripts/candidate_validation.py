"""Developer-only launcher from a trusted plugin checkout, never from a candidate archive."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
from windows_tools import native_tool


TRUST_SHA256 = '979c2d8cfd7e19317ae8e5752bad59f6431ac92d69777b5661b27ed7e1dd2639'
VERIFIER = r'''
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$env:PSModulePath=Join-Path $PSHOME 'Modules'
$PSModuleAutoLoadingPreference='All'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$a=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__ARGUMENTS__'))|ConvertFrom-Json
$held=New-Object 'System.Collections.Generic.List[System.IDisposable]'
try {
    $item=Get-Item -LiteralPath $a.Module
    while($null -ne $item){
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse verifier rejected.'}
        if($item -is [IO.FileInfo]){$item=$item.Directory}else{$item=$item.Parent}
    }
    $held.Add([IO.File]::Open($a.Module,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
    if((Get-FileHash -LiteralPath $a.Module).Hash -ine '__TRUST__'){throw 'Installed verifier drift.'}
    Import-Module $a.Module -Force
    $null=Get-KProCandidatePermit $a.CandidatePermitPath $a.CandidatePermitSha256 $a.ExpectedDeviceId $a.TransactionId $a.ExpectedArchitecture $a.SourceManifestSha256 $a.Mode $a.SourceRoot $held
    $invoke=@{}
    foreach($name in @('Mode','ExpectedDeviceId','TransactionId','ExpectedArchitecture','SourceManifestSha256','ManifestSha256',
                       'PackageRoot','DeliveryUserSid','CandidatePermitPath','CandidatePermitSha256','Apply')){$invoke[$name]=$a.$name}
    $invoke.ApproveCandidateValidation=$true
    # All candidate PS1 signatures and hashes are checked and held BEFORE execution.
    & (Join-Path $a.SourceRoot 'Invoke-FalconProCandidateValidation.ps1') @invoke
}finally{foreach($handle in $held){$handle.Dispose()}}
'''


def validate_result(reply, options):
    if not isinstance(reply, dict) or reply.get('validationOnly') is not True:
        raise ValueError('Candidate result lost validation-only identity')
    if 'schema' not in reply:
        if (options.get('Apply') is not False or reply.get('mode') != 'candidate-validation-plan' or
                'phase' in reply or reply.get('operation') != options['Mode']):
            raise ValueError('Invalid candidate plan result')
    else:
        if (reply['schema'] != 'FalconProCandidateLifecycleResult/v1' or 'mode' in reply or
                reply.get('productionEligible') is not False or reply.get('phase') not in (
                    'awaiting_reboot','recovery_awaiting_reboot','validation_complete','validation_rolled_back','validation_aborted','cancelled_no_change')):
            raise ValueError('Invalid candidate lifecycle result')
        if reply['phase']=='validation_aborted' and (reply.get('operation')!='install' or
                reply.get('installedVersion')!='' or options['Mode']!='rollback'):
            raise ValueError('Invalid candidate aborted-install outcome')
        for field, option in (('deviceId','ExpectedDeviceId'),('transactionId','TransactionId'),
                              ('architecture','ExpectedArchitecture'),('sourceManifestSha256','SourceManifestSha256'),
                              ('manifestSha256','ManifestSha256'),('candidatePermitSha256','CandidatePermitSha256')):
            if reply.get(field) != options[option]:
                raise ValueError('Candidate result binding mismatch')
    return reply


def run(options, *, approval=False):
    if os.name != 'nt' or approval is not True:
        raise ValueError('Explicit local Windows candidate validation consent required')
    module = Path(__file__).resolve().parents[3] / 'tools/KProReleaseTrust.psm1'
    if hashlib.sha256(module.read_bytes()).hexdigest() != TRUST_SHA256:
        raise ValueError('Trusted plugin verifier drift')
    arguments = dict(options, Module=str(module))
    encoded_args = base64.b64encode(json.dumps(arguments).encode()).decode()
    code = VERIFIER.replace('__TRUST__', TRUST_SHA256).replace('__ARGUMENTS__', encoded_args)
    command = [str(native_tool('WindowsPowerShell/v1.0/powershell.exe')), '-NoProfile', '-NonInteractive',
               '-ExecutionPolicy', 'RemoteSigned', '-EncodedCommand', base64.b64encode(code.encode('utf-16le')).decode()]
    result = subprocess.run(command, capture_output=True, timeout=600)
    if result.returncode != 0 or len(result.stdout) > 32768:
        raise ValueError('Candidate validation failed; inspect protected native transaction, never automatically retry')
    reply = json.loads(result.stdout.decode('utf-8-sig'))
    return validate_result(reply, options)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('install','upgrade','resume','rollback'), required=True)
    for name in ('source-root','package-root','expected-device-id','transaction-id','source-manifest-sha256',
                 'manifest-sha256','expected-architecture','delivery-user-sid','candidate-permit-path','candidate-permit-sha256'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--approve-candidate-validation', action='store_true')
    parser.add_argument('--apply', action='store_true')
    args=vars(parser.parse_args())
    approved=args.pop('approve_candidate_validation')
    options={''.join(part.title() for part in key.split('_')):value for key,value in args.items()}
    try:
        print(json.dumps(run(options, approval=approved)))
    except Exception as exc:
        print(json.dumps({'validationOnly':True,'state':'attention_required','automaticRetry':False,'errorClass':type(exc).__name__}))
        raise SystemExit(1)
