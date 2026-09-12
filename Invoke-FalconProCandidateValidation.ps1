#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('install','upgrade','resume','rollback')][string]$Mode,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedDeviceId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$TransactionId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$SourceManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha256,
    [Parameter(Mandatory)][ValidateSet('x86','x64','arm64')][string]$ExpectedArchitecture,
    [Parameter(Mandatory)][string]$PackageRoot,
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-[0-9-]+$')][string]$DeliveryUserSid,
    [Parameter(Mandatory)][string]$CandidatePermitPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$CandidatePermitSha256,
    [switch]$ApproveCandidateValidation,
    [switch]$Apply
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $ApproveCandidateValidation){throw 'Explicit candidate validation consent required.'}
$held=New-Object 'System.Collections.Generic.List[System.IDisposable]'
try {
    $module=Join-Path $PSScriptRoot 'tools/KProReleaseTrust.psm1'
    $item=Get-Item -LiteralPath $module
    while($null -ne $item){
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse source rejected.'}
        if($item -is [IO.FileInfo]){$item=$item.Directory}else{$item=$item.Parent}
    }
    $stream=[IO.File]::Open($module,'Open','Read','Read');$held.Add($stream)
    if((Get-FileHash -LiteralPath $module).Hash -ine '9403c82406972819dba630231250699717531c5761c8a781bc9763fb8bdd21f0'){throw 'Native trust module mismatch.'}
    Import-Module $module -Force
    $permit=Get-KProCandidatePermit $CandidatePermitPath $CandidatePermitSha256 $ExpectedDeviceId $TransactionId $ExpectedArchitecture $SourceManifestSha256 $Mode $PSScriptRoot $held
    if($permit.packages[0].manifestSha256 -cne $ManifestSha256){throw 'Candidate target mismatch.'}
    $invoke=@{Mode=$Mode;ExpectedDeviceId=$ExpectedDeviceId;TransactionId=$TransactionId;SourceManifestSha256=$SourceManifestSha256;
        ManifestSha256=$ManifestSha256;ExpectedArchitecture=$ExpectedArchitecture;PackageRoot=$PackageRoot;DeliveryUserSid=$DeliveryUserSid;
        CandidatePermitPath=$CandidatePermitPath;CandidatePermitSha256=$CandidatePermitSha256;ApproveCandidateValidation=$true;Approve=$true;Apply=[bool]$Apply}
    if($WhatIfPreference){$invoke.WhatIf=$true}
    & (Join-Path $PSScriptRoot 'Invoke-FalconProLifecycle.ps1') @invoke
}finally{foreach($handle in $held){$handle.Dispose()}}
