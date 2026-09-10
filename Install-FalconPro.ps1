#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedDeviceId,
    [Parameter(Mandatory)][string]$PackageRoot,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-[0-9-]+$')][string]$DeliveryUserSid,
    [switch]$ApproveInstallation,
    [switch]$Apply
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-TargetAbsent {
    $facts = (& (Join-Path $PSScriptRoot 'plugins\kpro-alerts\scripts\EndpointFacts.ps1')) | ConvertFrom-Json
    if ($facts.schema -cne 'FalconProEndpointFacts/v1' -or
        $facts.deviceId -cne $ExpectedDeviceId -or $facts.supported -isnot [bool] -or
        -not $facts.supported -or $facts.service -cne 'absent' -or $facts.driver -cne 'absent' -or
        $facts.conflicts -isnot [bool] -or $facts.conflicts -or
        $facts.residualFiles -isnot [bool] -or $facts.residualFiles) {
        throw 'Target is unverified, unsupported or not cleanly absent. Do not reinstall.'
    }
}

# No target is selected by a cloud model, hostname guess or alert payload.
Assert-TargetAbsent
$installArgs = @{PackageRoot=$PackageRoot; ManifestSha256=$ManifestSha256; DeliveryUserSid=$DeliveryUserSid}
$installer = Join-Path $PSScriptRoot 'Install-KProAlert.ps1'
# Always run the existing signature, publisher, release and policy gates first.
$plan = (& $installer @installArgs) | ConvertFrom-Json
if ($plan.mode -cne 'verified-plan' -or $plan.candidateValidation -ne $false) {
    throw 'Only an admitted production release can be offered for installation.'
}
if (-not $Apply) {
    [ordered]@{schema='FalconProInstallPlan/v1'; deviceId=$ExpectedDeviceId;
        manifestSha256=$ManifestSha256; requiresExplicitApproval=$true;
        requiresAdministrator=$true; plan=$plan} | ConvertTo-Json -Depth 6
    return
}
if (-not $ApproveInstallation) { throw 'First installation requires explicit user approval of this device and manifest.' }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Re-run the approved command in an elevated native PowerShell; do not bypass UAC.'
}
if (-not $PSCmdlet.ShouldProcess($ExpectedDeviceId, "Install FalconPro package $ManifestSha256")) { return }
# Reprobe immediately before mutation, never reuse an earlier MCP absence result.
Assert-TargetAbsent
& $installer @installArgs -Apply
