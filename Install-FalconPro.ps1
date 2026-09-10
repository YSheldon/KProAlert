#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedDeviceId,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$SourceManifestSha256,
    [Parameter(Mandatory)][string]$PackageRoot,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-[0-9-]+$')][string]$DeliveryUserSid,
    [switch]$ApproveInstallation,
    [switch]$Apply
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-SourceFiles {
    # Bootstrap independently verifies this entry script before execution.
    $manifestPath = Join-Path $PSScriptRoot 'onboarding-source.json'
    $manifestItem = Get-Item -LiteralPath $manifestPath -Force
    if ($manifestItem.Length -gt 16384 -or
        (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -ne $SourceManifestSha256) {
        throw 'Untrusted onboarding source manifest.'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $names = @('Install-FalconPro.ps1','Install-KProAlert.ps1',
        'plugins/kpro-alerts/scripts/EndpointFacts.ps1','tools/KProReleaseTrust.psm1')
    if ($manifest.schema -cne 'FalconProOnboardingSource/v1' -or @($manifest.files).Count -ne $names.Count) {
        throw 'Unsupported onboarding source manifest.'
    }
    $seen = @{}
    foreach ($entry in $manifest.files) {
        if ($entry.name -cnotin $names -or $seen.ContainsKey($entry.name) -or
            $entry.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid source entry.' }
        $seen[$entry.name] = $true
        $path = Join-Path $PSScriptRoot $entry.name
        $item = Get-Item -LiteralPath $path -Force
        if ($item -isnot [IO.FileInfo] -or $item.Length -gt 1MB) { throw 'Invalid source file.' }
        while ($null -ne $item) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse source is not accepted.' }
            if ($item -is [IO.FileInfo]) { $item = $item.Directory } else { $item = $item.Parent }
        }
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.sha256) {
            throw 'Onboarding source hash mismatch; execute no helpers.'
        }
    }
}
Assert-SourceFiles

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
        sourceManifestSha256=$SourceManifestSha256;
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
Assert-SourceFiles
Assert-TargetAbsent
& $installer @installArgs -Apply
