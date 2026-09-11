#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$PackageRoot,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-[0-9-]+$')][string]$DeliveryUserSid,
    [switch]$ValidateCandidate,
    [switch]$Apply
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputHandles=New-Object 'System.Collections.Generic.List[System.IDisposable]'

function Read-LockedInput([string]$Path,[int]$Maximum) {
    $stream=[IO.File]::Open($Path,'Open','Read','Read')
    $inputHandles.Add($stream)
    if($stream.Length -le 0 -or $stream.Length -gt $Maximum){throw 'Input size rejected.'}
    $bytes=New-Object byte[] ([int]$stream.Length)
    $position=0
    while($position -lt $bytes.Length) {
        $count=$stream.Read($bytes,$position,$bytes.Length-$position)
        if($count -eq 0){throw 'Short input read.'}
        $position+=$count
    }
    return ,$bytes
}

function Assert-PlainPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse paths are not accepted.' }
        if ($item -is [IO.FileInfo]) { $item = $item.Directory } else { $item = $item.Parent }
    }
}
function Invoke-ServiceCommand([string[]]$Arguments) {
    & (Join-Path $script:NativeSystemRoot 'System32\sc.exe') @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Service operation failed ($LASTEXITCODE)." }
}
function New-KProProtectionService([string]$ExecutablePath) {
    $binaryPath = '"' + $ExecutablePath + '"'
    # Preserve literal quotes; a failed readback must not leave an auto-start item.
    New-Service -Name KProSvc -BinaryPathName $binaryPath -StartupType Manual `
        -DisplayName 'FalconPro Protection' -ErrorAction Stop | Out-Null
    $registered = Get-CimInstance Win32_Service -Filter "Name='KProSvc'" -ErrorAction Stop
    if ($null -eq $registered -or $registered.PathName -cne $binaryPath -or
        $registered.StartMode -ne 'Manual' -or $registered.StartName -ne 'LocalSystem') {
        throw 'Service registration readback mismatch; do not start the service.'
    }
}

try {
$source = (Resolve-Path -LiteralPath $PackageRoot).ProviderPath
Assert-PlainPath $source
$manifestPath = Join-Path $source 'release-manifest.json'
Assert-PlainPath $manifestPath
if ((Get-Item -LiteralPath $manifestPath).Length -gt 65536) { throw 'Manifest is too large.' }
$manifestBytes = Read-LockedInput $manifestPath 65536
$sha = [Security.Cryptography.SHA256]::Create()
try { $computedManifestHash = ([BitConverter]::ToString($sha.ComputeHash($manifestBytes))).Replace('-','') }
finally { $sha.Dispose() }
if ($computedManifestHash -ne $ManifestSha256) { throw 'Untrusted manifest hash.' }
$attestationPath = Join-Path $source 'release-attestation.ps1'
Assert-PlainPath $attestationPath
if ((Get-Item -LiteralPath $attestationPath).Length -gt 65536) { throw 'Attestation is too large.' }
$attestationBytes = Read-LockedInput $attestationPath 65536
$trustModule=Join-Path $PSScriptRoot 'tools/KProReleaseTrust.psm1'
Assert-PlainPath $trustModule
$null=Read-LockedInput $trustModule 1048576
if ((Get-FileHash -LiteralPath $trustModule).Hash -ine 'd558a5f3acd31ce847e119bf00a7193711045d9f30add5d72305bce0bd7d3870') { throw 'Native trust module mismatch.' }
Import-Module $trustModule -Force
$attestationIdentity = Assert-KProReleaseAttestation -Bytes $attestationBytes
$attestationText = ConvertFrom-KProAttestationText -Bytes $attestationBytes
$attestedHashes = @([regex]::Matches($attestationText,
    '(?m)^# KPRO-MANIFEST-SHA256: ([A-Fa-f0-9]{64})\r?$'))
if ($attestedHashes.Count -ne 1 -or $attestedHashes[0].Groups[1].Value -ne $ManifestSha256) {
    throw 'Signed attestation does not bind this manifest.'
}
# The attestation is data only: never invoke or dot-source it.
$manifest = [Text.Encoding]::UTF8.GetString($manifestBytes).TrimStart([char]0xfeff) | ConvertFrom-Json
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    throw 'Use native 64-bit PowerShell for installation on this OS.'
}
if ([Environment]::OSVersion.Version.Major -lt 10) { throw 'This installer requires Windows 10 or later.' }
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
$script:NativeSystemRoot=[IO.Path]::GetFullPath([string]$os.WindowsDirectory)
$processorArchitectures = @(Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -ExpandProperty Architecture -Unique)
if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000 -or
    $processorArchitectures.Count -ne 1 -or $processorArchitectures[0] -notin @(9,12)) {
    throw 'This installer supports Windows 11 x64 and ARM64 workstations.'
}
$arch = if ($processorArchitectures[0] -eq 12) { 'arm64' } else { 'x64' }
$layout = Get-KProPackageLayout -Architecture $arch
if ($manifest.platform -cne $layout.Platform) { throw 'Release platform does not match the native OS.' }
$candidate = $ValidateCandidate -and $manifest.releaseStatus -eq 'candidate'
if ($manifest.schema -ne 'KProAlertRelease/v1' -or
    ($manifest.releaseStatus -ne 'verified' -and -not $candidate) -or $manifest.architecture -ne $arch) {
    throw 'Release schema/status/architecture gate failed.'
}
foreach ($gate in @('serviceF1ArtifactProduct','driverMicrosoftProduct','dllProduct','policySignature','endToEnd','privateRawEventSpool')) {
    if ($candidate -and $gate -eq 'endToEnd') { continue }
    if ($manifest.gates.$gate -ne $true) { throw "Release gate is incomplete: $gate" }
}
$required = @($layout.Service,$layout.Dll,$layout.Driver,'DrvCfg2.dat','default-policy.hex')
if (@($manifest.files).Count -ne $required.Count) { throw 'Unexpected file count.' }
$seen = @{}
foreach ($entry in $manifest.files) {
    if ($entry.name -cnotin $required -or $seen.ContainsKey($entry.name)) { throw 'Invalid or duplicate package filename.' }
    $seen[$entry.name] = $true
    $path = Join-Path $source $entry.name
    Assert-PlainPath $path
    $captured=Read-LockedInput $path 67108864
    if ((Get-Item -LiteralPath $path).Length -ne $entry.size -or $entry.size -le 0 -or $entry.size -gt 64MB) { throw 'File size mismatch.' }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.sha256) { throw 'File hash mismatch.' }
    if ([IO.Path]::GetExtension($path) -in @('.exe','.dll','.sys')) {
        Assert-KProPeArchitecture -Bytes $captured -Architecture $arch
        if ((Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'Valid') { throw 'Windows signature validation failed.' }
    }
}
foreach ($service in @('KProSvc','KProFilter','KDirProSvc','KCritDirCtrlSvc')) {
    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
        throw "Existing protection service detected: $service. Use a separately validated upgrade/coexistence path."
    }
}
$nativeProgramFiles=Get-KProNativeProgramFiles
Assert-KProProgramFilesRoot $nativeProgramFiles
$destination = Join-Path $nativeProgramFiles 'KProAlert'
if (Test-Path -LiteralPath $destination) { throw 'Destination exists; refusing to overwrite.' }
$plan = [ordered]@{mode='verified-plan';attestationIdentity=$attestationIdentity;candidateValidation=[bool]$candidate;architecture=$arch;version=$manifest.version;destination=$destination;
    installsDriver=$true;installsElamDriver=$false;automaticAiRemediation=$false;requiresAdministrator=$true;
    deliveryUserSid=$DeliveryUserSid}
if (-not $Apply) { $plan | ConvertTo-Json; return }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator consent is required. Re-run in an elevated native PowerShell.'
}
if (-not $PSCmdlet.ShouldProcess($destination, 'Install signed FalconPro service and driver; apply signed policy at service startup')) { return }
New-Item -ItemType Directory -Path $destination | Out-Null
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl',
        'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
$deliverySid = New-Object Security.Principal.SecurityIdentifier($DeliveryUserSid)
$deliveryAccount = $deliverySid.Translate([Security.Principal.NTAccount])
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
    $deliverySid, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl -LiteralPath $destination -AclObject $acl
foreach ($entry in $manifest.files) {
    $target = Join-Path $destination $entry.name
    Copy-Item -LiteralPath (Join-Path $source $entry.name) -Destination $target
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $entry.sha256) { throw 'Staged hash mismatch.' }
}
[IO.File]::WriteAllBytes((Join-Path $destination 'release-manifest.json'),$manifestBytes)
[IO.File]::WriteAllBytes((Join-Path $destination 'release-attestation.ps1'),$attestationBytes)
foreach ($privateDirectoryName in @('private-event-spool', 'logs')) {
$privateSpool = Join-Path $destination $privateDirectoryName
New-Item -ItemType Directory -Path $privateSpool | Out-Null
$privateAcl = New-Object Security.AccessControl.DirectorySecurity
$privateAcl.SetAccessRuleProtection($true,$false)
$privateAcl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
foreach ($privateSid in @('S-1-5-18','S-1-5-32-544')) {
    $privateAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier($privateSid)), 'FullControl',
        'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
Set-Acl -LiteralPath $privateSpool -AclObject $privateAcl
$readback = Get-Acl -LiteralPath $privateSpool
$rawOwner = (New-Object Security.Principal.NTAccount($readback.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
if (-not $readback.AreAccessRulesProtected -or $rawOwner -ne 'S-1-5-32-544' -or $readback.Access.Count -ne 2) {
    throw 'Private evidence ACL readback failed; service will not start.'
}
foreach ($rule in $readback.Access) {
    $ruleSid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($ruleSid -notin @('S-1-5-18','S-1-5-32-544') -or $rule.AccessControlType -ne 'Allow' -or
        ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) {
        throw 'Private evidence permissions are too broad or incomplete.'
    }
}
}
$spool = Join-Path $destination 'alert-spool'
New-Item -ItemType Directory -Path $spool | Out-Null
$spoolAcl = Get-Acl -LiteralPath $spool
# Delivery can consume committed files, but cannot forge new producer files.
$spoolAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
    $deliverySid, 'ReadAndExecute,Delete', 'ObjectInherit', 'InheritOnly', 'Allow')))
Set-Acl -LiteralPath $spool -AclObject $spoolAcl
$archive = Join-Path $spool 'archive'
New-Item -ItemType Directory -Path $archive | Out-Null
$archiveAcl = Get-Acl -LiteralPath $archive
$archiveAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
    $deliverySid, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl -LiteralPath $archive -AclObject $archiveAcl
$serviceExe = Join-Path $destination $layout.Service
New-KProProtectionService $serviceExe
Invoke-ServiceCommand @('sidtype','KProSvc','unrestricted')
Set-Service -Name KProSvc -StartupType Automatic -ErrorAction Stop
Invoke-ServiceCommand @('start','KProSvc')
$service = Get-Service KProSvc
$service.WaitForStatus('Running',[TimeSpan]::FromSeconds(90))
Start-Sleep -Seconds 3
$service.Refresh()
if ($service.Status -ne 'Running') { throw 'Service failed after startup; preserve installation for diagnostics.' }
$driver = Get-Service KProFilter -ErrorAction Stop
if ($driver.Status -ne 'Running') { throw 'Driver not running; installation is not complete.' }
$healthPath = Join-Path $destination 'collector-health.json'
$deadline = [DateTime]::UtcNow.AddSeconds(30)
$collectorReady = $false
do {
    if (Test-Path -LiteralPath $healthPath -PathType Leaf) {
        $receiptFile = Get-Item -LiteralPath $healthPath
        if ($receiptFile.Length -le 4096 -and $receiptFile.LastWriteTimeUtc -gt [DateTime]::UtcNow.AddSeconds(-60)) {
            $health = Get-Content -LiteralPath $healthPath -Raw | ConvertFrom-Json
            $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='KProSvc'"
            $collectorReady = $health.schema -eq 'KProCollectorHealth/v1' -and $health.status -eq 0 -and
                $health.stopped -eq $false -and $health.pid -eq $serviceInfo.ProcessId
        }
    }
    if (-not $collectorReady) { Start-Sleep -Seconds 1 }
} while (-not $collectorReady -and [DateTime]::UtcNow -lt $deadline)
if (-not $collectorReady) { throw 'Fresh successful collector receipt missing; installation is not complete.' }
[ordered]@{mode='service-running';destination=$destination;driverRunning=$true;
    collectorReady=$collectorReady;eventEndToEndVerified=$false;aiConfigured=$false;rebootRecoveryVerified=$false} | ConvertTo-Json
} finally {
    foreach($handle in $inputHandles){$handle.Dispose()}
}
