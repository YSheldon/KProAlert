#Requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try {
    $module=Join-Path $PSScriptRoot '../../../tools/KProReleaseTrust.psm1'
    if((Get-FileHash -LiteralPath $module).Hash -ine '9403c82406972819dba630231250699717531c5761c8a781bc9763fb8bdd21f0'){throw 'Native trust module mismatch.'}
    Import-Module $module -Force
    # Always read native registry state, including from a WOW64 caller.
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $base.OpenSubKey('SOFTWARE\Microsoft\Cryptography')
        if ($null -eq $key) { throw 'Device identity unavailable.' }
        try { $guid = [string]$key.GetValue('MachineGuid') } finally { $key.Dispose() }
        if ($guid -notmatch '^[a-fA-F0-9-]{36}$') { throw 'Device identity invalid.' }
        $key = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion')
        if ($null -eq $key) { throw 'Native installation directory unavailable.' }
        try { $programFiles = [string]$key.GetValue('ProgramFilesDir') } finally { $key.Dispose() }
    } finally { $base.Dispose() }
    if (-not [IO.Path]::IsPathRooted($programFiles)) { throw 'Native directory invalid.' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $device = ([BitConverter]::ToString($sha.ComputeHash(
        [Text.Encoding]::UTF8.GetBytes('FalconPro-device-v1:' + $guid.ToLowerInvariant())))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $arch = @(Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -ExpandProperty Architecture -Unique)
    $architecture = 'unknown'
    if ($arch.Count -eq 1) {
        if ([int]$arch[0] -eq 0) { $architecture = 'x86' }
        elseif ([int]$arch[0] -eq 9) { $architecture = 'x64' }
        elseif ([int]$arch[0] -eq 12) { $architecture = 'arm64' }
    }
    $osVersion = [Version]$os.Version
    $buildNumber = [int]$os.BuildNumber
    $platform = 'unknown'
    if ([int]$os.ProductType -eq 1 -and $architecture -in @('x86','x64','arm64')) {
        try{$platform=Get-KProPlatformForWindows $osVersion $buildNumber $architecture ([int]$os.ProductType)}catch{$platform='unknown'}
    }
    $services = @(Get-CimInstance Win32_Service -Filter "Name='KProSvc' OR Name='KDirProSvc' OR Name='KCritDirCtrlSvc'" -ErrorAction Stop)
    $drivers = @(Get-CimInstance Win32_SystemDriver -Filter "Name='KProFilter'" -ErrorAction Stop)
    function Get-State($Items) {
        $itemsArray = @($Items)
        if ($itemsArray.Count -eq 0) { return 'absent' }
        if ($itemsArray.Count -ne 1) { return 'unknown' }
        if ($itemsArray[0].State -eq 'Running') { return 'running' }
        if ($itemsArray[0].State -eq 'Stopped') { return 'stopped' }
        return 'unknown'
    }
    $driverPaths = @(
        [IO.Path]::GetFullPath((Join-Path $os.WindowsDirectory 'System32\drivers\KProFilter.sys'))
        [IO.Path]::GetFullPath((Join-Path $os.WindowsDirectory 'System32\drivers\KProFilter32.sys'))
        [IO.Path]::GetFullPath((Join-Path $os.WindowsDirectory 'System32\drivers\KProFilterArm.sys'))
    )
    $residual = $false
    foreach ($path in @((Join-Path $programFiles 'KProAlert')) + $driverPaths) {
        if (Test-Path -LiteralPath $path -ErrorAction Stop) { $residual = $true }
    }
    [ordered]@{schema='FalconProEndpointFacts/v2'; deviceId=$device; architecture=$architecture;
        platform=$platform; productType=[int]$os.ProductType; osVersion=$os.Version; buildNumber=$buildNumber;
        supported=($platform -ne 'unknown');
        service=(Get-State @($services | Where-Object Name -eq 'KProSvc'));
        driver=(Get-State $drivers);
        conflicts=(@($services | Where-Object Name -ne 'KProSvc').Count -ne 0);
        residualFiles=$residual} | ConvertTo-Json -Compress
} catch {
    # Never turn access denied, WMI failure or an unreadable path into absence.
    '{"schema":"FalconProEndpointFacts/v1","error":"probe_failed"}'
    exit 1
}
