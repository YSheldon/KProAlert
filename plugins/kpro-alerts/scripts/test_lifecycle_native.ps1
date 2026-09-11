$ErrorActionPreference='Stop'
$root=Resolve-Path (Join-Path $PSScriptRoot '../../..')
$path=Join-Path $root 'Invoke-FalconProLifecycle.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
$functions=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)
foreach($name in @('Read-Captured','Digest','Decode','Read-Package','Write-State','Assert-Collector','Cancel-UnchangedUpgrade')) {
    $definition=@($functions|Where-Object Name -eq $name)
    if($definition.Count -ne 1){throw ('Missing native function '+$name)}
    . ([scriptblock]::Create($definition[0].Extent.Text))
}
$held=New-Object 'System.Collections.Generic.List[System.IDisposable]'
$folder=Join-Path ([IO.Path]::GetTempPath()) ('FalconPro-native-test-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $folder
try {
    $file=Join-Path $folder 'payload'
    [IO.File]::WriteAllBytes($file,[byte[]](1,2,3))
    $captured=Read-Captured $file 3
    if($captured.Length -ne 3 -or $captured[2] -ne 3){throw 'Read failed.'}
    $blocked=$false
    try{[IO.File]::WriteAllText($file,'replace')}catch{$blocked=$true}
    if(-not $blocked){throw 'Captured input was writable.'}
    foreach($h in $held){$h.Dispose()};$held.Clear()
    $denied=$false
    try{$null=Read-Captured $file 2}catch{$denied=$true}
    if(-not $denied){throw 'Size bound did not hold.'}
    foreach($h in $held){$h.Dispose()};$held.Clear()
    $transactionRoot=$folder
    $state=[ordered]@{phase='';updatedUtc='';transactionId='a'*32}
    Write-State 'uninstall_pending'
    $stored=Decode ([IO.File]::ReadAllBytes((Join-Path $folder 'result.json')))
    if($stored.phase -ne 'uninstall_pending'){throw 'Intent not persisted.'}
    Write-State 'uninstalled'
    $stored=Decode ([IO.File]::ReadAllBytes((Join-Path $folder 'result.json')))
    if($stored.phase -ne 'uninstalled'){throw 'Atomic state replacement failed.'}
    $script:trustCalled=$false
    function Assert-KProReleaseAttestation {param($Bytes) $script:trustCalled=$true;throw 'fixture rejects signature'}
    [IO.File]::WriteAllText((Join-Path $folder 'release-manifest.json'),'{}')
    [IO.File]::WriteAllText((Join-Path $folder 'release-attestation.ps1'),'untrusted')
    $denied=$false
    try{$null=Read-Package $folder (Digest ([IO.File]::ReadAllBytes((Join-Path $folder 'release-manifest.json'))))}catch{$denied=$true}
    if(-not $denied -or -not $script:trustCalled){throw 'Untrusted release was accepted.'}
    $installed=$folder
    [IO.File]::WriteAllText((Join-Path $folder 'collector-health.json'),'{"schema":"KProCollectorHealth/v1","status":0,"stopped":false,"pid":123}')
    function Get-CimInstance {param($ClassName,$Filter) [pscustomobject]@{State='Running';ProcessId=123}}
    $script:driverStatus='Stopped'
    function Get-Service {param($Name,$ErrorAction) [pscustomobject]@{Status=$script:driverStatus}}
    $denied=$false
    try{Assert-Collector}catch{$denied=$true}
    if(-not $denied){throw 'Collector accepted a stopped driver.'}
    $script:driverStatus='Running'
    Assert-Collector
    function Assert-OrdinaryService {}
    function Assert-Protected {param($Path)}
    function Read-Package {param($Root,$Expected) [pscustomobject]@{version='1.0.0.1'}}
    $script:failSnapshot=$false
    function Snapshot {param($InstalledHash,$Expected) if($script:failSnapshot){throw 'Changed policy'};[pscustomobject]@{digestSha256='d'*64}}
    function Release-Files {foreach($h in $held){$h.Dispose()};$held.Clear()}
    foreach($phase in @('prepared','backup_ready','uninstall_pending')) {
        $oldHash=Digest ([IO.File]::ReadAllBytes((Join-Path $installed 'release-manifest.json')))
        $state=[ordered]@{operation='upgrade';phase=$phase;oldManifestSha256=$oldHash;policyDigest='d'*64;installedVersion='';updatedUtc=''}
        Cancel-UnchangedUpgrade
        if($state.phase -cne 'cancelled_no_change' -or $state.installedVersion -cne '1.0.0.1'){throw 'Unchanged upgrade not cancelled.'}
        $state.phase=$phase
        $script:failSnapshot=$true
        $denied=$false
        try{Cancel-UnchangedUpgrade}catch{$denied=$true}
        if(-not $denied -or $state.phase -cne $phase){throw 'Uncertain old policy was accepted as unchanged.'}
        $script:failSnapshot=$false
    }
    'PASS: native capture, size limits, intent persistence and signature rejection'
}finally {
    foreach($h in $held){$h.Dispose()}
    $resolved=[IO.Path]::GetFullPath($folder)
    if($resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
