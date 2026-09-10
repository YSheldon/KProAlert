$ErrorActionPreference='Stop'
$root=Resolve-Path (Join-Path $PSScriptRoot '../../..')
$path=Join-Path $root 'Invoke-FalconProLifecycle.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
$functions=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)
foreach($name in @('Read-Captured','Digest','Decode','Read-Package','Write-State')) {
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
    'PASS: native capture, size limits, intent persistence and signature rejection'
}finally {
    foreach($h in $held){$h.Dispose()}
    $resolved=[IO.Path]::GetFullPath($folder)
    if($resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
