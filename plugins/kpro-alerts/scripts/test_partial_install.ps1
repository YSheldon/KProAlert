$ErrorActionPreference='Stop'
$root=(Get-Item $PSScriptRoot).Parent.Parent.Parent.FullName
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Invoke-FalconProLifecycle.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Parser failure'}
foreach($name in @('Assert-PartialFilePrefix','Assert-DefaultDataStream','Assert-InstallRootMarker','Assert-PartialInstallation','Archive-PartialInstallation','Abort-PartialFirstInstall')){
    $f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    if(-not $f){throw "Missing function: $name"}
    . ([scriptblock]::Create($f.Extent.Text))
}
$folder=Join-Path ([IO.Path]::GetTempPath()) ('FalconPro-partial-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $folder|Out-Null
try{
    $source=Join-Path $folder 'source.bin';$partial=Join-Path $folder 'partial.bin'
    [IO.File]::WriteAllBytes($source,[byte[]](1,2,3,4))
    foreach($bytes in @(@(),@(1),@(1,2,3,4))){
        [IO.File]::WriteAllBytes($partial,[byte[]]$bytes)
        Assert-PartialFilePrefix $partial $source
    }
    foreach($bytes in @(@(1,9),@(1,2,3,4,5))){
        [IO.File]::WriteAllBytes($partial,[byte[]]$bytes)
        $denied=$false;try{Assert-PartialFilePrefix $partial $source}catch{$denied=$true}
        if(-not $denied){throw 'Invalid prefix accepted'}
    }
    $large=New-Object byte[] 131077
    (New-Object Random(123)).NextBytes($large)
    [IO.File]::WriteAllBytes($source,$large)
    $prefix=New-Object byte[] 70005
    [Array]::Copy($large,$prefix,$prefix.Length)
    [IO.File]::WriteAllBytes($partial,$prefix)
    Assert-PartialFilePrefix $partial $source
    $prefix[70004]=$prefix[70004] -bxor 1
    [IO.File]::WriteAllBytes($partial,$prefix)
    $denied=$false;try{Assert-PartialFilePrefix $partial $source}catch{$denied=$true}
    if(-not $denied){throw 'Cross-buffer suffix mismatch accepted'}
    # These tests exercise the filesystem/state algorithm, not native ACL/service admission.
    function Assert-Protected {param($Path)}
    function Read-Captured {param($Path,$Maximum) return ,[IO.File]::ReadAllBytes($Path)}
    function Release-Files {}
    function Assert-PartialRuntimeAbsent {}
    function Assert-RecoveryTargetAbsent {if(Test-Path $installed){throw 'Root still present'}}
    function Get-Service {param($Name,$ErrorAction)}
    function Get-Process {param($Name,$ErrorAction)}
    function Write-State {param($Phase) $script:state.phase=$Phase}
    $script:nativeProgramFiles=$folder
    $script:TransactionId='a'*32
    $script:ExpectedDeviceId='d'*64
    $script:ManifestSha256='b'*64
    $script:SourceManifestSha256='c'*64
    $script:PackageRoot=Join-Path $folder 'package'
    New-Item -ItemType Directory -Path $PackageRoot|Out-Null
    [IO.File]::WriteAllBytes((Join-Path $PackageRoot 'KProSvc.exe'),[byte[]](1,2,3,4))
    [IO.File]::WriteAllText((Join-Path $PackageRoot 'release-manifest.json'),'manifest')
    [IO.File]::WriteAllText((Join-Path $PackageRoot 'release-attestation.ps1'),'attestation')
    $new=[pscustomobject]@{files=@([pscustomobject]@{name='KProSvc.exe'})}
    $marker=@{schema='FalconProInstallRoot/v1';transactionId=$TransactionId;deviceId=$ExpectedDeviceId;
        manifestSha256=$ManifestSha256;sourceManifestSha256=$SourceManifestSha256}
    $script:installed=Join-Path $folder 'KProAlert'
    $archive=Join-Path $folder ('KProAlert.partial-'+$TransactionId)
    New-Item -ItemType Directory -Path $installed|Out-Null
    $marker|ConvertTo-Json|Set-Content (Join-Path $installed '.falconpro-install.json') -Encoding UTF8
    [IO.File]::WriteAllBytes((Join-Path $installed 'KProSvc.exe'),[byte[]](1,2))
    $script:state=[pscustomobject]@{phase='install_pending';partialEvidenceDirectory=''}
    [IO.File]::WriteAllText((Join-Path $installed 'unknown.txt'),'preserve me')
    $denied=$false;try{Archive-PartialInstallation $new}catch{$denied=$true}
    if(-not $denied -or -not(Test-Path $installed) -or (Test-Path $archive)){throw 'Unknown files were moved'}
    Remove-Item -LiteralPath (Join-Path $installed 'unknown.txt')
    $marker.deviceId='e'*64
    $marker|ConvertTo-Json|Set-Content (Join-Path $installed '.falconpro-install.json') -Encoding UTF8
    $denied=$false;try{Archive-PartialInstallation $new}catch{$denied=$true}
    if(-not $denied -or -not(Test-Path $installed)){throw 'Wrong marker accepted'}
    $marker.deviceId=$ExpectedDeviceId
    $marker|ConvertTo-Json|Set-Content (Join-Path $installed '.falconpro-install.json') -Encoding UTF8
    New-Item -ItemType Directory -Path (Join-Path $installed 'logs')|Out-Null
    Set-Content -LiteralPath $installed -Stream 'falconpro-test' -Value 'preserve unknown directory stream'
    $denied=$false;try{Archive-PartialInstallation $new}catch{$denied=$true}
    if(-not $denied -or -not(Test-Path $installed)){throw 'Root alternate stream accepted'}
    if([IO.Path]::GetFullPath($installed) -cne [IO.Path]::GetFullPath((Join-Path $folder 'KProAlert'))){throw 'Fixture cleanup escaped root'}
    Remove-Item -LiteralPath $installed -Recurse -Force
    New-Item -ItemType Directory -Path $installed|Out-Null
    New-Item -ItemType Directory -Path (Join-Path $installed 'logs')|Out-Null
    $marker|ConvertTo-Json|Set-Content (Join-Path $installed '.falconpro-install.json') -Encoding UTF8
    [IO.File]::WriteAllBytes((Join-Path $installed 'KProSvc.exe'),[byte[]](1,2))
    $outside=Join-Path $folder 'outside'
    New-Item -ItemType Directory -Path $outside|Out-Null
    [IO.File]::WriteAllText((Join-Path $outside 'untouched.txt'),'do not traverse')
    $link=Join-Path $installed 'logs'
    [IO.Directory]::Delete($link)
    New-Item -ItemType Junction -Path $link -Target $outside|Out-Null
    $denied=$false;try{Archive-PartialInstallation $new}catch{$denied=$true}
    if(-not $denied -or -not(Test-Path (Join-Path $outside 'untouched.txt'))){throw 'Reparse entry accepted'}
    if([IO.Path]::GetFullPath($link) -cne [IO.Path]::GetFullPath((Join-Path $installed 'logs'))){throw 'Link cleanup escaped fixture'}
    [IO.Directory]::Delete($link)
    New-Item -ItemType Directory -Path $link|Out-Null
    Archive-PartialInstallation $new
    $archive=$state.partialEvidenceDirectory
    if((Test-Path $installed) -or -not(Test-Path $archive) -or $state.phase -cne 'partial_archived'){throw 'Bound partial archive failed'}
    $state.phase='partial_archive_pending'
    Archive-PartialInstallation $new
    if($state.phase -cne 'partial_archived'){throw 'Interrupted rename was not reconciled'}
    New-Item -ItemType Directory -Path $installed|Out-Null
    $state.phase='partial_archive_pending'
    $denied=$false;try{Archive-PartialInstallation $new}catch{$denied=$true}
    if(-not $denied -or -not(Test-Path $installed) -or -not(Test-Path $archive)){throw 'Ambiguous two-root state accepted'}
    [IO.Directory]::Delete($installed)
    $oldRoot=Join-Path $folder 'recovery'
    New-Item -ItemType Directory -Path $oldRoot|Out-Null
    [IO.File]::WriteAllBytes((Join-Path $oldRoot 'KProSvc.exe'),[byte[]](8,7,6,5))
    [IO.File]::WriteAllText((Join-Path $oldRoot 'release-manifest.json'),'old manifest')
    [IO.File]::WriteAllText((Join-Path $oldRoot 'release-attestation.ps1'),'old attestation')
    $marker.manifestSha256='e'*64
    $oldArchives=@()
    foreach($attempt in @(1,2)){
        New-Item -ItemType Directory -Path $installed|Out-Null
        $marker|ConvertTo-Json|Set-Content (Join-Path $installed '.falconpro-install.json') -Encoding UTF8
        [IO.File]::WriteAllBytes((Join-Path $installed 'KProSvc.exe'),[byte[]](8,7))
        $state.phase='recovery_install_pending'
        Archive-PartialInstallation $new -Recovery -ExpectedPackageHash ('e'*64) -CandidateRoot $oldRoot
        if($state.phase -cne 'recovery_partial_archived' -or (Test-Path $installed)){throw 'Recovery partial context rejected'}
        $oldArchives+= $state.partialRecoveryEvidenceDirectory
    }
    if($oldArchives[0] -eq $oldArchives[1] -or -not(Test-Path $oldArchives[0]) -or -not(Test-Path $oldArchives[1])){throw 'Repeated recovery overwrote evidence'}
    New-Item -ItemType Directory -Path $installed|Out-Null
    $marker.manifestSha256=$ManifestSha256
    $marker|ConvertTo-Json|Set-Content (Join-Path $installed '.falconpro-install.json') -Encoding UTF8
    [IO.File]::WriteAllBytes((Join-Path $installed 'KProSvc.exe'),[byte[]](1))
    $script:candidateValidation=$false
    $script:state=[pscustomobject]@{operation='install';phase='install_pending';installedVersion='';partialEvidenceDirectory=''}
    Abort-PartialFirstInstall $new
    if($state.phase -cne 'installation_aborted' -or (Test-Path $installed)){throw 'First-install partial did not terminate safely'}
    'PASS: exact/prefix files, wrong data/marker, unknown files and archive interruption'
}finally{
    $resolved=[IO.Path]::GetFullPath($folder)
    if($resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase)){
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
