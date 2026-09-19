$ErrorActionPreference='Stop'
$root=Resolve-Path (Join-Path $PSScriptRoot '../../..')
Import-Module (Join-Path $root 'tools/KProReleaseTrust.psm1') -Force
function Denied([scriptblock]$Action) { $rejected=$false;try{& $Action}catch{$rejected=$true};if(-not $rejected){throw 'Expected candidate rejection'} }
$device='a'*64;$transaction='b'*32;$source='c'*64;$hash='d'*64
$files=@('KProSvc.exe','KProProtect.dll','KProFilter.sys','DrvCfg2.dat','default-policy.hex')|ForEach-Object{[pscustomobject]@{name=$_;sha256='e'*64;size=123}}
$package=[pscustomobject]@{manifestSha256=$hash;attestationSha256='f'*64;files=$files}
$permit=[pscustomobject]@{schema='FalconProCandidatePermit/v1';deviceId=$device;transactionId=$transaction;architecture='x64';operation='install';sourceManifestSha256=$source;issuedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');expiresUtc=[DateTime]::UtcNow.AddHours(1).ToString('o');packages=@($package)}
$manifest=[pscustomobject]@{releaseStatus='candidate';gates=[pscustomobject]@{serviceF1ArtifactProduct=$true;driverMicrosoftProduct=$true;dllProduct=$true;policySignature=$true;endToEnd=$false;privateRawEventSpool=$true};files=$files}
Assert-KProCandidatePermitFacts $permit $device $transaction 'x64' $source 'install'
Assert-KProCandidatePackage $permit $manifest $hash ('f'*64)
$certificateFiles=@($files + @(
    [pscustomobject]@{name='FalconPplBootstrap.exe';sha256='e'*64;size=123},
    [pscustomobject]@{name='FalconElamControl.dll';sha256='e'*64;size=123},
    [pscustomobject]@{name='FalconElam.sys';sha256='e'*64;size=123}
))
$certificatePackage=[pscustomobject]@{manifestSha256=$hash;attestationSha256='f'*64;files=$certificateFiles}
$certificatePermit=[pscustomobject]@{schema=$permit.schema;deviceId=$device;transactionId=$transaction;architecture='x64';operation='install';sourceManifestSha256=$source;issuedUtc=$permit.issuedUtc;expiresUtc=$permit.expiresUtc;packages=@($certificatePackage)}
$certificateManifest=[pscustomobject]@{releaseStatus='candidate';serviceProtection='certificate-only';gates=$manifest.gates;files=$certificateFiles}
Assert-KProCandidatePackage $certificatePermit $certificateManifest $hash ('f'*64)
foreach($relativePath in @('Invoke-FalconProLifecycle.ps1','plugins/kpro-alerts/scripts/Invoke-PolicySnapshot.ps1')) {
    $sourceText=[IO.File]::ReadAllText((Join-Path $root $relativePath))
    $start=$sourceText.IndexOf('    $names=@($layout.Service')
    $end=$sourceText.IndexOf('    $seen=@{}',$start)
    if($start -lt 0 -or $end -le $start){throw 'Package validation block missing.'}
    $validateLayout=[scriptblock]::Create($sourceText.Substring($start,$end-$start))
    foreach($architecture in @('x64','arm64')) {
        $layout=Get-KProPackageLayout $architecture
        $baseNames=@($layout.Service,$layout.Dll,$layout.Driver,'DrvCfg2.dat','default-policy.hex')
        $manifest=[pscustomobject]@{files=@($baseNames|ForEach-Object{[pscustomobject]@{name=$_}})}
        & $validateLayout
        $manifest|Add-Member serviceProtection 'certificate-only'
        Denied {& $validateLayout}
        $manifest.files=@(($baseNames+@($layout.CertificateOnly))|ForEach-Object{[pscustomobject]@{name=$_}})
        & $validateLayout
        $manifest.serviceProtection='unknown'
        Denied {& $validateLayout}
    }
}
$manifest=[pscustomobject]@{releaseStatus='candidate';gates=$certificateManifest.gates;files=$files}
Denied {Assert-KProCandidatePermitFacts $permit ('0'*64) $transaction 'x64' $source 'install'}
Denied {Assert-KProCandidatePermitFacts $permit $device ('0'*32) 'x64' $source 'install'}
Denied {Assert-KProCandidatePermitFacts $permit $device $transaction 'arm64' $source 'install'}
Denied {Assert-KProCandidatePermitFacts $permit $device $transaction 'x64' ('0'*64) 'install'}
Denied {Assert-KProCandidatePermitFacts $permit $device $transaction 'x64' $source 'upgrade'}
Denied {Assert-KProCandidatePackage $permit $manifest ('0'*64) ('f'*64)}
Denied {Assert-KProCandidatePackage $permit $manifest $hash ('0'*64)}
$permit.expiresUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o')
Denied {Assert-KProCandidatePermitFacts $permit $device $transaction 'x64' $source 'install'}
$permit.expiresUtc=[DateTime]::UtcNow.AddHours(1).ToString('o')
$manifest.gates.policySignature=$false
Denied {Assert-KProCandidatePackage $permit $manifest $hash ('f'*64)}
$manifest.gates.policySignature=$true;$manifest.gates.endToEnd=$true
Denied {Assert-KProCandidatePackage $permit $manifest $hash ('f'*64)}
$manifest.releaseStatus='verified'
Denied {Assert-KProCandidatePackage $permit $manifest $hash ('f'*64)}
$manifest.releaseStatus='candidate'
$manifest.gates.endToEnd=$false
$manifest.files=@($files|ForEach-Object{[pscustomobject]@{name=$_.name;sha256=$_.sha256;size=$_.size}})
$manifest.files[0].sha256='0'*64
Denied {Assert-KProCandidatePackage $permit $manifest $hash ('f'*64)}
$manifest.files=$files[0..3]
Denied {Assert-KProCandidatePackage $permit $manifest $hash ('f'*64)}
Denied {& (Join-Path $root 'Invoke-FalconProCandidateValidation.ps1') -Mode install -ExpectedDeviceId $device -TransactionId $transaction -SourceManifestSha256 $source -ManifestSha256 $hash -ExpectedArchitecture x64 -PackageRoot . -DeliveryUserSid S-1-5-21-1-2-3-1001 -CandidatePermitPath missing.ps1 -CandidatePermitSha256 ('f'*64)}
$tmp=Join-Path ([IO.Path]::GetTempPath()) ('candidate-invalid-'+[Guid]::NewGuid().ToString('N')+'.ps1')
$handles=New-Object 'System.Collections.Generic.List[System.IDisposable]'
try {
    [IO.File]::WriteAllText($tmp,'# FALCONPRO-CANDIDATE-JSON: e30=')
    $invalidHash=(Get-FileHash $tmp).Hash.ToLowerInvariant()
    Denied {Get-KProCandidatePermit $tmp $invalidHash $device $transaction 'x64' $source 'install' $root $handles}
}finally{foreach($h in $handles){$h.Dispose()};Remove-Item -LiteralPath $tmp}
'PASS: candidate device, transaction, source, architecture, expiry, package, policy and evidence boundaries'
