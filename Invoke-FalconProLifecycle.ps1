#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('install','upgrade','resume','rollback')][string]$Mode,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedDeviceId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$TransactionId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$SourceManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha256,
    [Parameter(Mandatory)][ValidateSet('x64','arm64')][string]$ExpectedArchitecture,
    [Parameter(Mandatory)][string]$PackageRoot,
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-[0-9-]+$')][string]$DeliveryUserSid,
    [switch]$Approve,
    [string]$CandidatePermitPath,
    [ValidatePattern('^[a-f0-9]{64}$')][string]$CandidatePermitSha256,
    [switch]$ApproveCandidateValidation,
    [switch]$Apply
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$held=New-Object 'System.Collections.Generic.List[System.IDisposable]'
$transactionLock=$null
$state=$null
$transactionRoot=$null
$candidatePermit=$null
$candidateValidation=[bool]($CandidatePermitPath -or $CandidatePermitSha256 -or $ApproveCandidateValidation)
if($candidateValidation -and (-not $CandidatePermitPath -or -not $CandidatePermitSha256 -or -not $ApproveCandidateValidation)) {
    throw 'Explicit candidate permit and validation approval required.'
}

function Read-Captured([string]$Path,[int]$Maximum) {
    $item=Get-Item -LiteralPath $Path -Force
    $ancestor=$item
    while($null -ne $ancestor) {
        if($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse input rejected.'}
        if($ancestor -is [IO.FileInfo]){$ancestor=$ancestor.Directory}else{$ancestor=$ancestor.Parent}
    }
    $stream=[IO.File]::Open($item.FullName,'Open','Read','Read')
    $held.Add($stream)
    if($stream.Length -le 0 -or $stream.Length -gt $Maximum){throw 'Input size rejected.'}
    $data=New-Object byte[] ([int]$stream.Length)
    $position=0
    while($position -lt $data.Length) {
        $count=$stream.Read($data,$position,$data.Length-$position)
        if($count -eq 0){throw 'Short file read.'}
        $position+=$count
    }
    return ,$data
}
function Digest([byte[]]$Bytes) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}
    finally{$sha.Dispose()}
}
function Decode([byte[]]$Bytes) {
    $utf8=New-Object Text.UTF8Encoding($false,$true)
    return ($utf8.GetString($Bytes).TrimStart([char]0xfeff)|ConvertFrom-Json)
}
function Protected-Directory([string]$Path) {
    if(Test-Path -LiteralPath $Path){throw 'Transaction directory already exists.'}
    $null=New-Item -ItemType Directory -Path $Path
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl',
            'ContainerInherit,ObjectInherit','None','Allow')))
    }
    # Permit the initiating user to read progress, never supply native authority.
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier($DeliveryUserSid)),'ReadAndExecute',
        'ContainerInherit,ObjectInherit','None','Allow')))
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-Protected $Path
}
function Assert-Protected([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force
    $mask=[Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    while($null -ne $item -and $item.FullName.TrimEnd('\') -ine $nativeProgramFiles.TrimEnd('\')) {
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse native path.'}
        $acl=Get-Acl -LiteralPath $item.FullName
        $raw=New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorBinaryForm(),0)
        if($null -eq $raw.DiscretionaryAcl){throw 'NULL DACL rejected.'}
        if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Native owner rejected.'}
        foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $mask) -ne 0 -and
                $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Native path is user writable.'}
        }
        if($item -is [IO.FileInfo]){$item=$item.Directory}else{$item=$item.Parent}
    }
    if($null -eq $item){throw 'Native path escaped Program Files.'}
}
function Write-State([string]$Phase) {
    $state.phase=$Phase
    $state.updatedUtc=[DateTime]::UtcNow.ToString('o')
    $bytes=[Text.Encoding]::UTF8.GetBytes(($state|ConvertTo-Json -Depth 8 -Compress))
    $target=Join-Path $transactionRoot 'result.json'
    $temp=Join-Path $transactionRoot ([Guid]::NewGuid().ToString('N')+'.tmp')
    $stream=[IO.File]::Open($temp,'CreateNew','Write','None')
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    if(Test-Path -LiteralPath $target){
        [IO.File]::Replace($temp,$target,(Join-Path $transactionRoot 'previous-result.json'),$true)
    }else{[IO.File]::Move($temp,$target)}
}
function Read-Package([string]$Root,[string]$Expected) {
    $bytes=Read-Captured (Join-Path $Root 'release-manifest.json') 65536
    if((Digest $bytes) -cne $Expected){throw 'Package manifest mismatch.'}
    $attestation=Read-Captured (Join-Path $Root 'release-attestation.ps1') 65536
    $null=Assert-KProReleaseAttestation -Bytes $attestation
    $text=ConvertFrom-KProAttestationText -Bytes $attestation
    $bindings=@([regex]::Matches($text,'(?m)^# KPRO-MANIFEST-SHA256: ([A-Fa-f0-9]{64})\r?$'))
    if($bindings.Count -ne 1 -or $bindings[0].Groups[1].Value -ine $Expected){throw 'Attestation mismatch.'}
    $manifest=Decode $bytes
    $layout=Get-KProPackageLayout -Architecture $ExpectedArchitecture
    if($manifest.schema -cne 'KProAlertRelease/v1' -or ($manifest.releaseStatus -cne 'verified' -and -not $candidateValidation) -or
        $manifest.platform -cne $layout.Platform -or $manifest.architecture -cne $ExpectedArchitecture -or
        $manifest.version -cnotmatch '^(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){3}$'){throw 'Package release rejected.'}
    if($candidateValidation){Assert-KProCandidatePackage $candidatePermit $manifest $Expected (Digest $attestation)}
    foreach($gate in @('serviceF1ArtifactProduct','driverMicrosoftProduct','dllProduct','policySignature','endToEnd','privateRawEventSpool')) {
        if($candidateValidation -and $manifest.releaseStatus -ceq 'candidate' -and $gate -ceq 'endToEnd'){continue}
        if($manifest.gates.$gate -isnot [bool] -or -not $manifest.gates.$gate){throw 'Release evidence incomplete.'}
    }
    $names=@($layout.Service,$layout.Dll,$layout.Driver,'DrvCfg2.dat','default-policy.hex')
    if(@($manifest.files).Count -ne $names.Count){throw 'Package count mismatch.'}
    $seen=@{}
    foreach($entry in $manifest.files) {
        if($entry.name -cnotin $names -or $seen.ContainsKey($entry.name)){throw 'Package name rejected.'}
        $seen[$entry.name]=$true
        $path=Join-Path $Root $entry.name
        $content=Read-Captured $path 67108864
        if($content.Length -ne $entry.size -or (Digest $content) -ine $entry.sha256){throw 'Package file mismatch.'}
        if([IO.Path]::GetExtension($path) -in @('.exe','.dll','.sys')) {
            Assert-KProPeArchitecture -Bytes $content -Architecture $ExpectedArchitecture
            if((Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'Valid'){throw 'Package signature invalid.'}
        }
    }
    return $manifest
}
function Copy-Package([string]$From,[string]$To,$Manifest) {
    Protected-Directory $To
    foreach($name in @($Manifest.files.name)+@('release-manifest.json','release-attestation.ps1')) {
        $content=Read-Captured (Join-Path $From $name) 67108864
        [IO.File]::WriteAllBytes((Join-Path $To $name),$content)
        if((Get-FileHash -LiteralPath (Join-Path $To $name)).Hash -ine (Digest $content)){throw 'Backup/staging readback mismatch.'}
    }
}
function Release-Files {foreach($file in $held){$file.Dispose()};$held.Clear()}
function Snapshot([string]$InstalledHash,[string]$Expected='') {
    $args=@{ExpectedDeviceId=$ExpectedDeviceId;TransactionId=($TransactionId+$TransactionId);ManifestSha256=$InstalledHash}
    if($candidateValidation){$args.CandidatePermitPath=$CandidatePermitPath;$args.CandidatePermitSha256=$CandidatePermitSha256;$args.SourceManifestSha256=$SourceManifestSha256}
    if($Expected){$args.ExpectedDigest=$Expected}
    $native=& (Join-Path $sourceRoot 'plugins/kpro-alerts/scripts/Invoke-PolicySnapshot.ps1') @args | ConvertFrom-Json
    if($native.schema -cne 'FalconProNativeSnapshot/v1' -or $native.exitCode -ne 0){throw 'Native policy snapshot unavailable.'}
    $reply=Decode ([Convert]::FromBase64String($native.stdoutBase64))
    $age=([DateTime]::UtcNow-[DateTime]::FromFileTimeUtc([long]$reply.observedAtFileTime)).TotalSeconds
    if($reply.schema -cne 'FalconProPolicySnapshot/v1' -or $reply.success -ne $true -or $reply.hr -ne 0 -or
        $reply.transactionId -cne ($TransactionId+$TransactionId) -or $reply.deviceSha256 -cne $ExpectedDeviceId -or
        $reply.servicePid -ne $native.servicePid -or $age -lt -1 -or $age -gt 30 -or
        $reply.digestSha256 -cnotmatch '^[a-f0-9]{64}$' -or ($Expected -and $reply.digestSha256 -cne $Expected)) {
        throw 'Native snapshot binding/freshness failed.'
    }
    return $reply
}
function Assert-OrdinaryService {
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
    try {
        $key=$base.OpenSubKey('SYSTEM\CurrentControlSet\Services\KProSvc')
        if($null -eq $key){throw 'Installed service missing.'}
        try{if([int]$key.GetValue('LaunchProtected',0) -ne 0){throw 'PPL requires the service-internal upgrade transport.'}}
        finally{$key.Dispose()}
    }finally{$base.Dispose()}
}
function Assert-Collector {
    $service=Get-CimInstance Win32_Service -Filter "Name='KProSvc'"
    $driver=Get-Service KProFilter -ErrorAction Stop
    $health=Decode (Read-Captured (Join-Path $installed 'collector-health.json') 4096)
    $file=Get-Item -LiteralPath (Join-Path $installed 'collector-health.json')
    if($service.State -ne 'Running' -or $driver.Status -ne 'Running' -or $health.schema -cne 'KProCollectorHealth/v1' -or
       $health.status -ne 0 -or $health.stopped -ne $false -or $health.pid -ne $service.ProcessId -or
       $file.LastWriteTimeUtc -lt [DateTime]::UtcNow.AddSeconds(-60)){throw 'Fresh collector status missing.'}
}
function Cancel-UnchangedUpgrade {
    if($state.operation -cne 'upgrade' -or
       $state.phase -cnotin @('prepared','backup_ready','uninstall_pending','cancelled_no_change')) {
        throw 'This state cannot be reconciled as an unchanged upgrade.'
    }
    Assert-OrdinaryService
    Assert-Protected $installed
    $currentHash=Digest (Read-Captured (Join-Path $installed 'release-manifest.json') 65536)
    if($state.oldManifestSha256) {
        if($state.oldManifestSha256 -cne $currentHash -or $state.policyDigest -cnotmatch '^[a-f0-9]{64}$') {
            throw 'Old installation no longer matches the transaction.'
        }
    } elseif($state.phase -cne 'prepared') {throw 'Recovery binding is incomplete.'}
    $old=Read-Package $installed $currentHash
    $snapshot=Snapshot $currentHash $state.policyDigest
    Assert-Collector
    $state.oldManifestSha256=$currentHash
    $state.policyDigest=$snapshot.digestSha256
    $state.installedVersion=$old.version
    Release-Files
    # No stop, uninstall or reinstall occurs. This proves current integrity, not
    # uninterrupted availability during an earlier uncertain uninstall attempt.
    if($state.phase -cne 'cancelled_no_change'){Write-State 'cancelled_no_change'}
}
function Assert-RecoveryTargetAbsent {
    $facts=& (Join-Path $sourceRoot 'plugins/kpro-alerts/scripts/EndpointFacts.ps1') | ConvertFrom-Json
    if($facts.schema -cne 'FalconProEndpointFacts/v1' -or $facts.deviceId -cne $ExpectedDeviceId -or
       $facts.architecture -cne $ExpectedArchitecture -or $facts.supported -ne $true -or
       $facts.service -cne 'absent' -or $facts.driver -cne 'absent' -or
       $facts.conflicts -ne $false -or $facts.residualFiles -ne $false) {throw 'Recovery target is not cleanly absent.'}
}
try {
    $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator approval required.'}
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
    try {
        $key=$base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion')
        try{$nativeProgramFiles=[string]$key.GetValue('ProgramFilesDir')}finally{$key.Dispose()}
        $key=$base.OpenSubKey('SOFTWARE\Microsoft\Cryptography')
        try{$guid=[string]$key.GetValue('MachineGuid')}finally{$key.Dispose()}
    }finally{$base.Dispose()}
    if((Digest ([Text.Encoding]::UTF8.GetBytes('FalconPro-device-v1:'+$guid.ToLowerInvariant()))) -cne $ExpectedDeviceId){throw 'Device mismatch.'}
    $os=Get-CimInstance Win32_OperatingSystem
    $arch=@(Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Architecture -Unique)
    if(-not [Environment]::Is64BitProcess -or $arch.Count -ne 1 -or $arch[0] -notin @(9,12) -or $os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000){throw 'Unsupported native platform.'}
    $nativeArchitecture=if($arch[0] -eq 12){'arm64'}else{'x64'}
    if($nativeArchitecture -cne $ExpectedArchitecture){throw 'Native architecture differs from approved plan.'}
    $sourceBytes=Read-Captured (Join-Path $PSScriptRoot 'onboarding-source.json') 16384
    if((Digest $sourceBytes) -cne $SourceManifestSha256){throw 'Source manifest mismatch.'}
    $sourceManifest=Decode $sourceBytes
    $names=@('Install-FalconPro.ps1','Install-KProAlert.ps1','Invoke-FalconProLifecycle.ps1','Uninstall-KProAlert.ps1',
             'plugins/kpro-alerts/scripts/EndpointFacts.ps1','plugins/kpro-alerts/scripts/Invoke-PolicySnapshot.ps1','tools/KProReleaseTrust.psm1')
    $sourceSchema='FalconProOnboardingSource/v2'
    if($candidateValidation){$names+='Invoke-FalconProCandidateValidation.ps1';$sourceSchema='FalconProCandidateSource/v1'}
    if($sourceManifest.schema -cne $sourceSchema -or @($sourceManifest.files).Count -ne $names.Count){throw 'Lifecycle source manifest required.'}
    $sources=@{}
    foreach($entry in $sourceManifest.files) {
        if($entry.name -cnotin $names -or $sources.ContainsKey($entry.name)){throw 'Source entry rejected.'}
        $data=Read-Captured (Join-Path $PSScriptRoot $entry.name) 1048576
        if((Digest $data) -cne $entry.sha256){throw 'Source hash mismatch.'}
        $sources[$entry.name]=$data
    }
    if((Digest $sources['tools/KProReleaseTrust.psm1']) -cne '979c2d8cfd7e19317ae8e5752bad59f6431ac92d69777b5661b27ed7e1dd2639'){throw 'Native trust module mismatch.'}
    Import-Module (Join-Path $PSScriptRoot 'tools/KProReleaseTrust.psm1') -Force
    Assert-KProProgramFilesRoot $nativeProgramFiles
    if($candidateValidation) {
        $candidatePermit=Get-KProCandidatePermit $CandidatePermitPath $CandidatePermitSha256 $ExpectedDeviceId $TransactionId $ExpectedArchitecture $SourceManifestSha256 $Mode $PSScriptRoot $held
        if($candidatePermit.packages[0].manifestSha256 -cne $ManifestSha256){throw 'Candidate target manifest mismatch.'}
        $descriptorBytes=Read-Captured $CandidatePermitPath 65536
    } else {
        $descriptorBytes=Read-Captured (Join-Path (Split-Path $PSScriptRoot -Parent) 'FalconPro-release.ps1') 65536
        $descriptor=Get-KProSignedReleaseDescriptor -Bytes $descriptorBytes
        if($descriptor.sourceManifestSha256 -cne $SourceManifestSha256 -or $descriptor.packageManifestSha256 -cne $ManifestSha256 -or
            $descriptor.platform -cne (Get-KProPackageLayout $ExpectedArchitecture).Platform){throw 'Native descriptor binding mismatch.'}
    }
    $new=Read-Package $PackageRoot $ManifestSha256
    if($candidateValidation -and $new.releaseStatus -cne 'candidate'){throw 'Validation target must remain candidate.'}
    $installed=Join-Path $nativeProgramFiles 'KProAlert'
    $parent=Join-Path $nativeProgramFiles 'FalconProTransactions'
    if(-not(Test-Path -LiteralPath $parent)){Protected-Directory $parent}
    Assert-Protected $parent
    $transactionLock=[IO.File]::Open((Join-Path $parent 'lifecycle.lock'),'OpenOrCreate','ReadWrite','None')
    $transactionRoot=Join-Path $parent $TransactionId
    $candidateInstallArgs=@{}
    if($candidateValidation) {
        $CandidatePermitPath=Join-Path $transactionRoot 'candidate-permit.ps1'
        $candidateInstallArgs=@{ValidateCandidate=$true;CandidatePermitPath=$CandidatePermitPath;CandidatePermitSha256=$CandidatePermitSha256;
            ExpectedDeviceId=$ExpectedDeviceId;CandidateTransactionId=$TransactionId;CandidateOperation=$candidatePermit.operation;SourceManifestSha256=$SourceManifestSha256}
    }
    if($Mode -in @('resume','rollback')) {
        Assert-Protected $transactionRoot
        $state=Decode (Read-Captured (Join-Path $transactionRoot 'result.json') 16384)
        Release-Files
        $resultSchema=if($candidateValidation){'FalconProCandidateLifecycleResult/v1'}else{'FalconProLifecycleResult/v1'}
        if($state.schema -cne $resultSchema -or $state.transactionId -cne $TransactionId -or
           $state.deviceId -cne $ExpectedDeviceId -or $state.manifestSha256 -cne $ManifestSha256 -or
           $state.sourceManifestSha256 -cne $SourceManifestSha256 -or $state.deliveryUserSid -cne $DeliveryUserSid -or
           $state.architecture -cne $ExpectedArchitecture){throw 'Transaction mismatch.'}
        if($candidateValidation -and ($state.validationOnly -ne $true -or $state.candidatePermitSha256 -cne $CandidatePermitSha256 -or
            $state.operation -cne $candidatePermit.operation)){throw 'Candidate transaction mismatch.'}
        if(-not $candidateValidation -and $state.PSObject.Properties['validationOnly'] -and $state.validationOnly){throw 'Candidate cannot resume as production.'}
        $sourceRoot=Join-Path $transactionRoot 'onboarding'
        if($candidateValidation){$CandidatePermitPath=Join-Path $transactionRoot 'candidate-permit.ps1'}
        foreach($name in $names){Assert-Protected (Join-Path $sourceRoot $name)}
        if($Mode -eq 'resume' -and $state.phase -ceq 'cancelled_no_change') {
            Cancel-UnchangedUpgrade
            $state|ConvertTo-Json -Depth 8 -Compress
            return
        }
        if($Mode -eq 'rollback') {
            if(-not $Apply -or -not $Approve){throw 'Explicit recovery approval required.'}
            if($state.phase -cin @('prepared','backup_ready','uninstall_pending')) {
                Cancel-UnchangedUpgrade
                $state|ConvertTo-Json -Depth 8 -Compress
                return
            }
            if($state.oldManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or
               $state.phase -notin @('uninstalled','install_pending','awaiting_reboot')){throw 'Transaction not eligible for recovery.'}
            $recovery=Join-Path $transactionRoot 'recovery-package'
            Assert-Protected $recovery
            $oldPackage=Read-Package $recovery $state.oldManifestSha256
            if(Get-Service KProSvc -ErrorAction SilentlyContinue) {
                Assert-OrdinaryService
                $null=Read-Package $installed $ManifestSha256
                $null=Snapshot $ManifestSha256 $state.policyDigest
                Release-Files
                Write-State 'recovery_uninstall_pending'
                $removed=& (Join-Path $sourceRoot 'Uninstall-KProAlert.ps1') -ManifestSha256 $ManifestSha256 -Apply -Confirm:$false | ConvertFrom-Json
                if($removed.mode -cne 'uninstalled' -or $removed.productAuthorized -ne $true){throw 'New product uninstall incomplete.'}
                $state.recoveryEvidenceDirectory=$removed.evidenceDirectory
            }
            if((Get-Service KProSvc,KProFilter -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $installed)){throw 'Partial installation requires product recovery.'}
            Release-Files
            Assert-RecoveryTargetAbsent
            Write-State 'recovery_install_pending'
            # Recovery is already bound to this protected transaction's exact old
            # package, not the new release descriptor used for initial installation.
            $restored=& (Join-Path $sourceRoot 'Install-KProAlert.ps1') `
                -PackageRoot $recovery -ManifestSha256 $state.oldManifestSha256 `
                -DeliveryUserSid $DeliveryUserSid @candidateInstallArgs -Apply -Confirm:$false | ConvertFrom-Json
            if($restored.mode -cne 'service-running' -or $restored.collectorReady -ne $true){throw 'Recovery runtime failed.'}
            $null=Snapshot $state.oldManifestSha256 $state.policyDigest
            $state.installedVersion=$oldPackage.version
            $state.bootIdentity=$os.LastBootUpTime.ToUniversalTime().ToString('o')
            Write-State 'recovery_awaiting_reboot'
            $state|ConvertTo-Json -Depth 8 -Compress
            return
        }
        if($state.phase -notin @('awaiting_reboot','recovery_awaiting_reboot')){throw 'Uncertain native step: inspect product state, do not replay.'}
        if($state.bootIdentity -eq $os.LastBootUpTime.ToUniversalTime().ToString('o')){throw 'A normal user-controlled reboot is still required.'}
        $recovering=$state.phase -eq 'recovery_awaiting_reboot'
        $hash=if($recovering){$state.oldManifestSha256}else{$ManifestSha256}
        $null=Snapshot $hash $state.policyDigest
        Assert-Collector
        Write-State $(if($candidateValidation){if($recovering){'validation_rolled_back'}else{'validation_complete'}}elseif($recovering){'rolled_back'}else{'complete'})
        $state|ConvertTo-Json -Depth 8 -Compress
        return
    }
    if(Test-Path -LiteralPath $transactionRoot){throw 'Transaction already exists; use resume after inspecting its state.'}
    if(-not $Apply){@{mode=$(if($candidateValidation){'candidate-validation-plan'}else{'verified-plan'});validationOnly=$candidateValidation;operation=$Mode;version=$new.version;installsElamDriver=$false;requiresApproval=$true}|ConvertTo-Json;return}
    if(-not $Approve){throw 'Explicit installation/upgrade approval required.'}
    if(-not $PSCmdlet.ShouldProcess($ExpectedDeviceId,$Mode+' FalconPro '+$new.version)){return}
    Protected-Directory $transactionRoot
    $sourceRoot=Join-Path $transactionRoot 'onboarding'
    Protected-Directory $sourceRoot
    foreach($name in $names) {
        $path=Join-Path $sourceRoot $name
        $null=New-Item -ItemType Directory -Force -Path ([IO.Path]::GetDirectoryName($path))
        [IO.File]::WriteAllBytes($path,$sources[$name])
        if((Get-FileHash -LiteralPath $path).Hash -ine (Digest $sources[$name])){throw 'Staged source mismatch.'}
    }
    [IO.File]::WriteAllBytes((Join-Path $sourceRoot 'onboarding-source.json'),$sourceBytes)
    if($candidateValidation){
        $CandidatePermitPath=Join-Path $transactionRoot 'candidate-permit.ps1'
        [IO.File]::WriteAllBytes($CandidatePermitPath,$descriptorBytes)
    }else{[IO.File]::WriteAllBytes((Join-Path $transactionRoot 'FalconPro-release.ps1'),$descriptorBytes)}
    $state=[ordered]@{schema='FalconProLifecycleResult/v1';transactionId=$TransactionId;deviceId=$ExpectedDeviceId;
        sourceManifestSha256=$SourceManifestSha256;manifestSha256=$ManifestSha256;deliveryUserSid=$DeliveryUserSid;
        operation=$Mode;version=$new.version;architecture=$ExpectedArchitecture;installedVersion=$new.version;phase='prepared';updatedUtc='';oldManifestSha256='';policyDigest='';
        bootIdentity=$os.LastBootUpTime.ToUniversalTime().ToString('o');evidenceDirectory='';recoveryEvidenceDirectory='';errorClass=''}
    if($candidateValidation){$state.schema='FalconProCandidateLifecycleResult/v1';$state.validationOnly=$true;$state.productionEligible=$false;$state.candidatePermitSha256=$CandidatePermitSha256}
    Write-State 'prepared'
    Copy-Package $PackageRoot (Join-Path $transactionRoot 'package') $new
    if($Mode -eq 'upgrade') {
        Assert-OrdinaryService
        Assert-Protected $installed
        $oldHash=Digest (Read-Captured (Join-Path $installed 'release-manifest.json') 65536)
        $old=Read-Package $installed $oldHash
        if([version]$new.version -le [version]$old.version){throw 'Same-version replacement/downgrade rejected.'}
        foreach($name in @('default-policy.hex','DrvCfg2.dat')) {
            $oldEntry=@($old.files|Where-Object name -eq $name)[0]
            $newEntry=@($new.files|Where-Object name -eq $name)[0]
            if($oldEntry.sha256 -ine $newEntry.sha256){throw 'Signed policy/runtime migration is not an ordinary binary upgrade.'}
        }
        $snapshot=Snapshot $oldHash
        $state.oldManifestSha256=$oldHash
        $state.policyDigest=$snapshot.digestSha256
        Copy-Package $installed (Join-Path $transactionRoot 'recovery-package') $old
        Write-State 'backup_ready'
        $null=Snapshot $oldHash $state.policyDigest
        Release-Files
        Write-State 'uninstall_pending'
        $uninstall=& (Join-Path $sourceRoot 'Uninstall-KProAlert.ps1') -ManifestSha256 $oldHash -Apply -Confirm:$false | ConvertFrom-Json
        if($uninstall.mode -cne 'uninstalled' -or $uninstall.productAuthorized -ne $true -or
           $uninstall.serviceAbsent -ne $true -or $uninstall.driverServiceAbsent -ne $true){throw 'Product uninstall incomplete.'}
        $state.evidenceDirectory=$uninstall.evidenceDirectory
        Write-State 'uninstalled'
    }
    Release-Files
    Write-State 'install_pending'
    if($candidateValidation) {
        Assert-RecoveryTargetAbsent
        $installedResult=& (Join-Path $sourceRoot 'Install-KProAlert.ps1') -PackageRoot (Join-Path $transactionRoot 'package') `
            -ManifestSha256 $ManifestSha256 -DeliveryUserSid $DeliveryUserSid @candidateInstallArgs -Apply -Confirm:$false | ConvertFrom-Json
    }else{
        $installedResult=& (Join-Path $sourceRoot 'Install-FalconPro.ps1') -ExpectedDeviceId $ExpectedDeviceId `
        -SourceManifestSha256 $SourceManifestSha256 -PackageRoot (Join-Path $transactionRoot 'package') `
        -ManifestSha256 $ManifestSha256 -DeliveryUserSid $DeliveryUserSid -ApproveInstallation -Apply -Confirm:$false | ConvertFrom-Json
    }
    if($installedResult.mode -cne 'service-running' -or $installedResult.driverRunning -ne $true -or
       $installedResult.collectorReady -ne $true){throw 'Installation runtime readback incomplete.'}
    $snapshot=Snapshot $ManifestSha256 $state.policyDigest
    $state.policyDigest=$snapshot.digestSha256
    Write-State 'awaiting_reboot'
    $state|ConvertTo-Json -Depth 8 -Compress
}catch {
    if($null -ne $state -and $null -ne $transactionRoot) {
        $state.errorClass=$_.Exception.GetType().Name
        # Keep pending intent intact: it must not be mistaken for a safe retry.
        try{Write-State $state.phase}catch{}
    }
    '{"schema":"FalconProLifecycleError/v1","state":"attention_required","automaticRetry":false}'
    exit 1
}finally {
    Release-Files
    if($null -ne $transactionLock){$transactionLock.Dispose()}
}
