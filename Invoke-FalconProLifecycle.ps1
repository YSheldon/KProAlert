#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('install','upgrade','resume','rollback')][string]$Mode,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedDeviceId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$TransactionId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$SourceManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha256,
    [Parameter(Mandatory)][string]$PackageRoot,
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-[0-9-]+$')][string]$DeliveryUserSid,
    [switch]$Approve,
    [switch]$Apply
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$held=New-Object 'System.Collections.Generic.List[System.IDisposable]'
$transactionLock=$null
$state=$null
$transactionRoot=$null

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
    if($manifest.schema -cne 'KProAlertRelease/v1' -or $manifest.releaseStatus -cne 'verified' -or
        $manifest.platform -cne 'windows11-x64' -or $manifest.architecture -cne 'x64' -or
        $manifest.version -cnotmatch '^(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){3}$'){throw 'Package release rejected.'}
    foreach($gate in @('serviceF1ArtifactProduct','driverMicrosoftProduct','dllProduct','policySignature','endToEnd','privateRawEventSpool')) {
        if($manifest.gates.$gate -isnot [bool] -or -not $manifest.gates.$gate){throw 'Release evidence incomplete.'}
    }
    $names=@('KProSvc.exe','KProProtect.dll','KProFilter.sys','DrvCfg2.dat','default-policy.hex')
    if(@($manifest.files).Count -ne $names.Count){throw 'Package count mismatch.'}
    $seen=@{}
    foreach($entry in $manifest.files) {
        if($entry.name -cnotin $names -or $seen.ContainsKey($entry.name)){throw 'Package name rejected.'}
        $seen[$entry.name]=$true
        $path=Join-Path $Root $entry.name
        $content=Read-Captured $path 67108864
        if($content.Length -ne $entry.size -or (Digest $content) -ine $entry.sha256){throw 'Package file mismatch.'}
        if([IO.Path]::GetExtension($path) -in @('.exe','.dll','.sys') -and
            (Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'Valid'){throw 'Package signature invalid.'}
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
    $health=Decode (Read-Captured (Join-Path $installed 'collector-health.json') 4096)
    $file=Get-Item -LiteralPath (Join-Path $installed 'collector-health.json')
    if($service.State -ne 'Running' -or $health.schema -cne 'KProCollectorHealth/v1' -or
       $health.status -ne 0 -or $health.stopped -ne $false -or $health.pid -ne $service.ProcessId -or
       $file.LastWriteTimeUtc -lt [DateTime]::UtcNow.AddSeconds(-60)){throw 'Fresh collector status missing.'}
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
    if(-not [Environment]::Is64BitProcess -or $arch.Count -ne 1 -or $arch[0] -ne 9 -or $os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000){throw 'Unsupported native platform.'}
    $sourceBytes=Read-Captured (Join-Path $PSScriptRoot 'onboarding-source.json') 16384
    if((Digest $sourceBytes) -cne $SourceManifestSha256){throw 'Source manifest mismatch.'}
    $sourceManifest=Decode $sourceBytes
    $names=@('Install-FalconPro.ps1','Install-KProAlert.ps1','Invoke-FalconProLifecycle.ps1','Uninstall-KProAlert.ps1',
             'plugins/kpro-alerts/scripts/EndpointFacts.ps1','plugins/kpro-alerts/scripts/Invoke-PolicySnapshot.ps1','tools/KProReleaseTrust.psm1')
    if($sourceManifest.schema -cne 'FalconProOnboardingSource/v2' -or @($sourceManifest.files).Count -ne $names.Count){throw 'Lifecycle source manifest required.'}
    $sources=@{}
    foreach($entry in $sourceManifest.files) {
        if($entry.name -cnotin $names -or $sources.ContainsKey($entry.name)){throw 'Source entry rejected.'}
        $data=Read-Captured (Join-Path $PSScriptRoot $entry.name) 1048576
        if((Digest $data) -cne $entry.sha256){throw 'Source hash mismatch.'}
        $sources[$entry.name]=$data
    }
    Import-Module (Join-Path $PSScriptRoot 'tools/KProReleaseTrust.psm1') -Force
    $new=Read-Package $PackageRoot $ManifestSha256
    $installed=Join-Path $nativeProgramFiles 'KProAlert'
    $parent=Join-Path $nativeProgramFiles 'FalconProTransactions'
    if(-not(Test-Path -LiteralPath $parent)){Protected-Directory $parent}
    Assert-Protected $parent
    $transactionLock=[IO.File]::Open((Join-Path $parent 'lifecycle.lock'),'OpenOrCreate','ReadWrite','None')
    $transactionRoot=Join-Path $parent $TransactionId
    if($Mode -in @('resume','rollback')) {
        Assert-Protected $transactionRoot
        $state=Decode (Read-Captured (Join-Path $transactionRoot 'result.json') 16384)
        Release-Files
        if($state.schema -cne 'FalconProLifecycleResult/v1' -or $state.transactionId -cne $TransactionId -or
           $state.deviceId -cne $ExpectedDeviceId -or $state.manifestSha256 -cne $ManifestSha256 -or
           $state.sourceManifestSha256 -cne $SourceManifestSha256 -or $state.deliveryUserSid -cne $DeliveryUserSid){throw 'Transaction mismatch.'}
        $sourceRoot=Join-Path $transactionRoot 'onboarding'
        foreach($name in $names){Assert-Protected (Join-Path $sourceRoot $name)}
        if($Mode -eq 'rollback') {
            if(-not $Apply -or -not $Approve){throw 'Explicit recovery approval required.'}
            if($state.oldManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or
               $state.phase -notin @('uninstalled','install_pending','awaiting_reboot')){throw 'Transaction not eligible for recovery.'}
            $recovery=Join-Path $transactionRoot 'recovery-package'
            Assert-Protected $recovery
            $null=Read-Package $recovery $state.oldManifestSha256
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
            Write-State 'recovery_install_pending'
            $restored=& (Join-Path $sourceRoot 'Install-FalconPro.ps1') -ExpectedDeviceId $ExpectedDeviceId `
                -SourceManifestSha256 $SourceManifestSha256 -PackageRoot $recovery -ManifestSha256 $state.oldManifestSha256 `
                -DeliveryUserSid $DeliveryUserSid -ApproveInstallation -Apply -Confirm:$false | ConvertFrom-Json
            if($restored.mode -cne 'service-running' -or $restored.collectorReady -ne $true){throw 'Recovery runtime failed.'}
            $null=Snapshot $state.oldManifestSha256 $state.policyDigest
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
        Write-State $(if($recovering){'rolled_back'}else{'complete'})
        $state|ConvertTo-Json -Depth 8 -Compress
        return
    }
    if(Test-Path -LiteralPath $transactionRoot){throw 'Transaction already exists; use resume after inspecting its state.'}
    if(-not $Apply){@{mode='verified-plan';operation=$Mode;version=$new.version;installsElamDriver=$false;requiresApproval=$true}|ConvertTo-Json;return}
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
    $state=[ordered]@{schema='FalconProLifecycleResult/v1';transactionId=$TransactionId;deviceId=$ExpectedDeviceId;
        sourceManifestSha256=$SourceManifestSha256;manifestSha256=$ManifestSha256;deliveryUserSid=$DeliveryUserSid;
        operation=$Mode;version=$new.version;phase='prepared';updatedUtc='';oldManifestSha256='';policyDigest='';
        bootIdentity=$os.LastBootUpTime.ToUniversalTime().ToString('o');evidenceDirectory='';recoveryEvidenceDirectory='';errorClass=''}
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
    $installedResult=& (Join-Path $sourceRoot 'Install-FalconPro.ps1') -ExpectedDeviceId $ExpectedDeviceId `
        -SourceManifestSha256 $SourceManifestSha256 -PackageRoot (Join-Path $transactionRoot 'package') `
        -ManifestSha256 $ManifestSha256 -DeliveryUserSid $DeliveryUserSid -ApproveInstallation -Apply -Confirm:$false | ConvertFrom-Json
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
