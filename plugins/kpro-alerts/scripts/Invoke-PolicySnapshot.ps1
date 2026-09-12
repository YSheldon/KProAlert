#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedDeviceId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$TransactionId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha256,
    [ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedDigest,
    [string]$CandidatePermitPath,
    [ValidatePattern('^[a-f0-9]{64}$')][string]$CandidatePermitSha256,
    [ValidatePattern('^[a-f0-9]{64}$')][string]$SourceManifestSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$held=New-Object 'System.Collections.Generic.List[System.IDisposable]'
$child=$null

function Assert-ProgramFilesAcl {
    $acl=Get-Acl -LiteralPath $script:NativeProgramFiles
    $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorBinaryForm(),0)
    if($null -eq $descriptor.DiscretionaryAcl -or
        -not ($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent)) {
        throw 'Native Program Files DACL unavailable.'
    }
    $installer=New-Object Security.Principal.NTAccount('NT SERVICE','TrustedInstaller')
    $trusted=@('S-1-5-18','S-1-5-32-544',$installer.Translate([Security.Principal.SecurityIdentifier]).Value)
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted){throw 'OS directory owner untrusted.'}
    $writeMask=[Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly){continue}
        if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $writeMask) -ne 0 -and
            $rule.IdentityReference.Value -notin $trusted){throw 'OS directory writable by untrusted principal.'}
    }
}

function Assert-ProtectedPath([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force
    $ancestor=$item
    while($null -ne $ancestor) {
        if($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse path rejected.'}
        if($ancestor -is [IO.FileInfo]){$ancestor=$ancestor.Directory}else{$ancestor=$ancestor.Parent}
    }
    $prefix=$script:NativeProgramFiles.TrimEnd('\')+'\'
    if(-not $item.FullName.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Native sources must be staged below Program Files.'
    }
    $writeMask=[Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    $protectedAnchor=$false
    while($item.FullName.TrimEnd('\') -ine $script:NativeProgramFiles.TrimEnd('\')) {
        $acl=Get-Acl -LiteralPath $item.FullName
        $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if($owner -notin @('S-1-5-18','S-1-5-32-544')){throw 'Administrator-controlled staging required.'}
        $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorBinaryForm(),0)
        if($null -eq $descriptor.DiscretionaryAcl -or
            -not ($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent)) {
            throw 'NULL or absent DACL rejected.'
        }
        foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $writeMask) -ne 0 -and
                $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) {
                throw 'Writable source is not a native trust boundary.'
            }
        }
        if($item -is [IO.DirectoryInfo] -and $acl.AreAccessRulesProtected){$protectedAnchor=$true}
        if($item -is [IO.FileInfo]){$item=$item.Directory}else{$item=$item.Parent}
    }
    if(-not $protectedAnchor){throw 'Protected directory ACL anchor required.'}
}
function Read-Locked([string]$Path,[long]$Maximum) {
    Assert-ProtectedPath $Path
    Assert-ProtectedPath ([IO.Path]::GetDirectoryName($Path))
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $held.Add($stream)
    if($stream.Length -le 0 -or $stream.Length -gt $Maximum){throw 'File exceeds native limit.'}
    $bytes=New-Object byte[] ([int]$stream.Length)
    $offset=0
    while($offset -lt $bytes.Length) {
        $count=$stream.Read($bytes,$offset,$bytes.Length-$offset)
        if($count -eq 0){throw 'Short native file read.'}
        $offset+=$count
    }
    return ,$bytes
}
function Get-Digest([byte[]]$Bytes) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}
    finally{$sha.Dispose()}
}
try {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
        ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess)) {
        throw 'Elevated native Windows execution required.'
    }
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
    try {
        $key=$base.OpenSubKey('SOFTWARE\Microsoft\Cryptography')
        try{$guid=[string]$key.GetValue('MachineGuid')}finally{if($key){$key.Dispose()}}
        $key=$base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion')
        try{$programFiles=[string]$key.GetValue('ProgramFilesDir')}finally{if($key){$key.Dispose()}}
    }finally{$base.Dispose()}
    if($guid -cnotmatch '^[a-fA-F0-9-]{36}$' -or $programFiles -notmatch '^[A-Za-z]:\\' -or
        (Get-Digest ([Text.Encoding]::UTF8.GetBytes('FalconPro-device-v1:'+$guid.ToLowerInvariant()))) -cne $ExpectedDeviceId) {
        throw 'Bound device mismatch.'
    }
    $script:NativeProgramFiles=[IO.Path]::GetFullPath($programFiles).TrimEnd('\')
    Assert-ProgramFilesAcl
    Assert-ProtectedPath $PSCommandPath
    $root=Join-Path $programFiles 'KProAlert'
    $cpus=@(Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Architecture -Unique)
    if($cpus.Count -ne 1 -or $cpus[0] -notin @(0,9,12)){throw 'Unsupported native architecture.'}
    $architecture=switch([int]$cpus[0]){0{'x86'}9{'x64'}12{'arm64'}}
    $serviceName=switch($architecture){'arm64'{'KProSvcArm.exe'}'x86'{'KProSvc32.exe'}default{'KProSvc.exe'}}
    $exe=Join-Path $root $serviceName
    $service=Get-CimInstance Win32_Service -Filter "Name='KProSvc'"
    if($null -eq $service -or $service.State -ne 'Running' -or $service.ProcessId -eq 0 -or
        $service.StartName -ne 'LocalSystem' -or $service.PathName -cne ('"'+$exe+'"')) {
        throw 'Installed service identity mismatch.'
    }
    $manifestBytes=Read-Locked (Join-Path $root 'release-manifest.json') 65536
    if((Get-Digest $manifestBytes) -cne $ManifestSha256){throw 'Installed manifest mismatch.'}
    $module=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../tools/KProReleaseTrust.psm1'))
    $moduleBytes=Read-Locked $module 65536
    # Bound helper dependency; updating it requires a new reviewed/signed helper.
    if((Get-Digest $moduleBytes) -cne '9403c82406972819dba630231250699717531c5761c8a781bc9763fb8bdd21f0') {
        throw 'Native trust module mismatch.'
    }
    Import-Module $module -Force
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $platform=Get-KProPlatformForWindows ([Version]$os.Version) ([int]$os.BuildNumber) $architecture ([int]$os.ProductType)
    $layout=Get-KProPackageLayout -Architecture $architecture -Platform $platform
    $attestation=Read-Locked (Join-Path $root 'release-attestation.ps1') 65536
    $null=Assert-KProReleaseAttestation -Bytes $attestation
    $text=ConvertFrom-KProAttestationText -Bytes $attestation
    $bindings=@([regex]::Matches($text,'(?m)^# KPRO-MANIFEST-SHA256: ([A-Fa-f0-9]{64})\r?$'))
    if($bindings.Count -ne 1 -or $bindings[0].Groups[1].Value -ne $ManifestSha256){throw 'Attestation binding mismatch.'}
    $manifest=[Text.Encoding]::UTF8.GetString($manifestBytes).TrimStart([char]0xfeff)|ConvertFrom-Json
    $candidateValidation=[bool]($CandidatePermitPath -or $CandidatePermitSha256)
    if($candidateValidation) {
        if(-not $CandidatePermitPath -or -not $CandidatePermitSha256 -or -not $SourceManifestSha256 -or
           $TransactionId.Substring(0,32) -cne $TransactionId.Substring(32,32)){throw 'Candidate snapshot binding missing.'}
        $sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
        $permit=Get-KProCandidatePermit $CandidatePermitPath $CandidatePermitSha256 $ExpectedDeviceId $TransactionId.Substring(0,32) $architecture $SourceManifestSha256 'snapshot' $sourceRoot $held
        Assert-KProCandidatePackage $permit $manifest $ManifestSha256 (Get-Digest $attestation)
    }
    if($manifest.schema -cne 'KProAlertRelease/v1' -or ($manifest.releaseStatus -cne 'verified' -and -not $candidateValidation) -or
        $manifest.platform -cne $layout.Platform -or $manifest.architecture -cne $architecture) {
        throw 'Installed package is not an admitted release.'
    }
    foreach($gate in @('serviceF1ArtifactProduct','driverMicrosoftProduct','dllProduct','policySignature',
                       'endToEnd','privateRawEventSpool')) {
        if($candidateValidation -and $manifest.releaseStatus -ceq 'candidate' -and $gate -ceq 'endToEnd'){continue}
        if($manifest.gates.$gate -isnot [bool] -or $manifest.gates.$gate -ne $true){throw 'Installed release gate missing.'}
    }
    $names=@($layout.Service,$layout.Dll,$layout.Driver,'DrvCfg2.dat','default-policy.hex')
    if(@($manifest.files).Count -ne $names.Count){throw 'Invalid release file count.'}
    $seen=@{}
    foreach($file in $manifest.files) {
        if($file.name -cnotin $names -or $seen.ContainsKey($file.name)){throw 'Invalid release file.'}
        $seen[$file.name]=$true
        $bytes=Read-Locked (Join-Path $root $file.name) 67108864
        if($bytes.Length -ne $file.size -or (Get-Digest $bytes) -ne $file.sha256){throw 'Installed file drift.'}
        if([IO.Path]::GetExtension($file.name) -in @('.exe','.dll')){
            Assert-KProPeArchitecture -Bytes $bytes -Architecture $architecture -RequireForceIntegrity (-not $layout.Legacy)
        }
    }
    if((Get-AuthenticodeSignature -LiteralPath $exe).Status -ne 'Valid'){throw 'Service signature failed.'}
    $child=New-Object Diagnostics.Process
    $child.StartInfo=New-Object Diagnostics.ProcessStartInfo
    $child.StartInfo.FileName=$exe
    $verb=if($ExpectedDigest){'--upgrade-verify'}else{'--upgrade-snapshot'}
    $child.StartInfo.Arguments=$verb+' '+$TransactionId
    if($ExpectedDigest){$child.StartInfo.Arguments+=' '+$ExpectedDigest}
    $child.StartInfo.WorkingDirectory=$root
    $child.StartInfo.UseShellExecute=$false
    $child.StartInfo.CreateNoWindow=$true
    $child.StartInfo.RedirectStandardOutput=$true
    $child.StartInfo.RedirectStandardError=$true
    $null=$child.Start()
    $stdout=$child.StandardOutput.ReadToEndAsync()
    $stderr=$child.StandardError.ReadToEndAsync()
    if(-not $child.WaitForExit(20000)) {
        # Only the spawned query client, never the resident service.
        $child.Kill()
        throw 'Native query timed out; upgrade denied.'
    }
    $raw=$stdout.GetAwaiter().GetResult()
    $errorText=$stderr.GetAwaiter().GetResult()
    if($child.ExitCode -ne 0 -or $raw.Length -gt 4096 -or $errorText.Length -ne 0){throw 'Snapshot query failed.'}
    $after=Get-CimInstance Win32_Service -Filter "Name='KProSvc'"
    if($after.State -ne 'Running' -or $after.ProcessId -ne $service.ProcessId -or $after.PathName -cne $service.PathName) {
        throw 'Resident service changed during query.'
    }
    [ordered]@{schema='FalconProNativeSnapshot/v1';servicePid=[uint32]$service.ProcessId;
        manifestSha256=$ManifestSha256;exitCode=$child.ExitCode;
        stdoutBase64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($raw))}|ConvertTo-Json -Compress
}catch {
    '{"schema":"FalconProNativeSnapshot/v1","error":"native_snapshot_failed"}'
    exit 1
}finally {
    if($null -ne $child){$child.Dispose()}
    foreach($item in $held){$item.Dispose()}
}
