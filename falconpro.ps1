#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('status','install','upgrade','resume','rollback')][string]$Mode='status',
    [ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedDeviceId,
    [string]$Destination,
    [string]$PlanPath,
    [switch]$Apply,
    [switch]$Approve
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$held=New-Object 'System.Collections.Generic.List[System.IDisposable]'
$trustedSourceNames=@('falconpro.ps1','Install-FalconPro.ps1','Install-KProAlert.ps1','Invoke-FalconProLifecycle.ps1','Uninstall-KProAlert.ps1',
    'plugins/kpro-alerts/scripts/EndpointFacts.ps1','plugins/kpro-alerts/scripts/Invoke-PolicySnapshot.ps1','tools/KProReleaseTrust.psm1')
$trustDigest='9403c82406972819dba630231250699717531c5761c8a781bc9763fb8bdd21f0'
$api='https://api.github.com/repos/YSheldon/KProAlert/releases/latest'
$assetPrefix='/YSheldon/KProAlert/releases/download/'

function Assert-Plain([string]$Path){
    $item=Get-Item -LiteralPath $Path -Force
    while($null -ne $item){
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse input rejected.'}
        if($item -is [IO.FileInfo]){$item=$item.Directory}else{$item=$item.Parent}
    }
}
function Read-BoundFile([string]$Path,[int]$Maximum){
    Assert-Plain $Path
    $stream=[IO.File]::Open($Path,'Open','Read','Read');$held.Add($stream)
    if($stream.Length -le 0 -or $stream.Length -gt $Maximum){throw 'Input size rejected.'}
    $bytes=New-Object byte[] ([int]$stream.Length);$position=0
    while($position -lt $bytes.Length){$n=$stream.Read($bytes,$position,$bytes.Length-$position);if($n -eq 0){throw 'Short read.'};$position+=$n}
    return ,$bytes
}
function Digest([byte[]]$Bytes){
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
}
function Json([byte[]]$Bytes){
    return ((New-Object Text.UTF8Encoding($false,$true)).GetString($Bytes).TrimStart([char]0xfeff)|ConvertFrom-Json)
}
function Assert-Keys($Object,[string[]]$Names){
    if($null -eq $Object -or @($Object.PSObject.Properties).Count -ne $Names.Count -or
       @($Object.PSObject.Properties.Name|Where-Object{$_ -cnotin $Names}).Count){throw 'Unexpected object fields.'}
}
function Assert-AssetUrl([string]$Url){
    $u=[Uri]$Url
    if($u.Scheme -cne 'https' -or $u.Authority -cne 'github.com' -or $u.UserInfo -or $u.Query -or $u.Fragment -or
       $Url -cnotmatch '^https://github\.com/YSheldon/KProAlert/releases/download/[A-Za-z0-9_-][A-Za-z0-9._-]*/[A-Za-z0-9_-][A-Za-z0-9._-]*$'){
        throw 'Release URL rejected.'
    }
}
function Read-Url([string]$Url,[int]$Maximum){
    if($Url -cne $api){Assert-AssetUrl $Url}
    $next=$Url
    for($redirect=0;$redirect -le 5;$redirect++){
        $request=[Net.HttpWebRequest]::Create($next)
        $request.AllowAutoRedirect=$false;$request.Timeout=30000;$request.ReadWriteTimeout=30000
        $request.UserAgent='FalconPro-bootstrap';$request.Accept='application/octet-stream'
        $request.UseDefaultCredentials=$false
        $response=$null
        try{
            $response=$request.GetResponse();$status=[int]$response.StatusCode
            if($status -in @(301,302,303,307,308)){
                $u=New-Object Uri(([Uri]$next),$response.Headers['Location'])
                if($u.Scheme -cne 'https' -or $u.Authority -cnotin @('github.com','release-assets.githubusercontent.com','objects.githubusercontent.com') -or $u.UserInfo){throw 'Redirect origin rejected.'}
                if($u.Host -ceq 'github.com'){Assert-AssetUrl $u.AbsoluteUri}
                $next=$u.AbsoluteUri;continue
            }
            if($status -ne 200 -or $response.ContentLength -gt $Maximum){throw 'Download response rejected.'}
            $stream=$response.GetResponseStream();$memory=New-Object IO.MemoryStream
            try{
                $buffer=New-Object byte[] 65536
                while(($n=$stream.Read($buffer,0,$buffer.Length)) -gt 0){
                    if($memory.Length+$n -gt $Maximum){throw 'Download exceeds budget.'}
                    $memory.Write($buffer,0,$n)
                }
                return ,$memory.ToArray()
            }finally{$memory.Dispose();$stream.Dispose()}
        }finally{if($response){$response.Close()}}
    }
    throw 'Too many download redirects.'
}
function Expand-BoundZip([string]$Archive,[string]$Target,[string[]]$Names){
    if(Test-Path -LiteralPath $Target){throw 'Extraction destination exists.'}
    Assert-Plain ([IO.Path]::GetDirectoryName($Target))
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip=[IO.Compression.ZipFile]::OpenRead($Archive)
    try{
        if($zip.Entries.Count -gt 100){throw 'Too many ZIP entries.'}
        $seen=@{};$total=0L
        foreach($entry in $zip.Entries){
            $name=$entry.FullName
            if($name.Contains('\') -or $name.Contains(':') -or $name.StartsWith('/') -or '..' -in $name.Split('/') -or
               (($entry.ExternalAttributes -shr 16) -band 0xf000) -eq 0xa000){throw 'Unsafe ZIP entry.'}
            if($name.EndsWith('/')){
                if(-not @($Names|Where-Object{$_.StartsWith($name,[StringComparison]::Ordinal)}).Count){throw 'Unknown ZIP directory.'}
                continue
            }
            if($name -cnotin $Names -or $seen.ContainsKey($name) -or $entry.Length -le 0 -or $entry.Length -gt 64MB){throw 'ZIP member rejected.'}
            $seen[$name]=$true;$total+=$entry.Length
            if($total -gt 256MB){throw 'Expanded ZIP exceeds budget.'}
        }
        if($seen.Count -ne $Names.Count){throw 'Incomplete ZIP member set.'}
        $null=New-Item -ItemType Directory -Path $Target
        foreach($entry in $zip.Entries){
            if($entry.FullName.EndsWith('/')){continue}
            $path=Join-Path $Target $entry.FullName
            $null=New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($path)) -Force
            Assert-Plain ([IO.Path]::GetDirectoryName($path))
            $input=$entry.Open();$output=$null
            try{
                $output=[IO.File]::Open($path,'CreateNew','Write','None');$buffer=New-Object byte[] 65536;$remaining=$entry.Length
                while($remaining -gt 0){$n=$input.Read($buffer,0,[int][Math]::Min($buffer.Length,$remaining));if($n -eq 0){throw 'Short ZIP member.'};$output.Write($buffer,0,$n);$remaining-=$n}
                if($input.ReadByte() -ne -1){throw 'ZIP member size changed.'}
            }finally{if($output){$output.Dispose()};$input.Dispose()}
        }
    }finally{$zip.Dispose()}
}
function Assert-Descriptor($Descriptor,[string]$Platform){
    Assert-Keys $Descriptor @('schema','version','platform','releaseStatus','packageManifestSha256','sourceManifestSha256','assets')
    if($Descriptor.schema -cne 'FalconProReleaseDescriptor/v1' -or $Descriptor.releaseStatus -cne 'verified' -or $Descriptor.platform -cne $Platform -or
       $Descriptor.version -cnotmatch '^(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){3}$'){throw 'Descriptor platform/status/version rejected.'}
    foreach($part in $Descriptor.version.Split('.')){if([int]$part -gt 65535){throw 'Version out of range.'}}
    foreach($key in @('packageManifestSha256','sourceManifestSha256')){if($Descriptor.$key -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid descriptor digest.'}}
    Assert-Keys $Descriptor.assets @('package','onboarding')
    foreach($kind in @('package','onboarding')){
        $asset=$Descriptor.assets.$kind;Assert-Keys $asset @('url','sha256','size');Assert-AssetUrl $asset.url
        if($asset.sha256 -cnotmatch '^[a-f0-9]{64}$' -or ($asset.size -isnot [int] -and $asset.size -isnot [long]) -or $asset.size -le 0 -or $asset.size -gt 256MB){throw 'Asset metadata rejected.'}
    }
}
function Assert-ReleaseTree([string]$Root,$Descriptor,$Layout){
    $sources=Join-Path $Root 'onboarding';$package=Join-Path $Root 'package'
    $sourceBytes=Read-BoundFile (Join-Path $sources 'onboarding-source.json') 16384
    if((Digest $sourceBytes) -cne $Descriptor.sourceManifestSha256){throw 'Source manifest changed.'}
    $sourceManifest=Json $sourceBytes
    if($sourceManifest.schema -cne 'FalconProOnboardingSource/v3' -or @($sourceManifest.files).Count -ne $trustedSourceNames.Count){throw 'Source schema rejected.'}
    $seen=@{}
    foreach($entry in $sourceManifest.files){
        Assert-Keys $entry @('name','sha256')
        if($entry.name -cnotin $trustedSourceNames -or $seen.ContainsKey($entry.name)){throw 'Source set rejected.'}
        $seen[$entry.name]=$true;$bytes=Read-BoundFile (Join-Path $sources $entry.name) 1MB
        if((Digest $bytes) -cne $entry.sha256){throw 'Source hash changed.'}
        if($entry.name.EndsWith('.ps1')){$null=Assert-KProReleaseAttestation -Bytes $bytes}
    }
    if((Digest (Read-BoundFile (Join-Path $sources 'tools/KProReleaseTrust.psm1') 1MB)) -cne $trustDigest){throw 'Downloaded trust module differs.'}
    $bytes=Read-BoundFile (Join-Path $package 'release-manifest.json') 65536
    if((Digest $bytes) -cne $Descriptor.packageManifestSha256){throw 'Package manifest changed.'}
    $manifest=Json $bytes
    if($manifest.schema -cne 'KProAlertRelease/v1' -or $manifest.releaseStatus -cne 'verified' -or $manifest.version -cne $Descriptor.version -or
       $manifest.platform -cne $Descriptor.platform -or $manifest.architecture -cne $architecture){throw 'Package platform/status/version rejected.'}
    foreach($gate in @('serviceF1ArtifactProduct','driverMicrosoftProduct','dllProduct','policySignature','endToEnd','privateRawEventSpool')){
        if($manifest.gates.$gate -isnot [bool] -or -not $manifest.gates.$gate){throw 'Package evidence gate incomplete.'}
    }
    $attestation=Read-BoundFile (Join-Path $package 'release-attestation.ps1') 65536
    $null=Assert-KProReleaseAttestation -Bytes $attestation
    $markers=[regex]::Matches((ConvertFrom-KProAttestationText -Bytes $attestation),'(?m)^# KPRO-MANIFEST-SHA256: ([A-Fa-f0-9]{64})\r?$')
    if($markers.Count -ne 1 -or $markers[0].Groups[1].Value -ine $Descriptor.packageManifestSha256){throw 'Attestation binding failed.'}
    $names=@($Layout.Service,$Layout.Dll,$Layout.Driver,'DrvCfg2.dat','default-policy.hex');$seen=@{}
    if(@($manifest.files).Count -ne $names.Count){throw 'Package count rejected.'}
    foreach($entry in $manifest.files){
        if($entry.name -cnotin $names -or $seen.ContainsKey($entry.name)){throw 'Package file set rejected.'}
        $seen[$entry.name]=$true;$path=Join-Path $package $entry.name;$bytes=Read-BoundFile $path 64MB
        if($bytes.Length -ne $entry.size -or (Digest $bytes) -cne $entry.sha256){throw 'Package file changed.'}
        if([IO.Path]::GetExtension($path) -in @('.exe','.dll','.sys')){
            Assert-KProPeArchitecture $bytes $architecture
            if([IO.Path]::GetExtension($path) -ne '.sys'){Assert-KProPeArchitecture $bytes $architecture -RequireForceIntegrity (-not $Layout.Legacy)}
            if((Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'Valid'){throw 'Package signature invalid.'}
        }
    }
}
function Invoke-Elevated([string]$Executable,[string[]]$Arguments){
    Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace FalconPro {
 public static class BootstrapUac {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Info {
   public uint Size,Mask; public IntPtr Window; public string Verb,File,Parameters,Directory; public int Show;
   public IntPtr Instance,IdList; public string Class; public IntPtr ClassKey; public uint HotKey; public IntPtr Icon,Process;
  }
  [DllImport("shell32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ShellExecuteExW(ref Info info);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr handle,out uint code);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("ole32.dll")] static extern int CoInitializeEx(IntPtr reserved,uint flags);
  [DllImport("ole32.dll")] static extern void CoUninitialize();
  public static int Run(string file,string arguments) {
   int initialized=CoInitializeEx(IntPtr.Zero,6);
   if(initialized!=0&&initialized!=1)throw new COMException("Cannot initialize the UAC shell apartment.",initialized);
   Info i=new Info();i.Size=(uint)Marshal.SizeOf(typeof(Info));i.Mask=0x140;i.Verb="runas";i.File=file;i.Parameters=arguments;i.Show=0;
   try {
    bool ok=ShellExecuteExW(ref i);int error=ok?0:Marshal.GetLastWin32Error();
    if(!ok){if(error==1223&&i.Process==IntPtr.Zero)return 1223;throw new Win32Exception(error);}
    if(i.Process==IntPtr.Zero)return -1;
    uint waited=WaitForSingleObject(i.Process,600000);if(waited==258)return -1;
    if(waited!=0)throw new Win32Exception(Marshal.GetLastWin32Error());
    uint code;if(!GetExitCodeProcess(i.Process,out code))throw new Win32Exception(Marshal.GetLastWin32Error());
    // Child exit 1223 is not cancellation of the UAC prompt.
    return code==1223?-2:unchecked((int)code);
   } finally {try{if(i.Process!=IntPtr.Zero)CloseHandle(i.Process);}finally{CoUninitialize();}}
  }
 }
}
'@
    $quoted=foreach($arg in $Arguments){
        if($arg -match '["\x00\r\n]'){throw 'Invalid native argument.'}
        '"'+[regex]::Replace($arg,'(\\+)$','$1$1')+'"'
    }
    return [FalconPro.BootstrapUac]::Run($Executable,($quoted -join ' '))
}

$tls=[Net.ServicePointManager]::SecurityProtocol
$stage='local_dependencies'
try{
    [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
    $module=Join-Path $PSScriptRoot 'tools/KProReleaseTrust.psm1'
    if((Digest (Read-BoundFile $module 1MB)) -cne $trustDigest){throw 'Trusted bootstrap dependency changed.'}
    Import-Module $module -Force
    $stage='bootstrap_signature'
    $null=Assert-KProReleaseAttestation -Bytes (Read-BoundFile $PSCommandPath 65536)
    $factsScript=Join-Path $PSScriptRoot 'plugins/kpro-alerts/scripts/EndpointFacts.ps1'
    $null=Assert-KProReleaseAttestation -Bytes (Read-BoundFile $factsScript 65536)
    $stage='endpoint_identity'
    $facts=& $factsScript|ConvertFrom-Json
    if($facts.schema -cne 'FalconProEndpointFacts/v2' -or $facts.deviceId -cnotmatch '^[a-f0-9]{64}$'){throw 'Local endpoint facts unavailable.'}
    if($Mode -eq 'status'){$facts|ConvertTo-Json -Compress;return}
    $stage='prerequisites'
    $framework=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction Stop
    if([int]$framework.Release -lt 461808){throw '.NET Framework 4.7.2 or later is required.'}
    if(-not $facts.supported -or $facts.deviceId -cne $ExpectedDeviceId -or $facts.conflicts){throw 'Endpoint is unsupported, conflicting or not bound.'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$sid=$identity.User.Value
    if($sid -cnotmatch '^S-1-5-21-[0-9-]+$'){throw 'A local user identity is required.'}
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Start the bootstrap as a normal user; it requests UAC after approval.'}
    $architecture=$facts.architecture;$platform=$facts.platform
    $layout=Get-KProPackageLayout $architecture -Platform $platform
    if($PlanPath){
        $stage='plan_binding'
        $plan=Json (Read-BoundFile ([IO.Path]::GetFullPath($PlanPath)) 65536)
        Assert-Keys $plan @('schema','operation','deviceId','architecture','platform','transactionId','releaseRoot','version','manifestSha256','sourceManifestSha256','deliveryUserSid','requiresApproval','installPerformed')
        if($plan.schema -cne 'FalconProLifecyclePlan/v3' -or $plan.deviceId -cne $ExpectedDeviceId -or $plan.architecture -cne $architecture -or
           $plan.platform -cne $platform -or $plan.deliveryUserSid -cne $sid -or $plan.transactionId -cnotmatch '^[a-f0-9]{32}$' -or
           $plan.requiresApproval -isnot [bool] -or -not $plan.requiresApproval -or $plan.installPerformed -isnot [bool] -or $plan.installPerformed -or
           $plan.operation -cnotin @('install','upgrade') -or ($Mode -cin @('install','upgrade') -and $Mode -cne $plan.operation)) {throw 'Plan binding rejected.'}
        $root=[IO.Path]::GetFullPath($plan.releaseRoot)
        if($root -cne $plan.releaseRoot){throw 'Absolute canonical release root required.'}
    }else{
        $stage='release_discovery'
        if($Mode -cnotin @('install','upgrade')){throw 'Resume/rollback requires the original plan.'}
        $ok=if($Mode -ceq 'install'){$facts.service -ceq 'absent' -and $facts.driver -ceq 'absent' -and -not $facts.residualFiles}else{$facts.service -ceq 'running' -and $facts.driver -ceq 'running'}
        if(-not $ok){throw 'Endpoint state does not permit this operation.'}
        if(-not $Destination){$Destination=Join-Path ([IO.Path]::GetTempPath()) ('FalconPro-'+[Guid]::NewGuid().ToString('N'))}
        $root=[IO.Path]::GetFullPath($Destination).TrimEnd('\');Assert-Plain ([IO.Path]::GetDirectoryName($root))
        if(Test-Path -LiteralPath $root){throw 'Use a new staging directory.'}
        $release=Json (Read-Url $api 1MB)
        if($release.draft -isnot [bool] -or $release.draft -or $release.prerelease -isnot [bool] -or $release.prerelease -or
           $release.tag_name -cnotmatch '^[A-Za-z0-9_-][A-Za-z0-9._-]*$' -or @($release.assets).Count -gt 100){throw 'Stable release not published.'}
        $descriptorName=switch($platform){'windows11-x64'{'FalconPro-release.ps1'}'windows11-arm64'{'FalconPro-release-arm64.ps1'}default{'FalconPro-release-'+$platform+'.ps1'}}
        $asset=@($release.assets|Where-Object name -CEQ $descriptorName)
        if($asset.Count -ne 1){throw 'This platform release is not published.'}
        $descriptorBytes=Read-Url $asset[0].browser_download_url 65536
        $descriptor=Get-KProSignedReleaseDescriptor -Bytes $descriptorBytes;Assert-Descriptor $descriptor $platform
        $prefix='https://github.com'+$assetPrefix+$release.tag_name+'/'
        foreach($url in @($asset[0].browser_download_url,$descriptor.assets.package.url,$descriptor.assets.onboarding.url)){
            if(-not $url.StartsWith($prefix,[StringComparison]::Ordinal)){throw 'Release tag mismatch.'}
        }
        $stage='release_download'
        $null=New-Item -ItemType Directory -Path $root
        foreach($kind in @('package','onboarding')){
            $a=$descriptor.assets.$kind;$bytes=Read-Url $a.url $a.size
            if($bytes.Length -ne $a.size -or (Digest $bytes) -cne $a.sha256){throw 'Downloaded archive changed.'}
            $zip=Join-Path $root ($kind+'.zip');[IO.File]::WriteAllBytes($zip,$bytes)
            $names=if($kind -ceq 'package'){@($layout.Service,$layout.Dll,$layout.Driver,'DrvCfg2.dat','default-policy.hex','release-manifest.json','release-attestation.ps1')}else{@($trustedSourceNames)+@('onboarding-source.json')}
            Expand-BoundZip $zip (Join-Path $root $kind) $names
        }
        [IO.File]::WriteAllBytes((Join-Path $root 'FalconPro-release.ps1'),$descriptorBytes)
        $plan=[ordered]@{schema='FalconProLifecyclePlan/v3';operation=$Mode;deviceId=$ExpectedDeviceId;architecture=$architecture;platform=$platform;
            transactionId=[Guid]::NewGuid().ToString('N');releaseRoot=$root;version=$descriptor.version;manifestSha256=$descriptor.packageManifestSha256;
            sourceManifestSha256=$descriptor.sourceManifestSha256;deliveryUserSid=$sid;requiresApproval=$true;installPerformed=$false}
    }
    $stage='release_verification'
    $descriptor=Get-KProSignedReleaseDescriptor -Bytes (Read-BoundFile (Join-Path $root 'FalconPro-release.ps1') 65536)
    Assert-Descriptor $descriptor $platform
    if($descriptor.packageManifestSha256 -cne $plan.manifestSha256 -or $descriptor.sourceManifestSha256 -cne $plan.sourceManifestSha256 -or $descriptor.version -cne $plan.version){throw 'Plan differs from signed release.'}
    Assert-ReleaseTree $root $descriptor $layout
    if(-not $PlanPath){
        $PlanPath=Join-Path $root 'lifecycle-plan.json';$f=[IO.File]::Open($PlanPath,'CreateNew','Write','None')
        try{$b=[Text.Encoding]::UTF8.GetBytes(($plan|ConvertTo-Json -Depth 8));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
    }
    if(-not $Apply){@{state='ready_for_approval';plan=$plan;planPath=$PlanPath;installPerformed=$false}|ConvertTo-Json -Depth 8;return}
    if(-not $Approve){throw 'Explicit approval of this local device and version is required.'}
    $windows=[string](Get-CimInstance Win32_OperatingSystem).WindowsDirectory
    $system=if([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess){'Sysnative'}else{'System32'}
    $exe=Join-Path $windows ($system+'\WindowsPowerShell\v1.0\powershell.exe')
    $arguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',(Join-Path $root 'onboarding/Invoke-FalconProLifecycle.ps1'),
        '-Mode',$Mode,'-ExpectedDeviceId',$ExpectedDeviceId,'-ExpectedArchitecture',$architecture,'-ExpectedPlatform',$platform,
        '-TransactionId',$plan.transactionId,'-SourceManifestSha256',$plan.sourceManifestSha256,'-ManifestSha256',$plan.manifestSha256,
        '-PackageRoot',(Join-Path $root 'package'),'-DeliveryUserSid',$sid,'-Approve','-Apply')
    $stage='native_elevation'
    $exitCode=Invoke-Elevated $exe $arguments
    if($exitCode -eq 1223){@{state='elevation_cancelled';nativeExitCode=1223;operationStarted=$false;outcomeUncertain=$false;installPerformed=$false;automaticRetry=$false}|ConvertTo-Json;return}
    if($exitCode -ne 0){@{state='attention_required';nativeExitCode=$exitCode;operationStarted=$true;outcomeUncertain=$true;automaticRetry=$false}|ConvertTo-Json;exit 1}
    $stage='native_result'
    $receipt=Json (Read-BoundFile (Join-Path (Get-KProNativeProgramFiles) ('FalconProTransactions\'+$plan.transactionId+'\result.json')) 16384)
    foreach($field in @('deviceId','architecture','platform','transactionId','sourceManifestSha256','manifestSha256','deliveryUserSid','operation','version')){
        if($receipt.$field -cne $plan.$field){throw 'Native result binding failed.'}
    }
    if($receipt.schema -cne 'FalconProLifecycleResult/v1' -or $receipt.phase -cnotin @('awaiting_reboot','complete','recovery_awaiting_reboot','rolled_back','cancelled_no_change','installation_aborted')){throw 'Native result incomplete.'}
    if($receipt.phase -ceq 'installation_aborted' -and ($Mode -cne 'rollback' -or $plan.operation -cne 'install' -or $receipt.installedVersion -cne '')){throw 'Invalid aborted-install outcome.'}
    @{state=$receipt.phase;transactionId=$plan.transactionId;version=$receipt.installedVersion;rebootRequired=$receipt.phase.EndsWith('awaiting_reboot');automaticRetry=$false}|ConvertTo-Json
}catch{
    @{state='blocked';stage=$stage;errorClass=$_.Exception.GetType().Name;automaticRetry=$false}|ConvertTo-Json
    exit 1
}finally{
    foreach($item in $held){$item.Dispose()}
    [Net.ServicePointManager]::SecurityProtocol=$tls
}
