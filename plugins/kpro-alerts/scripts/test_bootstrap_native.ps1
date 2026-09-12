$ErrorActionPreference='Stop'
$repo=(Get-Item $PSScriptRoot).Parent.Parent.Parent.FullName
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'falconpro.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($name in @('Assert-Plain','Digest','Json','Assert-Keys','Assert-AssetUrl','Expand-BoundZip','Assert-Descriptor')){
    $f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    if(-not $f){throw "Missing function $name"}
    . ([scriptblock]::Create($f.Extent.Text))
}
Import-Module (Join-Path $repo 'tools/KProReleaseTrust.psm1') -Force
$uac=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-Elevated'},$true)
$compile=$uac.Find({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-Type'},$true)
& ([scriptblock]::Create($compile.Extent.Text))
$info=[FalconPro.BootstrapUac].GetNestedType('Info',[Reflection.BindingFlags]::NonPublic)
if([Runtime.InteropServices.Marshal]::SizeOf([Activator]::CreateInstance($info)) -ne $(if([IntPtr]::Size -eq 8){112}else{60})){throw 'SHELLEXECUTEINFO ABI mismatch'}
function Reject([scriptblock]$Action){$failed=$false;try{& $Action}catch{$failed=$true};if(-not $failed){throw 'Invalid input was accepted'}}
foreach($url in @('http://github.com/YSheldon/KProAlert/releases/download/v1/a.zip','https://github.com.evil.invalid/a',
    'https://github.com/YSheldon/KProAlert/releases/download/v1/a.zip?q=x','https://github.com/YSheldon/KProAlert/releases/download/v1/../a.zip')){
    Reject {Assert-AssetUrl $url}
}
$url='https://github.com/YSheldon/KProAlert/releases/download/v1/a.zip'
Assert-AssetUrl $url
$d=[pscustomobject]@{schema='FalconProReleaseDescriptor/v1';version='1.2.0.300';platform='windows7-x86';releaseStatus='verified';
    packageManifestSha256='a'*64;sourceManifestSha256='b'*64;assets=[pscustomobject]@{
        package=[pscustomobject]@{url=$url;sha256='c'*64;size=100};onboarding=[pscustomobject]@{url=$url;sha256='d'*64;size=100}}}
Assert-Descriptor $d 'windows7-x86'
Reject {Assert-Descriptor $d 'windows11-x64'}
$d.assets.package.size='100';Reject {Assert-Descriptor $d 'windows7-x86'};$d.assets.package.size=100
$d.releaseStatus='candidate';Reject {Assert-Descriptor $d 'windows7-x86'};$d.releaseStatus='verified'
$d.version='01.2.0.300';Reject {Assert-Descriptor $d 'windows7-x86'}
$root=Join-Path ([IO.Path]::GetTempPath()) ('FalconPro-bootstrap-test-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
Add-Type -AssemblyName System.IO.Compression.FileSystem
try{
    $id=0
    foreach($names in @(@('item.txt'),@('../item.txt'),@('item.txt','ITEM.txt'),@('item.txt:stream'),@('unexpected.txt'))){
        $id++;$zipPath=Join-Path $root ($id.ToString()+'.zip');$target=Join-Path $root ($id.ToString()+'-out')
        $zip=[IO.Compression.ZipFile]::Open($zipPath,'Create')
        try{foreach($name in $names){$e=$zip.CreateEntry($name);$s=$e.Open();try{$s.WriteByte(42)}finally{$s.Dispose()}}}finally{$zip.Dispose()}
        if($id -eq 1){
            Expand-BoundZip $zipPath $target @('item.txt')
            if([IO.File]::ReadAllBytes((Join-Path $target 'item.txt'))[0] -ne 42){throw 'Unpacked bytes differ'}
            Reject {Expand-BoundZip $zipPath $target @('item.txt')}
        }else{Reject {Expand-BoundZip $zipPath $target @('item.txt')};if(Test-Path $target){throw 'Invalid ZIP created destination'}}
    }
}finally{
    $full=[IO.Path]::GetFullPath($root)
    if(-not $full.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture escaped temp'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
$image=New-Object byte[] 512;$image[0]=0x4d;$image[1]=0x5a
[BitConverter]::GetBytes([int]128).CopyTo($image,60);$image[128]=0x50;$image[129]=0x45
[BitConverter]::GetBytes([uint16]0x14c).CopyTo($image,132)
[BitConverter]::GetBytes([uint16]224).CopyTo($image,148)
[BitConverter]::GetBytes([uint16]0x10b).CopyTo($image,152)
Assert-KProPeArchitecture $image x86 -RequireForceIntegrity $false
Reject {Assert-KProPeArchitecture $image x86 -RequireForceIntegrity $true}
[BitConverter]::GetBytes([uint16]0x80).CopyTo($image,222)
Assert-KProPeArchitecture $image x86 -RequireForceIntegrity $true
Reject {Assert-KProPeArchitecture $image x86 -RequireForceIntegrity $false}
Reject {Assert-KProPeArchitecture $image x64}
'PASS: bootstrap descriptor/ZIP bounds, x86 PE and legacy/modern integrity distinction'
