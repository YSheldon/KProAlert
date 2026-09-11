$ErrorActionPreference='Stop'
$root=Resolve-Path (Join-Path $PSScriptRoot '../../..')
Import-Module (Join-Path $root 'tools/KProReleaseTrust.psm1') -Force
$savedProgramFiles=$env:ProgramFiles
try {
    $env:ProgramFiles='C:\attacker-controlled-placeholder'
    $actual=Get-KProNativeProgramFiles
    if($actual -eq $env:ProgramFiles -or -not [IO.Path]::IsPathRooted($actual)){throw 'Untrusted environment selected the install directory.'}
} finally {$env:ProgramFiles=$savedProgramFiles}
$arm=Get-KProPackageLayout -Architecture arm64
$x64=Get-KProPackageLayout -Architecture x64
if($arm.Service -cne 'KProSvcArm.exe' -or $arm.Dll -cne 'KProProtectArm.dll' -or $arm.Driver -cne 'KProFilterArm.sys') {throw 'ARM delivery names are incorrect.'}
if($x64.Service -cne 'KProSvc.exe' -or $x64.Dll -cne 'KProProtect.dll' -or $x64.Driver -cne 'KProFilter.sys') {throw 'x64 names changed.'}
$image=New-Object byte[] 512
$image[0]=0x4d;$image[1]=0x5a
[BitConverter]::GetBytes([int]128).CopyTo($image,60)
$image[128]=0x50;$image[129]=0x45
[BitConverter]::GetBytes([uint16]0xaa64).CopyTo($image,132)
[BitConverter]::GetBytes([uint16]0x20b).CopyTo($image,152)
Assert-KProPeArchitecture -Bytes $image -Architecture arm64
$denied=$false
try{Assert-KProPeArchitecture -Bytes $image -Architecture x64}catch{$denied=$true}
if(-not $denied){throw 'ARM binary admitted as x64.'}
[BitConverter]::GetBytes([int]510).CopyTo($image,60)
$denied=$false
try{Assert-KProPeArchitecture -Bytes $image -Architecture arm64}catch{$denied=$true}
if(-not $denied){throw 'Out-of-bounds PE offset admitted.'}
foreach($scriptName in @('Install-FalconPro.ps1','Install-KProAlert.ps1')) {
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root $scriptName),[ref]$null,[ref]$null)
    $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-LockedInput'},$true)
    if($null -eq $function){throw "Missing locked input capture in $scriptName"}
    . ([scriptblock]::Create($function.Extent.Text))
    $inputHandles=New-Object 'System.Collections.Generic.List[System.IDisposable]'
    $temp=Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N')+'.txt')
    try {
        [IO.File]::WriteAllText($temp,'signed input')
        $captured=Read-LockedInput $temp 1024
        if([Text.Encoding]::UTF8.GetString($captured) -cne 'signed input'){throw 'Capture differs.'}
        $denied=$false
        try{$writer=[IO.File]::Open($temp,'Open','Write','ReadWrite');$writer.Dispose()}catch{$denied=$true}
        if(-not $denied){throw 'Input remained writable after capture.'}
        $denied=$false
        try{[IO.File]::Delete($temp)}catch{$denied=$true}
        if(-not $denied){throw 'Input remained replaceable after capture.'}
    } finally {
        foreach($handle in $inputHandles){$handle.Dispose()}
        if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp}
    }
}
'PASS: architecture-specific names and PE mismatch rejection'
