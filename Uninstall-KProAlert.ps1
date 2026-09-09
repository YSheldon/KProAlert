#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ManifestSha256,
    [switch]$Apply
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:ProgramFiles 'KProAlert'
$manifest = Join-Path $root 'release-manifest.json'
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw 'Installed manifest missing; use manual product recovery.' }
foreach ($path in @($root,$manifest)) {
    if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse installation rejected.' }
}
if ((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ne $ManifestSha256) { throw 'Installed manifest mismatch.' }
$package = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
$entry = @($package.files | Where-Object {$_.name -ceq 'KProSvc.exe'})
$exe = Join-Path $root 'KProSvc.exe'
if ($entry.Count -ne 1 -or (Get-FileHash -LiteralPath $exe).Hash -ne $entry[0].sha256) { throw 'Installed service hash mismatch.' }
if ((Get-AuthenticodeSignature -LiteralPath $exe).Status -ne 'Valid') { throw 'Installed service signature invalid.' }
$service = Get-CimInstance Win32_Service -Filter "Name='KProSvc'"
if (-not $service -or $service.PathName -cne ('"'+$exe+'"')) { throw 'Unexpected service path; do not touch another installation.' }
if (-not $Apply) {
    @{mode='uninstall-plan';usesProductAuthorization=$true;retainsEvidence=$true;
      stopUserDeliverySeparately=$true} | ConvertTo-Json
    return
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator consent is required.'
}
if (-not $PSCmdlet.ShouldProcess($root, 'Product-authorized uninstall and evidence-preserving archive')) { return }
function Invoke-Sc([string[]]$Arguments) {
    & "$env:SystemRoot\System32\sc.exe" @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Service command failed ($LASTEXITCODE); retain evidence." }
}
# Keep a copy in the protected installation evidence after the product finishes.
$result = Join-Path $root ('uninstall-'+[Guid]::NewGuid().ToString('N')+'.json')
if ((Get-Service KProSvc).Status -ne 'Stopped') {
    Invoke-Sc @('stop','KProSvc')
    (Get-Service KProSvc).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(90))
}
# Service arguments cross sc.exe; use a space-free SystemRoot receipt directory.
$receiptRoot = Join-Path $env:SystemRoot ('Temp\KProAlertUninstall-'+[Guid]::NewGuid().ToString('N'))
if ($receiptRoot.Contains(' ')) { throw 'Unsupported SystemRoot path; use product recovery.' }
New-Item -ItemType Directory -Path $receiptRoot | Out-Null
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl',
        'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
Set-Acl -LiteralPath $receiptRoot -AclObject $acl
$receiptPath = Join-Path $receiptRoot 'result.json'
Invoke-Sc @('start','KProSvc','--uninstall',$receiptPath)
$deadline = [DateTime]::UtcNow.AddSeconds(90)
do {
    Start-Sleep -Milliseconds 500
    $stopped = (Get-Service KProSvc).Status -eq 'Stopped'
} until (($stopped -and (Test-Path -LiteralPath $receiptPath)) -or [DateTime]::UtcNow -gt $deadline)
if (-not $stopped -or -not (Test-Path -LiteralPath $receiptPath)) { throw 'Product uninstall did not finish.' }
$receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
Copy-Item -LiteralPath $receiptPath -Destination $result
if ($receipt.hr -ne 0 -or $receipt.success -ne $true) { throw 'Product authorization/uninstall failed; no service or file deletion performed.' }
if (Get-Service KProFilter -ErrorAction SilentlyContinue) { throw 'Driver remains registered; preserve environment for diagnosis.' }
if (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\drivers\KProFilter.sys')) { throw 'Driver file remains; preserve environment for diagnosis.' }
Invoke-Sc @('delete','KProSvc')
if (Get-Service KProSvc -ErrorAction SilentlyContinue) { throw 'Service deletion still pending.' }
$archive = Join-Path $env:ProgramFiles ('KProAlert.uninstalled-'+[Guid]::NewGuid().ToString('N'))
if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($archive)) -ne [IO.Path]::GetFullPath($env:ProgramFiles)) {
    throw 'Archive escaped intended parent.'
}
Move-Item -LiteralPath $root -Destination $archive
@{mode='uninstalled';productAuthorized=$true;serviceAbsent=$true;driverServiceAbsent=$true;
  evidenceDirectory=$archive;receiptDirectory=$receiptRoot;userDataDeleted=$false} | ConvertTo-Json
