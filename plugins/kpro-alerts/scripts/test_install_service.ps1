$ErrorActionPreference = 'Stop'
$root = (Get-Item $PSScriptRoot).Parent.Parent.Parent.FullName
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Install-KProAlert.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Installer parse failure' }
$function = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-KProProtectionService'}, $true)
if (-not $function) { throw 'Missing service creation helper' }
. ([scriptblock]::Create($function.Extent.Text))
$script:failure = ''
function New-Service {
    param($Name, $BinaryPathName, $StartupType, $DisplayName, $ErrorAction)
    if ($Name -ne 'KProSvc' -or $StartupType -ne 'Manual') { throw 'Wrong service contract' }
    if ($script:failure -eq 'create') { throw 'Simulated SCM failure' }
    if ($BinaryPathName -cne '"C:\Program Files\KProAlert\KProSvc.exe"') { throw 'Path quoting lost' }
    $script:registeredPath = $BinaryPathName
}
function Get-CimInstance {
    param($ClassName, $Filter, $ErrorAction)
    if ($ClassName -ne 'Win32_Service' -or $Filter -ne "Name='KProSvc'") { throw 'Unexpected readback' }
    if ($script:failure -eq 'query') { throw 'Simulated CIM failure' }
    $path = if ($script:failure -eq 'path') { $script:registeredPath.Trim('"') } else { $script:registeredPath }
    $mode = if ($script:failure -eq 'mode') { 'Auto' } else { 'Manual' }
    $account = if ($script:failure -eq 'account') { 'LocalService' } else { 'LocalSystem' }
    [pscustomobject]@{PathName=$path;StartMode=$mode;StartName=$account}
}
New-KProProtectionService 'C:\Program Files\KProAlert\KProSvc.exe'
foreach ($failure in @('path','mode','account','query','create')) {
    $script:failure = $failure
    $rejected = $false
    try { New-KProProtectionService 'C:\Program Files\KProAlert\KProSvc.exe' } catch { $rejected = $true }
    if (-not $rejected) { throw "Failure accepted: $failure" }
}
'PASS: quoted manual creation and five fail-closed branches; no SCM mutation'
