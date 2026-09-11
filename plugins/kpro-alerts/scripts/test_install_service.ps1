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

$aclFunction = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-KProInstallRootAcl'}, $true)
if (-not $aclFunction) { throw 'Missing install root ACL readback helper' }
. ([scriptblock]::Create($aclFunction.Extent.Text))
$delivery = 'S-1-5-21-1-2-3-1001'
function New-TestRootAcl([string]$Failure) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection(($Failure -ne 'inheritance'),$false)
    $owner = if ($Failure -eq 'owner') { $delivery } else { 'S-1-5-32-544' }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($owner)))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544',$delivery)) {
        if ($Failure -eq 'missing' -and $sid -eq 'S-1-5-18') { continue }
        $rights = if ($sid -eq $delivery) { 'ReadAndExecute' } else { 'FullControl' }
        if ($Failure -eq 'write' -and $sid -eq $delivery) { $rights = 'Modify' }
        $inherit = if ($Failure -eq 'children') { 'None' } else { 'ContainerInherit,ObjectInherit' }
        $type = if ($Failure -eq 'deny' -and $sid -eq $delivery) { 'Deny' } else { 'Allow' }
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)), $rights, $inherit, 'None', $type)))
    }
    if ($Failure -eq 'extra') {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier('S-1-1-0')), 'Read', 'Allow')))
    }
    return $acl
}
Assert-KProInstallRootAcl (New-TestRootAcl '') $delivery
foreach ($failure in @('owner','inheritance','missing','write','children','deny','extra')) {
    $rejected = $false
    try { Assert-KProInstallRootAcl (New-TestRootAcl $failure) $delivery } catch { $rejected = $true }
    if (-not $rejected) { throw "Unsafe root ACL accepted: $failure" }
}
'PASS: install root owner/DACL and seven fail-closed cases; no filesystem ACL mutation'
