$ErrorActionPreference='Stop'
$repo=(Get-Item $PSScriptRoot).Parent.Parent.Parent.FullName
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'Invoke-FalconProLifecycle.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Parser failure'}
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Resume-TransactionService'},$true)
if(-not $function){throw 'Missing recovery function'}
. ([scriptblock]::Create($function.Extent.Text))
$installed='C:\Program Files\KProAlert';$ExpectedArchitecture='x64'
$expectedHash='e'*64
function Assert-InstallRootMarker {
    param($Path,$ExpectedPackageHash)
    $script:Checks+='marker'
    if($script:Fault -ceq 'marker' -or $Path -cne $installed -or $ExpectedPackageHash -cne $expectedHash){throw 'Marker rejected'}
}
function Assert-OrdinaryService { $script:Checks+='ordinary';if($script:Fault -ceq 'ppl'){throw 'PPL rejected'} }
function Read-Package {param($Path,$Hash) $script:Checks+='package';if($script:Fault -ceq 'package'){throw 'Package rejected'};[pscustomobject]@{version='1.2.0.1'}}
function Get-KProPackageLayout {param($Architecture) @{Service='KProSvc.exe'}}
function Get-CimInstance {
    param($Class,$Filter,$ErrorAction)
    if($script:Fault -ceq 'missing'){return}
    [pscustomobject]@{State=$script:Status;PathName=$script:Image}
}
function Start-Service {
    param($Name,$ErrorAction)
    if(($script:Checks -join ',') -cne 'marker,ordinary,package'){throw 'Started before identity checks'}
    $script:Starts++
    if($script:Fault -ceq 'start'){throw 'Start failed'}
}
function Get-Service {
    param($Name,$ErrorAction)
    $item=New-Object PSObject
    $item|Add-Member ScriptMethod WaitForStatus {
        param($Status,$Timeout)
        if($Status -cne 'Running' -or $Timeout.TotalSeconds -ne 90){throw 'Unbounded/incorrect wait'}
        $script:Waits++
        if($script:Fault -ceq 'wait'){throw 'Wait failed'}
    }
    $item
}
function Reset-Case([string]$State='Stopped') {
    $script:Status=$State;$script:Image='"'+(Join-Path $installed 'KProSvc.exe')+'"'
    $script:Starts=0;$script:Waits=0;$script:Fault='';$script:Checks=@()
}
Reset-Case
$result=Resume-TransactionService $expectedHash
if($result.version -cne '1.2.0.1' -or $Starts -ne 1 -or $Waits -ne 1){throw 'Stopped service not resumed once'}
Reset-Case 'Running'
$null=Resume-TransactionService $expectedHash
if($Starts -ne 0 -or $Waits -ne 0){throw 'Running service restarted'}
foreach($faultName in @('marker','ppl','package','missing','path','pending','start','wait')){
    Reset-Case
    $script:Fault=$faultName
    if($faultName -ceq 'path'){$script:Image='"C:\Other\KProSvc.exe"'}
    if($faultName -ceq 'pending'){$script:Status='Start Pending'}
    $failed=$false;try{$null=Resume-TransactionService $expectedHash}catch{$failed=$true}
    if(-not $failed){throw "Invalid recovery accepted: $faultName"}
    if($faultName -notin @('start','wait') -and $Starts -ne 0){throw "Rejected identity started: $faultName"}
    if($Starts -gt 1){throw 'Recovery automatically retried service start'}
}
'PASS: marker/package/PPL/path/state gates; stopped resume; running no-op; no failed-start retry'
