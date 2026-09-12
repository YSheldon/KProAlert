$ErrorActionPreference='Stop'
$repo=(Get-Item $PSScriptRoot).Parent.Parent.Parent.FullName
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'Invoke-FalconProLifecycle.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Parser failure'}
$blocks=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
    $n.Clauses[0].Item1.Extent.Text -ceq '$Mode -eq ''rollback'''},$true))
if($blocks.Count -ne 1){throw 'Rollback route not unique'}
$route=[scriptblock]::Create($blocks[0].Extent.Text)
$folder=Join-Path ([IO.Path]::GetTempPath()) ('FalconPro-route-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $folder|Out-Null
try{
    $sourceRoot=$folder;$transactionRoot=$folder;$installed=Join-Path $folder 'installed'
    $Mode='rollback';$Apply=$true;$Approve=$true;$candidateValidation=$false
    $ManifestSha256='b'*64;$candidateInstallArgs=@{LifecycleTransactionId='a'*32}
    $os=[pscustomobject]@{LastBootUpTime=[DateTime]::UtcNow}
    $new=[pscustomobject]@{version='2.0.0.0';kind='new'}
    [IO.File]::WriteAllText((Join-Path $sourceRoot 'Install-KProAlert.ps1'),@'
param($PackageRoot,$ManifestSha256,$DeliveryUserSid,$LifecycleTransactionId,[switch]$Apply,$Confirm)
$global:InstallCalls+=@([pscustomobject]@{root=$PackageRoot;hash=$ManifestSha256;transaction=$LifecycleTransactionId})
if($global:FailInstall){throw 'injected restore failure'}
'{"mode":"service-running","collectorReady":true}'
'@)
    function Assert-Protected {param($Path)}
    function Assert-OrdinaryService {}
    function Assert-Collector {}
    function Assert-RecoveryTargetAbsent {}
    function Release-Files {}
    function Get-Service {param($Name,$ErrorAction) if($script:serviceExists){[pscustomobject]@{Name='KProSvc';Status=$script:serviceStatus}}}
    function Resume-TransactionService {
        param($ExpectedPackageHash)
        if($script:wrongMarker){throw 'Wrong installation marker'}
        $script:Resumes+=@($ExpectedPackageHash)
        $script:serviceStatus='Running'
        [pscustomobject]@{version='1.0.0.0';kind='old'}
    }
    function Read-Package {param($Root,$Expected) $script:Reads+=@([pscustomobject]@{root=$Root;hash=$Expected});[pscustomobject]@{version='1.0.0.0';kind='old'}}
    function Snapshot {param($Hash,$Expected) if($script:serviceExists -and $script:serviceStatus -ne 'Running'){throw 'Stopped service cannot snapshot'};$script:Snapshots+=@($Hash);[pscustomobject]@{digestSha256='c'*64}}
    function Write-State {param($Phase) $script:state.phase=$Phase}
    function Cancel-UnchangedUpgrade {throw 'Unexpected unchanged-upgrade branch'}
    function Archive-PartialInstallation {
        param($Package,[switch]$Recovery,$ExpectedPackageHash,$CandidateRoot)
        $script:Archives+=@([pscustomobject]@{kind=$Package.kind;recovery=[bool]$Recovery;hash=$ExpectedPackageHash;root=$CandidateRoot})
    }
    function Abort-PartialFirstInstall {param($Package) $script:state.phase='installation_aborted'}
    function Reset-Case([string]$Phase){
        $script:state=[pscustomobject]@{operation='upgrade';phase=$Phase;oldManifestSha256='e'*64;
            policyDigest='c'*64;installedVersion='';bootIdentity=''}
        $script:Reads=@();$script:Snapshots=@();$script:Archives=@();$global:InstallCalls=@()
        $script:Resumes=@();$script:serviceStatus='Running';$script:wrongMarker=$false
        $script:serviceExists=$false;$global:FailInstall=$false
    }
    Reset-Case 'recovery_partial_archive_pending'
    & $route|Out-Null
    if($state.phase -cne 'recovery_awaiting_reboot' -or $Archives.Count -ne 1 -or -not $Archives[0].recovery -or
       $Archives[0].kind -cne 'old' -or $Archives[0].hash -cne ('e'*64) -or
       $InstallCalls.Count -ne 1 -or $InstallCalls[0].hash -cne ('e'*64)){throw 'Recovery route used the new package'}
    Reset-Case 'recovery_install_pending'
    $script:serviceExists=$true
    & $route|Out-Null
    if($InstallCalls.Count -ne 0 -or $Snapshots[0] -cne ('e'*64) -or $state.phase -cne 'recovery_awaiting_reboot'){
        throw 'Running recovered service was reinstalled or checked as new'
    }
    Reset-Case 'recovery_install_pending'
    $script:serviceExists=$true;$script:serviceStatus='Stopped'
    & $route|Out-Null
    if($Resumes.Count -ne 1 -or $Resumes[0] -cne ('e'*64) -or $InstallCalls.Count -ne 0){throw 'Stopped recovery service was not safely resumed'}
    foreach($status in @('Running','Stopped')){
        Reset-Case 'recovery_install_pending'
        $script:serviceExists=$true;$script:serviceStatus=$status;$script:wrongMarker=$true
        $failed=$false;try{& $route|Out-Null}catch{$failed=$true}
        if(-not $failed -or $InstallCalls.Count -ne 0 -or $Snapshots.Count -ne 0){throw 'Unmarked installed service was adopted'}
    }
    Reset-Case 'recovery_install_pending'
    $global:FailInstall=$true
    $failed=$false;try{& $route|Out-Null}catch{$failed=$true}
    if(-not $failed -or $state.phase -cne 'recovery_install_pending'){throw 'Failed restore lost retry state'}
    $global:FailInstall=$false
    & $route|Out-Null
    if($state.phase -cne 'recovery_awaiting_reboot'){throw 'Restore retry remained blocked'}
    Reset-Case 'install_pending'
    $state.operation='install';$state.oldManifestSha256=''
    & $route|Out-Null
    if($state.phase -cne 'installation_aborted' -or $Reads.Count -ne 0 -or $InstallCalls.Count -ne 0){throw 'First install invented a recovery package'}
    'PASS: old-package recovery routing, running recovery reconciliation, retry and first-install abort'
}finally{
    $path=[IO.Path]::GetFullPath($folder)
    if($path.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase)){
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}
