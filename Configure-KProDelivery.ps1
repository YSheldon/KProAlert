#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Python,
    [string]$Spool = (Join-Path $env:ProgramFiles 'KProAlert\alert-spool'),
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'KProAlert'),
    [string]$LarkCli,
    [string]$Base,
    [string]$Table,
    [switch]$Publish,
    [switch]$Remove,
    [switch]$Apply
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$taskName = 'KProAlert-Delivery-' + $sid
$pythonPath = (Resolve-Path -LiteralPath $Python).ProviderPath
if ([IO.Path]::GetFileName($pythonPath) -ne 'pythonw.exe') { throw 'Use the venv pythonw.exe for a windowless user task.' }
$scriptPath = Join-Path $PSScriptRoot 'plugins\kpro-alerts\scripts\delivery_worker.py'
if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { throw 'Delivery worker missing.' }
$state = [IO.Path]::GetFullPath($StateDirectory)
$configPath = Join-Path $state 'delivery.json'
$arguments = '"' + $scriptPath + '" --config "' + $configPath + '"'
function Resolve-TaskSid([string]$Identity) {
    if ($Identity -match '^S-1-') { return (New-Object Security.Principal.SecurityIdentifier($Identity)).Value }
    return (New-Object Security.Principal.NTAccount($Identity)).Translate([Security.Principal.SecurityIdentifier]).Value
}
function Assert-KProTaskIdentity($Task) {
    if ($Task.Actions.Count -ne 1 -or $Task.Actions[0].Execute -ne $pythonPath -or
        $Task.Actions[0].Arguments -ne $arguments -or $Task.Description -ne 'KProAlert user-session delivery v1' -or
        (Resolve-TaskSid $Task.Principal.UserId) -ne $sid -or $Task.Principal.LogonType -ne 'Interactive' -or
        $Task.Principal.RunLevel -ne 'Limited' -or $Task.Triggers.Count -ne 1 -or
        $Task.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskLogonTrigger' -or
        (Resolve-TaskSid $Task.Triggers[0].UserId) -ne $sid) {
        throw 'Task identity differs; refusing to act.'
    }
}
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($Remove) {
    if (-not $existing) { throw 'Delivery task is not registered.' }
    Assert-KProTaskIdentity $existing
    if (-not $Apply) { @{mode='remove-plan';task=$taskName;retainsEvidence=$true} | ConvertTo-Json; return }
    if ($PSCmdlet.ShouldProcess($taskName, 'Stop and remove this user delivery task; retain data')) {
        if ($existing.State -eq 'Running') { Stop-ScheduledTask -TaskName $taskName }
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Task remains registered.' }
        @{mode='removed';retainsEvidence=$true} | ConvertTo-Json
    }
    return
}
if ($existing) { throw 'Existing delivery task: inspect or remove it explicitly; never overwrite.' }
if (Test-Path -LiteralPath $configPath) { throw 'Existing delivery configuration: retain and reconcile it.' }
if (-not (Test-Path -LiteralPath $Spool -PathType Container)) { throw 'Install protection before configuring delivery.' }
if ($Publish -and (-not $LarkCli -or -not $Base -or -not $Table)) { throw 'Publication requires all three explicit Feishu settings.' }
if ($Publish) { $LarkCli = (Resolve-Path -LiteralPath $LarkCli).ProviderPath }
$plan = @{mode='plan';task=$taskName;userSid=$sid;runLevel='Limited';trigger='User logon';
    publishesToFeishu=[bool]$Publish;stateDirectory=$state;automaticRemediation=$false}
if (-not $Apply) { $plan | ConvertTo-Json; return }
if (-not $PSCmdlet.ShouldProcess($taskName, 'Register and start current-user background delivery')) { return }
if (-not (Test-Path -LiteralPath $state)) { New-Item -ItemType Directory -Path $state | Out-Null }
if ((Get-Item -LiteralPath $state).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse state directory rejected.' }
$cfg = [ordered]@{schema='KProDelivery/v1';database=(Join-Path $state 'events.db');
    spool=(Resolve-Path -LiteralPath $Spool).ProviderPath;device=('device-' + [Guid]::NewGuid().ToString('N'));
    interval=10;health=(Join-Path $state 'delivery-health.json');publish=[bool]$Publish}
if ($Publish) { $cfg.cli=$LarkCli; $cfg.base=$Base; $cfg.table=$Table }
$configJson = $cfg | ConvertTo-Json -Depth 3
$stream = [IO.File]::Open($configPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $bytes=[Text.Encoding]::UTF8.GetBytes($configJson); $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) }
finally { $stream.Dispose() }
$action = New-ScheduledTaskAction -Execute $pythonPath -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $sid
$principal = New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description 'KProAlert user-session delivery v1' | Out-Null
$created = Get-ScheduledTask -TaskName $taskName
try { Assert-KProTaskIdentity $created }
catch {
    Disable-ScheduledTask -TaskName $taskName | Out-Null
    throw 'Task registration readback mismatch; newly created task disabled for diagnosis.'
}
Start-ScheduledTask -TaskName $taskName
@{mode='registered';task=$taskName;healthPath=$cfg.health;runtimeVerified=$false;
    onlyWhileUserLoggedOn=$true;automaticRemediation=$false} | ConvertTo-Json
