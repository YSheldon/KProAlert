$ErrorActionPreference='Stop'
$repo=(Get-Item $PSScriptRoot).Parent.Parent.Parent.FullName
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'Install-KProAlert.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Parser failure'}
$block=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and
    $n.Body.Extent.Text.Trim() -eq '{ Copy-Item -LiteralPath (Join-Path $source $entry.name) -Destination $target }'},$true))
if($block.Count -ne 1){throw 'Missing bounded package-copy error context'}
$copy=[scriptblock]::Create($block[0].Extent.Text)
$root=Join-Path ([IO.Path]::GetTempPath()) ('FalconPro-copy-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root|Out-Null
$held=$null
try {
    $source=Join-Path $root 'source'
    New-Item -ItemType Directory -Path $source|Out-Null
    $entry=@{name='default-policy.hex'}
    $from=Join-Path $source $entry.name
    $target=Join-Path $root 'default-policy.hex'
    [IO.File]::WriteAllBytes($from,[byte[]](1,2,3))
    $held=[IO.File]::Open($target,'CreateNew','ReadWrite','None')
    $caught=$false
    try { & $copy }
    catch {
        $caught=$true
        if($_.Exception.HResult -ne -2147024864 -or
           $_.Exception.Data['FalconPro.CopySource'] -cne $from -or
           $_.Exception.Data['FalconPro.CopyDestination'] -cne $target){throw 'Sharing failure lost exact source/destination or HRESULT'}
    }
    if(-not $caught){throw 'Sharing failure was swallowed'}
    $held.Dispose();$held=$null
    & $copy
    if([Convert]::ToBase64String([IO.File]::ReadAllBytes($target)) -cne 'AQID'){throw 'Successful copy changed'}
    Remove-Item -LiteralPath $from
    $caught=$false
    try { & $copy }
    catch {
        $caught=$true
        if($_.Exception.HResult -eq -2147024864 -or
           $_.Exception.Data['FalconPro.CopySource'] -cne $from -or
           $_.Exception.Data['FalconPro.CopyDestination'] -cne $target){throw 'Missing source mislabeled or context lost'}
    }
    if(-not $caught){throw 'Missing source failure was swallowed'}
    'PASS: exact private copy context, HRESULT preservation, failure propagation and normal copy'
} finally {
    if($held){$held.Dispose()}
    $resolved=[IO.Path]::GetFullPath($root)
    if(-not $resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture escaped temp'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
