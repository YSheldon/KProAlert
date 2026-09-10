#Requires -Version 5.1
param([Parameter(Mandatory)][string]$DescriptorPath)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../../../tools/KProReleaseTrust.psm1') -Force
$item=Get-Item -LiteralPath $DescriptorPath
if($item.Length -gt 65536){throw 'Descriptor exceeds budget.'}
$bytes=[IO.File]::ReadAllBytes($item.FullName)
$publisher=Assert-KProReleaseAttestation -Bytes $bytes
$text=ConvertFrom-KProAttestationText -Bytes $bytes
$matches=[regex]::Matches($text,'(?m)^# FALCONPRO-RELEASE-JSON: ([A-Za-z0-9+/=]+)\r?$')
if($matches.Count -ne 1){throw 'Exactly one signed descriptor payload required.'}
# The descriptor is data only. It is never invoked or dot-sourced.
@{publisher=$publisher;payloadBase64=$matches[0].Groups[1].Value}|ConvertTo-Json -Compress
