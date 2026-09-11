Set-StrictMode -Version Latest

function ConvertFrom-KProAttestationText {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    if (-not $Bytes.Length -or $Bytes.Length -gt 65536) { throw 'Invalid attestation size.' }
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xff -and $Bytes[1] -eq 0xfe) {
        $encoding = New-Object Text.UnicodeEncoding($false,$false,$true)
        $text = $encoding.GetString($Bytes,2,$Bytes.Length-2)
    } else {
        $offset=0
        if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xef -and $Bytes[1] -eq 0xbb -and $Bytes[2] -eq 0xbf) { $offset=3 }
        $encoding = New-Object Text.UTF8Encoding($false,$true)
        $text = $encoding.GetString($Bytes,$offset,$Bytes.Length-$offset)
    }
    if ($text.IndexOf([char]0) -ge 0) { throw 'NUL is not permitted in attestation text.' }
    return $text
}

function Assert-KProArtifactIdentityFacts {
    param([string]$Status, [bool]$HasTimestamp, [string[]]$EkuOids, [string[]]$PcaFingerprints)
    # Durable subscriber identity and Microsoft PCA, captured from a verified release signer.
    $subscriber = '1.3.6.1.4.1.311.97.295511681.952035411.79500323.351512044'
    $pca = '3D29798CC5D3F0644A7E0DC9CB1CADE523EA5EC83B335109B605BFEAA7D5F5C1'
    if ($Status -ne 'Valid' -or -not $HasTimestamp -or
        $EkuOids -notcontains '1.3.6.1.5.5.7.3.3' -or
        $EkuOids -notcontains '1.3.6.1.4.1.311.97.1.0' -or
        $EkuOids -notcontains $subscriber -or $PcaFingerprints -notcontains $pca) {
        throw 'Release signer is not the approved timestamped Artifact Signing identity.'
    }
}

function Assert-KProReleasePublisher {
    param([Parameter(Mandatory)]$Signature)
    if ($Signature.Status -ne 'Valid' -or -not $Signature.SignerCertificate -or -not $Signature.TimeStamperCertificate) {
        throw 'A valid Authenticode signature and verified timestamp are required.'
    }
    if ($Signature.SignerCertificate.Thumbprint -eq '939F263EA341994910FA2A9573A16643FD34FE04') {
        return 'product'
    }
    $certificate = $Signature.SignerCertificate
    $ekuOids = @()
    foreach ($extension in $certificate.Extensions) {
        if ($extension.Oid.Value -eq '2.5.29.37') {
            $eku = New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($extension,$extension.Critical)
            $ekuOids += @($eku.EnhancedKeyUsages | ForEach-Object Value)
        }
    }
    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    try {
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        # Authenticode above verifies signing time using the timestamp. A short-lived
        # leaf may now be expired; never permit an unknown CA or ignore revocation.
        $chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreNotTimeValid
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(15)
        [void]$chain.ChainPolicy.ApplicationPolicy.Add((New-Object Security.Cryptography.Oid('1.3.6.1.5.5.7.3.3')))
        if (-not $chain.Build($certificate)) { throw 'Release signer chain/revocation validation failed.' }
        $fingerprints = @()
        for ($index=1; $index -lt $chain.ChainElements.Count; $index++) {
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $fingerprints += ([BitConverter]::ToString($sha.ComputeHash($chain.ChainElements[$index].Certificate.RawData))).Replace('-','')
            } finally { $sha.Dispose() }
        }
        Assert-KProArtifactIdentityFacts -Status ([string]$Signature.Status) -HasTimestamp $true -EkuOids $ekuOids -PcaFingerprints $fingerprints
        return 'artifact-signing'
    } finally { $chain.Dispose() }
}

function Get-KProAttestationVerificationBytes {
    param([byte[]]$Bytes, [version]$EngineVersion = $PSVersionTable.PSVersion)
    if ($EngineVersion -lt [version]'7.4') {
        # Older -Content requires UTF-16LE. Derive it from the captured snapshot,
        # without rewriting or reopening the file and without tolerating a mismatch.
        $text = ConvertFrom-KProAttestationText -Bytes $Bytes
        return ,([Text.Encoding]::Unicode.GetBytes($text))
    }
    return ,$Bytes
}

function Assert-KProReleaseAttestation {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    if (-not $Bytes.Length -or $Bytes.Length -gt 65536) { throw 'Invalid attestation size.' }
    $content = Get-KProAttestationVerificationBytes -Bytes $Bytes
    $signature = Get-AuthenticodeSignature -Content $content -SourcePathOrExtension '.ps1'
    return Assert-KProReleasePublisher -Signature $signature
}

function Get-KProPackageLayout {
    param([Parameter(Mandatory)][ValidateSet('x64','arm64')][string]$Architecture)
    if ($Architecture -eq 'arm64') {
        return @{Platform='windows11-arm64';Service='KProSvcArm.exe';Dll='KProProtectArm.dll';Driver='KProFilterArm.sys';Machine=0xaa64}
    }
    return @{Platform='windows11-x64';Service='KProSvc.exe';Dll='KProProtect.dll';Driver='KProFilter.sys';Machine=0x8664}
}

function Assert-KProPeArchitecture {
    param([Parameter(Mandatory)][byte[]]$Bytes,[Parameter(Mandatory)][ValidateSet('x64','arm64')][string]$Architecture)
    if ($Bytes.Length -lt 64 -or $Bytes[0] -ne 0x4d -or $Bytes[1] -ne 0x5a) { throw 'Invalid PE header.' }
    $offset=[BitConverter]::ToInt32($Bytes,60)
    if ($offset -lt 64 -or $offset -gt $Bytes.Length-26 -or
        [BitConverter]::ToUInt32($Bytes,$offset) -ne 0x4550 -or
        [BitConverter]::ToUInt16($Bytes,$offset+24) -ne 0x20b) { throw 'Invalid PE layout.' }
    $layout=Get-KProPackageLayout $Architecture
    if ([BitConverter]::ToUInt16($Bytes,$offset+4) -ne $layout.Machine) { throw 'PE architecture does not match native endpoint.' }
}

function Get-KProSignedReleaseDescriptor {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $null=Assert-KProReleaseAttestation -Bytes $Bytes
    $text=ConvertFrom-KProAttestationText -Bytes $Bytes
    $markers=@([regex]::Matches($text,'(?m)^# FALCONPRO-RELEASE-JSON: ([A-Za-z0-9+/=]+)\r?$'))
    if ($markers.Count -ne 1) { throw 'Exactly one signed descriptor payload required.' }
    $utf8=New-Object Text.UTF8Encoding($false,$true)
    $descriptor=$utf8.GetString([Convert]::FromBase64String($markers[0].Groups[1].Value)) | ConvertFrom-Json
    if ($descriptor.schema -cne 'FalconProReleaseDescriptor/v1' -or $descriptor.releaseStatus -cne 'verified' -or
        $descriptor.platform -cnotin @('windows11-x64','windows11-arm64') -or
        $descriptor.sourceManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $descriptor.packageManifestSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid admitted descriptor.' }
    return $descriptor
}

function Get-KProNativeProgramFiles {
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
    try {
        $key=$base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion')
        if ($null -eq $key) { throw 'Native Program Files registry key is missing.' }
        try { $path=[string]$key.GetValue('ProgramFilesDir') } finally { $key.Dispose() }
    } finally { $base.Dispose() }
    if ($path -notmatch '^[A-Za-z]:\\') { throw 'Native Program Files path is invalid.' }
    return [IO.Path]::GetFullPath($path).TrimEnd('\')
}

function Assert-KProProgramFilesRoot {
    param([Parameter(Mandatory)][string]$Path)
    $item=Get-Item -LiteralPath $Path -Force
    if ($item -isnot [IO.DirectoryInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Native Program Files is not a plain directory.' }
    $acl=Get-Acl -LiteralPath $Path
    $raw=New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorBinaryForm(),0)
    if ($null -eq $raw.DiscretionaryAcl) { throw 'Native Program Files DACL is missing.' }
    $installer=New-Object Security.Principal.NTAccount('NT SERVICE','TrustedInstaller')
    $trusted=@('S-1-5-18','S-1-5-32-544',$installer.Translate([Security.Principal.SecurityIdentifier]).Value)
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'Native Program Files owner is untrusted.' }
    $write=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -ne 0 -and $rule.IdentityReference.Value -notin $trusted) {
            throw 'Native Program Files is writable by an untrusted principal.'
        }
    }
}

Export-ModuleMember -Function Assert-KProReleaseAttestation,ConvertFrom-KProAttestationText,Get-KProPackageLayout,Assert-KProPeArchitecture,Get-KProSignedReleaseDescriptor,Get-KProNativeProgramFiles,Assert-KProProgramFilesRoot
