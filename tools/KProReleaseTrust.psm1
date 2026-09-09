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

function Assert-KProReleaseAttestation {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    if (-not $Bytes.Length -or $Bytes.Length -gt 65536) { throw 'Invalid attestation size.' }
    $signature = Get-AuthenticodeSignature -Content $Bytes -SourcePathOrExtension '.ps1'
    return Assert-KProReleasePublisher -Signature $signature
}

Export-ModuleMember -Function Assert-KProReleaseAttestation,ConvertFrom-KProAttestationText
