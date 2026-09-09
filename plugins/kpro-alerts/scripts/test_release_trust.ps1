param([string]$ArtifactProofPath,[string]$OtherPublisherProofPath,[string]$SignedPs1ProofPath)
$ErrorActionPreference='Stop'
$root=(Get-Item $PSScriptRoot).Parent.Parent.Parent.FullName
Import-Module (Join-Path $root 'tools\KProReleaseTrust.psm1') -Force
$module=Get-Module KProReleaseTrust
if($SignedPs1ProofPath){
    $signedBytes=[IO.File]::ReadAllBytes($SignedPs1ProofPath)
    if((Assert-KProReleaseAttestation -Bytes $signedBytes) -ne 'artifact-signing'){throw 'Real PS1 publisher mismatch.'}
    $tampered=[byte[]]$signedBytes.Clone()
    $tampered[25]=$tampered[25] -bxor 1
    $rejected=$false
    try {Assert-KProReleaseAttestation -Bytes $tampered|Out-Null} catch {$rejected=$true}
    if(-not $rejected){throw 'Tampered real PS1 accepted.'}
    'PASS: real PS1 memory verification and tamper rejection'
}
$plain='# KPRO-MANIFEST-SHA256: '+('a'*64)+"`r`n"
$raw=[Text.Encoding]::UTF8.GetBytes($plain)
foreach($version in @('5.1','7.3','7.4')){
    $actual=& $module {param($b,$v) Get-KProAttestationVerificationBytes -Bytes $b -EngineVersion $v} $raw ([version]$version)
    $expected=if([version]$version -lt [version]'7.4'){[Text.Encoding]::Unicode.GetBytes($plain)}else{$raw}
    if([Convert]::ToBase64String([byte[]]$actual) -ne [Convert]::ToBase64String($expected)){throw 'Wrong Authenticode content encoding for engine.'}
}
foreach($encoded in @(
    ,([Text.Encoding]::ASCII.GetBytes($plain))
    ,([byte[]](@(0xef,0xbb,0xbf)+[Text.Encoding]::UTF8.GetBytes($plain)))
    ,([byte[]](@(0xff,0xfe)+[Text.Encoding]::Unicode.GetBytes($plain)))
)){
    if((ConvertFrom-KProAttestationText -Bytes $encoded) -cne $plain){throw 'Attestation BOM decoding mismatch.'}
}
foreach($encoded in @(,([byte[]]@(0xff,0xfe,0x23)), ,([byte[]]@(0xef,0xbb,0xbf,0xff)))){
    $badEncodingRejected=$false
    try {ConvertFrom-KProAttestationText -Bytes $encoded|Out-Null} catch {$badEncodingRejected=$true}
    if(-not $badEncodingRejected){throw 'Malformed attestation encoding accepted.'}
}
$eku='1.3.6.1.4.1.311.97.295511681.952035411.79500323.351512044'
$pca='3D29798CC5D3F0644A7E0DC9CB1CADE523EA5EC83B335109B605BFEAA7D5F5C1'
$facts=@{Status='Valid';HasTimestamp=$true;EkuOids=@('1.3.6.1.5.5.7.3.3','1.3.6.1.4.1.311.97.1.0',$eku);PcaFingerprints=@($pca)}
& $module {param($f) Assert-KProArtifactIdentityFacts @f} $facts
foreach($kind in @('status','timestamp','subscriber','pca','codeSigning')){
    $bad=$facts.Clone()
    switch($kind){
        status {$bad.Status='HashMismatch'}
        timestamp {$bad.HasTimestamp=$false}
        subscriber {$bad.EkuOids=@('1.3.6.1.5.5.7.3.3','1.3.6.1.4.1.311.97.1.0','1.3.6.1.4.1.311.97.1.2.3')}
        pca {$bad.PcaFingerprints=@('0'*64)}
        codeSigning {$bad.EkuOids=@('1.3.6.1.4.1.311.97.1.0',$eku)}
    }
    $rejected=$false
    try {& $module {param($f) Assert-KProArtifactIdentityFacts @f} $bad} catch {$rejected=$true}
    if(-not $rejected){throw "Invalid publisher facts accepted: $kind"}
}
$rejected=$false
try {Assert-KProReleaseAttestation -Bytes ([Text.Encoding]::UTF8.GetBytes('# unsigned'))} catch {$rejected=$true}
if(-not $rejected){throw 'Unsigned attestation accepted.'}
$rsa=New-Object Security.Cryptography.RSACng(2048)
try {
    $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=InMemoryUntrustedTest', $rsa,
        [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $untrusted=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),[DateTimeOffset]::UtcNow.AddHours(1))
    try {
        # Simulate an upstream Valid claim to independently test the chain gate.
        # No certificate or key is installed in any system store.
        $claimed=[pscustomobject]@{Status='Valid';SignerCertificate=$untrusted;TimeStamperCertificate=$untrusted}
        $rejected=$false
        try {& $module {param($s) Assert-KProReleasePublisher -Signature $s} $claimed|Out-Null} catch {$rejected=$true}
        if(-not $rejected){throw 'Unknown CA chain accepted.'}
    } finally {$untrusted.Dispose()}
} finally {$rsa.Dispose()}
if($ArtifactProofPath){
    $signature=Get-AuthenticodeSignature -LiteralPath $ArtifactProofPath
    $identity=& $module {param($s) Assert-KProReleasePublisher -Signature $s} $signature
    if($identity -ne 'artifact-signing'){throw 'Expected real Artifact Signing proof.'}
    'PASS: actual Artifact Signing publisher chain and timestamp'
}
if($OtherPublisherProofPath){
    $signature=Get-AuthenticodeSignature -LiteralPath $OtherPublisherProofPath
    if($signature.Status -ne 'Valid' -or -not $signature.TimeStamperCertificate){throw 'Negative fixture is not a valid timestamped signature.'}
    $rejected=$false
    try {& $module {param($s) Assert-KProReleasePublisher -Signature $s} $signature|Out-Null} catch {$rejected=$true}
    if(-not $rejected){throw 'Other valid publisher was accepted.'}
    'PASS: other real valid publisher rejected'
}
'PASS: publisher, PCA, purpose, timestamp and unsigned-content rejection'
