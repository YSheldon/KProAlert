# Signed Windows release contract

No binary release is published until all gates pass. The public installer must
consume an immutable versioned release and a trusted expected manifest SHA-256,
not a mutable latest URL or file-supplied checksum alone.

The first preview is restricted to Windows 11 x64 workstations (not ARM64 or
Windows Server). Its manifest must declare platform=windows11-x64. The initial
native architecture package has exactly five payload files:
KProSvc.exe, KProProtect.dll, KProFilter.sys, DrvCfg2.dat, default-policy.hex.
The x86/x64 release archives normalize basenames for the selected native host.
Do not install the x86 driver on an x64 host. Unsupported host matrices fail closed.

KProAlertRelease/v1 records version, architecture, releaseStatus=verified and
files (name, SHA256, size). gates records completed release evidence for:
serviceF1ArtifactProduct, driverMicrosoftProduct, dllProduct, policySignature,
endToEnd and privateRawEventSpool. Boolean claims in this file are NOT cryptographic signature evidence.
Publication verifies actual signatures; installation additionally validates Windows
Authenticode on every executable/DLL/SYS and exact immutable file hashes.

Runtime config and policy are signed by the existing product trust chain, not by
this Python plugin. Do not publish fixture private keys or issue a production policy
with example signing keys. The driver remains the authority for accepting policy.

privateRawEventSpool admits only the newly validated service hash that writes
original evidence into SYSTEM/Administrators-only private-event-spool and numeric/
boolean projections into alert-spool. The installer sets and reads back protected
raw ACLs and owner before starting the service. Deleting a user copy cannot remove
the primary evidence. Existing raw-spool service candidates must be rebuilt,
re-signed and tested before they can satisfy this gate.

The package also contains release-attestation.ps1, an Authenticode-signed data file with
exactly one `# KPRO-MANIFEST-SHA256: <digest>` comment. The installer never executes
it. Its digest must match both release-manifest.json and the operator's expected hash.
The installer authenticates content derived exclusively from the same captured
snapshot it parses. It accepts either
the existing product certificate or the explicitly pinned Artifact Signing
subscriber EKU plus Microsoft PCA fingerprint, after Valid Authenticode and
timestamp checks and online certificate-chain/revocation validation. It never
accepts an arbitrary trusted publisher or pins a rotating Artifact leaf certificate.
Only certificate time is ignored during the additional identity-chain build,
because Authenticode has already verified timestamp-based validity; unknown CAs
and revocation errors are not ignored. The attestation is decoded with strict
BOM-aware UTF-8 or UTF-16 LE parsing; malformed encoding and NUL are rejected.
This changes no driver public key, runtime configuration or policy.

For PowerShell earlier than 7.4, the `Get-AuthenticodeSignature -Content` API
requires UTF-16LE. The verifier strictly decodes the captured snapshot and supplies
that API's required in-memory representation; it never rewrites or reopens the
file and never tolerates HashMismatch. PowerShell 7.4+ receives the original bytes.
Both paths retain the same captured-text binding and publisher/timestamp checks.
See the [Microsoft parameter contract](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature#-content).

The publisher gate is implemented in tools/KProReleaseTrust.psm1, which must
travel with the reviewed installer source. No release-provided file can override
its allowed publisher identity. The scoped PS1 signing/verification and exact-hash
artifact recovery succeeded in pipeline 2802; a Windows PowerShell 5.1 no-Apply
installer plan and tamper-rejection check also passed. This does not close the
separate installer Apply/reboot/uninstall or public release gates.
No attestation is generated with verified gates until actual release tests pass.

The previous service candidate completed its 171 Apply/reboot/uninstall lifecycle,
but did not isolate raw evidence from the delivery account. That result cannot
satisfy the new `privateRawEventSpool` gate. The changed service requires fresh
signing and lifecycle/ACL validation before a new attestation can claim that gate.

The privacy r4 candidate subsequently completed the 171 install, normal reboot,
post-boot protection, safe-batch import/archive and authorized uninstall checks.
Its private/log directory ACL readback passed. This is Windows 11 x64 candidate
evidence only: assistant runtime acceptance and a public Release download test
remain separate, and the candidate manifest still has `endToEnd:false`.

The approved default is the maximum ransomware profile: ransomware enabled,
report-only risk escalation enabled (`policyFlags=5`, `decisionMode=3`), with no
protected directory objects or blanket raw-disk exceptions. This includes heuristic
risk blocking and its false-positive tradeoff; it is not a guarantee of no damage.
The user must be informed of deterministic bait and first-sector protection and
their compatibility implications before enabling them.

CertificateOnly/PPL packaging requires additional verified bootstrap/control/resource
files and a separately validated manifest schema extension. Do not infer PPL is active
from install success or silently weaken a PPL-required runtime config.
