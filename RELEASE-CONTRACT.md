# Signed Windows release contract

No binary release is published until all gates pass. The public installer must
consume an immutable versioned release and a trusted expected manifest SHA-256,
not a mutable latest URL or file-supplied checksum alone.

The initial native architecture package has exactly five payload files:
KProSvc.exe, KProProtect.dll, KProFilter.sys, DrvCfg2.dat, default-policy.hex.
The x86/x64 release archives normalize basenames for the selected native host.
Do not install the x86 driver on an x64 host. Unsupported host matrices fail closed.

KProAlertRelease/v1 records version, architecture, releaseStatus=verified and
files (name, SHA256, size). gates records completed release evidence for:
serviceF1ArtifactProduct, driverMicrosoftProduct, dllProduct, policySignature,
endToEnd. Boolean claims in this file are NOT cryptographic signature evidence.
Publication verifies actual signatures; installation additionally validates Windows
Authenticode on every executable/DLL/SYS and exact immutable file hashes.

Runtime config and policy are signed by the existing product trust chain, not by
this Python plugin. Do not publish fixture private keys or issue a production policy
with example signing keys. The driver remains the authority for accepting policy.

The package also contains release-attestation.ps1, a product-signed data file with
exactly one `# KPRO-MANIFEST-SHA256: <digest>` comment. The installer never executes
it. Its valid Authenticode signer must match the trusted product certificate, and
its digest must match both release-manifest.json and the operator's expected hash.
No attestation is generated with verified gates until actual release tests pass.

The approved default is the maximum ransomware profile: ransomware enabled,
report-only risk escalation enabled (`policyFlags=5`, `decisionMode=3`), with no
protected directory objects or blanket raw-disk exceptions. This includes heuristic
risk blocking and its false-positive tradeoff; it is not a guarantee of no damage.
The user must be informed of deterministic bait and first-sector protection and
their compatibility implications before enabling them.

CertificateOnly/PPL packaging requires additional verified bootstrap/control/resource
files and a separately validated manifest schema extension. Do not infer PPL is active
from install success or silently weaken a PPL-required runtime config.
