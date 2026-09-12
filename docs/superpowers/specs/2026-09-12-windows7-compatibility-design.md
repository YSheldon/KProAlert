# Windows 7 And Later Endpoint Compatibility

Status: implementation in progress under the user's Windows 7-and-later request.
This document is not a runtime support or release admission claim.

## Boundary

Support the protection endpoint independently from the AI client's own operating
system requirements. Windows 7 SP1 and Windows 8 cannot host the current Python
3.10+ MCP dependency set. Do not ship an obsolete Python runtime to hide that
constraint. Provide a signed PowerShell endpoint bootstrap for those systems;
AI clients on supported hosts may guide its local execution and read only the
user-authorized exported/synchronized telemetry.

Keep one public repository address, no policy private key on the endpoint, no
ELAM installation, no automatic reboot and no automatic AI destructive actions.
Driver policy/event protocols remain unchanged. Server SKUs require separately
named admission rather than being silently included by a version comparison.

## Platform Selection

- Windows 7 SP1 / Windows 8, native x86 or x64: Legacy user-mode build without
  FORCE_INTEGRITY, but retain F1 -> Artifact Signing -> product signing where
  required. Select the native Microsoft/product-signed driver.
- Windows 8.1 / Windows 10 / Windows 11: native-architecture modern user-mode
  package, with independent signature and PE checks. Do not select x86 merely
  because the bootstrap runs under WOW64.
- ARM64: retain current Windows 11 ARM64 admission; any additional ARM64 OS
  version needs import/dependency review and native validation before release.
- Pre-SP1 Windows 7, older operating systems, malformed/unknown facts and
  architecture/manifest mismatches stop before mutation.

Reuse the established CI material mapping: Legacy source artifacts can be copied
to the canonical service/DLL filenames only BEFORE final manifest generation.
Copying never changes signed image bytes. Do not add a KProSvcLegacy service
name to production or overwrite an admitted x64/ARM64 package with x86 files.

## Bootstrap And Signed Contracts

The legacy PowerShell path must implement the same fixed GitHub-origin download,
exact size/hash checks, signed descriptor/publisher validation, native endpoint
binding, protected transaction staging, DLL Install interface, signed policy,
upgrade snapshot and recovery rules as the existing coordinator. It must not
depend on Python or lark-cli/Node being installed on Windows 7.

PowerShell 5.1/.NET Framework 4.7.2 prerequisites and required SHA-2/system certificate support
are explicit preflight gates, not reasons to ignore signature errors. Missing
prerequisites produce an actionable result before installation. Installing a
prerequisite or changing system trust requires its own authorized path.

Windows 8 can be classified for legacy image selection but cannot satisfy this
entry's supported PowerShell/.NET prerequisites. It is not admitted for release;
an OS upgrade is required. Windows 7 SP1 and Windows 8.1 remain separate lanes.

New platform labels bind OS family as well as native architecture. Existing
Windows 11 descriptor/plan versions remain readable with their original scope.
The native installer independently recomputes platform choice; a manifest cannot
declare itself legacy to bypass modern-package requirements on a newer system.

## Acceptance

Static/model tests cover SP1 boundaries, x86/x64/WOW64/native ARM64 selection,
wrong package/Force Integrity rejection, missing prerequisites and signature
failure. Build and inspect both Legacy service architectures from the same
source. Sign final artifacts before manifest/descriptor hashes are calculated.

Native tests cover Win7 x86/x64, Windows 8/8.1/10/11 as admitted targets, and the
separate ARM64 endpoint. Run cold download, decline/approve UAC, signed install,
benign protection/events, normal reboot, upgrade, recovery and cleanup with fresh
preflight/queue evidence. No office-PC driver install/reboot is authorized here.
AI query/notification acceptance and endpoint protection are separate results.
