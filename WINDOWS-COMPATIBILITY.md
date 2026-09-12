# Windows Endpoint Entry

The repository address remains `https://github.com/YSheldon/KProAlert`.
The protection endpoint has a signed PowerShell-only entry, `falconpro.ps1`, so installing
the Windows service does not depend on Python or an AI application running on
that computer. The AI connector still requires its supported Python/MCP runtime
and the client application's operating-system support.

## Package Selection

| Endpoint | Package platform | Service / DLL source | Runtime names |
|---|---|---|---|
| Windows 7 SP1 x86 | windows7-x86 | Legacy32, without Force Integrity | KProSvc32.exe / KProProtect32.dll / KProFilter32.sys |
| Windows 7 SP1 x64 | windows7-x64 | Legacy, without Force Integrity | KProSvc.exe / KProProtect.dll / KProFilter.sys |
| Windows 8.1 x86/x64 | windows81-x86 / windows81-x64 | Matching modern images | Architecture-specific 32 or unsuffixed names |
| Windows 10 x86/x64 | windows10-x86 / windows10-x64 | Matching modern images | Architecture-specific 32 or unsuffixed names |
| Windows 11 x64 | windows11-x64 | Modern x64 | Unsuffixed names |
| Windows 11 ARM64 | windows11-arm64 | Native ARM64 | KProSvcArm.exe / KProProtectArm.dll / KProFilterArm.sys |

The legacy selector classifies Windows 8 as legacy, but this is not native
acceptance: the PowerShell 5.1 and .NET Framework 4.7.2 prerequisites must be
available. Windows 8 has no supported combination for these prerequisites;
upgrade its OS before using this entry. Pre-SP1 Windows 7, Windows Server,
down-level ARM64 and inconsistent platform facts are not admitted.

These are implemented selection rules, not completed per-platform runtime
acceptance. A platform without an admitted signed Release stops at discovery.
No Windows 7 package is declared released by this document.

## Local Installation

The assistant first runs status through the user's local Windows execution
channel. A cloud bot must not use its own machine as the endpoint.
Use the signed entry from the verified Release onboarding archive. The unsigned
development checkout refuses execution at its bootstrap signature gate. The
assistant verifies the archive against the signed release descriptor first; no
checksum or package-path reconstruction is required from an ordinary user.

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\falconpro.ps1 -Mode status
```

Using the returned device identity, request a download and plan:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\falconpro.ps1 -Mode install -ExpectedDeviceId <device-id>
```

After the user confirms that device and release, use the returned plan path:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\falconpro.ps1 -Mode install -ExpectedDeviceId <device-id> -PlanPath <plan-path> -Apply -Approve
```

Start this entry as a normal user; it invokes the native signed installer through
UAC. A cancelled prompt returns `elevation_cancelled`. An uncertain started child
returns `attention_required` and must not be automatically repeated. Reboots are
user-controlled. Use `-Mode resume` with the original plan after reboot, or
`-Mode rollback` to request the original transaction's admitted recovery path.
For upgrades, create a new plan with `-Mode upgrade` and apply it the same way.

Modern hosts can also use `falconpro.py`; both entries use the same signed native
lifecycle. `FalconProLifecyclePlan/v3` adds a required `platform` field. Python
still reads v1/v2 plans under their original Windows 11 scope; PowerShell accepts
v3 plans. Do not edit platform fields or combine another release's scripts with
an existing signed source manifest.

OnboardingSource/v3 includes the signed `falconpro.ps1` in its exact eight-file
source set. Candidate validation sources use CandidateSource/v2 with the extra
signed developer entry. The PowerShell bootstrap verifies its own signature and
the local endpoint-probe signature before calling that probe, then verifies the
downloaded source and package again before UAC. Existing Windows 11 onboarding
v2 packages remain readable through the older Python entry.

## Publisher Requirements

Each OS/architecture gets its own immutable package and descriptor. The release
assembler accepts `--platform` when verifying a non-default platform. Legacy
EXE/DLL files are copied to the names in the table before calculating the manifest;
signed bytes must not change. Installation checks PE architecture and requires
Force Integrity on modern user-mode images and its absence on legacy images.

Service identity order is F1, Artifact Signing, then product signing. Drivers
retain Microsoft hardware and product signatures. Exact descriptor, manifest,
source and file hashes are checked before invoking elevated helpers. No policy
key, test root certificate or ELAM installation is part of this entry. Existing
runtime config and policy remain driver-validated; platform selection requires
no new server policy field or driver protocol change.

Check PowerShell/.NET and SHA-2/certificate prerequisites on legacy machines.
Signature failures remain errors. Installing prerequisites or changing system
trust is not a side effect of the bootstrap.
