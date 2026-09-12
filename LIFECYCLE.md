# FalconPro Installation, Upgrade And Statistics

Give Codex, Grok Bot, WorkBuddy or Cursor this address:
https://github.com/YSheldon/KProAlert

The Windows endpoint entry is the signed `falconpro.ps1` from the verified
Release onboarding archive. It does not require Python on the protected PC.
The optional `falconpro.py` entry and AI connectors retain their own Python/MCP
requirements. The published default branch and reviewed revision, not an
unrelated source-directory prototype, define the integration. Client runtime
registration and Windows installation are verified independently.

See WINDOWS-COMPATIBILITY.md for the Windows 7 SP1, 8.1, 10 and 11 package matrix
and PowerShell/.NET prerequisites. Implemented OS selection is not per-platform
runtime acceptance or a released package.
The endpoint probe, signed release descriptor, manifest and PE Machine must all
agree; unknown or changed architecture is rejected before installation. ARM64
uses `KProSvcArm.exe`, `KProProtectArm.dll` and `KProFilterArm.sys`. It never
selects x64 components just because the AI tool runs under emulation.

## Installation

1. `powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\falconpro.ps1 -Mode status`
   identifies the execution host. Confirm the actual Windows PC before binding
   its returned device ID. A cloud bot must use an authorized local endpoint
   channel; it must not bind its own cloud computer as the protected PC.
2. `powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\falconpro.ps1 -Mode install -ExpectedDeviceId <confirmed-device-id>` downloads and
   checks the stable signed release and outputs a persistent plan path. It needs
   no user-supplied package path, checksum, SID or policy key.
3. After approval, run the same PowerShell command with `-PlanPath <plan-path> -Apply -Approve`.
   The entry revalidates downloaded sources, the signed descriptor and all file
   hashes, verifies the native entry signature, then requests Windows elevation.
  The native executor stages files under administrator-controlled Program Files
  and invokes the existing DLL-backed product installer.
4. `awaiting_reboot` means service, driver, collector and current effective-policy
   checks passed. Schedule a normal reboot at the user's chosen time. Run the same
   command with `-Mode resume` after reboot. `complete` requires a new boot identity,
   the same effective policy digest and fresh collector status.

If there is no verified stable release descriptor, the operation stops before
elevation or installation. The existing controlled-validation prerelease remains
ineligible. The new native entry must be signed and packaged before this command
can execute it. This source implementation does not declare a public release ready.

New plans use `FalconProLifecyclePlan/v3` and bind native architecture and OS
platform. The PowerShell entry requires onboarding v3 and plan v3. The Python
entry still reads older plans under their original Windows 11 scope; existing
v1 plans are x64-only, and revalidation is required. Native PowerShell
helpers use process-local `RemoteSigned`, in addition to explicit signature and
publisher verification. They do not change the machine execution policy or
suppress UAC. Program Files is resolved from the native registry, not caller
environment variables.

The local launcher requests `runas` through Windows `ShellExecuteExW`, retaining
normal UAC and zone checks. Only native `ERROR_CANCELLED` (1223) with no launched
process returns `elevation_cancelled`, `operationStarted=false` and
`outcomeUncertain=false`. This describes the current invocation; it does not
erase or close an older pending transaction. No elevated receipt or registry
state is read as a substitute for the user's cancelled launch. A started child
that exits 1223 is not a UAC cancellation. Timeout, missing process handle and
other launch/wait errors remain `attention_required` without automatic retry or
forced process termination. A cancellation is never installation success.

## Four Clients

`python falconpro.py setup --client <codex|grok|workbuddy|cursor> --database <local-db>`
previews the connection; `--apply` registers through the existing adapters.
Cloud readers use `--cli`, `--base`, and `--table` with their own authorization.

Codex and WorkBuddy use their installed native CLI. Cursor backs up and merges
only `mcpServers.kpro-alerts`, preserves unrelated settings, and refuses project
overrides, disabled or conflicting entries. Grok Bot returns `AddMcpServer`
parameters for the bot's real host tool. It is not a fabricated CLI or a claim
that all hosts understand the same marketplace manifest. Keep the same MCP name
on update and verify `integration_status` in the actual client process.

Use NOTIFICATIONS.md for native scheduling and alert guidance. New installation
does not automatically opt in to messages, metrics or destructive remediation.

## Upgrade And Recovery

Use the same signed PowerShell entry with `-Mode upgrade -ExpectedDeviceId
<confirmed-device-id>` to prepare a plan, then add `-PlanPath <plan-path>
-Apply -Approve` to execute the confirmed upgrade.

The old service must support the effective-policy snapshot interface. The updater
accepts a strictly higher four-component release version and unchanged signed
policy/runtime bytes. It verifies a recovery package, persists each pending intent,
requests product-authorized uninstall, preserves the old evidence archive, installs
the new release, and verifies the same effective-policy digest. The user database,
notification cursor and metrics ID are outside the replacement payload.

After reboot use `-Mode resume`. A pending interrupted step is not replayed. Inspect
the protected `Program Files/FalconProTransactions/<transactionId>/result.json`.
For an admitted recoverable upgrade, `-Mode rollback -Apply -Approve` restores only
the transaction's exact prior signed package through the same product installer;
it does not sign policy, force-unload drivers, delete broken partial installations
or permit an arbitrary downgrade. `recovery_awaiting_reboot` requires another
normal reboot and `-Mode resume` before `rolled_back` can be returned.

New lifecycle-owned installs write an administrator-protected
`.falconpro-install.json` before copying payloads. It binds the device,
transaction, package and signed source manifest. Recovery may archive a partial
root only when that marker matches, no service/process/filter remains, there are
no unknown entries, reparse points or alternate data streams, and every present
file is an exact file or prefix from the admitted new package. No partial file
is executed. The root is atomically renamed to a transaction-specific archive,
never deleted. `partial_archive_pending` records intent before the rename;
recovery reconciles an existing bound archive instead of blindly repeating it.
Each archive has a fresh suffix and is retained in the protected journal; at
most eight partial archives are admitted for one transaction. A failed recovery
installation is checked against the OLD recovery package and old marker hash,
not the new package. Explicit rollback can archive that interrupted recovery and
retry restoring the old package. If the old service already runs, the coordinator
first revalidates its files, effective policy and collector instead of reinstalling.
For a failed first install with no previous version, explicit rollback safely
archives an admitted partial root and returns `installation_aborted` (candidate:
`validation_aborted`); it does not invent an old package or installation success.
Ambiguous roots, missing markers, mismatched bytes and unverified post-service
failures still stop for product recovery. Existing unmarked installs are not
silently adopted. The internal `LifecycleTransactionId` is supplied by the common
coordinator, not by a policy server. Driver policy and event protocols are unchanged.

For an interrupted upgrade in `prepared`, `backup_ready` or `uninstall_pending`,
explicit `--rollback --apply --approve` may return `cancelled_no_change` only
after revalidating the old installation's protected paths, signatures, all
payload hashes, live service/driver and fresh effective-policy snapshot. It
does not stop or reinstall anything and does not count as installation success.
It proves the old installation is intact now, not that no brief interruption
occurred earlier. Missing/stopped components or uncertain policy still require
diagnosis; absence alone never proves that product-authorized uninstall succeeded.
Keep the downloaded release directory and approved plan until the transaction is
closed, including a cancellation readback. Resume/recovery revalidates these signed
inputs as well as protected transaction data; it does not trust the journal alone.

The current public package uses an ordinary service. PPL upgrades are rejected
before stopping protection; their service-internal uninstall transport still needs
implementation/signing and separate native acceptance. Missing snapshot support,
changed policy, partial installation or failed product uninstall preserves evidence
and requires diagnosis. No ELAM driver is installed by this lifecycle.

A recovery retry may resume an ordinary stopped service only after checking its
transaction marker, device/source/package identities, full signed package and
exact SCM executable path. Running recovery services need the same binding; an
unmarked installation is never adopted. PPL, pending/unknown service states and
failed starts preserve evidence rather than force-stop, delete or retry. This
does not turn a first-install registered-service failure into a partial-directory
archive: that state still requires product-authorized recovery.

## Optional Statistics

Use a private state folder and enable only after separate user consent:

```text
python falconpro.py metrics --database <private-folder>/metrics.db enable --consent
python falconpro.py metrics --database <private-folder>/metrics.db status
```

Pass `--metrics-database <same-file>` to install/upgrade/resume commands. Starts
are journaled before native invocation; only completed post-reboot verification
records success. An uncertain elevated result is not reported as a definite
failure. A full or unavailable metrics journal does not stop protection.

`metrics ... upload --cli <lark-cli> --base <base> --table <table>` previews a
bounded minimal payload without reserving rows. After destination authorization,
add `--apply` to upload, read back the exact fields and acknowledge each row.
`prepare` and `ack` remain the manual connector handoff. On uncertainty use
`uncertain` and `recover`; do not resend automatically. The publisher has no
built-in receiver or secret on the endpoint. Use one journal across AI tools to
avoid multiple IDs. See [INSTALL-METRICS.md](INSTALL-METRICS.md).

`python falconpro.py statistics --input <authorized-export.json> --complete`
aggregates consenting installation IDs, 7/30-day activity, versions, install
starts/failures and upgrade starts/successes/failures. Use `--complete` only after
all pages were exported. Upgrades do not add new installations. Reinstalls and
opt-out mean these counts are not unique people; simulated records are excluded.

## Publisher Order

Sign service EXEs F1, Artifact Signing, then product signing. Validate all final
signatures. Drivers require Microsoft hardware and product signatures. Policy
signing stays in the protected GitHub signing workflow. Do not reuse test-signed
ARM64 files in a public release.

The native ARM64 DLL also requires the verified Artifact Signing identity for
normal integrity-enforced loading. Product signing alone is not evidence that
the DLL can load. Validate signatures and actual loading with test signing off.

Sign the onboarding PS1 files, then run `tools/build_release_bundle.py --package
<verified-package> --signed-sources <signed-source-tree> --output <new-folder>
--tag <immutable-tag>`. It creates exact-set archives and the unsigned data-only
descriptor. Sign that descriptor last, then use `--verify --output <folder>`.
Never normalize signed script bytes or execute the descriptor. Publication remains
a separate reviewed action after same-candidate native and client acceptance.
For ARM64 the descriptor is `FalconPro-release-arm64.ps1` and the package is
`FalconPro-Windows11-arm64.zip`; verify with `--architecture arm64`. The x64
descriptor remains `FalconPro-release.ps1`. Both platforms share an identical
onboarding archive built from the same signed source tree. Do not substitute
one platform's descriptor or runtime archive for the other.
