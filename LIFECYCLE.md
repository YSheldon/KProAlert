# FalconPro Installation, Upgrade And Statistics

Give Codex, Grok Bot, WorkBuddy or Cursor this address:
https://github.com/YSheldon/KProAlert

The common entry is `falconpro.py`, run with this repository's documented Python
venv. Run `python falconpro.py --help` for commands. The published default branch
and reviewed revision, not an unrelated KPro source-directory prototype, are the
source of the integration. Client runtime registration and Windows installation
are verified independently.

The Windows installation lane supports Windows 11 x64 and ARM64 workstations.
The endpoint probe, signed release descriptor, manifest and PE Machine must all
agree; unknown or changed architecture is rejected before installation. ARM64
uses `KProSvcArm.exe`, `KProProtectArm.dll` and `KProFilterArm.sys`. It never
selects x64 components just because the AI tool runs under emulation. Win7/x86
driver support elsewhere in the product is not a public-installer support claim.

## Installation

1. `python falconpro.py status` identifies the execution host. Confirm the actual
   Windows PC before binding its returned device ID. A cloud bot returns
   `local_channel_required`; it can configure its own Feishu reader and hand the
   Windows steps to an authorized endpoint channel.
2. `python falconpro.py install --device-id <confirmed-device-id>` downloads and
   checks the stable signed release and outputs a persistent plan path. It needs
   no user-supplied package path, checksum, SID or policy key.
3. After approval, run `python falconpro.py install --plan <plan-path> --apply --approve`.
   The entry revalidates downloaded sources, the signed descriptor and all file
   hashes, verifies the native entry signature, then requests Windows elevation.
  The native executor stages files under administrator-controlled Program Files
  and invokes the existing DLL-backed product installer.
4. `awaiting_reboot` means service, driver, collector and current effective-policy
   checks passed. Schedule a normal reboot at the user's chosen time. Run the same
   command with `--resume` after reboot. `complete` requires a new boot identity,
   the same effective policy digest and fresh collector status.

If there is no verified stable release descriptor, the operation stops before
elevation or installation. The existing controlled-validation prerelease remains
ineligible. The new native entry must be signed and packaged before this command
can execute it. This source implementation does not declare a public release ready.

New plans use `FalconProLifecyclePlan/v2` and bind the native architecture.
Existing v1 plans are x64-only; revalidation is still required. Native PowerShell
helpers use process-local `RemoteSigned`, in addition to explicit signature and
publisher verification. They do not change the machine execution policy or
suppress UAC. Program Files is resolved from the native registry, not caller
environment variables.

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

Use `python falconpro.py upgrade --device-id <confirmed-device-id>` and then
`python falconpro.py upgrade --plan <plan-path> --apply --approve`.

The old service must support the effective-policy snapshot interface. The updater
accepts a strictly higher four-component release version and unchanged signed
policy/runtime bytes. It verifies a recovery package, persists each pending intent,
requests product-authorized uninstall, preserves the old evidence archive, installs
the new release, and verifies the same effective-policy digest. The user database,
notification cursor and metrics ID are outside the replacement payload.

After reboot use `--resume`. A pending interrupted step is not replayed. Inspect
the protected `Program Files/FalconProTransactions/<transactionId>/result.json`.
For an admitted recoverable upgrade, `--rollback --apply --approve` restores only
the transaction's exact prior signed package through the same product installer;
it does not sign policy, force-unload drivers, delete broken partial installations
or permit an arbitrary downgrade. `recovery_awaiting_reboot` requires another
normal reboot and `--resume` before `rolled_back` can be returned.

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
