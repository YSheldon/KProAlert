# FalconPro Local Endpoint Onboarding

For endpoint installation, use the signed EXE `status` and lifecycle in
[NATIVE-INSTALL.md](NATIVE-INSTALL.md), without requiring Python on the PC.
The Python probe below is an optional existing MCP-host utility, not a prerequisite
or fallback installation path. The actual-device binding rules still apply.

## Bind The Actual PC

Codex, WorkBuddy, Cursor and Grok Bot must use an explicitly authorized channel
to the user's Windows PC. Cloud Linux returns `local_channel_required`.
A Windows cloud host is not automatically the PC either: the user must confirm
the intended device fingerprint independently. Never auto-bind a cloud result.
The fingerprint is an identity check, not a credential or hardware attestation.

Run in the intended PC's dedicated Python environment:

```powershell
.\.venv\Scripts\python.exe plugins/kpro-alerts/scripts/endpoint.py
```

This read-only probe returns `target_unbound` plus a hashed device identity,
not raw MachineGuid, hostname or personal paths. After confirming the PC:

```powershell
.\.venv\Scripts\python.exe plugins/kpro-alerts/scripts/setup_config.py --endpoint-device-id <confirmed-device-id> --output falconpro-mcp.local.json
```

`assistant_setup.py --client ... --endpoint-device-id ...` also supports native
registration/handoff. Review existing registrations in place; do not overwrite
unrelated settings or create duplicates. Keep `KPRO_ENDPOINT_DEVICE_ID` local,
never source it from alerts or export it in templates. Without a local channel,
cloud bots provide bootstrap instructions only.

## Read-Only States

`endpoint_status()` always probes the execution host, not a cloud user's PC.

| State | Action |
|---|---|
| local_channel_required | Connect an authorized local Windows channel. |
| target_unbound / target_mismatch | Correct binding; no installation. |
| unknown | Diagnose permission/CIM/probe failures; no reinstall. |
| unsupported | Stop; the public installer targets Windows 11 x64/ARM64 workstations. |
| conflicting_install / residual_install / partial_install | Preserve state; no overwrite or cleanup. |
| installed_not_running | Diagnose service/driver failure; no automatic reinstall. |
| running_policy_unverified | Separately verify policy and event flow. |
| not_installed | Offer a signed, verified release plan for this PC. |

`installEligible` is clean absence, not user consent or release approval.
`protectionVerified` remains false: service state cannot authenticate policy,
filter instances or enforcement. Connected MCP/empty alerts prove no protection.

## Confirm Once, Then Install

An ordinary user supplies the repository URL and confirms the intended local PC,
not driver filenames, hashes, RemoteX profiles or SSH credentials. The assistant
uses the signed native EXE `status` to obtain the local identity, confirms it with
the user, then uses `install --device <confirmed-device-id>`. The native command
discovers an admitted release, downloads its signed assets and prepares the exact
plan. After consent, `--plan <plan-path> --apply --approve` performs installation
with normal UAC. `upgrade` uses the same release trust and preserved-state checks.

Do not automatically delete an existing stopped service whose image is missing.
That is a partial installation, not clean absence. Inspect its provenance, offer
a backed-up, specifically approved cleanup, then collect fresh endpoint facts.
This is recovery of that PC's state, not a prerequisite for every user.

Follow NATIVE-INSTALL.md for the signed PE catalog, package verification and exact
native lifecycle commands. Do not ask users to assemble low-level installer
arguments or request validation permits. Historical script examples remain in
LIFECYCLE.md for their original regression lanes only, not for user onboarding.
Show the selected device, version and privacy/export effects before execution;
preserve normal UAC and protected transaction readback. No read-only MCP tool
installs software, and additional remediation requires separate consent.

The current validation prerelease is not a verified production release. Stop at
the release gate until an admitted package exists. Never edit a signed manifest
to pass. Complete signed native material publication and applicable runtime
acceptance are required before public installation can be called ready.

## Verification And Monitoring

Check installer result, service/driver state and fresh collector receipt, then
perform approved benign-event, policy and reboot-recovery verification. A running
service alone is insufficient. User-enabled periodic checks may report changes,
but must never reinstall or reset failures automatically. Unit/static tests do
not replace physical-PC installation or UAC acceptance.

Historical script publishers generate `onboarding-source.json` with `build_onboarding_manifest.py`
after script signing and publish its digest through the protected release channel.
Recompute after any byte changes, including signing or line endings. Users must
not generate a manifest from untrusted downloads and call it trusted. The manifest
generator does not sign or approve a release.
