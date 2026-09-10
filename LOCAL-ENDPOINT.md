# FalconPro Local Endpoint Onboarding

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
| unsupported | Stop; public installer supports Windows 11 x64 workstations only. |
| conflicting_install / residual_install / partial_install | Preserve state; no overwrite or cleanup. |
| installed_not_running | Diagnose service/driver failure; no automatic reinstall. |
| running_policy_unverified | Separately verify policy and event flow. |
| not_installed | Offer a signed, verified release plan for this PC. |

`installEligible` is clean absence, not user consent or release approval.
`protectionVerified` remains false: service state cannot authenticate policy,
filter instances or enforcement. Connected MCP/empty alerts prove no protection.

## Confirm Once, Then Install

Download an immutable admitted public release through the normal download
channel. Verify the expected manifest digest from a trusted release source,
never an alert URL. Keep reviewed installer sources and package on the local PC.

```powershell
.\Install-FalconPro.ps1 -ExpectedDeviceId <confirmed-device-id> -PackageRoot <verified-package> -ManifestSha256 <trusted-manifest-sha256> -DeliveryUserSid <local-user-sid>
```

Show the verified plan, device, package hash and privacy/export effects. Only
after explicit approval of that device/package, run the same command in native
administrator PowerShell with `-ApproveInstallation -Apply`. Normal UAC/admin
consent is required. The wrapper rechecks identity and clean absence immediately
before the existing signature/release-gated installer. It has no candidate
bypass. No MCP tool installs software; further remediation needs separate consent.

The current validation prerelease is not a verified production release. Stop at
the release gate until an admitted package exists. Never edit a signed manifest
to pass. This new wrapper/probe need signed packaging and local runtime acceptance
before public automatic installation can be called ready.

## Verification And Monitoring

Check installer result, service/driver state and fresh collector receipt, then
perform approved benign-event, policy and reboot-recovery verification. A running
service alone is insufficient. User-enabled periodic checks may report changes,
but must never reinstall or reset failures automatically. Unit/static tests do
not replace physical-PC installation or UAC acceptance.
