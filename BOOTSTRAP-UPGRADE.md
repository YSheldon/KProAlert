# FalconPro Acquisition And Upgrade Status

The new [LIFECYCLE.md](LIFECYCLE.md) describes the executable ordinary-service
upgrade path, durable recovery and common CLI. The older `upgrade_state.py`
library below remains a non-executing model and does not grant native authority.
Signed lifecycle onboarding v2 and native upgrade/reboot acceptance are still
required before the new path is publicly released. PPL upgrades remain blocked.

## Download Without Manual Checksums

After binding the actual local Windows endpoint, the assistant can run:

```powershell
python plugins/kpro-alerts/scripts/bootstrap.py plan
```

No PackageRoot, SID or checksum is supplied by the user. The helper checks the
bound endpoint, discovers a stable release in the existing public repository,
verifies `FalconPro-release.ps1` with the existing Windows publisher policy,
then trusts its archive sizes/digests. It extracts only the known package and
onboarding files, verifies both manifest digests and fills the native installer
plan arguments. It does NOT elevate or install automatically.

Only the fixed repository's HTTPS release URLs and GitHub asset CDN redirects
are accepted. Downloads and expanded archives are bounded; unexpected names,
path traversal, alternate streams, duplicate names and archive links are rejected.
Asset URLs must belong to the same discovered release tag. Download/extraction
refuses administrator/root execution and checks existing reparse ancestors.
This is not an atomic filesystem isolation boundary against a compromised
same-user process; protected native staging remains mandatory before elevation.
No token is attached to public downloads. Do not copy credentials from another
assistant or change host security settings to make verification pass.

The new descriptor verifier and download helper still require their own reviewed
packaging and native acceptance. A Git URL alone does not authenticate modified
local helper code: use a verified/pinned bootstrap distribution. Prior to any
elevation, move the admitted sources/package to administrator-controlled staging
and independently verify the signed entry point, as required by LOCAL-ENDPOINT.md.

## Signed Release Descriptor

The release asset is a signed data-only `.ps1` containing exactly one line:

```text
# FALCONPRO-RELEASE-JSON: <base64 UTF-8 JSON>
```

It must not be executed. After Windows publisher/timestamp validation its strict
JSON schema is `FalconProReleaseDescriptor/v1`, with version (four numbers),
platform `windows11-x64`, releaseStatus `verified`, packageManifestSha256,
sourceManifestSha256, and assets.package / assets.onboarding. Each asset has
exactly url, sha256 and size. All digests refer to final signed bytes.

No such verified stable descriptor is claimed published by this change. The
existing candidate release must still be refused. Signing a descriptor or setting
a boolean does not replace installation, reboot, policy and event acceptance.

## Upgrade Coordinator

`upgrade_state.py` is a durable coordination library, NOT a finished native
upgrader. It currently rejects same-version/downgrade replacements, unverified
recovery packages, undrained delivery and absent effective-policy snapshots.
Only unchanged signed policy/runtime hashes are admissible; migration requires
a separately verified path.

The persisted sequence is backup -> product-authorized uninstall -> install ->
policy/event/reboot verification. Intent is committed before each native step;
after a crash a pending step must be reconciled, never blindly replayed. Another
worker cannot claim the same step. User state must remain outside replacement
payloads or inside the authorized-uninstall evidence archive.

Recovery plans bind the exact previous package. They do not automatically restore
it or permit arbitrary downgrade. Receipt booleans are assertions from the future
trusted native adapter, not cryptographic proof; NEVER feed event/AI-generated
JSON into this library as authority to uninstall or mark success.

The service-side snapshot/recovery contract and read-only native proof adapter
now have source implementations. Still required before upgrade Apply can be exposed:
the signed service/helper release, native lifecycle adapter, protected
staging/transaction ownership, interrupted-upgrade reconciliation, and physical
upgrade/reboot/rollback tests. Current code deliberately performs no uninstall,
driver replacement, policy mutation or automatic rollback.

## Native Policy Proof

`native_upgrade.query_snapshot` obtains new stdout from the installed service;
it does not import saved or AI-supplied receipts. It rejects cloud execution,
unbound/different devices, stopped or conflicting protection, unadmitted helper
bytes, transport failure and malformed responses. The helper digest and installed
manifest digest must originate in admitted signed distributions, not alert text.

`Invoke-PolicySnapshot.ps1` requires elevated native x64 Windows and protected
staging below native Program Files. It rejects NULL DACLs and checks each source
ancestor to that OS directory, including a protected ACL anchor. It verifies the installed service identity, signed manifest attestation,
release gates and installed file hashes, holds deny-write/delete read handles,
then runs only `--upgrade-snapshot` or `--upgrade-verify`. It verifies that the
resident service PID is unchanged after the query. The known trust-module digest
is bound in the helper. Updating that dependency requires a new helper release.
Its unsigned source module has a repository LF rule so the bound bytes are stable
across checkouts; this rule never normalizes signed PS1 release artifacts.
No UAC bypass, remote endpoint selection, policy signing, service control or
uninstall is provided by this helper.

`policy_snapshot.parse_snapshot` validates the exact v1 native schema, exit and
HRESULT statuses, operation, PID, transaction, device, digest and 30-second
freshness. A one-second clock tolerance applies to invocation-start/future bounds.
It rejects duplicate keys, extra fields, noncanonical integer values and oversize
stdout. This parser alone does not authenticate externally supplied JSON.

Older installed services without these two commands cannot be upgraded through
this route. They remain running; an unknown command is not permission to fall
back to disk-only checks or force reinstallation. The same transaction and digest
must be verified immediately before authorized uninstall and after restoration.

These new helper sources are not yet included in the published signed onboarding
archive. Python/mock tests and PowerShell syntax checks do not prove an actual
PPL exchange, elevation, restart or upgrade. `nativeExecutionEnabled` stays false
until the remaining native lifecycle and release gates are satisfied.

For PPL services, the old external `sc stop` uninstall sequence is not a usable
upgrade transport. An independent service-internal, transaction-bound authorized
uninstall request is still needed. It is not implemented by the read-only snapshot
commands; do not bypass PPL or service self-protection to proceed.
