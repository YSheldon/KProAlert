# FalconPro Acquisition And Upgrade Status

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

Still required before upgrade Apply can be exposed: a service-side trusted
effective-policy snapshot/recovery contract, native lifecycle adapter, protected
staging/transaction ownership, interrupted-upgrade reconciliation, and physical
upgrade/reboot/rollback tests. Current code deliberately performs no uninstall,
driver replacement, policy mutation or automatic rollback.
