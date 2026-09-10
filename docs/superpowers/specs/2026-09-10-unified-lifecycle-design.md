# FalconPro Unified Lifecycle

Approved scope: one GitHub address for Codex, Grok Bot, WorkBuddy and Cursor,
signed Windows installation, upgrades, and opt-in user-authorized statistics.

## Existing contracts

Repository: https://github.com/YSheldon/KProAlert. The default branch is
`codex/public-preview`. The Windows preview supports Windows 11 x64. ARM64
test-signed evidence does not admit ARM64 to this release. Driver policy and
event protocols do not change. Policy private keys remain in GitHub Environment
Secrets; clients consume already-signed policy and runtime configuration.

## Delivery

`falconpro.py` is the common command entry: status, setup, install, upgrade,
metrics. Client registration reuses the existing adapters. Grok Bot registers
through its real AddMcpServer capability; cloud execution can query Feishu but
must hand off endpoint mutations to the bound Windows PC. Cursor merges one
MCP entry after validating and backing up existing settings.

`install` and `upgrade` download only from the fixed repository using the signed
release descriptor and exact archive/manifest hashes. No stable descriptor means
no mutation. A verified signed native entry owns elevation and protected staging.
An installation plan is the default; Apply requires user approval. All files are
revalidated after staging. Reparse paths, schema drift, stale files, unsupported
platforms, unknown services, and missing signatures reject the operation.

## Upgrade

Upgrade uses the current installation's signed manifest and the service-local
effective-policy snapshot. Only strictly increasing versions with unchanged
policy/runtime bytes are admitted. Policy changes require a separate signed
policy migration; the updater never resigns or edits a policy.

The native executor holds an exclusive transaction lock and records intent
before mutations. It verifies a recovery copy, performs product-authorized
uninstall, installs the new signed release, and verifies the same effective
policy digest. Evidence and user delivery data remain in the protected old
archive and external user state respectively. Failure stops at an explicit
recovery state. A restart of the command never blindly repeats an uncertain
uninstall/install. Resume performs read-only runtime and changed-boot checks.

The existing external stop transport is allowed only for ordinary services.
PPL upgrade remains blocked before any stop until a transaction-bound internal
uninstall interface is signed and verified. Snapshot success is not permission
to force-stop PPL. Completion after reboot requires effective policy readback
and fresh successful collector status; no automatic reboot interrupts user work.

## Statistics

Statistics are disabled by default. A dedicated local journal uses a random
installation ID shared by the four assistants on this PC. It records observed
install and upgrade starts/results, UTC day, version, architecture, and coarse
state. No hostname, SID, device fingerprint, file path, command line or credentials
are uploaded. Upgrade success never increments new installation count.

Upload is a prepare/acknowledge flow using the user's native Feishu connector,
explicit destination and credentials. Uncertain writes require readback and are
never resent automatically. Simulations are excluded. Counts mean consenting
reported installation IDs, not unique people; partial pages are not totals.

## Acceptance

Run existing tests plus native executor parsing/contract tests and transition
tests for conflict, decline, interruption, rollback preservation, unchanged
policy, and statistics deduplication. Validate signed downloads separately from
mock tests. Four client-native connected/query/notification receipts and physical
install/upgrade/reboot/recovery remain publication evidence. Publish no private
keys, credentials, local personal settings or raw event data.
