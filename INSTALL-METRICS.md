# FalconPro Optional Installation Statistics

## Privacy And Scope

Statistics are off by default, independent of protection and alert collection.
The user separately authorizes their AI tool to upload to a specific Feishu
table using that user's own authentication. There is no public receiver, bundled
token, publisher credential, hidden upload or new scheduled task.

Collected fields are only random installation/event IDs, UTC day, numeric
component version, architecture, OS family, lifecycle kind and coarse running
state and explicit simulation marker. Never reuse the endpoint fingerprint, MachineGuid, hostname, account,
file path or command line. Reuse one journal across AI tools for the same
installation; a clean reinstall/re-enrollment generates a new random identity.

Counts represent consenting, reported installation IDs, NOT unique people or
physical devices. Reinstalls, opt-out and multiple local journals affect counts.
No protection claim is inferred from an active ID. Reports are client assertions,
not remotely attested evidence and not suitable for licensing or billing.

## Local Workflow For Codex, Grok Bot, WorkBuddy And Cursor

Execute on the user-confirmed Windows endpoint, never a cloud bot computer.
Use the repository venv and an explicit private, user-writable state directory.
Keep metrics in a dedicated `metrics.db`, separate from events and notification
dedup state. Do not reuse another user's journal.

```powershell
python plugins/kpro-alerts/scripts/metrics_journal.py --database <private-folder>/metrics.db enable --consent
python plugins/kpro-alerts/scripts/metrics_journal.py --database <private-folder>/metrics.db record --kind install_success --version 1.2.0.267 --architecture x64 --os-family windows11
python plugins/kpro-alerts/scripts/metrics_journal.py --database <private-folder>/metrics.db prepare
```

The direct `metrics_journal.py prepare` command reserves rows for an explicit
handoff; it is not the user-facing preview. Use the upload preview below when
you need to inspect a batch without changing its state.

The example version is illustrative, never authoritative. Record success only
after the approved installer actually succeeded and its local result was checked.
`install_started` and `install_failure` are distinct; downloading, importing a
template, connecting MCP or planning an install is not install success.
Daily `status` records use unknown/not_running/running_policy_unverified; never
claim policy verification from service status. Duplicate daily identical status
observations coalesce. The bounded journal fails without affecting protection.

## Authorized Upload

Show the minimum-field payload and destination to the user before first upload.
Use the user's native Feishu connector to create records in the explicitly
authorized table. Match fields directly to schema keys; do not upload local
paths/configuration or attach raw logs. Use installationId + eventId as the
logical uniqueness key. For an existing remote record, compare the exact payload
before accepting it as the same event. Conflicting duplicates require diagnosis.

Preview is read-only and does not reserve or mutate journal rows. The explicit
apply path marks the batch before networking, writes only the allowlisted fields
with `base +record-upsert`, then reads the returned record with
`base +record-get --record-id ... --format json --as user`. Only an exact
readback of the event fields may acknowledge the journal row.

The common entry can perform the same explicit handoff with the user's authorized
Lark CLI:

```powershell
python falconpro.py metrics --database <private-folder>/metrics.db upload `
  --cli C:\path\to\lark-cli.exe --base <authorized-base> --table <authorized-table>
python falconpro.py metrics --database <private-folder>/metrics.db upload `
  --cli C:\path\to\lark-cli.exe --base <authorized-base> --table <authorized-table> --apply
```

The first command is a repeatable preview. The second writes only the allowlisted
fields, requires the user's existing `--as user` Lark authentication, accepts
the CLI's single top-level `data.record_id_list` receipt (and legacy nested
compatibility), verifies that record with readback, and only then acknowledges
it. A timeout, malformed response, or readback mismatch is marked `uncertain`
without retrying.

```powershell
python plugins/kpro-alerts/scripts/metrics_journal.py --database <private-folder>/metrics.db ack --event-id <event-id> --receipt <actual-rec-id>
```

On an uncertain response, mark `uncertain` and query the authorized table by the
uniqueness key. Never resend automatically. `status` lists up to 50 unconfirmed
IDs and a nextCursor; use `status --after <cursor>` for further pages. Use
`recover --event-id <id>` to read a revalidated payload without changing its state.
Recovery does not authorize resending: first reconcile the target table, and if
absence is established obtain approval before any new write. Recheck consent
before writing. Neither prepared nor acknowledged proves the user's PC is safe.
No script reads credentials; only the explicit `--apply` path invokes the
user-provided CLI to send the allowlisted fields.

For acceptance only, enable a separate journal with `--consent --simulation`.
All its records carry simulated=true and the aggregator excludes them from
production counts. Never mix that journal with a real installation identity.

## Interpretation And Opt-Out

`install_metrics.summarize` deduplicates events and reports successful installation
IDs, active reported installations over 7/30 UTC days, reported starts/failures
and 30-day version observations. Version counts can overlap after upgrades.
An uninstall makes that installation ID inactive even if delayed status arrives.
Use a complete authorized dataset for total statistics; a bounded page is not
the population. Accurate per-attempt failure rates require paired attempt
receipts and are not inferred from unmatched starts/failures in this version.

Export the full authorized metric-record array through the user's Feishu tool,
then run `python plugins/kpro-alerts/scripts/install_metrics.py --input <export.json>`.
Add `--complete` only after all pages are collected; otherwise sourceComplete
remains false. Reading the publisher's private data is not implied by plugin
installation: each reporting user must have the destination permission.

Users may run `disable` to stop local collection and remove the journal's stored
identity/events. This does not promise forensic erasure of backups or deletion
of already uploaded records. Remote retention/deletion is managed in the
user-authorized table. Never publish a global installation count from private
tables the publisher cannot read: shared reporting requires explicit access.

The historical `falconpro.py` script install/upgrade/resume entry accepts an existing opt-in
`--metrics-database`. It records observed starts and post-reboot completion;
upgrade completion does not increment installation count. Native uncertain
outcomes are not counted as definite failures. No cloud table is created and
telemetry remains disabled until the user consents. Native upload/readback must
be validated against the destination chosen by the user before claiming delivery.

The native Rust entry does not accept --metrics-database. Follow
[NATIVE-INSTALL.md](NATIVE-INSTALL.md) for endpoint execution and treat its verified
transaction receipt as evidence for a separately authorized metrics workflow.
Do not pass script-only flags, assume native receipts automatically upload
statistics, or use a cloud host's state as a local installation event. The native
receipt-to-metrics handoff source is implemented below; signed-native runtime
acceptance and destination upload evidence remain separate release gates.

The local journal supports an internal opaque observation digest for once-only
recording across days. It is namespaced to the random consenting installation ID,
never exported, and does not reset an acknowledged or uncertain delivery state.
Reusing an observation with conflicting facts is rejected. This is idempotency,
not receipt authentication: a caller must first validate the native observation.
There is no automatic native import or new network upload in this helper.

## Verified Native Receipt Import

After explicit metrics opt-in, the assistant can use `falconpro.py metrics-native`
with `--database`, `--entry`, `--entry-sha256`, `--device-id` and `--transaction`.
The entry hash must come from the admitted signed release, not from an arbitrary
receipt file. The Windows AI-host adapter pins the entry and its ancestors,
checks its hash and existing publisher policy, and invokes only the read-only
native `receipt` command. It accepts no JSON receipt file and never elevates,
installs, stops services, reboots or uploads. Without an existing enabled journal
it does not create a database or invoke the reader.

The native EXE itself has no interpreter dependency. This optional Python MCP-host
adapter uses that host's system PowerShell for publisher verification, with only
the child process module path restricted to its system modules. It is not the
endpoint installer and does not add an endpoint Python requirement.

Windows8/8.1 observations use `windows8`, a newly supported metrics OS-family
value. Update receiving validators/choice fields before enabling this platform;
never relabel it as Windows7/10. Null historical OS classification is rejected.
Native preview .2 predates `receipt`; it must fail as unsupported, not fall back
to trusting JSON. Preview .3 includes the command. Its signed Windows 11 x64
entry passed an existing completed-history read, repeat, wrong-device and missing-
transaction checks, without changing the journal or service PID. This does not
prove other architectures, full installation/PPL upgrade or metrics upload.

## Verified Native Observation Bridge

The transport-free bridge is
`plugins/kpro-alerts/scripts/native_observation.py`:

```python
collect_native_observation(database, reader)
```

`reader` must be a callable supplied by the separately verified native entry
point. It must return an object, not a path, JSON string, file, or imported
receipt. The bridge has no native process launcher, CLI input, network call, or
upload path. With no existing metrics opt-in, it returns without invoking the
reader and records nothing.

The reader result must contain exactly these ten keys:

```text
schema, observationId, operation, phase, version,
architecture, osFamily, day, testOnly, protectionVerified
```

The accepted values are:

- `schema` is `FalconProNativeObservation/v1`.
- `observationId` is exactly 64 lowercase hexadecimal characters.
- `operation` is `install` or `upgrade`; `phase` is `complete`.
- `version` has four numeric components, and `architecture` is `x86`, `x64`,
  or `arm64`.
- `osFamily` is `windows7`, `windows8`, `windows10`, or `windows11`.
  `windows8` covers Windows 8 and 8.1; a null or unknown OS is
  rejected rather than guessed.
- `day` is a non-future UTC epoch day; `testOnly` is an explicit boolean and
  `protectionVerified` must be exactly `false`.

After validation, `install` maps to `install_success` and `upgrade` maps to
`upgrade_success`. The stored metric always uses `state=unknown`; the native
observation ID is used only as the journal's internal opaque dedupe key and is
not exported as a public metric field. Device IDs, SIDs, paths, and command
lines are rejected as observation fields and are not stored or exported in
metrics. The local adapter still uses a device ID to bind the native request.

The bridge captures the initial consenting installation identity and simulation
mode before reading. The journal rechecks both values inside the same atomic
record transaction, so a disable/re-enable or simulation-mode race fails
closed. `testOnly=true` is accepted only by a simulation journal; such events
carry `simulated=true` and are excluded from production statistics. Production
observations cannot be written to a simulation journal.
