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

`prepare` marks the batch before returning it but DOES NOT upload. Only after
native write success and remote record readback may the AI run:

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
No script provided here sends data or reads credentials.

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

This implementation is an opt-in local journal and schema/aggregation library.
It is not yet automatically wired into the Windows service or installer, nor
does it create a cloud table or turn on telemetry. Native upload/readback must
be validated against the destination chosen by the user before claiming delivery.
