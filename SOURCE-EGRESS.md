# Source-egress observations (unreleased)

This independent, read-only channel is not a ransomware driver event type.
It does not prove network upload, enable blocking, or execute remediation.
The resident collector and live cloud acceptance remain release prerequisites.

Generate a standalone client configuration with the existing setup entry:

```text
falconpro.py setup --client grok --cli <lark-cli> --base <base-token> --source-egress-table <separate-table-id>
```

The selected table must have `recordId` and `observationJson` text columns and
a `simulated` checkbox column. `observationJson` contains the exact
`FalconProSourceEgressObservation/v1` JSON. Row identity and simulation flag
must match the embedded record. Do not reuse the ransomware or operations table.
This generates configuration; it does not create a table or change an assistant.

`source_egress_alerts(limit=20, offset=0)` returns a bounded page with `hasMore`
and `nextOffset`, not full statistics or a transactionally frozen snapshot.
Concurrent table edits may shift offset pagination. It returns cloud-stored
claims, not device attestation. Historical
baselines are not new uploads; application acceptance claims are not network
proof. A coverage gap is incomplete observation, not a clean verdict.

Before giving advice, ask whether the project is sensitive and whether the user
consented to the application's backup/synchronization. Do not claim that deleting
local evidence recalls remote data. Switching ransomware protection to enforce
does not prevent source upload. Simulated records must not count as real threats
or production usage. No source/archive contents or credentials belong in this table.
