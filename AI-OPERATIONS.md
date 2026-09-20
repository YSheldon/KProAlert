# Existing Events, AI Assessment And Operations Return

## Current Status

First-release scope, confirmed by the user: analyze only events already produced
by the existing signed driver. Preserve the installed signed policy and native
protection behavior. No driver update, re-signing, PPL change or new audit policy
is required for this analysis feature. Do not switch a protected endpoint to
Audit or disable existing protection to feed the AI.

The adapters share the same MCP contract (ZCode acceptance is deferred). Assessments, recommendations and
unapproved request records can be stored and explicitly uploaded with exact
Feishu readback. First-release AI does not execute termination, quarantine,
deletion, exceptions, isolation or policy changes. Existing driver blocking and
termination still operate according to the installed policy; they are observed
engine results, not actions performed by the AI.

`integration_status` declares `releaseScope=existing_driver_events_v1`,
`driverChangeRequired=false`, `policyMutationAvailable=false` and
`aiActionExecutionAvailable=false`. These are feature capabilities, not evidence
that a particular endpoint is installed or healthy.

The user subsequently selected `switch_to_enforce` as the first native action
to implement. This is a one-way, confirmation-required signed-policy transition,
not permission to switch to Audit or execute arbitrary remediation. Its native
execution channel is implemented on this candidate branch but is not released
or accepted on a signed endpoint yet; see [ENFORCE-ACTION.md](ENFORCE-ACTION.md).
Extended driver Audit events remain deferred and are not required. Real data delivery, five-client
runtime and notification acceptance, authorized uploads, and applicable existing
package installation/upgrade gates still apply to the first release.

## Phase Two Only: Signed Protection Modes

The enforcement action below can use the existing driver. The deferred part is
extended Audit event coverage and general two-way mode switching, not the signed
enforcement action's implementation work.

| Profile | decisionMode | PolicyFlags for ransomware-only defaults | Effect |
| --- | --- | --- | --- |
| enforce | 3 | 5 | Existing maximum profile, including approved risk blocking |
| audit | 1 | 1 | Ransomware signals retained, risk blocking disabled |

These retained templates are not part of first-release mode switching and must
not be dispatched or installed automatically for first-release analysis.
They are signing-service templates, not unsigned settings the AI may apply.
The private signer validates the profile, generates the envelope, and preserves
the existing driver public key. The endpoint must authenticate that envelope and
read back the effective policy after user-approved application. Changing a local
JSON field or the PPL runtime configuration is not a policy-mode switch.

The new audit event coverage requires the new driver candidate, not just a new
policy. Old released drivers do not audit ordinary protected-directory/bait
access or DR0 sector writes in mode 1. Until the new candidate is signed,
deployed and runtime-tested, do not advertise full audit coverage.

The new candidate adds Type 1 AccessAudited for matched objects and known DR0
sector-zero writes. `actionStatus=0` means FalconPro allowed the request; it does
not prove the filesystem or disk write ultimately succeeded. DR0 audit includes
legitimate/exempt callers and does not inspect content or predict a block.
Type 1 in mode 3 remains an existing exemption/authorization audit, not audit mode.
RENAME is operation 8, DELETE is 16. Requesting DELETE access to open a file is
not a deletion event; actual disposition and FILE_DELETE_ON_CLOSE are separate.

Audit observes selected engine events, not every I/O. Paging/high-IRQL,
cleanup-complete, recursive or unavailable-name paths retain safety guards.
Queues and storage have bounds; check loss and health before interpreting silence.
Audit records matched requests even from callers that would be exempt in Block;
it does not predict a denial or evaluate grant/root-process exceptions. Block
exemption behavior is unchanged. Ordinary audit WRITE uses only cached names;
a cache miss is a coverage limit, not permission to perform a synchronous query
on every write. DR0 name-query failures contribute to the existing health counter.

## Configure And Analyze

Use `falconpro.py setup --client <codex|grok|cursor|workbuddy|zcode>` with an
explicit `--database <events.db>` and `--operations-database <operations.db>`.
The latter configures `KPRO_OPERATIONS_DATABASE`; it does not enable remediation.
The generated `KPRO_ASSISTANT_CLIENT` label is configuration, not a verified
identity of a model or service. OAuth stays local and is not put into the template.

1. Verify `integration_status`, `endpoint_status` and `collector_status`.
2. Page `operations_events(after,limit)` and preserve `nextCursor`. Include
   `reportedDropped` and source limits in the analysis. Types 0 through 8 are
   accepted; full retained records, rather than bounded aggregate statistics,
   provide each event's evidence digest.
3. Call `assess_event` with that eventId/evidenceSha256, verdict, confidence,
   fixed reasonCodes and recommendedActions, model label and a stable 32-hex
   requestKey. Retrying the same content/key returns the same record; changing
   content with that key is rejected. Changed source evidence is rejected.
4. Use `propose_action` to bind a recommended action to the decision. This
   records `requires_native_confirmation`, `not_executed` and
   `executionAvailable=false`. It does not approve or perform the action.
5. Upload summaries only to a user-authorized destination. Keep simulated
   acceptance records out of production statistics.

`FalconProEventEvidence/v1` includes a pseudonymous device/session, numeric and
boolean telemetry, and a source digest. Paths, usernames and command lines are
not returned by default. `sourceAttestation=not_verified_by_native_broker` is
deliberate: local database integrity and actual endpoint origin are not proven by
a SHA-256 digest. The future native broker must verify its own original evidence.

`FalconProAIDecision/v1` is an AI assertion, not confirmed malware ground truth.
`FalconProActionRequest/v1` is a request, not an approval or execution receipt.
The candidate adds `FalconProNativeActionResult/v1`, described below. An AI
assessment or action request must never be relabeled as this result.

## Candidate Native Action Binding

This section describes unreleased candidate code, not installed release capability.
The existing driver protocol is unchanged. A new service safe-spool projection
adds `nativeSources` (private batch SHA-256 and original record index); older
events without it remain analysis-only. It is a locator, not an attestation.
Upgrade the collector/connector reader first, restart its actual MCP process and
verify `integration_status.codeSha256` before deploying this service candidate.
Older strict safe-batch readers reject the additional envelope field; unchanged
driver event records do not imply mixed service/collector versions are supported.
The new reader continues to accept old batches for analysis only.

The local Windows connector uses an admitted signed native entry configured with
`KPRO_NATIVE_ENTRY`, `KPRO_NATIVE_ENTRY_SHA256` and `KPRO_ENDPOINT_DEVICE_ID`.
These values select verified local release material, not commands supplied by
an event or model. Cloud-hosted assistants cannot execute on the user's PC by
running this tool in the cloud. No private signing key is distributed.

1. `propose_action` records an unapproved `switch_to_enforce` request.
2. `request_native_action(request_id)` resolves original private evidence,
   validates device/PPL/signatures/current policy and asks for native human
   confirmation. It accepts no paths, commands, approval flags or result JSON.
3. `native_action_result(request_id)` reads the protected native result. It is
   read-only and cannot change an uncertain request into a success.
4. `collect_native_action_result(request_id)` appends that freshly read result
   to the operations outbox; it does not upload or perform the action again.
5. Authorized delivery re-reads the native result before sending. Missing or
   changed native proof blocks delivery; exact remote readback precedes ACK.

Collection, readback and delivery also require the retained source event to
match its original evidence digest and native locator. Keep that event until
delivery is acknowledged; if it has expired or changed, delivery is blocked,
not silently accepted. Clients sharing one operations database deduplicate a
native result globally by request ID. Independent databases are separate
journals and must not be summed as unique actions without request-ID deduplication.

Linkage includes request/decision/event/evidence IDs, batch/index, source-session
hash/sequence, original record hash, native transaction and source/target policy
hashes. Exact before/after service snapshots are retained. Outcomes distinguish
cancelled, rejected, failed, outcome_uncertain, already_enforced_verified and
executed_verified. A missing/partial durable reservation must not be replayed.
It requires reconciliation, never a fabricated result or a new automatic try.
`diagnose_native_action(request_id)` performs that read-only inspection using
protected records and a current native snapshot. It may report a matching
transaction/post-state, but always keeps `executionVerified=false` and
`causalityVerified=false`. It cannot write a missing receipt, erase a reservation,
retry SetPolicy or turn an observation into a verified execution result.

`verificationProvenance=verified_locally_not_device_signed` is deliberate.
The endpoint administrator is inside the local trust boundary. These uploaded
records are not hardware-signed proof, malware ground truth, or proof of AI
identity. Simulated acceptance records do not count as production operations.

## Explicit Operations Upload

Use the user's separately authorized Lark CLI and the analysis table, not the
alert table or installation statistics. The CLI previews by default without
creating a missing journal or contacting Feishu:

```text
falconpro.py operations upload --database <operations.db> --source <events.db> --base <base> --table <analysis-table>
```

Add `--cli <authorized-lark-cli> --apply` to submit. The table needs text columns
`分析ID`, `关联告警ID`, `记录类型`, `分析来源`, `证据摘要`, `分析结论`, `处置建议`,
`记录时间`, `审批状态`, `执行状态`, `结构化记录`, and checkbox `模拟`.
Existing human-review fields are never written by AI.

Pending state is stored before any network write. A successful CLI exit is not
enough: exact field readback is required before ACK. Readback may retry three
times; writes never retry automatically. An uncertain result stays pending and
must be found by its exact 分析ID, then reconciled without sending again:

```text
falconpro.py operations reconcile --database <operations.db> --source <events.db> --cli <authorized-lark-cli> --base <base> --table <analysis-table> --record-id <64-hex-local-id> --remote-record-id <rec-id> --apply
```

Readback conflicts remain pending. Journal capacity is bounded; a capacity error
requires attention and must not be reported as successful collection. A local
simulation claim is confirmed only with an exact configured simulation ID list.

## Acceptance

Unit and real stdio MCP transport tests cover binding, replay rejection, privacy,
request-only semantics and uncertain-send reconciliation. A simulated assessment
and action request have been written to the authorized Feishu analysis table and
read back. These are communication tests, not real threats or real actions.
First-release acceptance requires the existing signed driver/DLL event stream,
source health/loss evidence, actual client invocation, authorized notification
delivery and summary readback. New native action results, policy application and
new audit-driver tests are deferred phase-two gates. Do not claim either phase
passed merely from connector tests.
