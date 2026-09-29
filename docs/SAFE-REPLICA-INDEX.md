# Safe Replica Index (Local Candidate)

The spool reader accepts both the existing `KProSafeEventBatch/v1` format and
the new `FalconProSafeReplica/v1` envelope. No new credentials or endpoint
Python/Lark dependency are introduced. Deploy the complete plugin scripts,
including `safe_replica.py`, then restart the existing MCP process and read
`integration_status`. Its code hash now includes the replica validator and store.
This source change has not been published or accepted on an endpoint.

## Data And Trust

The envelope contains prepared/commit/accepted metadata and a base64-encoded
safe numeric/boolean projection. The parser bounds sizes, rejects duplicate or
unknown fields and checks complete byte digests and producer identities. Raw
event bodies, private paths and credentials are not part of the envelope.

These checks do **not** authenticate public metadata. Imported sources remain
`analysis_only` / `unverified_public_metadata`; `nativeSourceVerified` stays
false. Neither a SQLite row, a successful import nor this public envelope grants
permission to delete protected evidence or execute an action.

The original four-column batches table is retained. Source identities, commit
identities and event associations are added transactionally with events and loss
counts. A changed helper/commit does not double count a producer batch. Loss
counts retain unsigned 64-bit precision without SQLite SUM overflow. Existing
event bytes, delivery state and old inline source locators remain unchanged.

New query-time source locators participate in the evidence digest. Changing a
locator invalidates an existing decision/request rather than silently rebinding
it. A second identical event source does not change the initially selected
locator. Native execution still requires protected local evidence verification
and explicit confirmation through the native flow.

## Capacity And Remaining Gates

Health reports the main DB, WAL and SHM file lengths separately and in total.
Once their observed total reaches the configured limit (default 512 MiB), new
imports are refused inside their write transaction. This is an observed
pre-import admission check, **not** a hard bound on transaction-internal WAL
growth, initialization, concurrent non-import writers or filesystem allocation.
The existing main-database page limit remains separate. No forced checkpoint,
automatic deletion or delivery/operations journal pruning is performed.

Archive-aware native lookup, durable active-action references, retired/expired
source transitions, hard aggregate disk budgeting and automatic reclamation
remain separate gates. Passing local parser/SQLite tests does not establish
signed SYSTEM/PPL helper execution, uninterrupted collection, client notification
delivery or release acceptance.

## Reported Retirement (2026-09-27 Candidate)

The envelope optionally carries `reportedSourceState: "retired"`. No other value
is accepted. The native service emits it only after complete protected Retired
chain, prior accepted/native-copy and safe-data verification without raw access.
Public clients cannot verify that protected provenance; the value stays a claim.

SQLite records it in the separate `source_lifecycle` table in the same import
transaction. Importing an older envelope cannot clear it or double-count loss.
`operations_events` adds bounded `reportedSourceStates` keyed by event ID and
`sourceStateProvenance: "unverified_public_metadata"`. The state follows the
selected native locator, including an existing legacy inline locator. It does
not change stored event bytes, evidence hashes or nativeSource, and is never
execution, deletion, notification or device-attestation authority.

Older five-field envelopes remain supported. Older strict MCP versions will
reject the new optional field. Deploy service/helper/plugin together and reload
the existing MCP before retirement activation. No driver/DLL or server policy
change is needed. This task has not reconfigured running clients or enabled
private raw deletion.

Latest focused suite:27 tests,1 host symlink skip. Full plugin:351 tests,
349 passed,0 failures,2 unchanged host symlink skips. Multi-source and legacy
inline-locator tests prevent retirement claims from being attributed to the
wrong selected source. Protected/PPL retired-reader and actual delivery remain
unverified; local SQLite tests do not replace them.
