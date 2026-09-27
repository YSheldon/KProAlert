# Local Retention Verification

Branch: `codex/collector-safe-replicas-20260926`.
Base: `91fdd2eed4da35205a87921f4d689cb3890c05b8`.
Local uncommitted candidate only; no push, merge, runtime installation or release.

## Verified

- Existing `.venv` full unittest discovery: 345 total, 343 pass, 0 failures,
  2 skipped for unavailable host symlink privileges. All launched test processes
  exited. No new SDK or toolchain was installed.
- Native collector-health regression covers optional typed diagnostics,
  malformed state/count/generation/flags, unknown-text stripping and reported
  provenance. Old health receipts remain compatible. The system Python lacked
  MCP and produced4 import errors; the verified full run uses the existing .venv.
  Logs: ../cold-integration-20260926/public-health-full-tests-venv.log.
- New safe-replica tests: 23 total, 22 pass, 1 of the same symlink skips.
- Runtime source-identity regression: altering either safe_replica.py or
  kpro_alert_bridge.py changes the actual production hash expression. Both
  subcases failed before the dependency list fix and passed after it.
- Package structure validator and git diff whitespace checks pass.
- Tests cover C++-generated synthetic format compatibility, strict parsing,
  full digest binding, producer/helper idempotency, event-source associations,
  migration compatibility, rollback, loss precision and physical-file observation.
- A mutable query-time locator initially failed to invalidate a request. That
  regression was reproduced and repaired by including the locator in evidence
  hash material without modifying old event rows.
- The physical-file budget tests failed on the missing API before implementation,
  then passed with actual temporary SQLite DB/WAL/SHM files and refusal readback.

## Boundaries

Public metadata never becomes native attestation or deletion authority. SQLite
import does not approve an action. The final aggregate-file check is observed
before import, not a hard bound on transaction-internal growth. No real event,
operations, delivery or notification journal was changed.

Root reviewed the worker-authored parser/transaction/locator changes. Delegated
review covered the separate C++ schedule/acceptance/replica implementation.
The later budget/source-fingerprint additions subsequently received independent
read-only review after the prior delegated usage interruption. No confirmed
new defect was found. The reviewer did not independently rerun tests or inspect
real databases; this is a source review, not runtime or delivery acceptance.

The service production loop is now connected in source, not deployed or tested
under the new signed runtime. Protected SYSTEM/PPL tests, physical accounting,
corruption recovery, reclamation, signed runtime/catalog updates, endpoint
and native-client acceptance remain separate work. The frozen privileged
fixture approvals are unchanged; this candidate does not substitute newer
binaries into that scope.
