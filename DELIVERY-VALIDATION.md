# User-session delivery validation, 2026-09-09

This is historical benign-event replay on a physical Windows workstation. It did
not install a driver, change protection policy, send cloud records or run malware.

- Fresh local capability/ownership preflight: no existing KProAlert delivery task.
- Actual Task Scheduler registration under the current user with Interactive
  logon, Limited privileges and an exact Python/worker/configuration action.
- Five retained test batches imported nine records; the database committed before
  source archival. The health receipt advanced and reported no loss.
- A 30.47-second idle worker observation recorded CPU time below OS timer
  resolution and a 10,280,960-byte peak working set. This measures the worker
  process only, not total protection/AI overhead or a release performance gate.
- Stopping/restarting the task produced a new worker PID, retained nine records
  and imported zero duplicates. Removing the task succeeded, and the worker exited.
- Configuration and evidence were retained; no persistent test task remains.

Subsequent cloud-budget unit tests enforce at most one outbound write per worker
cycle and durable continuation without duplicates. The existing uncertain-send
gate remains: a pending result requires reconciliation instead of blind resend.
Live Feishu reader tests verify descending last-update ordering and `nextOffset`.
Full pagination is best effort under concurrent writes, not snapshot isolation.

WorkBuddy's shipped CLI connected to the configured read-only MCP, and the desktop
connector manager displayed it connected. An in-conversation tool call and native
automatic notification are separate acceptance items and are not claimed here.
Official configuration references:
[MCP](https://www.codebuddy.cn/docs/cli/mcp) and
[configuration directory](https://www.codebuddy.cn/docs/cli/installation).

The public binary release remains blocked: the signing service accepted a
data-only PS1 attestation job but left its output unsigned. Neither Jenkins job
success nor valid signatures on the five payload files substitutes for the
required authenticated release manifest. No unsigned attestation is admitted.
