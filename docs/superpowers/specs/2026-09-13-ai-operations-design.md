# FalconPro AI Operations

User-approved scope: one repository entry for Codex, Grok Bot, Cursor, WorkBuddy
and ZCode; signed enforce/audit profiles; asynchronous event assessment;
per-action human authorization; local allowlisted execution; event/assessment/
action-result return for security operations. Existing PPL release work continues.

## Contracts

- Audit is driver decisionMode=1 with ransomwareBaitEnabled retained; enforce is
  decisionMode=3 and maximum ransomware flags. No caller rewrites signed envelopes.
  Ordinary protected-directory auditing and all filesystem operations are not
  claimed by the existing driver. Report engine events that exist, with loss and
  source-coverage state; audit does not manufacture AccessBlocked/termination.
- Event snapshots retain all supported numeric/boolean telemetry and a digest of
  the captured source record. Paths/command lines are not uploaded by default.
- FalconProAIDecision/v1 is append-only, tied to event ID and evidence digest.
  Verdict/confidence/model/client are AI assertions, not verified malware labels.
- FalconProActionRequest/v1 binds the decision, device, policy and subject evidence.
  Creating it is not approval. No MCP tool can set approved=true or fabricate
  execution success. The native endpoint broker must independently verify the
  original evidence, identity, policy, expiry and human consent before execution.
- Only verified broker results may advance requested -> executed/failed. The
  transport must come from the installed signed product and use fixed verbs.
  Until that broker is available, report executionUnavailable and retain requests.
- Operations records use a separate outbox; prepare precedes networking, exact
  Feishu readback precedes ACK. Uncertain sends are reconciled, never auto-retried.
  Simulation stays explicit and excluded from production metrics.

## Clients

All clients use the same MCP schema. ZCode native user settings are
~/.zcode/cli/config.json under mcp.servers; workspace .zcode/config.json wins.
Preserve enable=false and conflicts; do not hide fallback .agents servers.
Source: https://zcode.z.ai/cn/docs/mcp-services . No native app runtime acceptance
is inferred from a generated config or simulated MCP client.

## Delivery Work

Implement and verify adapters, immutable assessment/action records and readback
outbox first, then signed mode application and native per-action approval broker.
Validate real stdio requests and tamper/replay/failure behavior; sign changed
native artifacts and perform endpoint tests before public release claims.
No production private key or local OAuth material is distributed to assistants.
