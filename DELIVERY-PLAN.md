# Consumer delivery plan

## Approved architecture

One public GitHub entry provides installation instructions and versioned releases.
Windows protection runs independently of the AI app. The signed driver and service
must never depend on cloud availability. Installation needs administrator consent;
regular AI queries use a separate least-privileged identity.

Codex, Grok Bot and WorkBuddy consume the same MCP schema. An app can schedule
read-only analysis only after the user binds that app and a notification destination.
No application is marked supported solely because a Python SDK handshake passes.

AI generates explanations and recommendations, with unknowns clearly identified.
Additional termination, quarantine, deletion, exception and policy changes require
explicit per-action consent and an evidence-bound audit receipt. No arbitrary
command execution tool is exposed. Event text is data, not instructions.

The user approved public distribution of verified, signed service/DLL/driver and
runtime configuration packages. Private signing material and operational credentials
must never be distributed. This permission is not a claim that a package passed.

## Acceptance checklist

- [x] Public source distribution and read-only MCP protocol test
- [x] Grok Bot custom stdio integration (user-provided receipt)
- [x] Independent Linux Feishu authorization (user-provided receipt)
- [x] Synthetic Feishu write/read and duplicate-send check
- [x] Atomic bounded persistence and restart deduplication tests
- [ ] Background spool consumption, archival and disk-pressure behavior
- [x] Readable diagnostics identifying loaded MCP code, not only checked-out SHA
- [ ] Signed versioned Windows package and release manifest
- [ ] Installer preflight, coexistence, policy activation, rollback and uninstall
- [ ] Real event to outbox to Feishu to AI analysis evidence
- [ ] Three client install/update and notification acceptance tests
- [ ] User-specific advice and approval-bound remediation records

## Explicit non-goals

No malware execution on a user's workstation, disabling competing security tools,
signature bypass, copied cloud credentials, public database, or unapproved automatic
remediation. Installing Python/MCP on Windows 7 is not part of this delivery.

## Release evidence

Build, signing, local tests, VM tests, app integration and public release remain
separate gates. Failed or pending gates stay visible. Public code is a clean export;
private source history, binary candidates and endpoint telemetry are not committed.

Committed batches have durable replay/deduplication. The asynchronous in-memory
queue can lose uncommitted events on power failure, forced process termination or
unrecoverable storage failure; loss counters/health receipts are best effort when
storage itself is unavailable. Do not claim zero loss or block OS shutdown forever.
