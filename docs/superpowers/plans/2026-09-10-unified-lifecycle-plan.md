# FalconPro Unified Lifecycle Implementation Plan

> **For agentic workers:** This plan records the implementation that accompanies
> `docs/superpowers/specs/2026-09-10-unified-lifecycle-design.md`.

**Goal:** Provide one FalconPro entry point for four assistant integrations,
signed Windows installation/upgrade/recovery coordination, and explicit opt-in
installation statistics.

**Architecture:** `falconpro.py` delegates client registration, signed release
acquisition, lifecycle transaction execution, and metrics upload to focused
modules. The native PowerShell coordinator owns Windows administrator actions;
the Python layer validates release bindings and never becomes driver authority.
Metrics are a separate local journal and explicit Feishu upload adapter.

**Tech Stack:** Python 3.10+, SQLite, Windows PowerShell 5.1, signed PowerShell
release assets, existing KProSvc native snapshot/install interfaces, lark-cli.

**Spec:** `docs/superpowers/specs/2026-09-10-unified-lifecycle-design.md`

## Global Constraints

- Stable release descriptors must be signed and bind final archive and source hashes.
- Candidate or missing-gate releases stop before elevation.
- Windows mutation runs only on the bound local Windows endpoint.
- PPL upgrade cannot use external service stop; the internal PPL uninstall path remains a gate.
- Existing policy/runtime bytes must remain unchanged for ordinary upgrades.
- Statistics are disabled by default and contain no hostname, SID, path, command line, or credentials.
- User AI authentication is required for every Feishu upload; uncertain writes are reconciled, never blindly retried.

### Task 1: Unified Assistant Entry

**Files:** `falconpro.py`, `plugins/kpro-alerts/scripts/cursor_setup.py`, tests.

- [x] Keep Codex and WorkBuddy native registration through existing `assistant_setup.py`.
- [x] Return a real Grok `AddMcpServer` handoff without inventing a CLI.
- [x] Merge Cursor MCP configuration atomically, preserving project overrides and unrelated entries.
- [x] Test conflict, duplicate keys, live lock, idempotence, and runtime registration boundaries.

### Task 2: Signed Acquisition And Package Builder

**Files:** `tools/build_release_bundle.py`, `plugins/kpro-alerts/scripts/release_download.py`, onboarding manifests.

- [x] Keep GitHub release discovery restricted to the repository and release tag.
- [x] Accept only signed descriptor, exact archive size, exact archive SHA-256, and exact file manifest.
- [x] Package the signed onboarding v2 source set and reject old/incomplete source archives.
- [x] Keep candidate release status blocked from ordinary installation.

### Task 3: Native Lifecycle Transaction

**Files:** `Invoke-FalconProLifecycle.ps1`, `plugins/kpro-alerts/scripts/lifecycle.py`, native lifecycle tests.

- [x] Persist transaction intent before native mutation in protected Program Files state.
- [x] Bind device, release, policy, runtime, recovery archive, and transaction IDs.
- [x] Verify fresh native effective-policy snapshots before uninstall and after install.
- [x] Require a normal reboot and `--resume` for completion.
- [x] Add exact prior-package rollback with explicit approval; refuse arbitrary downgrade or PPL external stop.
- [x] Verify ACL/reparse/size/signature boundaries and preserve evidence on failure.

### Task 4: Opt-In Statistics

**Files:** `metrics_journal.py`, `install_metrics.py`, `metrics_upload.py`, tests.

- [x] Record install and upgrade starts/results in a dedicated local journal only after consent.
- [x] Keep a random installation ID and exclude simulations from statistics.
- [x] Provide bounded Feishu preview and explicit `--apply` upload using the user's lark-cli.
- [x] Acknowledge only verified `rec...` receipts; mark timeouts uncertain and do not retry automatically.
- [x] Aggregate installation, activity, version, install-failure, and upgrade metrics without claiming unique people.

### Task 5: Documentation And Validation

**Files:** `LIFECYCLE.md`, `README.md`, `START-HERE.md`, `ASSISTANT-SETUP.md`,
`INSTALL-METRICS.md`, `GROK-BOT.md`, workflow checks.

- [x] Document the four assistant handoffs, signed material flow, upgrade/recovery states, and metrics consent.
- [x] Run repository packaging validation, the Python suite, and native PowerShell capture/state tests.
- [ ] Publish a new signed onboarding v2 bundle and stable verified release.
- [ ] Perform physical upgrade/reboot/rollback acceptance on the signed same-candidate bytes.
- [ ] Complete native notification delivery evidence and platform-specific client runtime receipts.
