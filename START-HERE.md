# Start here: install with your AI assistant

Use [LIFECYCLE.md](LIFECYCLE.md) and the common `falconpro.py` entry for installation,
upgrade, four-client setup and optional statistics. Existing release gates below
still apply; the new executor needs its signed onboarding v2 distribution.

For automatic local detection and installation after first confirmation, follow
[LOCAL-ENDPOINT.md](LOCAL-ENDPOINT.md). Never treat the bot's cloud host as the PC.

Give your assistant this repository URL and ask:

Supported setup paths: Codex, WorkBuddy, Cursor, and Grok Bot. See
[ASSISTANT-SETUP.md](ASSISTANT-SETUP.md) for native registration versus configuration
handoff and the separate runtime acceptance checks.

After collection and read-only access are verified, follow
[NOTIFICATIONS.md](NOTIFICATIONS.md) for baseline initialization, duplicate
suppression, native scheduling and personalized follow-up. Do not mark notification
delivery complete merely because a draft was generated.

> Install FalconPro on my Windows PC, verify protection is active, and connect
> this assistant for alert analysis. Show what will change before administrator
> actions. Do not enable automatic destructive remediation.

## Instructions for the installing assistant

1. Identify where your commands run. Linux/cloud MCP execution is not the user's
   Windows PC. Never claim to install endpoint protection by installing Python in
   a cloud computer. Use an explicitly authorized local Windows channel for the
   protection component, and a separate read-only Feishu identity for cloud queries.
2. Resolve an immutable released version. Check release evidence and file hashes,
   Windows signatures, native architecture, OS support, free disk and existing
   security services. Do not use source-build outputs, test certificates or
   sample signing keys as production artifacts. At present the binary release
   gates are incomplete: stop before installing protection, not at source checkout.
3. Explain deterministic protection, the scope of signed policy, privacy/export
   choices, AI fees/availability and the effect on business-critical workflows.
   Confirm first machine installation and each high-risk additional action.
4. Use `falconpro.py install --device-id <confirmed-device-id>` to download the
   matching signed release and produce a plan. After approval, use
   `falconpro.py install --plan <plan-path> --apply --approve`. Do not reconstruct
   low-level installer arguments or ask an ordinary user to supply hashes. Use
   `--resume` after a normal reboot and `upgrade` for later signed releases.
   Public release admission is still required; do not bypass it for convenience.
5. Configure the background bridge and destination independently from MCP. Raw
   events stay in access-controlled local storage; only approved fields are exported.
   A disconnected AI app must not disable protection. Surface loss/quota/sync errors.
   Use [BACKGROUND-DELIVERY.md](BACKGROUND-DELIVERY.md) and the current-user
   Configure-KProDelivery.ps1 plan. This task has no administrator privileges and
   does not copy another machine's authentication state.
6. Install MCP in an isolated Python environment on its execution host. Use
   setup_config.py rather than replacing existing application settings. Keep the
   existing MCP identity on update; ensure the actual process exits and starts the
   new code, then verify integration_status codeSha256 and processId.
   Prefer [ASSISTANT-SETUP.md](ASSISTANT-SETUP.md) for native Codex/WorkBuddy
   registration or Grok host-tool handoff instead of manually reconstructing paths.
7. Verify a clearly labeled synthetic event first, followed by an authorized benign
   real trigger. Match alert ID, event type, operation and actual outcome end to end.
   Synthetic alerts must be excluded from real statistics and remediation.
   Only operator-confirmed synthetic IDs count as verified simulations; an editable
   SIMULATED- prefix alone is not authority to suppress a security alert.
8. Only enable a client-native analysis routine when that specific client and user
   consent are verified. Poll bounded pages, preserve a cursor/dedup state, summarize
   related events and notify on meaningful new risk or a failed protection state.
   The current plugin does not itself create or guarantee such routines.

## Advice contract

Use alert_guidance with the user-selected profile (home, office, developer or
business_critical) and actual alert ID. It supplies deterministic context; use the
assistant's reasoning to explain unknowns and ask focused questions. Do not equate
an event name with confirmed malware, or a partial block with zero damage.

Always separate observed evidence, inference, recommended actions and actions
actually executed. Preserve the operating user's business context and backup needs.
No tool currently executes quarantine, termination, deletion or policy changes.

## Current support matrix

| Integration | Proven | Not yet proven |
|---|---|---|
| Grok Bot custom stdio | User-reported tool load and synthetic Feishu read | Complete Windows installer, automatic routine |
| Codex | Actual readback of controlled real-event Feishu summaries | Current-process upgrade and automatic notification |
| WorkBuddy | Bundled engine connection and desktop connected indicator | In-conversation event analysis and notifications |
| Cursor | Native desktop MCP connection and read-only query | Current-revision install/upgrade and native notifications |
| Windows service | Signed native x64 canary; ARM64 Microsoft/product signature normal-load validation | New public installer/upgrade/recovery and per-architecture full release admission |

Current-user background delivery has separate physical runtime evidence; see
[DELIVERY-VALIDATION.md](DELIVERY-VALIDATION.md). Do not combine these narrower
results into a claim that all four applications install Windows protection.
