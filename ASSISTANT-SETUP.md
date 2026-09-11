# One repository entry, separate components

The common lifecycle entry is `falconpro.py`. This file covers MCP registration;
read [LIFECYCLE.md](LIFECYCLE.md) for signed Windows installation, upgrade,
reboot resume, recovery and metrics upload. Registration never counts as driver
installation or endpoint protection.

Give Codex, Grok Bot, WorkBuddy or Cursor `https://github.com/YSheldon/KProAlert` and ask it to install **FalconPro** following
START-HERE.md. The assistant must distinguish installing this query connector from
installing Windows endpoint protection. Protection targets Windows 11 x64 and
ARM64 workstations; a Linux Grok Bot cannot install a Windows driver into its own
container. RemoteX is not an end-user dependency. Use the AI client's existing
local Windows execution capability.

## Query connector setup

On first use, `falconpro.py setup --client codex` (or `cursor`, `grok`,
`workbuddy`) needs no database or Feishu credentials. It returns an explicitly
onboarding-only plan: status tools work, unconfigured event queries return an
error, and no database, service, driver or background task is created. After
review, `--apply` registers through the supported client interface; Grok still
uses its actual host registration tool. Existing conflicting configurations are
preserved, never reset to empty by this initial setup mode.

Configure a real local collector or an authorized Feishu source separately after
installation. `onboardingOnly=true` is not protection or notification success.

Prepare the documented isolated Python environment and install the pinned
requirements. Run the helper with that interpreter. It discovers an existing
Codex CLI or the Windows WorkBuddy bundled CLI, generates absolute paths and uses
their supported registration interfaces. It does not download a new client.

```powershell
.\.venv\Scripts\python.exe plugins/kpro-alerts/scripts/assistant_setup.py --client codex --database "$env:LOCALAPPDATA\KProAlert\events.db"
.\.venv\Scripts\python.exe plugins/kpro-alerts/scripts/assistant_setup.py --client codex --database "$env:LOCALAPPDATA\KProAlert\events.db" --apply
```

Use `--client workbuddy` for WorkBuddy. For a cloud reader, replace `--database`
with explicit `--cli <lark-cli> --base <authorized-base> --table <table>` after
independent OAuth login on that host. Tokens are not copied into generated config.

For a local installed service, also pass
`--collector-health "C:\Program Files\KProAlert\collector-health.json"`.
This enables `collector_status`; a missing or stale health file must not be treated
as healthy protection. Cloud readers cannot use a Windows host's local health path.

For `--client grok --apply`, the helper returns the same server definition and
`host_tool_required`. The Grok assistant must use its actual AddMcpServer tool;
there is no invented Grok CLI. A generic client can use `--client generic`.

### Cursor

Use `falconpro.py setup --client cursor` to plan and add `--apply` for the
non-destructive Cursor configuration merge. It changes only the named
`mcpServers.kpro-alerts` entry, preserves an identical entry, and stops before
changing a conflicting or disabled entry. Never enable auto-run or alter tool
permissions as part of installation. The lower-level `assistant_setup.py` keeps
its `host_tool_required` handoff behavior; use the common entry for installation.

The [official Cursor MCP configuration](https://cursor.com/docs/mcp) supports
`~/.cursor/mcp.json` globally. Check the active project's `.cursor/mcp.json` too:
a same-named project entry can override the global one. Do not overwrite a project
entry to force the global configuration. After registration, verify in Cursor that
the server is connected, call `integration_status`, and query the selected data
source. Source/configuration tests do not prove the Cursor runtime connected.

Cursor uses the same read-only analysis tools and signed Windows protection
package as the other clients. No Cursor marketplace listing is claimed.

An identical existing connector is kept. A conflicting/disabled/malformed
connector or an unrecognized inspection failure stops before any registration.
No other connector is replaced. Registration success is not runtime proof: the
client must actually load the tools and call integration_status and a source query.

## Protection is not installed by this helper

The helper never installs a driver, starts a service, creates a scheduled task,
changes policy or executes remediation. A nonexistent local database produces a
query error, not an empty "safe" verdict. Complete the separate signed Windows
release flow before claiming endpoint protection is active.

The first package must contain the privacy-isolated service: original events in
private-event-spool and diagnostic logs are SYSTEM/Administrators-only; alert-spool contains redacted
copies for user delivery. Older raw-spool candidates are not admitted by the new
installer. No completed general-availability release is implied by this source.

The delivery importer accepts only `KProSafeEventBatch/v1` with `redacted:true`.
It rejects original batches and string-valued event fields before database import
or archival. Projection failures contribute to the reported loss count. The AI
therefore cannot identify an executable or file from the numeric copy alone;
request a separately authorized local investigation when that context is needed.

Private evidence currently has a bounded quota and requires administrator-managed
retention. A full spool is an attention-required condition, not evidence that no
threat occurred. This preview does not claim loss-free unattended retention.
