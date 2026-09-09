# Installation and configuration

Status: MCP and controlled native Windows canary verified; the public Windows
installer/release is not yet accepted. The default branch contains the merged
preview, not a verified one-click protection release.

## Isolated Python environment

Requires Python 3.10+ on the AI tool execution host, independently of the driver's
Windows compatibility matrix. Python/MCP installation on Win7 is not supported here.

```powershell
git clone --branch codex/public-preview https://github.com/YSheldon/KProAlert.git
cd KProAlert
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r plugins/kpro-alerts/requirements.txt
.\.venv\Scripts\python.exe tools/validate_package.py
.\.venv\Scripts\python.exe plugins/kpro-alerts/scripts/test_mcp_stdio.py
```

## Generate configuration

Run using the virtual environment interpreter so the resulting configuration points
to the interpreter that has MCP installed:

```powershell
.\.venv\Scripts\python.exe plugins/kpro-alerts/scripts/setup_config.py --database C:/ProgramData/KProAlert/events.db --output kpro-mcp.local.json
```

For Feishu use `--cli` with the absolute lark-cli executable and `--base` / `--table`
with authorized resource IDs. These must all be supplied together. Authenticate
lark-cli separately on the execution host; never transfer access tokens from a
different computer. The generator refuses to overwrite an existing file.

The output is a standalone `mcpServers` JSON snippet for hosts accepting that shape,
not an automatic edit of Codex or Grok Bot settings. For other hosts translate its
command, args and env through the host's supported MCP configuration interface.
No credentials, public listener, tunnel, scheduled task or driver is installed.

## Remaining gates

- Codex marketplace install/readback and Grok Bot native installation proof.
- Public signed installer, production queue ACL and full retention/rollback acceptance.
- App-native notification and uncertain-send reconciliation.

For user-session background collection see [BACKGROUND-DELIVERY.md](BACKGROUND-DELIVERY.md).
Feishu queries return newest updates first and expose an optional numeric `offset`
and `nextOffset`. Preserve alert-ID/count deduplication while paging; concurrently
updated pages are not a consistent full-table statistics snapshot.

An empty database or Feishu table is not proof of active protection. AI tool calls
are pull queries, not automatic incoming alerts. Main merge requires separate approval.
