# Installation and configuration

Status: tested standalone MCP component, not a verified one-click Grok Bot installer.
Use the reviewed feature branch until the MR is merged. Do not install from main
expecting this feature before that merge.

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
- Signed KProSvc installer, queue ACL/retention and real event collection.
- Real publication/readback and crash-safe uncertain-send reconciliation.

An empty database or Feishu table is not proof of active protection. AI tool calls
are pull queries, not automatic incoming alerts. Main merge requires separate approval.
