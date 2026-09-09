# KProAlert

Public preview of the KPro alert integration tools and Codex plugin packaging.
This repository contains no drivers, signing material, credentials or telemetry.
It is a clean source export, not a mirror of private repository history.

For the user-facing installation workflow, read [START-HERE.md](START-HERE.md).
The binary release and automatic notification gates are not complete yet.

## Capabilities

- Read-only stdio MCP: local_alerts and feishu_alerts.
- Local SQLite import and deduplication of exported KPro event batches.
- Explicitly configured Feishu summary publication; no automatic publication.
- Standalone MCP configuration generation without overwriting client settings.

See INSTALL.md and GROK-BOT.md. Python 3.10+ is required on the MCP execution host.
Install dependencies in an isolated virtual environment. Configure data sources
and authorization independently on that host; never copy workstation credentials.

## Validation boundary

The user reported successful registration and discovery of both tools in Grok Bot
via custom stdio MCP with no data sources configured. This is not proof of native
marketplace installation, live telemetry delivery or unattended operation.

No driver installer is included. Signed service distribution, bounded retention,
uncertain-send reconciliation and real collection-to-notification verification
remain pending. Treat this as a preview, not a production security service.

## Tests

```
python tools/validate_package.py
python -m unittest discover -s plugins/kpro-alerts/scripts -p "test_*.py"
python plugins/kpro-alerts/scripts/test_mcp_stdio.py
```
