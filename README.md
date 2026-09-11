# FalconPro

Public preview of the FalconPro alert integration tools and Codex plugin packaging.

FalconPro is the product name across Codex, Grok Bot, WorkBuddy and Cursor.
Existing repository URLs, `kpro-alerts` IDs, `KPRO_*` variables, protocol schemas
and signed component filenames remain unchanged for compatibility. See [BRANDING.md](BRANDING.md).
This repository contains no drivers, signing material, credentials or telemetry.
It is a clean source export, not a mirror of private repository history.

For the user-facing installation workflow, read [START-HERE.md](START-HERE.md).
The common setup, signed download, installation, upgrade and opt-in statistics
entry is [falconpro.py](falconpro.py); see [LIFECYCLE.md](LIFECYCLE.md).
The binary release and automatic notification gates are not complete yet.
The current public GitHub release is still a controlled validation candidate;
the lifecycle source is implemented and tested, but it is not a stable GA
release until the signed onboarding v2 bundle and native upgrade evidence pass.

## Capabilities

- Read-only stdio MCP: local_alerts and feishu_alerts.
- Local SQLite import and deduplication of exported FalconPro event batches.
- Explicitly configured Feishu summary publication; no automatic publication.
- Standalone MCP configuration generation without overwriting client settings.
- Architecture-bound Windows 11 x64/ARM64 installation and ordinary-service
  upgrade/recovery sources, gated by signed release and native acceptance.
- Consent-based installation statistics with exact upload readback and
  uncertain-send protection; simulated acceptance records are excluded.

See INSTALL.md and GROK-BOT.md. Python 3.10+ is required on the MCP execution host.
Install dependencies in an isolated virtual environment. Configure data sources
and authorization independently on that host; never copy workstation credentials.

## Validation boundary

The user reported successful registration and discovery of both tools in Grok Bot
via custom stdio MCP with no data sources configured. This is not proof of native
marketplace installation, live telemetry delivery or unattended operation.

Installer and ordinary-service upgrade sources are included. The new lifecycle
entry requires signed onboarding assets and same-candidate native acceptance
before public installation is enabled. Treat this as a preview, not a completed
general-availability release.

## Tests

```
python tools/validate_package.py
python -m unittest discover -s plugins/kpro-alerts/scripts -p "test_*.py"
python plugins/kpro-alerts/scripts/test_mcp_stdio.py
```
