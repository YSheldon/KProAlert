# FalconPro

Public preview of the FalconPro alert integration tools and Codex plugin packaging.

FalconPro is the product name across Codex, Grok Bot, WorkBuddy, Cursor and ZCode.
Existing repository URLs, `kpro-alerts` IDs, `KPRO_*` variables, protocol schemas
and signed component filenames remain unchanged for compatibility. See [BRANDING.md](BRANDING.md).
This repository contains no drivers, signing material, credentials or telemetry.
It is a clean source export, not a mirror of private repository history.

For the user-facing installation workflow, read [START-HERE.md](START-HERE.md).
The endpoint entry is the signed native EXE workflow in
[NATIVE-INSTALL.md](NATIVE-INSTALL.md). Connector setup and opt-in statistics
remain separate utilities; `falconpro.py` is not the default endpoint installer.
The binary release and automatic notification gates are not complete yet.
The current public GitHub release is still a controlled validation candidate;
the lifecycle source is implemented and tested, but it is not a stable GA
release until complete signed native catalogs/packages and applicable gates pass.

## One Address, Two Components

Give the repository URL to your assistant and follow [START-HERE.md](START-HERE.md).
The assistant connector and the Windows protection service are separate components.
The native EXE handles protection; `falconpro.py setup` handles connectors. MCP alone never
means that a driver is installed or protection is active.

**RemoteX, SSH and SFTP are not end-user installation dependencies.** They may be
used by developers to operate remote test PCs, not by the product installer. Local
Codex, Cursor or WorkBuddy can use their authorized Windows execution channel. A
cloud Grok Bot must first have an authorized channel to the user's actual Windows
PC; otherwise it can provide instructions and read authorized cloud alerts only.

The intended protection flow is local device confirmation, signed release
download, one explicit installation approval with normal UAC, native verification,
then alert connection. No stable installable release has been published yet; the
current prerelease is a validation candidate and is deliberately rejected by
ordinary install/upgrade discovery.

## Capabilities

- Read-only stdio MCP: integration_status, endpoint_status, collector_status,
  local_alerts, feishu_alerts, alert_guidance, operations_events and operations_status.
- Explicit append-only assess_event and propose_action tools. An action request is
  neither human approval nor execution; the native action broker is not integrated.
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

See [AI-OPERATIONS.md](AI-OPERATIONS.md) for signed audit/enforce mode boundaries,
evidence-bound assessments and opt-in operations upload, and [ZCODE.md](ZCODE.md)
for the non-destructive ZCode connector adapter. These do not imply five-platform
native runtime acceptance or an already published audit-capable driver.

## Validation boundary

The user reported successful registration and discovery of both tools in Grok Bot
via custom stdio MCP with no data sources configured. This is not proof of native
marketplace installation, live telemetry delivery or unattended operation.

Historical script installer and ordinary-service upgrade sources are retained;
native Rust source is private. The native lifecycle requires signed catalog/package assets and same-candidate acceptance
before public installation is enabled. Treat this as a preview, not a completed
general-availability release.

## Tests

```
python tools/validate_package.py
python -m unittest discover -s plugins/kpro-alerts/scripts -p "test_*.py"
python plugins/kpro-alerts/scripts/test_mcp_stdio.py
```
