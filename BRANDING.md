# FalconPro Product Naming

All new product-facing titles, bot names, plugin descriptions, notification
headings and advice templates use **FalconPro**. The recommended assistant name
is **FalconPro Alert Assistant** (Chinese: FalconPro 告警助手).
This applies to Codex, Grok Bot, WorkBuddy and Cursor.

## Compatibility Names

The following are technical identifiers, not alternative product brands:

- Repository and existing download URLs: `YSheldon/KProAlert`.
- Plugin directory, skill ID and MCP registration ID: `kpro-alerts`.
- Environment variables: `KPRO_*`; JSON schema names: `KPro*/v1`.
- Signed binary names and Windows service IDs: `KProSvc`, `KProProtect`, `KProFilter`.
- Installer scripts, installation/state paths and existing scheduled-task IDs.

Do not rename these identifiers in existing installations or rewrite signed
release artifacts. Such migrations require separate compatibility and signing
validation. Existing evidence and release hashes retain their historical names.

## Shareable Templates

Use FalconPro in the title, role, advice and notification text. Exports must not
contain personal paths, credentials, bound data sources, recipients or real alerts.
Importing a role template does not install protection, authorize remediation or
activate a schedule. Each user binds their own sources and notification target.

The portable [FalconPro role template](FalconPro.bot-template.json) applies to all
four clients. It is not a vendor-native import manifest. For client-specific MCP
setup use [ASSISTANT-SETUP.md](ASSISTANT-SETUP.md); do not create a second MCP
registration merely to change its title.
