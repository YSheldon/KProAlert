# FalconPro for Grok Bot

Native role template: https://x.ai/bot/Wo-ftquvSgmRphqHSFP5w

The published FalconPro template contains generic role and safety instructions,
not credentials, personal source bindings, installed connectors or active routines.
Importing it alone does not install endpoint protection or enable notifications.

The reusable MCP implementation is `plugins/kpro-alerts/scripts/mcp_server.py`.
Install dependencies in a dedicated Python 3.10+ environment using the adjacent
requirements.txt. Start that interpreter with the absolute server script path.
It currently exposes stdio only. No HTTP listener or public tunnel is opened.

Tools:
- `integration_status()`: identifies the actual running code and configured sources.
- `local_alerts(limit=20)`: requires KPRO_ALERT_DATABASE on the executing host.
- `feishu_alerts(limit=20)`: requires KPRO_LARK_CLI (absolute executable path),
  KPRO_FEISHU_BASE and KPRO_FEISHU_TABLE, plus existing CLI user authentication.
- `feishu_operations(limit=20, offset=0)`: requires KPRO_LARK_CLI,
  KPRO_FEISHU_BASE and KPRO_FEISHU_OPERATIONS_TABLE. Reads linked AI decisions,
  requests and native-result records; it does not execute actions.

These describe the candidate implementation. If the running connector exposes
only `local_alerts` and `feishu_alerts`, it is an older process/build. Missing
tools are not evidence that a cloud record is absent or that OAuth failed.

## Updating an existing connector

Use an explicitly reviewed repository revision, retain a rollback copy and
preserve the existing host-local Feishu authorization and environment. Do not
copy another host's executable paths or tokens. Update the existing connector,
not a second MCP registration. Add the authorized operations table binding only
when that source is requested.

Restart the actual MCP process through Grok's native controls. Switching a
symlink or replacing files alone may leave the old interpreter running. Check
the newly loaded tool list and call `integration_status`; then perform a bounded
`feishu_operations` read. Record the checkout SHA separately from the returned
code hash. A PR candidate is not a released version.

For result interpretation, a linked native-result record supplies completion
for an immutable request that still records its original `not_executed` state.
Do not retry that request. `simulated=true` excludes acceptance data from
production statistics but does not imply that the native test action never ran.
Avoid attributing unrelated application failures to enforcement without evidence.

Configure these values in the MCP host environment, not as tool arguments.
Feishu tools project numeric fields only and return pagination status. A page is
not a full-dataset statistic. Paths and command lines are never returned.

Grok Bot must be able to run this server on an authorized host with lark-cli and
its own authenticated identity. A cloud runtime cannot use this workstation's
paths or credentials. Do not copy local access tokens into a cloud configuration.
If the deployed Grok Bot only accepts hosted MCP, authenticated HTTP hosting is a
separate pending task; stdio compatibility alone is not Grok Bot installation proof.

The public release branch does not pretend that a Codex manifest is a Grok Bot
manifest. Use `falconpro.py setup --client grok` to produce the real
`AddMcpServer` handoff, then verify the actual Grok process. Endpoint installation
and upgrade require [NATIVE-INSTALL.md](NATIVE-INSTALL.md)'s signed EXE flow; a Grok cloud
runtime cannot perform them.

Verification: run scripts/test_feishu_reader.py and scripts/test_mcp_stdio.py
from the plugin directory. These test projection and MCP protocol behavior, not
Grok Bot application integration or automatic notifications.
