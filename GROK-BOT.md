# FalconPro for Grok Bot

The reusable MCP implementation is `plugins/kpro-alerts/scripts/mcp_server.py`.
Install dependencies in a dedicated Python 3.10+ environment using the adjacent
requirements.txt. Start that interpreter with the absolute server script path.
It currently exposes stdio only. No HTTP listener or public tunnel is opened.

Tools:
- `local_alerts(limit=20)`: requires KPRO_ALERT_DATABASE on the executing host.
- `feishu_alerts(limit=20)`: requires KPRO_LARK_CLI (absolute executable path),
  KPRO_FEISHU_BASE and KPRO_FEISHU_TABLE, plus existing CLI user authentication.

Configure these values in the MCP host environment, not as tool arguments.
Feishu tools project numeric fields only and return pagination status. A page is
not a full-dataset statistic. Paths and command lines are never returned.

Grok Bot must be able to run this server on an authorized host with lark-cli and
its own authenticated identity. A cloud runtime cannot use this workstation's
paths or credentials. Do not copy local access tokens into a cloud configuration.
If the deployed Grok Bot only accepts hosted MCP, authenticated HTTP hosting is a
separate pending task; stdio compatibility alone is not Grok Bot installation proof.

No Grok Bot marketplace manifest or successful Grok Bot install is claimed yet.
The Codex manifest is not interchangeable with a Grok Bot manifest.

Verification: run scripts/test_feishu_reader.py and scripts/test_mcp_stdio.py
from the plugin directory. These test projection and MCP protocol behavior, not
Grok Bot application integration or automatic notifications.
