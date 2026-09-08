"""Stdio only: no listening socket, credentials or database path tool arguments."""
import os
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from query import recent
from feishu_reader import read

server = FastMCP('KPro Alerts')
read_only = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)


@server.tool(annotations=read_only)
def local_alerts(limit: int = 20) -> dict:
    """Read bounded local telemetry. Empty results do not prove no threat."""
    path = os.environ.get('KPRO_ALERT_DATABASE')
    if not path:
        return {'error': 'Local database is not configured'}
    try:
        return {'events': recent(path, limit), 'scope': 'bounded local records'}
    except Exception:
        return {'error': 'Local read failed; check collector and database locally'}


@server.tool(annotations=read_only)
def feishu_alerts(limit: int = 20) -> dict:
    """Read numeric Feishu alert summaries; never raw event text or command lines."""
    keys = ('KPRO_LARK_CLI', 'KPRO_FEISHU_BASE', 'KPRO_FEISHU_TABLE')
    values = [os.environ.get(key) for key in keys]
    if not all(values):
        return {'error': 'Feishu reader is not configured'}
    try:
        return read(*values, limit)
    except Exception:
        return {'error': 'Feishu read failed; verify configuration and authorization locally'}


if __name__ == '__main__':
    server.run(transport='stdio')
