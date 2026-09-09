"""Stdio only: no listening socket, credentials or database path tool arguments."""
import os
import hashlib
import re
import json
from importlib.metadata import version
from pathlib import Path
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from query import recent
from feishu_reader import read
from guidance import advise
from collector_health import read_health

_source_hash = hashlib.sha256(b''.join(
    Path(__file__).with_name(name).read_bytes()
    for name in ('mcp_server.py', 'query.py', 'feishu_reader.py', 'guidance.py', 'collector_health.py'))).hexdigest()
_started_pid = os.getpid()
_plugin_version = json.loads((Path(__file__).parents[1] / '.codex-plugin/plugin.json').read_text())['version']
_sdk_version = version('mcp')

server = FastMCP('KPro Alerts')
read_only = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)


@server.tool(annotations=read_only)
def integration_status() -> dict:
    """Identify the running code and configured sources, without exposing paths or credentials."""
    return dict(version=_plugin_version, mcpSdkVersion=_sdk_version, codeSha256=_source_hash, processId=_started_pid,
                localConfigured=bool(os.environ.get('KPRO_ALERT_DATABASE')),
                feishuConfigured=all(os.environ.get(k) for k in
                    ('KPRO_LARK_CLI', 'KPRO_FEISHU_BASE', 'KPRO_FEISHU_TABLE')),
                automaticRemediation=False, protectionStatus='not_probed')


@server.tool(annotations=read_only)
def collector_status() -> dict:
    """Read last local collector receipt, including age and loss; not a driver-running assertion."""
    path = os.environ.get('KPRO_COLLECTOR_HEALTH')
    if not path:
        return {'error': 'Collector health is not configured', 'protectionStatus': 'not_probed'}
    try:
        return read_health(path)
    except Exception:
        return {'error': 'Collector receipt unavailable or invalid', 'protectionStatus': 'not_probed'}


@server.tool(annotations=read_only)
def alert_guidance(alert_id: str, profile: str = 'home') -> dict:
    """Generate cautious personalized advice for a retrieved Feishu alert. Performs no action."""
    if not re.fullmatch(r'(?:SIMULATED-)?[a-f0-9]{64}', alert_id):
        return {'error': 'Invalid alert ID'}
    result = feishu_alerts(200)
    if 'error' in result:
        return result
    matches = [a for a in result['alerts'] if a.get('alertId') == alert_id]
    if len(matches) != 1:
        return {'error': 'Alert not uniquely present in the queried page',
                'hasMore': result['hasMore']}
    known_simulations = os.environ.get('KPRO_SIMULATED_ALERT_IDS', '').split(',')
    matches[0]['simulationVerified'] = alert_id in known_simulations and alert_id.startswith('SIMULATED-')
    try:
        return {'alertId': alert_id, 'guidance': advise(matches[0], profile)}
    except ValueError:
        return {'error': 'Unsupported profile or event schema'}


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
def feishu_alerts(limit: int = 20, offset: int = 0) -> dict:
    """Read numeric Feishu alert summaries; never raw event text or command lines."""
    keys = ('KPRO_LARK_CLI', 'KPRO_FEISHU_BASE', 'KPRO_FEISHU_TABLE')
    values = [os.environ.get(key) for key in keys]
    if not all(values):
        return {'error': 'Feishu reader is not configured'}
    try:
        return read(*values, limit, offset=offset)
    except Exception:
        return {'error': 'Feishu read failed; verify configuration and authorization locally'}


if __name__ == '__main__':
    server.run(transport='stdio')
