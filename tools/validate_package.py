"""Repository-owned packaging checks; no SDK or machine-local skill dependency."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
market = json.loads((root / '.agents/plugins/marketplace.json').read_text())
assert market['name'] == 'kpro-alerts'
entry, = market['plugins']
assert entry['source'] == {'source': 'local', 'path': './plugins/kpro-alerts'}
plugin = root / 'plugins/kpro-alerts'
manifest = json.loads((plugin / '.codex-plugin/plugin.json').read_text())
assert manifest['name'] == 'kpro-alerts'
assert manifest['skills'] == './skills/'
assert (plugin / 'skills/kpro-alerts/SKILL.md').is_file()
for name in ('query.py', 'mcp_server.py', 'feishu_reader.py', 'kpro_alert_bridge.py'):
    assert (plugin / 'scripts' / name).is_file(), name
print('PASS: plugin and marketplace package structure')
