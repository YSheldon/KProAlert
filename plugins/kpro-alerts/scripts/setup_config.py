"""Generate a standalone MCP configuration without modifying any client settings."""
import argparse
import json
import sys
import re
from pathlib import Path


def build_config(database=None, cli=None, base=None, table=None, collector_health=None, endpoint_device_id=None):
    if any((cli, base, table)) and not all((cli, base, table)):
        raise ValueError('Feishu requires CLI, base and table together')
    if not database and not cli and not endpoint_device_id:
        raise ValueError('configure a local database or Feishu source')
    env = {}
    if endpoint_device_id:
        if not isinstance(endpoint_device_id,str) or not re.fullmatch('[a-f0-9]{64}',endpoint_device_id):
            raise ValueError('Confirm the local Windows device fingerprint before binding')
        env['KPRO_ENDPOINT_DEVICE_ID'] = endpoint_device_id
    if database:
        env['KPRO_ALERT_DATABASE'] = str(Path(database).resolve())
    if collector_health:
        env['KPRO_COLLECTOR_HEALTH'] = str(Path(collector_health).resolve())
    if cli:
        exe = Path(cli).resolve(strict=True)
        if not exe.is_file():
            raise ValueError('CLI must be a file')
        env.update(KPRO_LARK_CLI=str(exe), KPRO_FEISHU_BASE=base,
                   KPRO_FEISHU_TABLE=table)
    return {'mcpServers': {'kpro-alerts': {
        'command': str(Path(sys.executable).resolve()),
        'args': [str(Path(__file__).resolve().with_name('mcp_server.py'))],
        'env': env}}}


def save_config(path, config):
    # Exclusive creation: never replace a user's existing client configuration.
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(config, stream, ensure_ascii=True, indent=2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database')
    parser.add_argument('--cli')
    parser.add_argument('--base')
    parser.add_argument('--table')
    parser.add_argument('--collector-health')
    parser.add_argument('--endpoint-device-id')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    config = build_config(args.database, args.cli, args.base, args.table, args.collector_health, args.endpoint_device_id)
    save_config(args.output, config)
    print('Configuration generated; no client settings or services changed.')
