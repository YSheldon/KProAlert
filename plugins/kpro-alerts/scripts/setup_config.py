"""Generate a standalone MCP configuration without modifying any client settings."""
import argparse
import json
import sys
import re
from pathlib import Path


def build_config(database=None, cli=None, base=None, table=None, collector_health=None, endpoint_device_id=None, *, onboarding_only=False, operations_database=None, assistant_client=None, native_entry=None, native_entry_sha256=None):
    if any((cli, base, table)) and not all((cli, base, table)):
        raise ValueError('Feishu requires CLI, base and table together')
    if type(onboarding_only) is not bool:
        raise ValueError('Onboarding mode must be explicit')
    if onboarding_only and any((database, cli, base, table)):
        raise ValueError('Onboarding-only mode cannot replace configured data sources')
    if not database and not cli and not endpoint_device_id and not onboarding_only:
        raise ValueError('configure a local database or Feishu source')
    env = {}
    if native_entry or native_entry_sha256:
        if not all((native_entry,native_entry_sha256,endpoint_device_id,database,operations_database)) or onboarding_only:
            raise ValueError('Native action binding requires entry, release hash, local device, event source and operations journal')
        from native_receipt_reader import _request
        env['KPRO_NATIVE_ENTRY']=_request(native_entry,native_entry_sha256,endpoint_device_id,'0'*64,identifier_length=64)
        env['KPRO_NATIVE_ENTRY_SHA256']=native_entry_sha256
    if operations_database:
        env['KPRO_OPERATIONS_DATABASE'] = str(Path(operations_database).resolve())
        if assistant_client:
            env['KPRO_ASSISTANT_CLIENT'] = assistant_client
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
    parser.add_argument('--operations-database')
    parser.add_argument('--native-entry')
    parser.add_argument('--native-entry-sha256')
    parser.add_argument('--onboarding-only', action='store_true')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    config = build_config(args.database, args.cli, args.base, args.table, args.collector_health, args.endpoint_device_id,
                          onboarding_only=args.onboarding_only,operations_database=args.operations_database,
                          native_entry=args.native_entry,native_entry_sha256=args.native_entry_sha256)
    save_config(args.output, config)
    print('Configuration generated; no client settings or services changed.')
