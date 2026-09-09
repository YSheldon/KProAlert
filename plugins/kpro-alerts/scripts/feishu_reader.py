"""Read only selected numeric fields. No paths, command lines or free text."""
import json
import re
import subprocess

FIELDS = {'eventType': 'eventType', 'operation': 'operation',
          '累计事件数': 'eventCount', '实际阻断次数': 'blockedCount',
          '终止成功次数': 'terminatedCount'}


def project(payload):
    if payload.get('ok') is not True:
        raise ValueError('Feishu read failed')
    data = payload['data']
    fields, rows = data['fields'], data['data']
    if not isinstance(rows, list) or len(rows) > 200:
        raise ValueError('invalid record count')
    output = []
    for row in rows:
        if not isinstance(row, list) or len(row) != len(fields):
            raise ValueError('unexpected record schema')
        item = {}
        for field, value in zip(fields, row):
            if field == '告警ID' and value is not None:
                if not isinstance(value, str) or not re.fullmatch(r'(?:SIMULATED-)?[a-f0-9]{64}', value):
                    raise ValueError('invalid alert identity')
                item['alertId'] = value
                item['simulated'] = value.startswith('SIMULATED-')
                continue
            if field not in FIELDS or value is None:
                continue
            if type(value) not in (int, float) or not 0 <= value <= 9007199254740991 or int(value) != value:
                raise ValueError('invalid numeric telemetry')
            item[FIELDS[field]] = int(value)
        if 'alertId' not in item:
            raise ValueError('missing alert identity; simulation status cannot be established')
        output.append(item)
    if type(data.get('has_more')) is not bool:
        raise ValueError('missing pagination status')
    return {'alerts': output, 'hasMore': data['has_more'],
            'scope': 'bounded page, not full statistics'}


def read(cli, base, table, limit):
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError('limit must be 1..200')
    args = [cli, 'base', '+record-list', '--base-token', base, '--table-id', table,
            '--limit', str(limit), '--format', 'json', '--as', 'user']
    for field in ['告警ID', *FIELDS]:
        args.extend(['--field-id', field])
    result = subprocess.run(args, capture_output=True, encoding='utf-8', timeout=30)
    if result.returncode:
        raise ValueError('Feishu CLI failed; verify authentication locally')
    return project(json.loads(result.stdout))
