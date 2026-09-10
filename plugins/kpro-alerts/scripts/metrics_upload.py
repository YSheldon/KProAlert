"""Explicit Feishu metrics upload using the user's already-authorized lark-cli."""
import argparse
import json
from pathlib import Path
import subprocess

from metrics_journal import Journal


def fields(event):
    return {
        '安装ID': event['installationId'],
        '事件ID': event['eventId'],
        '日期': event['day'],
        '类型': event['kind'],
        '版本': event['version'],
        '架构': event['architecture'],
        '系统': event['osFamily'],
        '状态': event['state'],
        '模拟': event['simulated'],
    }


def upload(database, cli, base, table, *, apply=False, runner=subprocess.run):
    if not cli or not base or not table:
        raise ValueError('Feishu CLI, base and table are required')
    with Journal(database) as journal:
        # Prepare is a transaction: the journal marks rows before networking.
        events = journal.prepare()
        result = dict(schema='FalconProMetricsUpload/v1', prepared=len(events),
                      uploaded=0, uncertain=0, applied=apply,
                      userAuthorizedDestination=True)
        if not apply:
            result['events'] = [dict(eventId=e['eventId'], kind=e['kind']) for e in events]
            return result
        for event in events:
            command = [str(Path(cli).resolve(strict=True)), 'base', '+record-upsert',
                       '--base-token', base, '--table-id', table, '--as', 'user',
                       '--json', json.dumps(fields(event), ensure_ascii=False)]
            try:
                response = runner(command, capture_output=True, text=True,
                                  timeout=60, check=True)
                payload = json.loads(response.stdout)
                data = payload.get('data', {})
                record_id = data.get('record_id') or data.get('record', {}).get('id')
                if payload.get('ok') is not True or not isinstance(record_id, str) or not record_id.startswith('rec'):
                    raise RuntimeError('Feishu write receipt missing')
                journal.ack(event['eventId'], record_id)
                result['uploaded'] += 1
            except Exception:
                journal.uncertain(event['eventId'])
                result['uncertain'] += 1
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True)
    parser.add_argument('--cli', required=True)
    parser.add_argument('--base', required=True)
    parser.add_argument('--table', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    print(json.dumps(upload(args.database, args.cli, args.base, args.table,
                             apply=args.apply), ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(json.dumps({'schema': 'FalconProMetricsUpload/v1', 'uploaded': 0,
                          'uncertain': 0, 'applied': False, 'errorClass': type(exc).__name__,
                          'error': str(exc)}, ensure_ascii=False))
        raise SystemExit(1)
