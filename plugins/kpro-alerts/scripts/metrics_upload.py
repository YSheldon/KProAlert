"""Explicit Feishu metrics upload using the user's already-authorized lark-cli."""
import argparse
import json
from pathlib import Path
import re
import shutil
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


def _resolve_cli(cli):
    if not isinstance(cli, (str, Path)) or not str(cli).strip():
        raise ValueError('Feishu CLI is required')
    raw = str(cli).strip()
    candidate = Path(raw)
    if not candidate.is_absolute() and len(candidate.parts) == 1:
        resolved = shutil.which(raw)
        if resolved:
            candidate = Path(resolved)
    try:
        candidate = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError('Feishu CLI executable was not found') from exc
    if not candidate.is_file():
        raise ValueError('Feishu CLI must be a file')
    return str(candidate)


def _parse_response(response, operation):
    stdout = getattr(response, 'stdout', None)
    if not isinstance(stdout, str):
        raise RuntimeError(operation + ' response was not text')
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(operation + ' response was not JSON') from exc
    if not isinstance(payload, dict):
        raise RuntimeError(operation + ' response was not an object')
    return payload


def _receipt(payload):
    if payload.get('ok') is not True:
        raise RuntimeError('Feishu write was not acknowledged')
    data = payload.get('data')
    if not isinstance(data, dict):
        raise RuntimeError('Feishu write receipt missing')
    record = data.get('record')
    if not isinstance(record, dict):
        record = {}
    ids = data.get('record_id_list')
    if ids is None:
        ids = record.get('record_id_list')
    if ids is not None:
        if not isinstance(ids, list) or len(ids) != 1:
            raise RuntimeError('ambiguous Feishu record receipt')
        receipt = ids[0]
    else:
        receipt = (data.get('record_id') or record.get('record_id') or
                   record.get('id'))
    if not isinstance(receipt, str) or not re.fullmatch(r'rec[A-Za-z0-9]{1,100}', receipt):
        raise RuntimeError('Verified Feishu record receipt required')
    return receipt


def _readback_record(payload, receipt):
    if payload.get('ok') is not True:
        raise RuntimeError('Feishu readback failed')
    data = payload.get('data')
    if not isinstance(data, dict):
        raise RuntimeError('Feishu readback data missing')
    has_more = data.get('has_more')
    if has_more is not None and type(has_more) is not bool:
        raise RuntimeError('Feishu readback pagination flag invalid')
    if has_more is True:
        raise RuntimeError('Feishu readback was not bounded to one record')
    record_ids = data.get('record_id_list')
    if record_ids is not None:
        if not isinstance(record_ids, list) or len(record_ids) != 1 or record_ids[0] != receipt:
            raise RuntimeError('Feishu readback receipt mismatch')

    rows = data.get('data')
    column_names = data.get('fields')
    if isinstance(column_names, list) and isinstance(rows, list):
        if len(rows) != 1 or any(not isinstance(name, str) for name in column_names):
            raise RuntimeError('Feishu readback record count or fields invalid')
        row = rows[0]
        if not isinstance(row, list) or len(row) != len(column_names):
            raise RuntimeError('Feishu readback row shape invalid')
        record = dict(zip(column_names, row))
    elif isinstance(data.get('items'), list):
        if len(data['items']) != 1 or not isinstance(data['items'][0], dict):
            raise RuntimeError('Feishu readback record count invalid')
        item = data['items'][0]
        record = item.get('fields')
        if not isinstance(record, dict):
            raise RuntimeError('Feishu readback fields missing')
        if item.get('record_id') is not None:
            record = {**record, 'record_id': item['record_id']}
    elif isinstance(data.get('records'), list):
        if len(data['records']) != 1 or not isinstance(data['records'][0], dict):
            raise RuntimeError('Feishu readback record count invalid')
        item = data['records'][0]
        record = item.get('fields')
        if not isinstance(record, dict):
            raise RuntimeError('Feishu readback fields missing')
        if item.get('record_id') is not None:
            record = {**record, 'record_id': item['record_id']}
    elif isinstance(data.get('record'), dict):
        raw_record = data['record']
        record = raw_record.get('fields', raw_record)
        if not isinstance(record, dict):
            raise RuntimeError('Feishu readback fields missing')
        if raw_record.get('record_id') is not None:
            record = {**record, 'record_id': raw_record['record_id']}
    else:
        raise RuntimeError('Feishu readback record missing')

    returned_receipt = record.get('record_id') or record.get('recordId')
    if returned_receipt is not None and returned_receipt != receipt:
        raise RuntimeError('Feishu readback receipt mismatch')
    return record


def _verify_readback(payload, event, receipt):
    record = _readback_record(payload, receipt)
    expected = fields(event)
    for name, value in expected.items():
        if name not in record or record[name] != value:
            raise RuntimeError('Feishu readback payload mismatch')


def upload(database, cli, base, table, *, apply=False, runner=subprocess.run):
    if not cli or not base or not table:
        raise ValueError('Feishu CLI, base and table are required')
    cli = _resolve_cli(cli) if apply else cli
    with Journal(database) as journal:
        # Preview is read-only; only an explicit apply reserves rows for upload.
        events = journal.prepare() if apply else journal.preview()
        result = dict(schema='FalconProMetricsUpload/v1', prepared=len(events),
                      uploaded=0, readBack=0, uncertain=0, applied=apply,
                      userAuthorizedDestination=True)
        if not apply:
            result['events'] = [dict(eventId=e['eventId'], kind=e['kind']) for e in events]
            return result
        for event in events:
            command = [cli, 'base', '+record-upsert',
                       '--base-token', base, '--table-id', table, '--as', 'user',
                       '--format', 'json', '--json', json.dumps(fields(event), ensure_ascii=False)]
            try:
                response = runner(command, capture_output=True, text=True,
                                  encoding='utf-8', timeout=60, check=True)
                record_id = _receipt(_parse_response(response, 'Feishu write'))
                read_command = [cli, 'base', '+record-get',
                                '--base-token', base, '--table-id', table,
                                '--record-id', record_id, '--format', 'json', '--as', 'user']
                for field_name in fields(event):
                    read_command.extend(['--field-id', field_name])
                read_response = runner(read_command, capture_output=True, text=True,
                                       encoding='utf-8', timeout=60, check=True)
                _verify_readback(_parse_response(read_response, 'Feishu readback'), event, record_id)
                result['readBack'] += 1
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
