"""Explicit operations outbox delivery through the user's authorized Feishu CLI."""
import json
import re
import subprocess
import time
from metrics_upload import _resolve_cli, _parse_response, _receipt, _readback_record
from operations import Operations, canonical, digest, preview


def fields(record):
    return {'分析ID': record['recordId'], '关联告警ID': record['eventId'], '记录类型': record['schema'],
            '分析来源': record['client'], '证据摘要': record['evidenceSha256'],
            '分析结论': record.get('verdict', 'action_request'),
            '处置建议': record.get('action', ','.join(record.get('recommendedActions', []))),
            '记录时间': record['recordedAt'],
            '审批状态': record['approvalState'], '执行状态': record['executionState'],
            '模拟': record['simulated'], '结构化记录': canonical(record)}


def _read_verified(cli, base, table, remote_id, expected, runner):
    command = [cli, 'base', '+record-get', '--base-token', base, '--table-id', table,
               '--record-id', remote_id, '--as', 'user', '--format', 'json']
    for field in expected:
        command += ['--field-id', field]
    for attempt in range(3):
        try:
            response = runner(command, capture_output=True, text=True, encoding='utf-8', timeout=30, check=True)
            actual = _readback_record(_parse_response(response, 'Operations readback'), remote_id, require_identity=True)
            if any(actual.get(k) != v for k, v in expected.items()):
                raise ValueError('Operations readback mismatch')
            return
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            if attempt == 2:
                raise
            time.sleep(0.25 * (attempt+1))


def upload(database, source, cli, base, table, *, apply=False, limit=100, runner=subprocess.run):
    if any(not isinstance(v, str) or not re.fullmatch('[A-Za-z0-9]{1,128}', v) for v in (base, table)):
        raise ValueError('Explicit operations destination required')
    destination = digest({'base': base, 'table': table})
    records = preview(database, limit)
    result = dict(schema='FalconProOperationsUpload/v1', uploaded=0, readBack=0, uncertain=0,
                  records=[r['recordId'] for r in records], applied=apply, failures=[])
    if not apply or not records:
        return result
    cli = _resolve_cli(cli) if apply else cli
    with Operations(database, source) as journal:
        for record in records:
            journal.reserve(record['recordId'], destination)
            expected = fields(record)
            stage = 'write'
            try:
                response = runner([cli, 'base', '+record-upsert', '--base-token', base, '--table-id', table,
                    '--as', 'user', '--format', 'json', '--json', json.dumps(expected, ensure_ascii=False)],
                    capture_output=True, text=True, encoding='utf-8', timeout=60, check=True)
                stage = 'write_receipt'
                remote_id = _receipt(_parse_response(response, 'Operations write'))
                stage = 'readback'
                _read_verified(cli, base, table, remote_id, expected, runner)
                stage = 'ack'
                journal.ack(record['recordId'], destination, remote_id)
                result['uploaded'] += 1
                result['readBack'] += 1
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                # Pending is durable, including a crash before/after the network call.
                result['uncertain'] += 1
                result['failures'].append(dict(recordId=record['recordId'], stage=stage, errorClass=type(error).__name__))
        return result


def reconcile(database, source, cli, base, table, record_id, remote_id, *, runner=subprocess.run):
    from operations import identifier
    identifier(record_id)
    if not isinstance(remote_id, str) or not re.fullmatch('rec[A-Za-z0-9]{1,100}', remote_id):
        raise ValueError('Explicit remote record ID required')
    if any(not isinstance(v,str) or not re.fullmatch('[A-Za-z0-9]{1,128}',v) for v in (base,table)):
        raise ValueError('Explicit destination required')
    destination=digest({'base':base,'table':table})
    with Operations(database, source) as journal:
        pending=journal.db.execute('SELECT state,destination FROM ops_outbox WHERE id=?',(record_id,)).fetchone()
        if pending != ('pending',destination):
            raise ValueError('Record is not pending for that destination')
        record=journal.get(record_id)
        _read_verified(_resolve_cli(cli),base,table,remote_id,fields(record),runner)
        journal.ack(record_id,destination,remote_id)
        return dict(recordId=record_id,remoteRecordId=remote_id,reconciled=True,resent=False)
