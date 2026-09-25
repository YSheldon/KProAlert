"""Explicit operations outbox delivery through the user's authorized Feishu CLI."""
import json
import re
import subprocess
import time
from metrics_upload import _resolve_cli, _parse_response, _receipt, _readback_record
from operations import Operations, canonical, digest, preview


def fields(record):
    conclusion = (record['executionState'] if record['schema']=='FalconProNativeActionResult/v1'
                  else record.get('verdict','action_request'))
    return {'分析ID': record['recordId'], '关联告警ID': record['eventId'], '记录类型': record['schema'],
            '分析来源': record['client'], '证据摘要': record['evidenceSha256'],
            '分析结论': conclusion,
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


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate cloud response member')
        result[key] = value
    return result


def _find_remote_record_id(cli, base, table, record_id, runner):
    query = {'logic': 'and', 'conditions': [['分析ID', '==', record_id]]}
    command = [cli, 'base', '+record-list', '--base-token', base, '--table-id', table,
               '--filter-json', json.dumps(query, ensure_ascii=False), '--limit', '2',
               '--format', 'json', '--as', 'user', '--field-id', '分析ID']
    response = runner(command, capture_output=True, text=True, encoding='utf-8',
                      timeout=30, check=True)
    output = getattr(response, 'stdout', None)
    if not isinstance(output, str) or len(output) > 1024 * 1024:
        raise RuntimeError('Operations lookup response is invalid')
    payload = json.loads(output, object_pairs_hook=_unique_pairs)
    data = payload.get('data') if isinstance(payload, dict) and payload.get('ok') is True else None
    if (not isinstance(data, dict) or data.get('fields') != ['分析ID'] or
            not isinstance(data.get('data'), list) or len(data['data']) > 2 or
            type(data.get('has_more')) is not bool):
        raise ValueError('Unexpected Operations lookup schema')
    rows = data['data']
    remote_ids = data.get('record_id_list')
    if not rows:
        if data['has_more']:
            raise ValueError('Operations lookup did not advance')
        return None
    if data['has_more'] or len(rows) != 1:
        raise ValueError('Ambiguous remote record for local analysis ID')
    if (not isinstance(rows[0], list) or rows[0] != [record_id] or
            not isinstance(remote_ids, list) or len(remote_ids) != 1 or
            not isinstance(remote_ids[0], str) or
            not re.fullmatch('rec[A-Za-z0-9]{1,100}', remote_ids[0])):
        raise ValueError('Operations lookup identity mismatch')
    return remote_ids[0]


def upload(database, source, cli, base, table, *, apply=False, limit=100, runner=subprocess.run):
    if any(not isinstance(v, str) or not re.fullmatch('[A-Za-z0-9]{1,128}', v) for v in (base, table)):
        raise ValueError('Explicit operations destination required')
    destination = digest({'base': base, 'table': table})
    records = preview(database, limit)
    result = dict(schema='FalconProOperationsUpload/v1', uploaded=0, readBack=0, uncertain=0, blocked=0,
                  records=[r['recordId'] for r in records], applied=apply, failures=[])
    if not apply or not records:
        return result
    with Operations(database, source) as journal:
        for record in records:
            if record['schema']=='FalconProNativeActionResult/v1':
                from native_actions import verify_delivery
                try:
                    verify_delivery(record,source)
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                    result['blocked']+=1
                    result['failures'].append(dict(recordId=record['recordId'],stage='native_verification',errorClass=type(error).__name__))
                    continue
            resolved_cli = _resolve_cli(cli)
            journal.reserve(record['recordId'], destination)
            expected = fields(record)
            stage = 'write'
            remote_id = None
            try:
                response = runner([resolved_cli, 'base', '+record-upsert', '--base-token', base, '--table-id', table,
                    '--as', 'user', '--format', 'json', '--json', json.dumps(expected, ensure_ascii=False)],
                    capture_output=True, text=True, encoding='utf-8', timeout=60, check=True)
                stage = 'write_receipt'
                remote_id = _receipt(_parse_response(response, 'Operations write'))
                stage = 'persist_remote_receipt'
                journal.remember_remote_id(record['recordId'], destination, remote_id)
                stage = 'readback'
                _read_verified(resolved_cli, base, table, remote_id, expected, runner)
                stage = 'ack'
                journal.ack(record['recordId'], destination, remote_id)
                result['uploaded'] += 1
                result['readBack'] += 1
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                # Pending is durable, including a crash before/after the network call.
                result['uncertain'] += 1
                failure = dict(recordId=record['recordId'], stage=stage,
                               errorClass=type(error).__name__)
                if remote_id is not None:
                    failure['remoteRecordId'] = remote_id
                result['failures'].append(failure)
        return result


def reconcile(database, source, cli, base, table, record_id, remote_id=None, *, runner=subprocess.run):
    from operations import identifier
    identifier(record_id)
    if remote_id is not None and (not isinstance(remote_id, str) or
                                  not re.fullmatch('rec[A-Za-z0-9]{1,100}', remote_id)):
        raise ValueError('Explicit remote record ID required')
    if any(not isinstance(v,str) or not re.fullmatch('[A-Za-z0-9]{1,128}',v) for v in (base,table)):
        raise ValueError('Explicit destination required')
    destination=digest({'base':base,'table':table})
    with Operations(database, source) as journal:
        pending=journal.db.execute('SELECT state,destination FROM ops_outbox WHERE id=?',(record_id,)).fetchone()
        if pending != ('pending',destination):
            raise ValueError('Record is not pending for that destination')
        stored_remote_id = journal.pending_remote_id(record_id, destination)
        if remote_id is None:
            remote_id = stored_remote_id or _find_remote_record_id(
                _resolve_cli(cli), base, table, record_id, runner)
        elif stored_remote_id is not None and remote_id != stored_remote_id:
            raise ValueError('Remote record ID differs from the persisted receipt')
        if remote_id is None:
            raise ValueError('No matching remote record; uncertain send was not resent')
        record=journal.get(record_id)
        if record['schema']=='FalconProNativeActionResult/v1':
            from native_actions import verify_delivery
            verify_delivery(record,source)
        _read_verified(_resolve_cli(cli),base,table,remote_id,fields(record),runner)
        if stored_remote_id is None:
            journal.remember_remote_id(record_id, destination, remote_id)
        journal.ack(record_id,destination,remote_id)
        return dict(recordId=record_id,remoteRecordId=remote_id,reconciled=True,resent=False)
