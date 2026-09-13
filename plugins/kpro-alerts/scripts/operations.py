"""Evidence-bound AI assessments and requested actions; native approval is separate."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3

from notification_journal import SAFE_NUMERIC_FIELDS, SAFE_BOOLEAN_FIELDS
from query import pseudonym, safe_timestamp
from spool import checked

CLIENTS = ('codex', 'grok', 'cursor', 'workbuddy', 'zcode', 'generic')
VERDICTS = ('benign', 'suspicious', 'malicious', 'unknown')
REASONS = ('bulk_overwrite', 'ransom_note', 'format_mismatch', 'rename_burst',
           'high_risk_name', 'recovery_destruction', 'known_user_activity',
           'deterministic_policy', 'insufficient_evidence', 'other')
ACTIONS = ('investigate', 'switch_to_audit', 'switch_to_enforce', 'terminate_process',
           'quarantine_file', 'delete_file', 'add_exception', 'restore_backup', 'isolate_network')
MAX_RECORDS = 100000
V1_CAPABILITIES = dict(releaseScope='existing_driver_events_v1', driverChangeRequired=False,
                       policyMutationAvailable=False, aiActionExecutionAvailable=False)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode('ascii')).hexdigest()


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
        raise ValueError('Expected a SHA-256 identifier')
    return value


def _choices(values, allowed):
    if (not isinstance(values, list) or len(values) > 10 or
            any(not isinstance(v, str) or v not in allowed for v in values) or
            len(set(values)) != len(values)):
        raise ValueError('Unsupported reason or action')


def _model(value):
    if not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9_.:/-]{1,100}', value):
        raise ValueError('Invalid model identifier')


def _validate_evidence(value):
    keys = {'schema','eventId','evidenceSha256','deviceId','sessionId','received','telemetry',
            'privacy','source','sourceAttestation','simulationClaimed','simulated'}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError('Unknown evidence fields')
    for key in ('eventId','evidenceSha256','deviceId','sessionId'):
        identifier(value[key])
    safe_timestamp(value['received'])
    if (value['schema'] != 'FalconProEventEvidence/v1' or value['privacy'] != 'numeric_projection' or
            value['source'] != 'local_event_store' or value['sourceAttestation'] != 'not_verified_by_native_broker' or
            type(value['simulationClaimed']) is not bool or type(value['simulated']) is not bool):
        raise ValueError('Invalid evidence provenance')
    telemetry = value['telemetry']
    if not isinstance(telemetry, dict) or set(telemetry) - set(SAFE_NUMERIC_FIELDS) - set(SAFE_BOOLEAN_FIELDS):
        raise ValueError('Unknown telemetry field')
    for key, item in telemetry.items():
        if key in SAFE_BOOLEAN_FIELDS:
            if type(item) is not bool:
                raise ValueError('Invalid boolean telemetry')
        elif type(item) is not int or not 0 <= item <= 2**64-1:
            raise ValueError('Invalid numeric telemetry')
    if type(telemetry.get('eventType')) is not int or not 0 <= telemetry['eventType'] <= 8 or type(telemetry.get('operation')) is not int:
        raise ValueError('Unsupported source event')


def decode_record(raw):
    if not isinstance(raw, str) or len(raw) > 65536:
        raise ValueError('Invalid operations record size')
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('Invalid operations record')
    record_id = identifier(value.get('recordId'))
    if digest({k:v for k,v in value.items() if k != 'recordId'}) != record_id:
        raise ValueError('Operations record digest mismatch')
    expected = {'FalconProAIDecision/v1':'not_requested',
                'FalconProActionRequest/v1':'requires_native_confirmation'}
    if (value.get('schema') not in expected or value.get('approvalState') != expected[value['schema']]
            or value.get('executionState') != 'not_executed'):
        raise ValueError('Record is not a supported assessment or action request')
    common = {'schema','eventId','evidenceSha256','approvalState','executionState','simulated',
              'requestKey','recordedAt','client','clientIdentityTrust','recordId'}
    specific = ({'evidence','verdict','confidence','reasonCodes','recommendedActions','model','assessmentTrust'}
                if value['schema'] == 'FalconProAIDecision/v1' else
                {'decisionId','action','policyVersion','processId','processCreateTime','executionAvailable'})
    if set(value) != common | specific:
        raise ValueError('Unknown operations fields')
    identifier(value['eventId'])
    identifier(value['evidenceSha256'])
    safe_timestamp(value['recordedAt'])
    if (value['client'] not in CLIENTS or type(value['simulated']) is not bool or
            value['clientIdentityTrust'] != 'configured_not_cryptographically_attested' or
            not isinstance(value['requestKey'], str) or not re.fullmatch('[a-f0-9]{32}', value['requestKey'])):
        raise ValueError('Invalid operations identity')
    if value['schema'] == 'FalconProAIDecision/v1':
        _validate_evidence(value['evidence'])
        if (value['verdict'] not in VERDICTS or type(value['confidence']) is not int or
                not 0 <= value['confidence'] <= 100 or value['assessmentTrust'] != 'ai_assertion' or
                any(value[key] != value['evidence'][key] for key in ('eventId','evidenceSha256','simulated'))):
            raise ValueError('Invalid assessment binding')
        _choices(value['reasonCodes'], REASONS)
        _choices(value['recommendedActions'], ACTIONS)
        _model(value['model'])
    else:
        identifier(value['decisionId'])
        if value['action'] not in ACTIONS or value['executionAvailable'] is not False:
            raise ValueError('Native execution is unavailable')
        for key in ('policyVersion','processId','processCreateTime'):
            item = value[key]
            if item is not None and (type(item) is not int or not 0 <= item <= 2**64-1):
                raise ValueError('Invalid subject binding')
    return value


def _source(path):
    path = checked(path)
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=3)
    db.execute('PRAGMA query_only=ON')
    db.execute('PRAGMA trusted_schema=OFF')
    return db


def _evidence(row):
    event_id, device, session, received, raw = row
    identifier(event_id)
    if not isinstance(raw, str) or len(raw.encode('utf-8')) > 65536:
        raise ValueError('Invalid source record size')
    event = json.loads(raw)
    if not isinstance(event, dict) or type(event.get('eventType')) is not int or not 0 <= event['eventType'] <= 8:
        raise ValueError('Unsupported source event')
    safe = {}
    for key in SAFE_NUMERIC_FIELDS:
        if key in event:
            value = event[key]
            if type(value) is not int or not 0 <= value <= 2**64 - 1:
                raise ValueError('Invalid numeric telemetry')
            safe[key] = value
    for key in SAFE_BOOLEAN_FIELDS:
        if key in event:
            if type(event[key]) is not bool:
                raise ValueError('Invalid boolean telemetry')
            safe[key] = event[key]
    if type(event.get('operation')) is not int:
        raise ValueError('Operation missing')
    return dict(schema='FalconProEventEvidence/v1', eventId=event_id,
                evidenceSha256=digest(dict(eventId=event_id, device=device, session=session, received=received, event=event)),
                deviceId=pseudonym(device), sessionId=pseudonym(session), received=safe_timestamp(received),
                telemetry=safe, privacy='numeric_projection', source='local_event_store',
                sourceAttestation='not_verified_by_native_broker', simulationClaimed=event.get('simulated') is True,
                simulated=event.get('simulated') is True and event_id in os.environ.get('KPRO_SIMULATED_ALERT_IDS','').split(','))


def evidence(path, event_id):
    identifier(event_id)
    db = _source(path)
    try:
        rows = db.execute('SELECT id,device,session,received,raw FROM events WHERE id=? LIMIT 2', (event_id,)).fetchall()
        if len(rows) != 1:
            raise ValueError('Event unavailable or duplicated')
        return _evidence(rows[0])
    finally:
        db.close()


def events(path, after=0, limit=100):
    if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError('Invalid bounded event cursor')
    db = _source(path)
    try:
        rows = db.execute('SELECT rowid,id,device,session,received,raw FROM events WHERE rowid>? ORDER BY rowid LIMIT ?',
                          (after, limit + 1)).fetchall()
        page = rows[:limit]
        loss = db.execute('SELECT COALESCE(SUM(dropped),0) FROM batches').fetchone()[0]
        return dict(events=[_evidence(row[1:]) for row in page], nextCursor=page[-1][0] if page else after,
                    hasMore=len(rows) > limit, reportedDropped=loss,
                    coverage='retained_engine_events_not_all_file_io', nativeSourceVerified=False)
    finally:
        db.close()


class Operations:
    def __init__(self, path, source, client='generic', *, now=None):
        if client not in CLIENTS:
            raise ValueError('Unsupported assistant identity')
        self.source, self.client = source, client
        self.now = now or (lambda: datetime.now(timezone.utc).isoformat())
        path = Path(path).absolute()
        checked(path if path.exists() else path.parent)
        source_path = checked(source)
        if (os.path.normcase(str(path)) == os.path.normcase(str(source_path)) or
                (path.exists() and os.path.samefile(path, source_path))):
            raise ValueError('Operations journal must be separate from the event source')
        self.db = sqlite3.connect(path, timeout=5)
        self.db.execute('PRAGMA trusted_schema=OFF')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        page_size = self.db.execute('PRAGMA page_size').fetchone()[0]
        self.db.execute('PRAGMA max_page_count=%d' % (512 * 1024 * 1024 // page_size))
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS ops_records (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, event_id TEXT NOT NULL,
                evidence_hash TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS ops_outbox (
                id TEXT PRIMARY KEY REFERENCES ops_records(id), state TEXT NOT NULL,
                record_id TEXT, destination TEXT);
            CREATE TABLE IF NOT EXISTS ops_requests (
                client TEXT NOT NULL, request_key TEXT NOT NULL, input_hash TEXT NOT NULL,
                record_id TEXT NOT NULL, PRIMARY KEY(client,request_key));
        ''')

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.db.close()

    @contextmanager
    def _transaction(self):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            yield

    def _append(self, payload, kind, event_id, evidence_hash, request_key, input_hash):
        if not isinstance(request_key, str) or not re.fullmatch('[a-f0-9]{32}', request_key):
            raise ValueError('A stable 128-bit request key is required')
        prior = self.db.execute('SELECT input_hash,record_id FROM ops_requests WHERE client=? AND request_key=?',
                                (self.client, request_key)).fetchone()
        if prior:
            if prior[0] != input_hash:
                raise ValueError('Request key reused for different content')
            return self.get(prior[1])
        if self.db.execute('SELECT COUNT(*) FROM ops_records').fetchone()[0] >= MAX_RECORDS:
            raise ValueError('Operations capacity reached')
        payload = {**payload, 'requestKey': request_key, 'recordedAt': self.now(), 'client': self.client,
                   'clientIdentityTrust': 'configured_not_cryptographically_attested'}
        record_id = digest(payload)
        payload = {**payload, 'recordId': record_id}
        raw = canonical(payload)
        if len(raw) > 65536:
            raise ValueError('Operations record exceeds limit')
        decode_record(raw)
        self.db.execute('INSERT INTO ops_records VALUES (?,?,?,?,?)', (record_id, kind, event_id, evidence_hash, raw))
        self.db.execute('INSERT INTO ops_outbox VALUES (?,\'new\',NULL,NULL)', (record_id,))
        self.db.execute('INSERT INTO ops_requests VALUES (?,?,?,?)', (self.client, request_key, input_hash, record_id))
        return payload

    def get(self, record_id):
        identifier(record_id)
        row = self.db.execute('SELECT payload FROM ops_records WHERE id=?', (record_id,)).fetchone()
        if row is None:
            raise ValueError('Operations record not found')
        return decode_record(row[0])

    def assess(self, event_id, evidence_hash, verdict, confidence, reasons, actions, model, request_key):
        identifier(evidence_hash)
        if verdict not in VERDICTS or type(confidence) is not int or not 0 <= confidence <= 100:
            raise ValueError('Invalid AI assessment')
        _choices(reasons, REASONS)
        _choices(actions, ACTIONS)
        _model(model)
        captured = evidence(self.source, event_id)
        if captured['evidenceSha256'] != evidence_hash:
            raise ValueError('Source evidence changed')
        payload = dict(schema='FalconProAIDecision/v1', eventId=event_id, evidenceSha256=evidence_hash,
                       evidence=captured, verdict=verdict, confidence=confidence, reasonCodes=sorted(reasons),
                       recommendedActions=sorted(actions), model=model, assessmentTrust='ai_assertion',
                       approvalState='not_requested', executionState='not_executed', simulated=captured['simulated'])
        with self._transaction():
            return self._append(payload, 'assessment', event_id, evidence_hash, request_key, digest(payload))

    def propose(self, decision_id, action, request_key):
        if action not in ACTIONS:
            raise ValueError('Unsupported action')
        with self._transaction():
            decision = self.get(decision_id)
            if decision['schema'] != 'FalconProAIDecision/v1' or action not in decision['recommendedActions']:
                raise ValueError('Action is not bound to an assessment')
            current = evidence(self.source, decision['eventId'])
            if current['evidenceSha256'] != decision['evidenceSha256']:
                raise ValueError('Source evidence changed')
            payload = dict(schema='FalconProActionRequest/v1', decisionId=decision_id,
                           eventId=decision['eventId'], evidenceSha256=decision['evidenceSha256'], action=action,
                           policyVersion=current['telemetry'].get('policyVersion'),
                           processId=current['telemetry'].get('processId'),
                           processCreateTime=current['telemetry'].get('processCreateTime'),
                           approvalState='requires_native_confirmation', executionState='not_executed',
                           executionAvailable=False, simulated=current['simulated'])
            return self._append(payload, 'action_request', decision['eventId'], decision['evidenceSha256'],
                                request_key, digest(payload))

    def preview(self, limit=100):
        return _preview(self.db, limit)

    def reserve(self, record_id, destination):
        identifier(record_id)
        identifier(destination)
        with self._transaction():
            changed = self.db.execute('UPDATE ops_outbox SET state=\'pending\',destination=? WHERE id=? AND state=\'new\'',
                                      (destination, record_id)).rowcount
            if changed != 1:
                raise ValueError('Record already reserved; reconcile before retry')

    def ack(self, record_id, destination, remote_id):
        if not isinstance(remote_id, str) or not re.fullmatch('rec[A-Za-z0-9]{1,100}', remote_id):
            raise ValueError('Invalid remote receipt')
        with self._transaction():
            changed = self.db.execute('UPDATE ops_outbox SET state=\'acknowledged\',record_id=? '
                                      'WHERE id=? AND state=\'pending\' AND destination=?',
                                      (remote_id, identifier(record_id), identifier(destination))).rowcount
            if changed != 1:
                raise ValueError('Receipt does not match pending destination')

    def status(self):
        return dict(schema='FalconProOperationsStatus/v1',
                    **V1_CAPABILITIES,
                    records=self.db.execute('SELECT COUNT(*) FROM ops_records').fetchone()[0],
                    deliveryStates=dict(self.db.execute('SELECT state,COUNT(*) FROM ops_outbox GROUP BY state')),
                    automaticRemediation=False, nativeActionBroker='not_integrated',
                    approvalAuthority='native_endpoint_only')


def _preview(db, limit):
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError('Invalid limit')
    rows = db.execute('SELECT r.payload FROM ops_records r JOIN ops_outbox o ON o.id=r.id '
                      'WHERE o.state=\'new\' ORDER BY r.rowid LIMIT ?', (limit,)).fetchall()
    return [decode_record(row[0]) for row in rows]


def preview(path, limit=100):
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError('Invalid limit')
    if not Path(path).exists():
        return []
    db = _source(path)
    try:
        return _preview(db, limit)
    finally:
        db.close()


def status(path):
    if not Path(path).is_file():
        return dict(state='not_initialized', automaticRemediation=False, **V1_CAPABILITIES)
    db = _source(path)
    try:
        return dict(schema='FalconProOperationsStatus/v1',
                    **V1_CAPABILITIES,
                    records=db.execute('SELECT COUNT(*) FROM ops_records').fetchone()[0],
                    deliveryStates=dict(db.execute('SELECT state,COUNT(*) FROM ops_outbox GROUP BY state')),
                    automaticRemediation=False, nativeActionBroker='not_integrated')
    finally:
        db.close()
