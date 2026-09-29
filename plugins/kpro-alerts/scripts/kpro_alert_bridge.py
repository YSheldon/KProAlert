"""Event outbox. Export is allowlisted; raw evidence stays local."""
import argparse
import hashlib
import json
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def _event_id(device, session, sequence):
    return hashlib.sha256(json.dumps([device, session, sequence]).encode()).hexdigest()


class Store:
    def __init__(self, path, max_events=100000, max_storage_bytes=512 * 1024 * 1024):
        if type(max_events) is not int or not 1 <= max_events <= 1000000:
            raise ValueError('invalid event capacity')
        if type(max_storage_bytes) is not int or not 1 <= max_storage_bytes <= 512 * 1024 * 1024:
            raise ValueError('invalid storage budget')
        self.max_events = max_events
        self.max_storage_bytes = max_storage_bytes
        self.db = sqlite3.connect(path, timeout=10)
        self.database_path = next(row[2] for row in self.db.execute('PRAGMA database_list') if row[1] == 'main')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA foreign_keys=ON')
        # Bound database growth; WAL checkpoints run at SQLite's default threshold.
        page_size = self.db.execute('PRAGMA page_size').fetchone()[0]
        self.db.execute('PRAGMA max_page_count=%d' % (512 * 1024 * 1024 // page_size))
        self.db.execute('''CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, device TEXT, session TEXT,
            received TEXT, raw TEXT NOT NULL)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS deliveries (
            id TEXT PRIMARY KEY, state TEXT, record_id TEXT, payload TEXT)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS batches (
            id TEXT PRIMARY KEY, device TEXT, session TEXT, dropped INTEGER)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS batch_sources (
            source_id TEXT PRIMARY KEY, batch_id TEXT NOT NULL UNIQUE REFERENCES batches(id),
            device TEXT NOT NULL, device_digest TEXT NOT NULL, generation TEXT NOT NULL,
            created INTEGER NOT NULL, producer_session TEXT NOT NULL, producer_batch_id TEXT NOT NULL,
            prepared_hash TEXT NOT NULL, raw_hash TEXT NOT NULL, safe_hash TEXT NOT NULL,
            collector_dropped TEXT NOT NULL, projection_dropped TEXT NOT NULL,
            source_state TEXT NOT NULL CHECK(source_state='analysis_only'),
            attestation TEXT NOT NULL CHECK(attestation='unverified_public_metadata'))''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS batch_commits (
            source_id TEXT NOT NULL REFERENCES batch_sources(source_id), commit_id TEXT NOT NULL,
            helper_hash TEXT NOT NULL, PRIMARY KEY(source_id,commit_id))''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS event_batches (
            event_id TEXT NOT NULL REFERENCES events(id), source_id TEXT NOT NULL REFERENCES batch_sources(source_id),
            record_index INTEGER NOT NULL CHECK(record_index BETWEEN 0 AND 1023),
            PRIMARY KEY(source_id,record_index))''')
        self.db.execute('CREATE INDEX IF NOT EXISTS event_batches_by_event ON event_batches(event_id)')
        self.db.execute('''CREATE TABLE IF NOT EXISTS source_lifecycle (
            source_id TEXT PRIMARY KEY REFERENCES batch_sources(source_id),
            reported_state TEXT NOT NULL CHECK(reported_state='retired'))''')

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.db.close()

    def ingest(self, device, session, event):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self._check_storage_budget()
            return self._ingest(device, session, event)

    def _storage_observation(self):
        sizes = []
        for suffix in ('', '-wal', '-shm'):
            if not self.database_path:
                sizes.append(0)
                continue
            try:
                sizes.append(Path(self.database_path + suffix).stat().st_size)
            except FileNotFoundError:
                if not suffix:
                    raise RuntimeError('database unavailable for storage budget measurement')
                sizes.append(0)
        total = sum(sizes)
        return dict(databaseFileBytes=sizes[0], databaseWalBytes=sizes[1], databaseShmBytes=sizes[2],
                    databaseTotalFileBytes=total,
                    storageBudgetState=('at_or_over_observed_limit' if total >= self.max_storage_bytes
                                        else 'within_observed_limit'),
                    storageBudgetEnforcement='observed_before_ingest_not_transaction_hard_cap')

    def _check_storage_budget(self):
        if not self.db.in_transaction:
            raise RuntimeError('storage budget check requires a write transaction')
        # This is an admission check, not a bound on the next transaction's WAL.
        # Never checkpoint or remove uncertain delivery state to create space.
        if self._storage_observation()['databaseTotalFileBytes'] >= self.max_storage_bytes:
            raise RuntimeError('observed storage budget reached; existing evidence retained')

    def _ingest(self, device, session, event):
        if any(not isinstance(v, str) or not 1 <= len(v) <= 128 for v in (device, session)) or not isinstance(event, dict):
            raise ValueError('device, driver session and event object required')
        for key in ('eventType', 'operation', 'sequence'):
            if type(event.get(key)) is not int or event[key] < 0:
                raise ValueError('invalid ' + key)
        if event['eventType'] > 8:
            raise ValueError('unsupported event type')
        raw = json.dumps(event, ensure_ascii=False, sort_keys=True, allow_nan=False)
        if len(raw.encode('utf-8')) > 65536:
            raise ValueError('event exceeds 64 KiB')
        uid = _event_id(device, session, event['sequence'])
        old = self.db.execute('SELECT raw FROM events WHERE id=?', (uid,)).fetchone()
        if old:
            if old[0] != raw:
                raise ValueError('sequence collision: use a new driver session ID')
            return False
        if self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0] >= self.max_events:
            raise RuntimeError('event capacity reached; archive acknowledged evidence before resuming')
        self.db.execute('INSERT INTO events VALUES (?,?,?,?,?)',
                        (uid, device, session, datetime.now(timezone.utc).isoformat(), raw))
        return True

    def ingest_replica(self, device, document):
        from safe_replica import loads_replica, parse_replica, SOURCE_STATE, ATTESTATION
        replica = loads_replica(document) if type(document) is bytes else parse_replica(document)
        if not isinstance(device, str) or not 1 <= len(device) <= 128:
            raise ValueError('local device label required')
        batch_id = 'replica:' + replica.slot
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self._check_storage_budget()
            prior = self.db.execute('SELECT source_id,prepared_hash,device FROM batch_sources WHERE batch_id=?',
                                    (batch_id,)).fetchone()
            if prior and prior != (replica.source_id, replica.prepared_hash, device):
                raise ValueError('conflicting producer batch identity')
            if not prior:
                if self.db.execute('SELECT COUNT(*) FROM batches').fetchone()[0] >= self.max_events:
                    raise RuntimeError('batch capacity reached')
                # Keep the legacy four-column table stable. Exact unsigned loss is
                # counted once from the source, not once per helper/commit version.
                self.db.execute('INSERT INTO batches VALUES (?,?,?,?)', (batch_id, device, replica.session, 0))
                self.db.execute('INSERT INTO batch_sources VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (replica.source_id, batch_id, device, replica.device, str(replica.generation), replica.created,
                     replica.session, replica.batch, replica.prepared_hash, replica.raw_hash, replica.safe_hash,
                     str(replica.collector_dropped), str(replica.projection_dropped), SOURCE_STATE, ATTESTATION))
            inserted = 0
            for event, index in zip(replica.records, replica.record_indices):
                uid = _event_id(device, replica.session, event['sequence'])
                old = self.db.execute('SELECT raw FROM events WHERE id=?', (uid,)).fetchone()
                if old:
                    existing = json.loads(old[0])
                    if isinstance(existing, dict) and '_nativeSource' in existing:
                        from native_provenance import validate_source
                        validate_source(existing.pop('_nativeSource'))
                    if json.dumps(existing, ensure_ascii=False, sort_keys=True, allow_nan=False) != json.dumps(
                            event, ensure_ascii=False, sort_keys=True, allow_nan=False):
                        raise ValueError('sequence collision: use a new driver session ID')
                else:
                    inserted += self._ingest(device, replica.session, event)
                self.db.execute('INSERT OR IGNORE INTO event_batches VALUES (?,?,?)', (uid, replica.source_id, index))
            if not self.db.execute('SELECT 1 FROM batch_commits WHERE source_id=? AND commit_id=?',
                                   (replica.source_id, replica.commit_id)).fetchone():
                if self.db.execute('SELECT COUNT(*) FROM batch_commits').fetchone()[0] >= self.max_events:
                    raise RuntimeError('replica commit capacity reached')
                self.db.execute('INSERT INTO batch_commits VALUES (?,?,?)',
                                (replica.source_id, replica.commit_id, replica.helper_hash))
            if replica.reported_state == 'retired':
                # Older replicas cannot clear a later retirement claim. This is
                # user-readable metadata, not protected native retirement proof.
                self.db.execute('INSERT OR IGNORE INTO source_lifecycle VALUES (?,?)',
                                (replica.source_id, 'retired'))
        return inserted

    def source_for_event(self, event_id):
        from safe_replica import source_for_event
        return source_for_event(self.db, event_id)

    def health(self):
        from safe_replica import reported_dropped
        return dict(storedEvents=self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0],
                    eventCapacity=self.max_events,
                    reportedDropped=reported_dropped(self.db),
                    uncertainDeliveries=self.db.execute("SELECT COUNT(*) FROM deliveries WHERE state='pending'").fetchone()[0],
                    storageByteLimit=self.max_storage_bytes,
                    databaseAllocatedBytes=self.db.execute('PRAGMA page_count').fetchone()[0]*self.db.execute('PRAGMA page_size').fetchone()[0],
                    collectorStatus='not_probed', protectionStatus='not_probed', **self._storage_observation())

    def export(self):
        groups = {}
        for uid, device, session, received, raw in self.db.execute(
                'SELECT * FROM events ORDER BY received,id'):
            e = json.loads(raw)
            # Fixed minute buckets bound aggregation; PID alone is not an identity.
            key = json.dumps([device, session, received[:16], e['eventType'],
                              e['operation'], e.get('processId'),
                              e.get('processCreateTime'), e.get('policyVersion'),
                              e.get('ruleId')], sort_keys=True)
            group_id = hashlib.sha256(key.encode()).hexdigest()
            if group_id not in groups:
                groups[group_id] = dict(alertId=group_id, deviceId=device,
                    sessionId=session, eventType=e['eventType'], operation=e['operation'],
                    firstReceived=received, lastReceived=received, eventCount=0)
            groups[group_id]['eventCount'] += 1
            groups[group_id]['lastReceived'] = received
        return list(groups.values())

    def sync(self, sender, max_deliveries=None):
        if max_deliveries is not None and (type(max_deliveries) is not int or not 1 <= max_deliveries <= 100):
            raise ValueError('invalid delivery budget')
        sent = 0
        for alert in self.export():
            payload = json.dumps(alert, sort_keys=True)
            uid = alert['alertId']
            # Persist the intent before networking. A crash leaves an uncertain send,
            # never permission to create the same remote record again blindly.
            with self.db:
                self.db.execute('BEGIN IMMEDIATE')
                previous = self.db.execute(
                    'SELECT state,record_id,payload FROM deliveries WHERE id=?', (uid,)).fetchone()
                if previous and previous[0] == 'pending':
                    raise RuntimeError('uncertain delivery requires reconciliation: ' + uid)
                if previous and previous[2] == payload:
                    continue
                if max_deliveries is not None and sent >= max_deliveries:
                    return True
                record_id = previous[1] if previous else None
                self.db.execute('INSERT OR REPLACE INTO deliveries VALUES (?,?,?,?)',
                                (uid, 'pending', record_id, payload))
            receipt = sender(alert, record_id)
            if not isinstance(receipt, str) or not receipt.startswith('rec'):
                raise RuntimeError('missing remote record receipt')
            with self.db:
                self.db.execute('UPDATE deliveries SET state=?,record_id=? WHERE id=?',
                                ('acknowledged', receipt, uid))
            sent += 1
        return False


def feishu_sender(cli, base, table):
    def send(alert, record_id):
        fields = {'告警ID': alert['alertId'], '设备ID': alert['deviceId'],
                  '会话ID': alert['sessionId'], 'eventType': alert['eventType'],
                  'operation': alert['operation'], '累计事件数': alert['eventCount'],
                  '首次时间': alert['firstReceived'], '末次时间': alert['lastReceived']}
        command = [cli, 'base', '+record-upsert', '--base-token', base,
                   '--table-id', table, '--as', 'user', '--json',
                   json.dumps(fields, ensure_ascii=False)]
        if record_id:
            command += ['--record-id', record_id]
        result = subprocess.run(command, capture_output=True, encoding='utf-8',
                                timeout=60, check=True)
        response = json.loads(result.stdout)
        if response.get('ok') is not True:
            raise RuntimeError('remote write not acknowledged')
        data = response.get('data', {})
        ids = data.get('record', {}).get('record_id_list')
        if ids is not None:
            if not isinstance(ids, list) or len(ids) != 1:
                raise RuntimeError('ambiguous record receipt')
            receipt = ids[0]
        else:
            receipt = data.get('record_id') or data.get('record', {}).get('id')
        if record_id is not None and receipt != record_id:
            raise RuntimeError('update receipt does not match requested record')
        return receipt
    return send


def ingest_document(store, device, document):
    if not isinstance(document, dict) or not isinstance(document.get('records'), list):
        raise ValueError('expected KProSvc batch')
    session = document.get('session')
    if not isinstance(session, str) or not session:
        raise ValueError('batch session required')
    dropped = document.get('dropped')
    if type(dropped) is not int or dropped < 0:
        raise ValueError('invalid dropped count')
    if len(document['records']) > 1024:
        raise ValueError('batch exceeds 1024 records')
    records=document['records']
    if 'nativeSources' in document:
        from native_provenance import validate_source
        sources=document['nativeSources']
        if not isinstance(sources,list) or len(sources)!=len(records):
            raise ValueError('Native source count differs from event count')
        sources=[validate_source(source) for source in sources]
        if any(not isinstance(record,dict) or '_nativeSource' in record for record in records):
            raise ValueError('Ambiguous native source locator')
        records=[dict(record,_nativeSource=source) for record,source in zip(records,sources)]
    digest = hashlib.sha256(json.dumps([device, document], sort_keys=True).encode()).hexdigest()
    with store.db:
        store.db.execute('BEGIN IMMEDIATE')
        store._check_storage_budget()
        if store.db.execute('SELECT 1 FROM batches WHERE id=?', (digest,)).fetchone():
            return 0
        if store.db.execute('SELECT COUNT(*) FROM batches').fetchone()[0] >= store.max_events:
            raise RuntimeError('batch capacity reached')
        count = sum(store._ingest(device, session, e) for e in records)
        store.db.execute('INSERT OR IGNORE INTO batches VALUES (?,?,?,?)',
                         (digest, device, session, dropped))
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    ingest = sub.add_parser('ingest')
    ingest.add_argument('--device', required=True)
    ingest.add_argument('--session', help='required for bare arrays; service batches carry their session')
    ingest.add_argument('--input', required=True, help='UTF-8 JSON event array')
    sub.add_parser('export')
    sub.add_parser('status')
    sync = sub.add_parser('sync')
    sync.add_argument('--cli', required=True, help='absolute lark-cli executable path')
    sync.add_argument('--base', required=True, help='authorized destination Base token')
    sync.add_argument('--table', required=True, help='authorized destination table ID')
    sync.add_argument('--apply', action='store_true', help='explicitly publish safe summaries')
    args = parser.parse_args()
    with Store(args.database) as store:
        if args.command == 'ingest':
            with open(args.input, encoding='utf-8-sig') as stream:
                events = json.load(stream)
            if isinstance(events, dict):
                count = ingest_document(store, args.device, events)
            elif isinstance(events, list):
                count = sum(store.ingest(args.device, args.session, e) for e in events)
            else:
                raise ValueError('expected event array')
            print(json.dumps(dict(inserted=count)))
        elif args.command == 'sync' and args.apply:
            store.sync(feishu_sender(args.cli, args.base, args.table))
        elif args.command == 'status':
            print(json.dumps(store.health()))
        else:
            print(json.dumps(store.export(), ensure_ascii=True))


if __name__ == '__main__':
    main()
