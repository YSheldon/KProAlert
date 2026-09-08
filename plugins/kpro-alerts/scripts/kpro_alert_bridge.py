"""Event outbox. Export is allowlisted; raw evidence stays local."""
import argparse
import hashlib
import json
import sqlite3
import subprocess
from datetime import datetime, timezone


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, timeout=10)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('''CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, device TEXT, session TEXT,
            received TEXT, raw TEXT NOT NULL)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS deliveries (
            id TEXT PRIMARY KEY, state TEXT, record_id TEXT, payload TEXT)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS batches (
            id TEXT PRIMARY KEY, device TEXT, session TEXT, dropped INTEGER)''')

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.db.close()

    def ingest(self, device, session, event):
        if not device or not session or not isinstance(event, dict):
            raise ValueError('device, driver session and event object required')
        for key in ('eventType', 'operation', 'sequence'):
            if type(event.get(key)) is not int or event[key] < 0:
                raise ValueError('invalid ' + key)
        if event['eventType'] > 8:
            raise ValueError('unsupported event type')
        raw = json.dumps(event, ensure_ascii=False, sort_keys=True)
        if len(raw.encode('utf-8')) > 65536:
            raise ValueError('event exceeds 64 KiB')
        identity = json.dumps([device, session, event['sequence']])
        uid = hashlib.sha256(identity.encode()).hexdigest()
        with self.db:
            old = self.db.execute('SELECT raw FROM events WHERE id=?', (uid,)).fetchone()
            if old:
                if old[0] != raw:
                    raise ValueError('sequence collision: use a new driver session ID')
                return False
            self.db.execute('INSERT INTO events VALUES (?,?,?,?,?)',
                            (uid, device, session, datetime.now(timezone.utc).isoformat(), raw))
        return True

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

    def sync(self, sender):
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
                record_id = previous[1] if previous else None
                self.db.execute('INSERT OR REPLACE INTO deliveries VALUES (?,?,?,?)',
                                (uid, 'pending', record_id, payload))
            receipt = sender(alert, record_id)
            if not isinstance(receipt, str) or not receipt.startswith('rec'):
                raise RuntimeError('missing remote record receipt')
            with self.db:
                self.db.execute('UPDATE deliveries SET state=?,record_id=? WHERE id=?',
                                ('acknowledged', receipt, uid))


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
        return data.get('record_id') or data.get('record', {}).get('id')
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
    count = sum(store.ingest(device, session, e) for e in document['records'])
    digest = hashlib.sha256(json.dumps([device, document], sort_keys=True).encode()).hexdigest()
    with store.db:
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
        else:
            print(json.dumps(store.export(), ensure_ascii=True))


if __name__ == '__main__':
    main()
