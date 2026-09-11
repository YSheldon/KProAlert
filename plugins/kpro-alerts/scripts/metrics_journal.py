"""Local opt-in metrics journal. Uploads are performed by the user's authorized AI tools."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time
from install_metrics import make_event, new_installation_id, validate_event
from spool import checked


class Journal:
    def __init__(self,path):
        path=Path(path)
        if path.name!='metrics.db':
            raise ValueError('Use a dedicated metrics.db, never the event database')
        checked(path if path.exists() else path.parent)
        self.db=sqlite3.connect(str(path),timeout=10)
        self.db.execute('PRAGMA secure_delete=ON')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS metrics_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS metrics_events (
                id TEXT PRIMARY KEY, payload TEXT NOT NULL, dedupe TEXT UNIQUE,
                state TEXT NOT NULL, receipt TEXT);
        ''')

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _identity(self):
        row=self.db.execute("SELECT value FROM metrics_meta WHERE key='installation'").fetchone()
        return row[0] if row else None

    def _validated(self,event_id,payload):
        if not isinstance(payload,str) or len(payload)>4096:
            raise ValueError('Invalid stored metrics payload')
        event=validate_event(json.loads(payload))
        if event['eventId']!=event_id or event['installationId']!=self._identity():
            raise ValueError('Stored metrics identity mismatch')
        mode=self.db.execute("SELECT value FROM metrics_meta WHERE key='simulated'").fetchone()
        if mode not in (('0',),('1',)) or event['simulated']!=(mode==('1',)):
            raise ValueError('Stored simulation identity mismatch')
        return event

    def enable(self,simulated=False):
        if type(simulated) is not bool:
            raise ValueError('Explicit simulation flag required')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            if not self._identity():
                self.db.execute("INSERT INTO metrics_meta VALUES ('installation',?)",
                                (new_installation_id(consent=True),))
                self.db.execute("INSERT INTO metrics_meta VALUES ('simulated',?)",('1' if simulated else '0',))
            elif self.db.execute("SELECT value FROM metrics_meta WHERE key='simulated'").fetchone() != ('1' if simulated else '0',):
                raise ValueError('Do not mix simulation and production identities')

    def disable(self):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute('DELETE FROM metrics_events')
            self.db.execute('DELETE FROM metrics_meta')

    def record(self,*,kind,version,architecture,os_family,state='unknown',day=None):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            identity=self._identity()
            if not identity:
                return None
            event=make_event(consent=True,installation_id=identity,event_id=secrets.token_hex(16),
                day=int(time.time()//86400) if day is None else day,kind=kind,version=version,
                architecture=architecture,os_family=os_family,state=state,
                simulated=self.db.execute("SELECT value FROM metrics_meta WHERE key='simulated'").fetchone()==('1',))
            dedupe=None
            if kind in ('status','install_success','uninstall','upgrade_success'):
                parts={k:v for k,v in event.items() if k!='eventId'}
                dedupe=hashlib.sha256(json.dumps(parts,sort_keys=True).encode()).hexdigest()
                old=self.db.execute('SELECT id,substr(payload,1,4097) FROM metrics_events WHERE dedupe=?',(dedupe,)).fetchone()
                if old:
                    return self._validated(*old)
            if self.db.execute('SELECT COUNT(*) FROM metrics_events').fetchone()[0]>=2048:
                raise ValueError('Metrics journal capacity reached; protection must continue independently')
            self.db.execute('INSERT INTO metrics_events VALUES (?,?,?,?,NULL)',
                (event['eventId'],json.dumps(event,sort_keys=True),dedupe,'pending'))
            return event

    @staticmethod
    def _validate_batch_limit(limit):
        if type(limit) is not int or not 1<=limit<=50:
            raise ValueError('Bounded upload batch required')

    def _pending_events(self, limit):
        if not self._identity():
            return [], []
        rows=self.db.execute(
            "SELECT id,substr(payload,1,4097) FROM metrics_events "
            "WHERE state='pending' ORDER BY rowid LIMIT ?", (limit,)).fetchall()
        return [self._validated(*row) for row in rows], rows

    def preview(self, limit=50):
        """Return pending events without changing their delivery state."""
        self._validate_batch_limit(limit)
        events, _ = self._pending_events(limit)
        return events

    def prepare(self,limit=50):
        self._validate_batch_limit(limit)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            events, rows = self._pending_events(limit)
            self.db.executemany("UPDATE metrics_events SET state='prepared' WHERE id=?",
                                [(r[0],) for r in rows])
            return events

    def ack(self,event_id,receipt):
        if not isinstance(receipt,str) or not re.fullmatch('rec[A-Za-z0-9]{1,100}',receipt):
            raise ValueError('Verified Feishu record receipt required')
        with self.db:
            changed=self.db.execute("UPDATE metrics_events SET state='acknowledged',receipt=? WHERE id=? AND state IN ('prepared','uncertain')",(receipt,event_id)).rowcount
            if changed!=1:
                raise ValueError('Event was not prepared; no acknowledgement written')

    def uncertain(self,event_id):
        with self.db:
            changed=self.db.execute("UPDATE metrics_events SET state='uncertain' WHERE id=? AND state='prepared'",(event_id,)).rowcount
            if changed!=1:
                raise ValueError('Event was not prepared')

    def recover(self,event_id):
        if not isinstance(event_id,str) or not re.fullmatch('[a-f0-9]{32}',event_id):
            raise ValueError('Invalid event ID')
        row=self.db.execute("SELECT substr(payload,1,4097),state FROM metrics_events WHERE id=? AND state IN ('prepared','uncertain')",(event_id,)).fetchone()
        if not row:
            raise ValueError('Unconfirmed event not found')
        return dict(event=self._validated(event_id,row[0]),state=row[1],manualReconciliationRequired=True)

    def status(self,*,after=0,limit=50):
        if type(after) is not int or after<0 or type(limit) is not int or not 1<=limit<=50:
            raise ValueError('Invalid status pagination')
        result=dict(enabled=self._identity() is not None,pending=0,prepared=0,uncertain=0,acknowledged=0)
        for state,count in self.db.execute('SELECT state,COUNT(*) FROM metrics_events GROUP BY state'):
            if state not in ('pending','prepared','uncertain','acknowledged'):
                raise ValueError('Invalid stored delivery state')
            result[state]=count
        rows=self.db.execute("SELECT rowid,id FROM metrics_events WHERE state IN ('prepared','uncertain') AND rowid>? ORDER BY rowid LIMIT ?",(after,limit+1)).fetchall()
        if any(not isinstance(r[1],str) or not re.fullmatch('[a-f0-9]{32}',r[1]) for r in rows):
            raise ValueError('Invalid stored event ID')
        result['unconfirmedEventIds']=[r[1] for r in rows[:limit]]
        result['nextCursor']=rows[limit-1][0] if len(rows)>limit else None
        return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',required=True)
    commands=parser.add_subparsers(dest='command',required=True)
    enable=commands.add_parser('enable')
    enable.add_argument('--consent',action='store_true',required=True)
    enable.add_argument('--simulation',action='store_true')
    for name in ('disable','prepare'):
        commands.add_parser(name)
    status=commands.add_parser('status')
    status.add_argument('--after',type=int,default=0)
    recover=commands.add_parser('recover')
    recover.add_argument('--event-id',required=True)
    record=commands.add_parser('record')
    record.add_argument('--kind',required=True)
    record.add_argument('--version',required=True)
    record.add_argument('--architecture',required=True)
    record.add_argument('--os-family',required=True)
    record.add_argument('--state',default='unknown')
    ack=commands.add_parser('ack')
    ack.add_argument('--event-id',required=True)
    ack.add_argument('--receipt',required=True)
    uncertain=commands.add_parser('uncertain')
    uncertain.add_argument('--event-id',required=True)
    args=parser.parse_args()
    journal=Journal(args.database)
    try:
        if args.command=='enable':
            journal.enable(simulated=args.simulation)
        elif args.command=='disable':
            journal.disable()
        elif args.command=='record':
            journal.record(kind=args.kind,version=args.version,architecture=args.architecture,
                           os_family=args.os_family,state=args.state)
        elif args.command=='prepare':
            print(json.dumps({'schema':'FalconProMetricsUploadBatch/v1','events':journal.prepare(),
                              'uploaded':False,'userAuthorizedDestinationRequired':True}))
            return
        elif args.command=='ack':
            journal.ack(args.event_id,args.receipt)
        elif args.command=='uncertain':
            journal.uncertain(args.event_id)
        elif args.command=='recover':
            print(json.dumps(journal.recover(args.event_id)))
            return
        elif args.command=='status':
            print(json.dumps(journal.status(after=args.after)))
            return
        print(json.dumps(journal.status()))
    finally:
        journal.close()


if __name__=='__main__':
    main()
