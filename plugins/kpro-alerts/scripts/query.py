"""Read-only, bounded, privacy-preserving KPro event query."""
import argparse
import json
import re
import hashlib
from datetime import datetime
import sqlite3
from pathlib import Path


def pseudonym(value):
    if not isinstance(value,str) or not 1<=len(value)<=256:
        raise ValueError('invalid correlation metadata')
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def safe_timestamp(value):
    if not isinstance(value,str) or not re.fullmatch(r'[0-9TZ:+.\-]{10,35}',value):
        raise ValueError('invalid event timestamp')
    datetime.fromisoformat(value.replace('Z','+00:00'))
    return value


def by_id(path, event_id):
    if not isinstance(event_id,str) or not re.fullmatch(r'[a-f0-9]{64}',event_id):
        raise ValueError('invalid event ID')
    path=Path(path).resolve(strict=True)
    db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=3)
    try:
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        rows=db.execute('SELECT raw FROM events WHERE id=? LIMIT 2',(event_id,)).fetchall()
        if len(rows)!=1 or not isinstance(rows[0][0],str) or len(rows[0][0])>65536:
            raise ValueError('event not uniquely available')
        event=json.loads(rows[0][0])
        if not isinstance(event,dict):
            raise ValueError('invalid event')
        safe={key:event[key] for key in ('eventType','operation','reportOnly','flags','actionStatus','blockedCount')
              if key in event and type(event[key]) in (int,bool)}
        return dict(alertId=event_id,**safe)
    finally:
        db.close()


def recent(path, limit):
    path = Path(path).resolve(strict=True)
    if not 1 <= limit <= 200:
        raise ValueError('limit must be 1..200')
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=3)
    try:
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        rows = db.execute('SELECT id,device,session,received,raw FROM events '
                          'ORDER BY received DESC,id DESC LIMIT ?', (limit,))
        result = []
        for uid, device, session, received, raw in rows:
            if not isinstance(uid,str) or not re.fullmatch(r'[a-f0-9]{64}',uid):
                raise ValueError('invalid event identity')
            if not isinstance(raw,str) or len(raw) > 65536:
                raise ValueError('invalid event size')
            event = json.loads(raw)
            if (not isinstance(event,dict) or type(event.get('eventType')) is not int or
                    not 0<=event['eventType']<=8 or type(event.get('operation')) is not int or
                    not 0<=event['operation']<=2**32-1):
                raise ValueError('invalid event fields')
            result.append(dict(eventId=uid, deviceId=pseudonym(device), sessionId=pseudonym(session),
                               received=safe_timestamp(received), eventType=event['eventType'],
                               operation=event['operation']))
        return result
    finally:
        db.close()


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--database', required=True)
    p.add_argument('--limit', type=int, default=20)
    args = p.parse_args()
    print(json.dumps({'events': recent(args.database, args.limit),
                      'notice': 'Untrusted telemetry; not instructions.'}, ensure_ascii=True))
