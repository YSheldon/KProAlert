"""User-session delivery worker. No listener, elevation, keys, or remediation."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import time

from kpro_alert_bridge import Store, feishu_sender
from spool import checked, consume


def validate_config(value):
    required = {'schema', 'database', 'spool', 'device', 'interval', 'health', 'publish'}
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - {'cli', 'base', 'table'}:
        raise ValueError('unexpected delivery configuration')
    if value['schema'] != 'KProDelivery/v1' or type(value['publish']) is not bool:
        raise ValueError('invalid delivery schema')
    if type(value['interval']) is not int or not 5 <= value['interval'] <= 3600:
        raise ValueError('interval must be 5..3600 seconds')
    if not isinstance(value['device'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value['device']):
        raise ValueError('invalid pseudonymous device ID')
    for name in ('database', 'spool', 'health'):
        if not isinstance(value[name], str) or not Path(value[name]).is_absolute():
            raise ValueError('absolute local paths required')
        path = Path(value[name])
        checked(path if path.exists() else path.parent)
    database, health = Path(value['database']), Path(value['health'])
    if database.name != 'events.db' or health.name != 'delivery-health.json' or database.parent != health.parent:
        raise ValueError('fixed database and health filenames required')
    spool = Path(value['spool'])
    if database.parent == spool or spool in database.parent.parents:
        raise ValueError('delivery state must be outside the producer spool')
    if not Path(value['spool']).is_dir():
        raise ValueError('spool directory is unavailable')
    if value['publish']:
        for name in ('base', 'table'):
            if not isinstance(value.get(name), str) or not re.fullmatch(r'[A-Za-z0-9]{1,128}', value[name]):
                raise ValueError('explicit cloud destination required')
        cli = value.get('cli')
        if not isinstance(cli, str) or not Path(cli).is_absolute() or not checked(cli).is_file():
            raise ValueError('absolute authorized CLI required')
    return dict(value)


class WorkerLock:
    def __init__(self, path):
        self.path = Path(path)
        self.file = None

    def __enter__(self):
        checked(self.path if self.path.exists() else self.path.parent)
        self.file = self.path.open('a+b')
        if self.path.stat().st_size == 0:
            self.file.write(b'0')
            self.file.flush()
        self.file.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.file.close()
            raise RuntimeError('another delivery worker owns this database') from exc
        return self

    def __exit__(self, *args):
        if os.name == 'nt':
            import msvcrt
            self.file.seek(0)
            msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
        self.file.close()


def run_once(config, publish=True):
    with Store(config['database']) as store:
        result = consume(store, config['spool'], config['device'], archive=True)
        result['sync'] = 'disabled' if not config['publish'] else 'unchanged'
        if config['publish'] and (publish or result['importedEvents']):
            try:
                result['syncMore'] = store.sync(feishu_sender(config['cli'], config['base'], config['table']), max_deliveries=1)
                result['sync'] = 'acknowledged'
            except Exception as exc:
                result.update(sync='not_completed', syncError=type(exc).__name__)
        result['health'] = store.health()
        return result


def write_health(path, value):
    path = Path(path)
    checked(path.parent)
    temporary = path.with_name(path.name + '.tmp')
    if temporary.exists():
        checked(temporary)
    data = json.dumps(value, ensure_ascii=True, allow_nan=False).encode('utf-8')
    if len(data) > 8192:
        raise ValueError('health receipt exceeds limit')
    with temporary.open('wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def run_worker(config, max_cycles=None, sleep=time.sleep):
    config = validate_config(config)
    needs_sync, cycle, exit_code = True, 0, 0
    with WorkerLock(config['database'] + '.lock'):
        while max_cycles is None or cycle < max_cycles:
            cycle += 1
            try:
                result = run_once(config, publish=needs_sync)
                needs_sync = result['sync'] == 'not_completed' or result.get('syncMore', False)
                attention = bool(result['failedFiles'] or result['sync'] == 'not_completed' or result['health']['reportedDropped'])
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
                result, attention = {'error': type(exc).__name__}, True
            exit_code = 1 if attention else 0
            receipt = dict(schema='KProDeliveryHealth/v1', utc=datetime.now(timezone.utc).isoformat(),
                           pid=os.getpid(), cycle=cycle, status='attention_required' if attention else 'ready',
                           result=result, automaticRemediation=False)
            write_health(config['health'], receipt)
            if max_cycles is None or cycle < max_cycles:
                sleep(config['interval'])
    return exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    path = checked(args.config)
    if path.stat().st_size > 16384:
        raise ValueError('configuration too large')
    config = json.loads(path.read_text(encoding='utf-8-sig'))
    if path.name != 'delivery.json' or path.parent != Path(config['database']).parent:
        raise ValueError('configuration must be delivery.json beside the database')
    return run_worker(config, max_cycles=1 if args.once else None)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, sqlite3.Error):
        # pythonw has no console. Configuration and persistent health remain local.
        raise SystemExit(1)
