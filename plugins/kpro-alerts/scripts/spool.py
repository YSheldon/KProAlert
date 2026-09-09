"""Bounded safe-batch importer; files move only after a durable database commit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sqlite3
import time
from kpro_alert_bridge import Store, ingest_document, feishu_sender

MAX_BATCH_BYTES = 5 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024


def validate_safe_batch(document):
    if (not isinstance(document, dict) or
            document.get('schema') != 'KProSafeEventBatch/v1' or
            document.get('redacted') is not True):
        raise ValueError('redacted service batch required')
    if set(document) - {'schema','redacted','session','batchId','dropped','projectionDropped','records'}:
        raise ValueError('unknown batch field')
    for name in ('session','batchId'):
        value=document.get(name,'')
        if not isinstance(value,str) or len(value)>128 or any(not(c.isascii() and (c.isalnum() or c in '-_.')) for c in value):
            raise ValueError('invalid batch identity')
    for name in ('dropped','projectionDropped'):
        value=document.get(name,0)
        if type(value) is not int or not 0<=value<=2**64-1:
            raise ValueError('invalid loss count')
    records=document.get('records')
    if not isinstance(records,list):
        raise ValueError('safe records required')
    for record in records:
        if not isinstance(record,dict) or any(
                not key.isascii() or not key.isalnum() or len(key)>80 or
                type(value) not in (int,bool) or
                (type(value) is int and not 0<=value<=2**64-1)
                for key,value in record.items()):
            raise ValueError('safe records must contain numeric or boolean fields only')


def checked(path):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('reparse/symlink paths are not supported')
    return path


def consume(store, spool_path, device, archive=False):
    root = checked(spool_path)
    if not root.is_dir():
        raise ValueError('spool must be a directory')
    result = dict(importedFiles=0, failedFiles=0, importedEvents=0, errors=[])
    # Bound enumeration as well as parsing. The producer must enforce its own quota.
    import heapq
    count = 0
    def candidates():
        nonlocal count
        with os.scandir(root) as entries:
            for entry in entries:
                if entry.name.endswith('.json'):
                    count += 1
                    if count > 10000:
                        raise RuntimeError('spool exceeds supported directory capacity')
                    yield Path(entry.path)
    files = heapq.nsmallest(256, candidates(), key=lambda p: p.name)
    result['hasMoreFiles'] = count > len(files)
    for path in sorted(files):
        try:
            checked(path)
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_BATCH_BYTES:
                raise ValueError('invalid batch size/type')
            with path.open('rb') as stream:
                content = stream.read(MAX_BATCH_BYTES + 1)
            if len(content) > MAX_BATCH_BYTES:
                raise ValueError('batch too large')
            digest = hashlib.sha256(content).hexdigest()
            document = json.loads(content.decode('utf-8-sig'))
            validate_safe_batch(document)
            document['dropped'] = document.get('dropped',0) + document.get('projectionDropped',0)
            # Producer file identity distinguishes equal empty loss-only batches.
            document = dict(document, batchId=path.name)
            target = None
            if archive:
                folder = root/'archive'
                folder.mkdir(exist_ok=True)
                checked(folder)
                size, count = 0, 0
                with os.scandir(folder) as archived:
                    for entry in archived:
                        size += entry.stat(follow_symlinks=False).st_size
                        count += 1
                        if count > 10000 or size + len(content) > MAX_ARCHIVE_BYTES:
                            raise RuntimeError('archive quota reached')
                target = folder/(digest + '-' + path.name)
                if target.exists():
                    raise RuntimeError('archive collision; reconcile rather than overwrite')
            result['importedEvents'] += ingest_document(store, device, document)
            if target:
                after = path.stat()
                if (after.st_size, after.st_mtime_ns, after.st_ino) != (info.st_size, info.st_mtime_ns, info.st_ino):
                    raise RuntimeError('batch changed after import')
                path.rename(target)
            result['importedFiles'] += 1
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            result['failedFiles'] += 1
            result['errors'].append(type(exc).__name__)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--database', required=True)
    p.add_argument('--spool', required=True)
    p.add_argument('--device', required=True)
    p.add_argument('--archive', action='store_true', help='move committed batches under spool/archive; never delete')
    p.add_argument('--watch', action='store_true', help='run until interrupted; no system task installed')
    p.add_argument('--interval', type=int, default=10)
    p.add_argument('--publish', action='store_true')
    p.add_argument('--cli')
    p.add_argument('--base')
    p.add_argument('--table')
    args = p.parse_args()
    if not 5 <= args.interval <= 3600:
        p.error('interval must be 5..3600 seconds')
    if args.publish and not all((args.cli, args.base, args.table)):
        p.error('publication requires explicit cli, base and table')
    with Store(args.database) as store:
        while True:
            try:
                result = consume(store, args.spool, args.device, args.archive)
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
                result = dict(importerStatus='blocked', importerError=type(exc).__name__)
            if args.publish:
                try:
                    store.sync(feishu_sender(args.cli, args.base, args.table))
                    result['sync'] = 'acknowledged'
                except Exception as exc:
                    result['sync'] = 'not_completed'
                    result['syncError'] = type(exc).__name__
            result['health'] = store.health()
            print(json.dumps(result), flush=True)
            if not args.watch:
                break
            time.sleep(args.interval)


if __name__ == '__main__':
    main()
