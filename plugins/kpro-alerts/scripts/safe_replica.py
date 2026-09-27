"""Strict public replica parsing. Checksums are metadata, never native attestation."""
import base64
import binascii
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

SCHEMA = 'FalconProSafeReplica/v1'
MAX_REPLICA_BYTES = 12 * 1024 * 1024
MAX_SAFE_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 1024
SOURCE_STATE = 'analysis_only'
ATTESTATION = 'unverified_public_metadata'
NUMBER_FIELDS = frozenset(('eventType operation decisionMode processId policyVersion sequence '
    'correlationId processCreateTime flags actionStatus droppedCount pathLengthBytes '
    'pathOriginalLengthBytes cmdlineLengthBytes cmdlineOriginalLengthBytes processImagePathLengthBytes '
    'processImagePathOriginalLengthBytes ransomwareSignals expectedFileFormat detectedFileFormat '
    'formatConfidence renameBurstCount parentProcessId parentProcessCreateTime processClassFlags '
    'behaviorRuleId behaviorWindowMs behaviorSignals uniqueFileCount distinctDirectoryCount writeCount '
    'newFileWriteCount overwriteCount renameCount deleteCount truncateCount extensionChangeCount '
    'bytesWritten destructiveFamilyCount behaviorReserved').split())
BOOLEAN_FIELDS = frozenset(('reportOnly pathTruncated cmdlineTrusted cmdlineTruncated '
    'processImagePathTrusted processImagePathTruncated directDiskMbr directDiskMbrContentChanged '
    'directDiskMbrInspectionUnavailable directDiskMbrF1Exempt directDiskMbrHashExempt '
    'ransomwareFormatMismatch ransomwareSuspiciousRename ransomwareSuspiciousCreate '
    'ransomwareDirectCreate ransomwareRansomNote ransomwareLongFileName ransomwareHashLikeFileName '
    'ransomwareHighAnomalyFileName ransomwareDisguisedDoubleExtension ransomwareSuspiciousUnicode '
    'ransomwareElfImage ransomwareFirstObserved ransomwareRecentProcess ransomwareRenameBurst '
    'ransomwareDirectoryRecentThreat ransomwareBlocked ransomwareRiskBlocked ransomwareAuthorizedException '
    'ransomwareRecoveryDestruction ransomwareRecoveryDestructionBlocked '
    'ransomwareRecoveryDestructionAuthorized').split())


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate replica JSON field')
        result[key] = value
    return result


def _constant(_):
    raise ValueError('non-finite JSON value')


def _json(data):
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=_unique, parse_constant=_constant)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError('invalid replica JSON') from exc


def _keys(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError('invalid replica fields')


def _u64(value):
    if type(value) is not int or not 0 <= value <= 2**64 - 1:
        raise ValueError('invalid unsigned count')
    return value


def _hex(value, length):
    if type(value) is not str or len(value) != length * 2 or not re.fullmatch('[a-f0-9]+', value):
        raise ValueError('invalid canonical record hex')
    return bytes.fromhex(value)


def _header(record, kind, payload_size):
    if len(record) != 128 + payload_size:
        raise ValueError('invalid record length')
    magic, header, version, actual_kind, reserved, generation, created, device, size, digest, tail = struct.unpack(
        '<8sIIIIQQ32sQ32s16s', record[:128])
    if (magic != b'FPRTN1\0\0' or header != 128 or version != 1 or actual_kind != kind or reserved or
            any(tail) or not generation or not 0 < created <= 253402300799 or not any(device) or
            size != payload_size or hashlib.sha256(record[128:]).digest() != digest):
        raise ValueError('invalid record header or digest')
    return device.hex(), generation, created


def _identifier(field, size):
    if not 1 <= size <= 128 or any(field[size:]) or not re.fullmatch(rb'[A-Za-z0-9_.-]+', field[:size]):
        raise ValueError('invalid producer identity')
    return field[:size].decode('ascii')


@dataclass(frozen=True)
class Replica:
    source_id: str
    slot: str
    device: str
    generation: int
    created: int
    session: str
    batch: str
    prepared_hash: str
    raw_hash: str
    safe_hash: str
    helper_hash: str
    commit_id: str
    collector_dropped: int
    projection_dropped: int
    records: tuple
    record_indices: tuple
    reported_state: str = 'unknown'


def loads_replica(content):
    if type(content) is not bytes or not 0 < len(content) <= MAX_REPLICA_BYTES:
        raise ValueError('replica exceeds bounded size')
    return parse_replica(_json(content))


def parse_replica(document):
    keys = {'schema', 'preparedHex', 'commitHex', 'acceptedHex', 'safeBase64'}
    if type(document) is not dict or set(document) not in (keys, keys | {'reportedSourceState'}):
        raise ValueError('invalid replica fields')
    state = document.get('reportedSourceState', 'unknown')
    if 'reportedSourceState' in document and state != 'retired':
        raise ValueError('invalid reported source state')
    if document['schema'] != SCHEMA:
        raise ValueError('unsupported replica schema')
    prepared = _hex(document['preparedHex'], 488)
    commit = _hex(document['commitHex'], 224)
    accepted = _hex(document['acceptedHex'], 160)
    identity = _header(prepared, 4, 360)
    if _header(commit, 6, 96) != identity or _header(accepted, 7, 32) != identity:
        raise ValueError('record identity mismatch')
    raw_hash, safe_hash = prepared[128:160].hex(), prepared[160:192].hex()
    raw_size, safe_size, record_count, dropped, session_size, batch_size = struct.unpack('<QQQQII', prepared[192:232])
    if (not any(prepared[128:160]) or not any(prepared[160:192]) or
            not 0 < raw_size <= MAX_SAFE_BYTES or not 0 < safe_size <= MAX_SAFE_BYTES or
            record_count > MAX_RECORDS or (not record_count and not dropped)):
        raise ValueError('invalid prepared batch limits')
    session = _identifier(prepared[232:360], session_size)
    batch = _identifier(prepared[360:488], batch_size)
    prepared_hash, commit_id = _sha(prepared), _sha(commit)
    if (commit[128:160].hex() != prepared_hash or commit[160:192].hex() != safe_hash or
            not any(commit[192:224]) or accepted[128:160].hex() != commit_id):
        raise ValueError('replica record binding mismatch')
    encoded = document['safeBase64']
    if type(encoded) is not str or not 0 < len(encoded) <= 4 * ((MAX_SAFE_BYTES + 2) // 3):
        raise ValueError('invalid safe base64 size')
    try:
        safe_bytes = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError('invalid safe base64') from exc
    if (len(safe_bytes) != safe_size or _sha(safe_bytes) != safe_hash or
            base64.b64encode(safe_bytes).decode('ascii') != encoded):
        raise ValueError('safe representation mismatch')
    safe = _json(safe_bytes)
    _keys(safe, ('schema', 'redacted', 'session', 'batchId', 'dropped', 'projectionDropped', 'records', 'nativeSources'))
    if (safe['schema'] != 'KProSafeEventBatch/v1' or safe['redacted'] is not True or
            safe['session'] != session or safe['batchId'] != batch or _u64(safe['dropped']) != dropped):
        raise ValueError('safe batch identity mismatch')
    projected = _u64(safe['projectionDropped'])
    records, sources = safe['records'], safe['nativeSources']
    if (type(records) is not list or len(records) > MAX_RECORDS or type(sources) is not list or
            len(sources) != len(records) or len(records) + projected != record_count):
        raise ValueError('safe record accounting mismatch')
    indices, previous = [], -1
    for record, source in zip(records, sources):
        if type(record) is not dict or not {'eventType', 'operation', 'sequence'} <= set(record):
            raise ValueError('safe event fields missing')
        for key, value in record.items():
            if key in NUMBER_FIELDS:
                _u64(value)
            elif key in BOOLEAN_FIELDS:
                if type(value) is not bool:
                    raise ValueError('invalid safe boolean')
            else:
                raise ValueError('unknown safe event field')
        _keys(source, ('schema', 'batchSha256', 'recordIndex'))
        index = _u64(source['recordIndex'])
        if (source['schema'] != 'FalconProCollectorSource/v1' or source['batchSha256'] != raw_hash or
                not previous < index < record_count):
            raise ValueError('invalid safe source locator')
        previous = index
        indices.append(index)
    slot = _sha(prepared[40:72] + prepared[24:32] + prepared[224:228] + prepared[232:360] +
                prepared[228:232] + prepared[360:488])
    device, generation, created = identity
    fields = dict(device=device, generation=generation, session=session, batchId=batch, rawHash=raw_hash, safeHash=safe_hash)
    source_id = _sha(json.dumps(fields, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii'))
    return Replica(source_id, slot, device, generation, created, session, batch, prepared_hash, raw_hash, safe_hash,
                   commit[192:224].hex(), commit_id, dropped, projected, tuple(records), tuple(indices), state)


def read_bounded(path):
    """Capture one regular, single-link public file without following reparse paths."""
    path = Path(path).absolute()
    handles = []
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        class FileInfo(ctypes.Structure):
            _fields_ = [('attributes', wintypes.DWORD), ('created', wintypes.FILETIME),
                        ('accessed', wintypes.FILETIME), ('written', wintypes.FILETIME),
                        ('volume', wintypes.DWORD), ('sizeHigh', wintypes.DWORD), ('sizeLow', wintypes.DWORD),
                        ('links', wintypes.DWORD), ('indexHigh', wintypes.DWORD), ('indexLow', wintypes.DWORD)]
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                      wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.GetFileInformationByHandle.argtypes = (wintypes.HANDLE, ctypes.POINTER(FileInfo))
        kernel.GetFileInformationByHandle.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        try:
            for item in (*reversed(path.parents), path):
                directory = item != path
                handle = kernel.CreateFileW(str(item), 0x80 if directory else 0x80000000, 1, None, 3,
                                            0x00200000 | (0x02000000 if directory else 0), None)
                if handle == ctypes.c_void_p(-1).value:
                    raise ValueError('replica path could not be pinned')
                handles.append(handle)
                info = FileInfo()
                if (not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)) or info.attributes & 0x400 or
                        bool(info.attributes & 0x10) != directory or
                        (not directory and (info.links != 1 or not 0 < (info.sizeHigh << 32 | info.sizeLow) <= MAX_REPLICA_BYTES))):
                    raise ValueError('invalid replica file type or size')
            with path.open('rb') as stream:
                content = stream.read(MAX_REPLICA_BYTES + 1)
        finally:
            for handle in reversed(handles):
                kernel.CloseHandle(handle)
    else:
        try:
            parent = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            handles.append(parent)
            for part in path.parts[1:-1]:
                parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                handles.append(parent)
            file = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            handles.append(file)
            before = os.fstat(file)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= MAX_REPLICA_BYTES:
                raise ValueError('invalid replica file type or size')
            with os.fdopen(os.dup(file), 'rb') as stream:
                content = stream.read(MAX_REPLICA_BYTES + 1)
            after = os.fstat(file)
            if (before.st_size, before.st_mtime_ns, before.st_nlink) != (after.st_size, after.st_mtime_ns, after.st_nlink):
                raise ValueError('replica changed during capture')
        finally:
            for handle in reversed(handles):
                os.close(handle)
    if not 0 < len(content) <= MAX_REPLICA_BYTES:
        raise ValueError('replica exceeds bounded size')
    return content


def source_for_event(db, event_id):
    """A locator only. Old databases/rows never acquire fabricated provenance."""
    from native_provenance import validate_source
    legacy = db.execute('SELECT raw FROM events WHERE id=?', (event_id,)).fetchone()
    if legacy:
        if not isinstance(legacy[0], str) or len(legacy[0].encode('utf-8')) > 65536:
            raise ValueError('invalid stored event size')
        event = json.loads(legacy[0])
        if isinstance(event, dict) and '_nativeSource' in event:
            return validate_source(event['_nativeSource'])
    present = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('batch_sources','event_batches')").fetchall()
    if len(present) != 2:
        return None
    row = db.execute('''SELECT s.raw_hash,e.record_index FROM event_batches e
        JOIN batch_sources s ON s.source_id=e.source_id WHERE e.event_id=? ORDER BY e.rowid LIMIT 1''', (event_id,)).fetchone()
    if row is None:
        return None
    return validate_source(dict(schema='FalconProCollectorSource/v1', batchSha256=row[0], recordIndex=row[1]))


def reported_source_states(db, event_ids):
    """Advisory state for the selected locator. Never authorizes source access."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='source_lifecycle'").fetchone():
        return {}
    result = {}
    for event_id in event_ids:
        locator = source_for_event(db, event_id)
        if locator is None:
            continue
        row = db.execute('''SELECT l.reported_state FROM event_batches e
            JOIN batch_sources s ON s.source_id=e.source_id
            LEFT JOIN source_lifecycle l ON l.source_id=s.source_id
            WHERE e.event_id=? AND s.raw_hash=? AND e.record_index=?
            ORDER BY e.rowid LIMIT 1''',
            (event_id, locator['batchSha256'], locator['recordIndex'])).fetchone()
        if row and row[0] is not None:
            if row[0] != 'retired':
                raise ValueError('invalid stored reported source state')
            result[event_id] = 'retired'
    return result


def reported_dropped(db):
    loss = sum(int(row[0]) for row in db.execute('SELECT dropped FROM batches'))
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='batch_sources'").fetchone():
        # One source per producer, irrespective of helper/commit versions.
        loss += sum(int(row[0]) + int(row[1]) for row in db.execute(
            'SELECT collector_dropped,projection_dropped FROM batch_sources'))
    return loss
