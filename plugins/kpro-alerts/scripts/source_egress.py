"""Strict metadata-only source-egress projection; no execution authority."""
import re
import json
import subprocess
import os
import time
from metrics_upload import _resolve_cli
from native_receipt_reader import _unique

_KINDS = {
    'historical_baseline': ('filesystem_observation', {'observedPackageCount'}),
    'package_observed': ('filesystem_observation', {'encryptedSizeBytes'}),
    'pending_retry_observed': ('application_claim', {'retryCount'}),
    'application_acceptance_claim': ('application_claim', {
        'extraMetadataChanged', 'reportedIncludedFileCount', 'reportedWorkspaceSizeBytes'}),
    'state_reset_observed': ('application_claim', set()),
    'observer_coverage_gap': ('coverage_gap', set()),
}
_REQUIRED = {'schema', 'recordId', 'workspaceId', 'source', 'kind', 'evidenceLevel',
             'observedAtUnixMs', 'simulated', 'historical', 'networkUploadConfirmed', 'coverageStatus'}


def project(record):
    if not isinstance(record, dict) or not isinstance(record.get('kind'), str):
        raise ValueError('Invalid source-egress record')
    kind = record['kind']
    if kind not in _KINDS:
        raise ValueError('Unsupported source-egress kind')
    evidence, optional = _KINDS[kind]
    if not _REQUIRED <= record.keys() or record.keys() - (_REQUIRED | optional):
        raise ValueError('Unexpected source-egress fields')
    if (record['schema'] != 'FalconProSourceEgressObservation/v1' or
            record['source'] != 'zcode_checkpoints' or record['evidenceLevel'] != evidence or
            record['coverageStatus'] != ('gap' if kind == 'observer_coverage_gap' else 'bounded_observation')):
        raise ValueError('Source-egress provenance mismatch')
    for key in ('recordId', 'workspaceId'):
        if not isinstance(record[key], str) or not re.fullmatch('[a-f0-9]{64}', record[key]):
            raise ValueError('Invalid source-egress identity')
    for key in ('simulated', 'historical', 'networkUploadConfirmed'):
        if type(record[key]) is not bool:
            raise ValueError('Invalid source-egress flag')
    if record['networkUploadConfirmed'] or record['historical'] != (kind == 'historical_baseline'):
        raise ValueError('Unsupported source-egress claim')
    for key in {'observedAtUnixMs'} | (optional & record.keys() - {'extraMetadataChanged'}):
        if type(record[key]) is not int or not 0 <= record[key] <= 0x7fffffffffffffff:
            raise ValueError('Invalid bounded source-egress count')
    if kind == 'application_acceptance_claim' and type(record.get('extraMetadataChanged')) is not bool:
        raise ValueError('Missing source-egress metadata flag')
    return dict(record)


def _bounded_cli(args, *, timeout=30, max_bytes=8*1024*1024, **unused):
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, bufsize=0)
    deadline = time.monotonic() + timeout
    raw = bytearray()
    try:
        if os.name == 'nt':
            import ctypes
            import msvcrt
            from ctypes import wintypes
            peek = ctypes.WinDLL('kernel32', use_last_error=True).PeekNamedPipe
            peek.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                             ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
            peek.restype = wintypes.BOOL
            handle = msvcrt.get_osfhandle(process.stdout.fileno())
        else:
            import select
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(args, timeout)
            count = min(65536, max_bytes + 1 - len(raw))
            if os.name == 'nt':
                available = wintypes.DWORD()
                if not peek(handle, None, 0, None, ctypes.byref(available), None):
                    error = ctypes.get_last_error()
                    if error == 109:  # All writers closed the pipe.
                        break
                    raise OSError(error, 'CLI pipe inspection failed')
                if not available.value:
                    time.sleep(min(0.01, remaining))
                    continue
                count = min(count, available.value)
            elif not select.select([process.stdout], [], [], remaining)[0]:
                raise subprocess.TimeoutExpired(args, timeout)
            chunk = os.read(process.stdout.fileno(), count)
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > max_bytes:
                raise ValueError('Source-egress CLI output exceeds limit')
        process.wait(timeout=max(0, deadline - time.monotonic()))
        return subprocess.CompletedProcess(args, process.returncode, raw.decode('utf-8'))
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def read(cli, base, table, limit=20, offset=0, *, runner=_bounded_cli):
    if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= 1000000:
        raise ValueError('Invalid source-egress page size')
    if any(not isinstance(v, str) or not re.fullmatch('[A-Za-z0-9]{1,128}', v) for v in (base, table)):
        raise ValueError('Explicit source-egress table required')
    args = [_resolve_cli(cli), 'base', '+record-list', '--base-token', base,
            '--table-id', table, '--limit', str(limit), '--offset', str(offset), '--format', 'json', '--as', 'user']
    fields = ('recordId', 'observationJson', 'simulated')
    for field in fields: args += ['--field-id', field]
    response = runner(args, capture_output=True, encoding='utf-8', timeout=30)
    if response.returncode or len(response.stdout) > 8*1024*1024:
        raise ValueError('Source-egress query failed')
    envelope = json.loads(response.stdout, object_pairs_hook=_unique)
    data = envelope.get('data') if isinstance(envelope, dict) else None
    if (not isinstance(envelope, dict) or envelope.get('ok') is not True or not isinstance(data, dict) or
            not isinstance(data.get('fields'), list) or len(data['fields']) != 3 or
            set(data['fields']) != set(fields) or not isinstance(data.get('data'), list) or
            len(data['data']) > limit or type(data.get('has_more')) is not bool):
        raise ValueError('Unexpected source-egress table response')
    records = []; seen = set()
    for row in data['data']:
        if not isinstance(row, list) or len(row) != 3: raise ValueError('Invalid source-egress row')
        cells = dict(zip(data['fields'], row))
        raw = cells['observationJson']
        if not isinstance(raw, str) or len(raw.encode('utf-8')) > 65536:
            raise ValueError('Invalid source-egress payload')
        record = project(json.loads(raw, object_pairs_hook=_unique))
        if (cells['recordId'] != record['recordId'] or type(cells['simulated']) is not bool or
                cells['simulated'] != record['simulated'] or record['recordId'] in seen):
            raise ValueError('Source-egress row identity mismatch')
        seen.add(record['recordId']); records.append(record)
    if data['has_more'] and not records: raise ValueError('Source-egress pagination made no progress')
    return dict(records=records, hasMore=data['has_more'], nextOffset=offset+len(records) if data['has_more'] else None,
                scope='bounded page, not full statistics; not a snapshot',
                trust='cloud_stored_claim_not_device_attested', actionExecutionAvailable=False)
