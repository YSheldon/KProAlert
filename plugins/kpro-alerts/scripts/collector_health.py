"""Read a bounded local collector status receipt, not proof of driver enforcement."""
import json
from pathlib import Path
import time


def read_health(path):
    source = Path(path)
    if source.is_symlink() or source.stat().st_size > 4096:
        raise ValueError('invalid health receipt')
    data = json.loads(source.read_text(encoding='utf-8'))
    if data.get('schema') != 'KProCollectorHealth/v1':
        raise ValueError('unknown health schema')
    result = {}
    for key in ('pid', 'tick', 'status', 'pendingEvents', 'collectorDropped', 'writtenBatches'):
        value = data.get(key)
        if type(value) is not int:
            raise ValueError('invalid health field')
        result[key] = value
    if type(data.get('stopped')) is not bool:
        raise ValueError('invalid stopped field')
    age = time.time() - source.stat().st_mtime
    result.update(stopped=data['stopped'], receiptAgeSeconds=max(0, round(age)),
                  receiptFresh=0 <= age <= 90, protectionStatus='not_probed',
                  kernelLossStatus='not_probed')
    return result
