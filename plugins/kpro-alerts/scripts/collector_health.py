"""Read a bounded local collector status receipt, not proof of driver enforcement."""
import json
from pathlib import Path
import time


def _native_health(data):
    if type(data) is not dict:
        raise ValueError('invalid native health')
    result = {}
    for key in ('phase', 'status', 'indexMissing', 'indexInvalid', 'producerBudget',
                'completedPasses', 'examinedThisPass', 'deferredThisPass',
                'copiesThisPass', 'replicasThisPass', 'terminalAcceptedThisPass',
                'unresolvedReferencesThisPass'):
        value = data.get(key)
        low, high = (-(1 << 31), (1 << 31) - 1) if key == 'status' else (0, (1 << 64) - 1)
        if type(value) is not int or not low <= value <= high:
            raise ValueError('invalid native health number')
        result[key] = value
    phases = ('idle', 'launch_pending', 'consumer_running', 'reconciling', 'stopped')
    if result['phase'] >= len(phases) or result['producerBudget'] > 5:
        raise ValueError('invalid native health state')
    for key in ('indexInitialized', 'childPending', 'retirementEnabled', 'notificationDeliveryVerified'):
        value = data.get(key)
        if type(value) is not bool:
            raise ValueError('invalid native health flag')
        output_key = {'retirementEnabled': 'reportedRetirementEnabled',
                      'notificationDeliveryVerified': 'reportedNotificationDeliveryVerified'}.get(key, key)
        result[output_key] = value
    generation = data.get('generation')
    if (type(generation) is not str or not generation.isascii() or not generation.isdecimal()
            or len(generation) > 20 or int(generation) >= 1 << 64
            or str(int(generation)) != generation or (result['indexInitialized'] and generation == '0')):
        raise ValueError('invalid native health generation')
    result.update(generation=generation, phaseName=phases[result['phase']],
                  verificationProvenance='unverified_local_health_metadata')
    clock_keys = ('clockStatus', 'clockVerified', 'clockRolledBack', 'clockHighWaterUtcSeconds')
    if any(key in data for key in clock_keys):
        clock_status, verified, rollback, high_water = (data.get(key) for key in clock_keys)
        if (type(clock_status) is not int or not -(1 << 31) <= clock_status < (1 << 31)
                or type(verified) is not bool or type(rollback) is not bool
                or type(high_water) is not int or not 0 <= high_water <= 253402300799):
            raise ValueError('invalid native clock health')
        result.update(clockStatus=clock_status, reportedClockVerified=verified,
                      clockRolledBack=rollback, clockHighWaterUtcSeconds=high_water)
    return result


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
    if 'nativeRetention' in data:
        result['nativeRetention'] = _native_health(data['nativeRetention'])
    return result
