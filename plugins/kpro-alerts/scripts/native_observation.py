"""Transport-free bridge from a verified native observation reader to metrics."""
import re
import time
from pathlib import Path

from metrics_journal import Journal


NATIVE_KEYS = frozenset({
    'schema', 'observationId', 'operation', 'phase', 'version',
    'architecture', 'osFamily', 'day', 'testOnly', 'protectionVerified',
})
_OPERATIONS = {'install', 'upgrade'}
_ARCHITECTURES = {'x86', 'x64', 'arm64'}
_OS_FAMILIES = {'windows7', 'windows8', 'windows10', 'windows11'}
_VERSION = re.compile(r'[0-9]{1,5}(?:\.[0-9]{1,5}){3}')
_OBSERVATION_ID = re.compile(r'[a-f0-9]{64}')
_MAX_DAY = 200000


def validate_native_observation(observation, *, today=None):
    """Validate and return the exact ten-key native observation object."""
    if not isinstance(observation, dict) or set(observation) != NATIVE_KEYS:
        raise ValueError('Unsupported native observation fields')
    if observation['schema'] != 'FalconProNativeObservation/v1':
        raise ValueError('Unsupported native observation schema')
    if (not isinstance(observation['observationId'], str) or
            not _OBSERVATION_ID.fullmatch(observation['observationId'])):
        raise ValueError('Lowercase observation digest required')
    if (not isinstance(observation['operation'], str) or
            observation['operation'] not in _OPERATIONS):
        raise ValueError('Unsupported native observation operation')
    if not isinstance(observation['phase'], str) or observation['phase'] != 'complete':
        raise ValueError('Only complete native observations are accepted')
    if (not isinstance(observation['version'], str) or
            not _VERSION.fullmatch(observation['version'])):
        raise ValueError('Numeric component version required')
    if (not isinstance(observation['architecture'], str) or
            observation['architecture'] not in _ARCHITECTURES):
        raise ValueError('Unsupported native observation architecture')
    if (not isinstance(observation['osFamily'], str) or
            observation['osFamily'] not in _OS_FAMILIES):
        raise ValueError('OS family required; do not guess null')
    if type(observation['day']) is not int or not 0 <= observation['day'] <= _MAX_DAY:
        raise ValueError('UTC epoch day required')
    if today is None:
        today = int(time.time() // 86400)
    elif type(today) is not int or not 0 <= today <= _MAX_DAY:
        raise ValueError('UTC epoch day bound required')
    if observation['day'] > today:
        raise ValueError('Future native observation is not accepted')
    if type(observation['testOnly']) is not bool:
        raise ValueError('Explicit test-only marker required')
    if observation['protectionVerified'] is not False:
        raise ValueError('Protection verification must remain false')
    return dict(observation)


def collect_native_observation(database, reader, *, today=None):
    """Record one verified observation from a callable reader.

    The reader is deliberately the only input channel. It must return a native
    observation object; paths, JSON strings, and imported receipts are rejected.
    """
    if not callable(reader):
        raise ValueError('Native observation reader callable required')
    if Path(database).name!='metrics.db':
        raise ValueError('Dedicated metrics journal required')
    if not Path(database).exists():
        return None
    with Journal(database) as journal:
        binding = journal.consent_binding()
        if binding is None:
            return None
        observation = validate_native_observation(reader(), today=today)
        if observation['testOnly'] != binding['simulated']:
            raise ValueError('Native test-only marker and simulation mode differ')
        kind = ('install_success' if observation['operation'] == 'install'
                else 'upgrade_success')
        return journal.record(
            kind=kind,
            version=observation['version'],
            architecture=observation['architecture'],
            os_family=observation['osFamily'],
            state='unknown',
            day=observation['day'],
            observation_key=observation['observationId'],
            expected_installation_id=binding['installation_id'],
            expected_simulated=binding['simulated'],
        )
