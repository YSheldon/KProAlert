"""Package integrity check, NOT a substitute for Windows signature validation."""
import hashlib
import re
from pathlib import Path
from release_platforms import layout, required_files

REQUIRED = required_files('x64')
GATES = {'serviceF1ArtifactProduct', 'driverMicrosoftProduct', 'dllProduct',
         'policySignature', 'endToEnd', 'privateRawEventSpool'}


def validate(manifest, root, architecture):
    if manifest.get('schema') != 'KProAlertRelease/v1' or manifest.get('releaseStatus') != 'verified':
        raise ValueError('unverified release manifest')
    target = layout(architecture)
    required = required_files(architecture)
    if manifest.get('architecture') != architecture or manifest.get('platform') != target['platform']:
        raise ValueError('package architecture mismatch')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?', str(manifest.get('version'))):
        raise ValueError('invalid release version')
    gates = manifest.get('gates', {})
    if any(gates.get(k) is not True for k in GATES):
        raise ValueError('release evidence gates incomplete')
    files = manifest.get('files')
    if not isinstance(files, list) or len(files) != len(required):
        raise ValueError('unexpected package file count')
    root = Path(root).resolve(strict=True)
    seen = set()
    for entry in files:
        name = entry.get('name')
        if name not in required or name in seen:
            raise ValueError('unexpected or duplicate filename')
        seen.add(name)
        path = root/name
        if path.is_symlink() or path.resolve(strict=True).parent != root or not path.is_file():
            raise ValueError('unsafe package path')
        if type(entry.get('size')) is not int or not 0 < entry['size'] <= 64*1024*1024:
            raise ValueError('invalid package file size')
        if path.stat().st_size != entry['size']:
            raise ValueError('package file size mismatch')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if not isinstance(entry.get('sha256'), str) or digest != entry['sha256'].lower():
            raise ValueError('package file hash mismatch')
    return dict(fileCount=len(seen), architecture=architecture,
                version=manifest['version'], windowsSignatureCheckRequired=True)
