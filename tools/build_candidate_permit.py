"""Prepare validation-only inputs for signing. Never signs, installs or promotes."""
import argparse
import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'plugins/kpro-alerts/scripts'))
from build_onboarding_manifest import NAMES
from release_platforms import layout, required_files


def digest(data):
    return hashlib.sha256(data).hexdigest()


def build(source_root, package_roots, device, transaction, architecture, operation):
    if not re.fullmatch('[a-f0-9]{64}', device) or not re.fullmatch('[a-f0-9]{32}', transaction):
        raise ValueError('Explicit device and transaction digests required')
    if architecture not in ('x86', 'x64', 'arm64') or operation not in ('install', 'upgrade'):
        raise ValueError('Unsupported candidate operation')
    if len(package_roots) != (2 if operation == 'upgrade' else 1):
        raise ValueError('Upgrade requires target and exact previous package')
    names = (*NAMES, 'Invoke-FalconProCandidateValidation.ps1')
    source = {'schema': 'FalconProCandidateSource/v2', 'files': [
        {'name': name, 'sha256': digest((source_root / name).read_bytes())} for name in names]}
    source_bytes = (json.dumps(source, indent=2) + '\n').encode()
    packages = []
    for root in package_roots:
        raw = (root / 'release-manifest.json').read_bytes()
        manifest = json.loads(raw.decode('utf-8-sig'))
        target=layout(architecture, manifest['platform'])
        if manifest['architecture'] != architecture:
            raise ValueError('Candidate architecture mismatch')
        status = manifest['releaseStatus']
        if manifest['schema'] != 'KProAlertRelease/v1' or status not in ('candidate', 'verified'):
            raise ValueError('Candidate schema/status invalid')
        if not packages and status != 'candidate':
            raise ValueError('Target must be a candidate, never a production promotion')
        for gate in ('serviceF1ArtifactProduct', 'driverMicrosoftProduct', 'dllProduct', 'policySignature', 'endToEnd', 'privateRawEventSpool'):
            expected = not (status == 'candidate' and gate == 'endToEnd')
            if manifest['gates'].get(gate) is not expected:
                raise ValueError('Signature/evidence gate incomplete')
        required = required_files(architecture,target['platform'])
        if len(manifest['files']) != 5 or {f['name'] for f in manifest['files']} != required:
            raise ValueError('Incomplete candidate files')
        for file in manifest['files']:
            if Path(file['name']).name != file['name'] or '/' in file['name'] or '\\' in file['name']:
                raise ValueError('Non-flat candidate filename')
            data = (root / file['name']).read_bytes()
            if type(file['size']) is not int or not 0 < file['size'] <= 67108864 or len(data) != file['size'] or digest(data) != file['sha256']:
                raise ValueError('Candidate file drift')
        packages.append({'manifestSha256': digest(raw),
                         'attestationSha256': digest((root / 'release-attestation.ps1').read_bytes()),
                         'files': manifest['files']})
    now = datetime.now(timezone.utc)
    permit = dict(schema='FalconProCandidatePermit/v1', deviceId=device, transactionId=transaction,
                  architecture=architecture, operation=operation, sourceManifestSha256=digest(source_bytes),
                  issuedUtc=now.isoformat().replace('+00:00', 'Z'),
                  expiresUtc=(now + timedelta(hours=24)).isoformat().replace('+00:00', 'Z'), packages=packages)
    marker = base64.b64encode(json.dumps(permit, separators=(',', ':')).encode()).decode()
    return source_bytes, ('# Validation only; data, never execute.\n# FALCONPRO-CANDIDATE-JSON: ' + marker + '\n').encode()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--package-root', type=Path, action='append', required=True)
    parser.add_argument('--device', required=True)
    parser.add_argument('--transaction', required=True)
    parser.add_argument('--architecture', choices=('x86', 'x64', 'arm64'), required=True)
    parser.add_argument('--operation', choices=('install', 'upgrade'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, permit = build(args.source_root, args.package_root, args.device, args.transaction, args.architecture, args.operation)
    args.output.mkdir(exist_ok=False)
    (args.output / 'onboarding-source.json').write_bytes(source)
    (args.output / 'candidate-permit.ps1').write_bytes(permit)
    print(json.dumps({'validationOnly': True, 'signed': False, 'productionEligible': False,
                      'sourceManifestSha256': digest(source)}))
