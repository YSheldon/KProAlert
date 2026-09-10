"""Prepare a verified local installation without manual package paths or checksum inputs."""
import argparse
import base64
import csv
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from endpoint import probe
from release_download import acquire, version_tuple
from release_manifest import validate
from windows_tools import native_tool


def verify_descriptor(data):
    if os.name!='nt':raise ValueError('A confirmed local Windows execution channel is required')
    with tempfile.TemporaryDirectory(prefix='FalconPro-descriptor-') as folder:
        path=Path(folder)/'descriptor.ps1'
        path.write_bytes(data)
        result=subprocess.run([native_tool('WindowsPowerShell/v1.0/powershell.exe'),
            '-NoProfile','-NonInteractive','-File',str(Path(__file__).with_name('Verify-ReleaseDescriptor.ps1')),
            '-DescriptorPath',str(path)],capture_output=True,text=True,timeout=45)
    if result.returncode or len(result.stdout)>100000:raise ValueError('Windows descriptor signature verification failed')
    reply=json.loads(result.stdout.lstrip('\ufeff'))
    if reply.get('publisher') not in ('product','artifact-signing'):raise ValueError('Unapproved descriptor publisher')
    return json.loads(base64.b64decode(reply['payloadBase64'],validate=True).decode('utf-8'))


def delivery_sid():
    result=subprocess.run([native_tool('whoami.exe'),'/user','/fo','csv','/nh'],capture_output=True,timeout=10)
    if result.returncode or len(result.stdout)>4096:raise ValueError('Local user SID unavailable')
    rows=list(csv.reader(result.stdout.decode('utf-8',errors='replace').splitlines()))
    if len(rows)!=1 or len(rows[0])!=2 or not re.fullmatch(r'S-1-5-21-[0-9-]{1,100}',rows[0][1]):
        raise ValueError('A local delivery user, not a cloud/system identity, is required')
    return rows[0][1]


def prepare(destination,expected_device_id,*,endpoint_probe=probe,download=acquire,sid_reader=delivery_sid):
    endpoint=endpoint_probe(expected_device_id)
    if endpoint['state']!='not_installed':
        return dict(state=endpoint['state'],installPerformed=False,
                    nextStep='Confirm the actual local device or diagnose existing protection; do not reinstall')
    descriptor=download(destination,verify_descriptor)
    root=Path(destination)
    manifest=json.loads((root/'package/release-manifest.json').read_text(encoding='utf-8-sig'))
    validate(manifest,root/'package','x64')
    if version_tuple(manifest['version'])!=version_tuple(descriptor['version']):
        raise ValueError('Descriptor/package version mismatch')
    sid=sid_reader()
    return dict(schema='FalconProBootstrapPlan/v1',state='ready_for_native_plan',
        deviceId=endpoint['deviceId'],version=descriptor['version'],installPerformed=False,
        requiresAdministrator=True,requiresExplicitApproval=True,requiresProtectedStaging=True,
        command=[str(root/'onboarding/Install-FalconPro.ps1'),'-ExpectedDeviceId',endpoint['deviceId'],
                 '-SourceManifestSha256',descriptor['sourceManifestSha256'],
                 '-PackageRoot',str(root/'package'),'-ManifestSha256',descriptor['packageManifestSha256'],
                 '-DeliveryUserSid',sid])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['plan'])
    args=parser.parse_args()
    parent=Path(tempfile.mkdtemp(prefix='FalconPro-download-'))
    try:
        print(json.dumps(prepare(parent/'release',os.environ.get('KPRO_ENDPOINT_DEVICE_ID',''))))
    except Exception as exc:
        # No remote payload, URL query, credential or raw verifier output is logged.
        print(json.dumps({'state':'blocked','errorClass':type(exc).__name__,'installPerformed':False}))
        raise SystemExit(1)
