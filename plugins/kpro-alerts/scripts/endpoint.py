"""Bound execution-host probe. Never installs or infers a cloud host is the user's PC."""
import json
import os
from pathlib import Path
import re
import subprocess
from windows_tools import native_tool


def _result(state, device_id=None, architecture=None):
    return dict(schema='FalconProEndpointStatus/v1', state=state,
                deviceId=device_id, executionHostOnly=True,
                installEligible=state == 'not_installed',
                automaticInstallAuthorized=False, requiresFirstInstallConsent=True,
                protectionVerified=False, architecture=architecture)


def classify(facts, expected_device_id):
    if not isinstance(facts, dict) or facts.get('schema') != 'FalconProEndpointFacts/v1':
        return _result('unknown')
    device=facts.get('deviceId')
    if not isinstance(device,str) or not re.fullmatch('[a-f0-9]{64}',device):
        return _result('unknown')
    architecture = facts.get('architecture')
    if any(type(facts.get(k)) is not bool for k in ('supported','conflicts','residualFiles')):
        return _result('unknown',device)
    if any(facts.get(k) not in ('absent','running','stopped','unknown') for k in ('service','driver')):
        return _result('unknown',device)
    if facts['supported'] and architecture not in ('x64', 'arm64'):
        return _result('unknown',device)
    def result(state):
        return _result(state, device, architecture)
    if not expected_device_id:
        return result('target_unbound')
    if not isinstance(expected_device_id,str) or not re.fullmatch('[a-f0-9]{64}',expected_device_id):
        return result('target_unbound')
    if device != expected_device_id:
        return result('target_mismatch')
    if not facts['supported']:
        return result('unsupported')
    if 'unknown' in (facts['service'],facts['driver']):
        return result('unknown')
    if facts['conflicts']:
        return result('conflicting_install')
    if facts['service']=='absent' and facts['driver']=='absent':
        return result('residual_install' if facts['residualFiles'] else 'not_installed')
    if 'absent' in (facts['service'],facts['driver']):
        return result('partial_install')
    if facts['service']=='running' and facts['driver']=='running':
        return result('running_policy_unverified')
    return result('installed_not_running')


def probe(expected_device_id='', *, platform=None, runner=None, tool_resolver=native_tool):
    if (platform or os.name) != 'nt':
        return _result('local_channel_required')
    runner=runner or subprocess.run
    script=Path(__file__).with_name('EndpointFacts.ps1')
    try:
        executable=tool_resolver('WindowsPowerShell/v1.0/powershell.exe')
        result=runner([str(executable),'-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(script)],
                      capture_output=True,text=True,timeout=25)
        if result.returncode != 0 or len(result.stdout)>16384:
            return _result('unknown')
        return classify(json.loads(result.stdout.lstrip('\ufeff')),expected_device_id)
    except (OSError,ValueError,TypeError,subprocess.TimeoutExpired):
        return _result('unknown')


if __name__=='__main__':
    print(json.dumps(probe(os.environ.get('KPRO_ENDPOINT_DEVICE_ID',''))))
