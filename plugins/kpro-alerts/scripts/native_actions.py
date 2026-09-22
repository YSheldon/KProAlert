"""Fixed native action transport. No caller-selected commands or receipt import."""
import json
import os
from pathlib import Path,PureWindowsPath
import re
import subprocess
from operations import evidence,identifier,canonical
from native_provenance import validate_source
from native_receipt_reader import _request,_locked_entry,_verify_publisher,_unique
from spool import checked

def _decimal(value,positive=False):
    if not isinstance(value,str) or not re.fullmatch('[0-9]{1,20}',value):raise ValueError('Invalid native integer')
    number=int(value)
    if not int(positive)<=number<2**64:raise ValueError('Native integer out of range')
    return number

def _snapshot(value,device):
    keys={'schema','success','hr','status','operation','servicePid','requestId','transactionId',
          'observedAtFileTime','expectedDigestSha256','digestSha256','policyFileSha256','runtimeFileSha256',
          'deviceSha256','policyVersion','policyFlags','acceptedSignedMessages'}
    if not isinstance(value,dict) or set(value)!=keys or value['schema']!='FalconProPolicySnapshot/v1':
        raise ValueError('Unknown native snapshot fields')
    if value['success'] is not True or any(type(value[k]) is not int or value[k]!=0 for k in ('hr','status')):
        raise ValueError('Native snapshot failed')
    if (type(value['operation']) is not int or value['operation']!=1 or type(value['servicePid']) is not int or
        not 0<value['servicePid']<2**32 or type(value['policyFlags']) is not int or not 0<=value['policyFlags']<2**32 or
        value['deviceSha256']!=device):raise ValueError('Native snapshot binding unavailable')
    for key in ('expectedDigestSha256','digestSha256','policyFileSha256','runtimeFileSha256','deviceSha256','transactionId'):
        identifier(value[key])
    if not isinstance(value['requestId'],str) or not re.fullmatch('[a-f0-9]{32}',value['requestId']):raise ValueError('Invalid native request ID')
    for key in ('observedAtFileTime','policyVersion'): _decimal(value[key],True)
    _decimal(value['acceptedSignedMessages'])

def _source_for_request(request,source):
    if request['schema']!='FalconProActionRequest/v1' or request['action']!='switch_to_enforce':
        raise ValueError('Only an existing switch_to_enforce request is supported')
    current=evidence(source,request['eventId'])
    if current['evidenceSha256']!=request['evidenceSha256'] or current['simulated']!=request['simulated']:
        raise ValueError('Action evidence changed')
    if 'nativeSource' not in current:
        raise ValueError('Historical event lacks native provenance; analysis only')
    return validate_source(current['nativeSource'])

def submission(journal,request_id):
    request=journal.get(request_id)
    return dict(schema='FalconProNativeActionSubmission/v1',request=request,
                nativeSource=_source_for_request(request,journal.source))

def validate_receipt(value,request,device):
    if not isinstance(value,dict) or value.get('schema')!='FalconProNativeActionReceipt/v1':
        raise ValueError('Native action has no verified receipt')
    keys={'schema','linkage','outcome','nativeTransaction','rawRecordSha256','before','after',
          'targetVersion','targetFlags','observedAtFileTime','bootId','verificationProvenance','error'}
    if set(value)!=keys or value['verificationProvenance']!='verified_locally_not_device_signed':
        raise ValueError('Unsupported native receipt')
    link=value['linkage']
    expected=dict(requestId=request['recordId'],decisionId=request['decisionId'],eventId=request['eventId'],
                  evidenceSha256=request['evidenceSha256'],deviceSha256=device,action='switch_to_enforce',simulated=request['simulated'])
    if not isinstance(link,dict) or any(link.get(k)!=v for k,v in expected.items()):
        raise ValueError('Native receipt request binding differs')
    if set(link)!=set(expected)|{'intentSha256','sourcePolicySha256','targetPolicySha256',
                               'nativeSource','sourceSessionSha256','sourceSequence','rawRecordSha256'}:
        raise ValueError('Unknown native linkage')
    for key in ('intentSha256','sourcePolicySha256','targetPolicySha256','sourceSessionSha256','rawRecordSha256'):
        identifier(link[key])
    validate_source(link['nativeSource'])
    _decimal(link['sourceSequence'],True)
    if link['rawRecordSha256']!=value['rawRecordSha256'] or type(link['simulated']) is not bool:
        raise ValueError('Native source binding differs')
    identifier(value['rawRecordSha256'])
    _decimal(value['observedAtFileTime'],True)
    _decimal(value['bootId'],True)
    _decimal(value['targetVersion'],True)
    if type(value['targetFlags']) is not int or not 0<=value['targetFlags']<2**32:raise ValueError('Invalid target flags')
    if value['error'] is not None and (not isinstance(value['error'],str) or not re.fullmatch('[a-z0-9_]{1,80}',value['error'])):
        raise ValueError('Invalid native error')
    _snapshot(value['before'],device)
    if value['after'] is not None:_snapshot(value['after'],device)
    if (not isinstance(value['nativeTransaction'],str) or not re.fullmatch('[a-f0-9]{32}',value['nativeTransaction']) or
        value['outcome'] not in ('cancelled','rejected','failed','outcome_uncertain','already_enforced_verified','executed_verified')):
        raise ValueError('Invalid native outcome')
    if value['before']['transactionId']!=value['nativeTransaction']*2:raise ValueError('Native transaction differs')
    if value['outcome'] in ('executed_verified','already_enforced_verified'):
        before,after=value['before'],value['after']
        if not isinstance(before,dict) or not isinstance(after,dict) or value['error'] is not None:
            raise ValueError('Native readback missing')
        for item in (before,after):
            if (item.get('success') is not True or item.get('hr')!=0 or item.get('status')!=0 or
                item.get('operation')!=1 or item.get('deviceSha256')!=device):
                raise ValueError('Native snapshot failed')
        def count(x):
            if not isinstance(x,str) or not re.fullmatch('[0-9]{1,20}',x):
                raise ValueError('Counter unavailable')
            return int(x)
        previous=count(before.get('acceptedSignedMessages'))
        current=count(after.get('acceptedSignedMessages'))
        expected_count=previous+(value['outcome']=='executed_verified')
        if (not 0<=previous<=current<2**64 or current!=expected_count or
            after.get('policyVersion')!=value['targetVersion'] or after.get('policyFlags')!=value['targetFlags'] or
            type(before.get('servicePid')) is not int or before['servicePid']<=0 or
            any(before.get(k)!=after.get(k) for k in ('servicePid','runtimeFileSha256','policyFileSha256','transactionId')) or
            (value['outcome']=='already_enforced_verified' and
             any(before.get(k)!=after.get(k) for k in ('policyVersion','policyFlags')))):
            raise ValueError('Native transition differs')
    return value

def _invoke(entry,entry_sha256,device,request_id,verb):
    if os.name!='nt':raise ValueError('Local Windows endpoint required; cloud runtime cannot execute')
    identifier(request_id)
    if verb not in ('action-inbox','action','action-result','action-diagnose'):raise ValueError('Unsupported native verb')
    entry=_request(entry,entry_sha256,device,request_id,identifier_length=64)
    command=[entry,verb,'--device',device]
    if verb!='action-inbox':command+=['--request-id',request_id]
    if verb=='action':command+=['--apply']
    with _locked_entry(entry,entry_sha256):
        _verify_publisher(entry)
        result=subprocess.run(command,input=b'',capture_output=True,timeout=360 if verb=='action' else 60)
    if len(result.stdout)>65536 or result.stderr:raise ValueError('Native reply unavailable')
    value=json.loads(result.stdout.decode('utf-8'),object_pairs_hook=_unique)
    if result.returncode or not isinstance(value,dict):raise ValueError('Native request refused or incomplete')
    return value

def request_action(journal,request_id,entry,entry_sha256,device):
    if os.name!='nt':raise ValueError('Local Windows endpoint required; cloud runtime cannot execute')
    payload=submission(journal,request_id)
    inbox=_invoke(entry,entry_sha256,device,request_id,'action-inbox')
    if inbox.get('schema')!='FalconProNativeActionInbox/v1' or inbox.get('deviceId')!=device:
        raise ValueError('Native inbox binding unavailable')
    path=PureWindowsPath(inbox.get('inbox',''))
    if not path.is_absolute() or tuple(p.lower() for p in path.parts[-2:])!=('falconpro','action-inbox'):
        raise ValueError('Unexpected native inbox')
    directory=Path(path);directory.mkdir(parents=True,exist_ok=True);checked(directory)
    file=directory/(request_id+'.json');raw=canonical(payload).encode('ascii')
    if len(raw)>8192:raise ValueError('Native request too large')
    try:
        with file.open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    except FileExistsError:
        checked(file)
        with file.open('rb') as stream:
            if stream.read(8193)!=raw:raise ValueError('Native request ID already contains different input')
    result=_invoke(entry,entry_sha256,device,request_id,'action')
    if result.get('schema')=='FalconProNativeActionStatus/v1':
        if result.get('requestId')!=request_id or result.get('executionVerified') is not False:
            raise ValueError('Invalid native pending state')
        return result
    receipt=validate_receipt(result,payload['request'],device)
    if receipt['linkage']['nativeSource']!=payload['nativeSource']:
        raise ValueError('Native source differs from submitted source')
    return receipt

def read_result(request,entry,entry_sha256,device,*,source):
    expected_source=_source_for_request(request,source)
    result=_invoke(entry,entry_sha256,device,request['recordId'],'action-result')
    receipt=validate_receipt(result,request,device)
    if receipt['linkage']['nativeSource']!=expected_source:
        raise ValueError('Native receipt source differs from event evidence')
    return receipt

def diagnose(request_id,entry,entry_sha256,device):
    value=_invoke(entry,entry_sha256,device,request_id,'action-diagnose')
    required={'schema','requestId','deviceSha256','executionVerified','causalityVerified','automaticReplay',
              'policyMutationPerformed','actionStoreWritesPerformed','transportQueryAttempted',
              'atomicObservation','reservationStage','resultAvailable','resultOutcome','conclusion'}
    optional={'sameBoot','currentPolicyVersion','currentPolicyFlags','currentAcceptedCount','linkage','before','current',
              'nativeTransaction','applyingMarkerValid','activeRecordMatches','pendingRecordStructurallyMatches','sameServiceInstance'}
    if (not required<=set(value) or set(value)-required-optional or
        value['schema']!='FalconProNativeActionDiagnosis/v1' or value['requestId']!=request_id or value['deviceSha256']!=device or
        any(value[k] is not False for k in ('executionVerified','causalityVerified','automaticReplay','policyMutationPerformed','actionStoreWritesPerformed','atomicObservation')) or
        value['conclusion'] not in ('reservation_incomplete_no_result','durable_result_available','cross_boot_unattributable',
            'live_state_unavailable','pending_transaction_observed','bound_post_state_observed','target_state_only','pre_state_observed','state_diverged')):
        raise ValueError('Invalid native diagnosis')
    for key in ('transportQueryAttempted','resultAvailable','sameBoot','applyingMarkerValid','activeRecordMatches',
                'pendingRecordStructurallyMatches','sameServiceInstance'):
        if key in value and type(value[key]) is not bool:raise ValueError('Invalid native diagnosis flag')
    if value['reservationStage'] not in ('reserved','intent','prepared','applying','result'):raise ValueError('Invalid reservation stage')
    if value['resultOutcome'] not in (None,'cancelled','rejected','failed','outcome_uncertain','already_enforced_verified','executed_verified'):
        raise ValueError('Invalid observed result')
    for key in ('before','current'):
        if key in value:_snapshot(value[key],device)
    if 'sameBoot' in value and type(value['sameBoot']) is not bool:raise ValueError('Invalid native boot state')
    for key in ('currentPolicyVersion','currentAcceptedCount'):
        if key in value:_decimal(value[key])
    if 'currentPolicyFlags' in value and (type(value['currentPolicyFlags']) is not int or not 0<=value['currentPolicyFlags']<2**32):
        raise ValueError('Invalid native flags')
    return value

def verify_delivery(record,source):
    """Re-read protected native evidence; a writable journal is not authority."""
    config=[os.environ.get(k) for k in ('KPRO_NATIVE_ENTRY','KPRO_NATIVE_ENTRY_SHA256','KPRO_ENDPOINT_DEVICE_ID')]
    if not all(config):raise ValueError('Native receipt verification is not configured')
    actual=read_result(record['request'],*config,source=source)
    if actual!=record['nativeReceipt']:
        raise ValueError('Native receipt changed or journal was modified')

def read_request(database,request_id):
    from operations import _source,decode_record
    identifier(request_id)
    db=_source(database)
    try:
        rows=db.execute('SELECT payload FROM ops_records WHERE id=? LIMIT 2',(request_id,)).fetchall()
        if len(rows)!=1:raise ValueError('Action request unavailable')
        record=decode_record(rows[0][0])
        if record['schema']!='FalconProActionRequest/v1' or record['recordId']!=request_id or record['action']!='switch_to_enforce':
            raise ValueError('Unsupported action request')
        return record
    finally:db.close()
