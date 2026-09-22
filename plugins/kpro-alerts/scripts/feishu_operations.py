"""Bounded cloud operations projection. Stored claims are not native authority."""
import json
import re
import subprocess
from operations import decode_record
from metrics_upload import _resolve_cli
from native_receipt_reader import _unique

FIELDS=('分析ID','结构化记录','模拟')


def project(payload):
    if not isinstance(payload,dict) or payload.get('ok') is not True:
        raise ValueError('Cloud operations read failed')
    data=payload.get('data')
    if (not isinstance(data,dict) or not isinstance(data.get('fields'),list) or
        len(data['fields'])!=3 or set(data['fields'])!=set(FIELDS) or
        not isinstance(data.get('data'),list) or len(data['data'])>200 or type(data.get('has_more')) is not bool):
        raise ValueError('Unexpected cloud operations schema')
    if data['has_more'] and not data['data']:
        raise ValueError('Cloud pagination made no progress')
    result=[];seen=set()
    for row in data['data']:
        if not isinstance(row,list) or len(row)!=3:raise ValueError('Invalid cloud row')
        cells=dict(zip(data['fields'],row))
        record=decode_record(cells['结构化记录'])
        if (cells['分析ID']!=record['recordId'] or type(cells['模拟']) is not bool or
            cells['模拟']!=record['simulated'] or record['recordId'] in seen):
            raise ValueError('Cloud operations identity differs')
        seen.add(record['recordId'])
        item={k:record[k] for k in ('recordId','schema','eventId','evidenceSha256','recordedAt','client',
            'approvalState','executionState','simulated')}
        if record['schema']=='FalconProAIDecision/v1':
            item.update({k:record[k] for k in ('verdict','confidence','reasonCodes','recommendedActions')})
        elif record['schema']=='FalconProActionRequest/v1':
            item.update(action=record['action'],decisionId=record['decisionId'])
        else:
            receipt=record['nativeReceipt']
            item.update(action=record['action'],requestId=record['request']['recordId'],
                decisionId=record['request']['decisionId'],reportedOutcome=receipt['outcome'],
                verificationProvenance=receipt['verificationProvenance'],
                beforePolicyVersion=receipt['before']['policyVersion'],targetPolicyVersion=receipt['targetVersion'])
            if receipt['after'] is not None:
                item['afterPolicyVersion']=receipt['after']['policyVersion']
        result.append(item)
    return dict(records=result,hasMore=data['has_more'],trust='cloud_stored_claim_not_device_attested',
        actionExecutionAvailable=False,scope='bounded page, not full statistics')


def read(cli,base,table,limit=20,offset=0):
    if type(limit) is not int or not 1<=limit<=200 or type(offset) is not int or not 0<=offset<=1000000:
        raise ValueError('Invalid bounded page')
    if any(not isinstance(v,str) or not re.fullmatch('[A-Za-z0-9]{1,128}',v) for v in (base,table)):
        raise ValueError('Explicit operations table required')
    args=[_resolve_cli(cli),'base','+record-list','--base-token',base,'--table-id',table,
        '--limit',str(limit),'--offset',str(offset),'--format','json','--as','user',
        '--sort-json',json.dumps([{'field':'记录时间','desc':True}],ensure_ascii=False)]
    for field in FIELDS:args+=['--field-id',field]
    response=subprocess.run(args,capture_output=True,encoding='utf-8',timeout=30)
    if response.returncode or len(response.stdout)>16*1024*1024:raise ValueError('Cloud operations query failed')
    value=project(json.loads(response.stdout,object_pairs_hook=_unique))
    if len(value['records'])>limit:
        raise ValueError('Cloud page exceeds requested bound')
    value['nextOffset']=offset+len(value['records']) if value['hasMore'] else None
    return value
