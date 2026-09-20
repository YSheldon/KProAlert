import json
import unittest
from operations import canonical,digest
from feishu_operations import project
from unittest.mock import patch
from types import SimpleNamespace


class FeishuOperationsTests(unittest.TestCase):
    def record(self):
        r=dict(schema='FalconProActionRequest/v1',decisionId='a'*64,eventId='b'*64,evidenceSha256='c'*64,
            action='investigate',policyVersion=1,processId=2,processCreateTime=3,
            approvalState='requires_native_confirmation',executionState='not_executed',executionAvailable=False,
            simulated=True,requestKey='d'*32,recordedAt='2026-09-20T00:00:00+00:00',client='codex',
            clientIdentityTrust='configured_not_cryptographically_attested')
        r['recordId']=digest(r)
        return r

    def payload(self,r):
        return dict(ok=True,data=dict(fields=['分析ID','结构化记录','模拟'],data=[[r['recordId'],canonical(r),True]],has_more=False))

    def test_request_stays_unexecuted_and_cloud_is_not_native_authority(self):
        r=self.record();result=project(self.payload(r))
        self.assertEqual(result['records'][0]['executionState'],'not_executed')
        self.assertEqual(result['trust'],'cloud_stored_claim_not_device_attested')
        self.assertFalse(result['actionExecutionAvailable'])
        self.assertTrue(result['records'][0]['simulated'])

    def test_tamper_mismatched_identity_and_extra_columns_fail_closed(self):
        r=self.record()
        for index,value in ((0,'e'*64),(1,canonical({**r,'executionState':'executed_verified'})),(2,False)):
            p=self.payload(r);p['data']['data'][0][index]=value
            with self.assertRaises(ValueError):project(p)
        p=self.payload(r);p['data']['fields'].append('cmdline');p['data']['data'][0].append('SECRET')
        with self.assertRaises(ValueError):project(p)

    def test_empty_page_requires_explicit_success_and_pagination(self):
        self.assertEqual(project(dict(ok=True,data=dict(fields=['分析ID','结构化记录','模拟'],data=[],has_more=False)))['records'],[])
        with self.assertRaises(ValueError):project(dict(ok=False))

    def test_no_progress_page_cannot_cause_infinite_pagination(self):
        with self.assertRaises(ValueError):
            project(dict(ok=True,data=dict(fields=['分析ID','结构化记录','模拟'],data=[],has_more=True)))

    def test_native_result_projection_is_a_claim_not_a_replayable_receipt(self):
        from test_native_actions import receipt_fixture
        request=self.record()
        request['action']='switch_to_enforce'
        request['recordId']=digest({k:v for k,v in request.items() if k!='recordId'})
        record=dict(schema='FalconProNativeActionResult/v1',request=request,nativeReceipt=receipt_fixture(request),
            action='switch_to_enforce',eventId=request['eventId'],evidenceSha256=request['evidenceSha256'],
            approvalState='native_receipt_recorded',executionState='executed_verified',simulated=True,
            verificationProvenance='verified_locally_not_device_signed',requestKey='e'*32,
            recordedAt=request['recordedAt'],client='codex',clientIdentityTrust=request['clientIdentityTrust'])
        record['recordId']=digest(record)
        result=project(self.payload(record))
        item=result['records'][0]
        self.assertEqual(item['reportedOutcome'],'executed_verified')
        self.assertEqual(item['requestId'],request['recordId'])
        self.assertEqual(item['beforePolicyVersion'],'12')
        self.assertEqual(item['afterPolicyVersion'],'13')
        self.assertNotIn('nativeReceipt',item)
        self.assertNotIn('deviceSha256',canonical(item))
        self.assertFalse(result['actionExecutionAvailable'])

    def test_query_respects_requested_page_bound_and_fixed_read_command(self):
        from feishu_operations import read
        payload=self.payload(self.record())
        observed=[]
        def run(args,**kwargs):
            observed.append(args)
            return SimpleNamespace(returncode=0,stdout=json.dumps(payload))
        with patch('feishu_operations._resolve_cli',return_value='lark.exe'),patch('feishu_operations.subprocess.run',side_effect=run):
            result=read('lark.exe','base123','tblOps',1,7)
            self.assertEqual(result['records'][0]['action'],'investigate')
            self.assertEqual(observed[0][:3],['lark.exe','base','+record-list'])
            self.assertEqual(observed[0][observed[0].index('--offset')+1],'7')
            second=self.record();second['requestKey']='f'*32
            second['recordId']=digest({k:v for k,v in second.items() if k!='recordId'})
            payload['data']['data'].append([second['recordId'],canonical(second),True])
            with self.assertRaises(ValueError):read('lark.exe','base123','tblOps',1)

if __name__=='__main__':unittest.main()
