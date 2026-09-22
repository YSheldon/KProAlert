import json
from pathlib import Path
import tempfile
import unittest
from kpro_alert_bridge import Store,ingest_document
from operations import Operations,events
from native_actions import submission,validate_receipt

def receipt_fixture(request,device='e'*64):
    link=dict(requestId=request['recordId'],decisionId=request['decisionId'],eventId=request['eventId'],
        evidenceSha256=request['evidenceSha256'],deviceSha256=device,action='switch_to_enforce',simulated=request['simulated'],
        intentSha256='1'*64,sourcePolicySha256='2'*64,targetPolicySha256='3'*64,
        nativeSource=dict(schema='FalconProCollectorSource/v1',batchSha256='b'*64,recordIndex=0),
        sourceSessionSha256='4'*64,sourceSequence='1',rawRecordSha256='5'*64)
    before=dict(schema='FalconProPolicySnapshot/v1',success=True,hr=0,status=0,operation=1,servicePid=100,
        requestId='6'*32,transactionId='7'*64,observedAtFileTime='134000000000000000',
        expectedDigestSha256='0'*64,digestSha256='8'*64,policyFileSha256='9'*64,runtimeFileSha256='a'*64,
        deviceSha256=device,policyVersion='12',policyFlags=1,acceptedSignedMessages='2')
    return dict(schema='FalconProNativeActionReceipt/v1',linkage=link,outcome='executed_verified',nativeTransaction='7'*32,
        rawRecordSha256='5'*64,before=before,after={**before,'policyVersion':'13','acceptedSignedMessages':'3'},
        targetVersion='13',targetFlags=1,observedAtFileTime='134000000000000001',bootId='134000000000000000',
        verificationProvenance='verified_locally_not_device_signed',error=None)

class NativeActionTests(unittest.TestCase):
    def test_diagnosis_cannot_claim_execution_or_enable_replay(self):
        from unittest.mock import patch
        from native_actions import diagnose
        value=dict(schema='FalconProNativeActionDiagnosis/v1',requestId='a'*64,deviceSha256='e'*64,
            executionVerified=False,causalityVerified=False,automaticReplay=False,policyMutationPerformed=False,
            actionStoreWritesPerformed=False,transportQueryAttempted=False,atomicObservation=False,
            reservationStage='reserved',resultAvailable=False,resultOutcome=None,conclusion='reservation_incomplete_no_result')
        with patch('native_actions._invoke',return_value=value):
            self.assertEqual(diagnose('a'*64,'entry.exe','b'*64,'e'*64),value)
        for key in ('executionVerified','causalityVerified','automaticReplay','policyMutationPerformed','actionStoreWritesPerformed'):
            with patch('native_actions._invoke',return_value={**value,key:True}):
                with self.assertRaises(ValueError):diagnose('a'*64,'entry.exe','b'*64,'e'*64)

    def test_receipt_rejects_cross_transaction_and_raw_record_substitution(self):
        import copy
        request=dict(recordId='a'*64,eventId='b'*64,decisionId='c'*64,evidenceSha256='d'*64,simulated=True)
        receipt=receipt_fixture(request)
        self.assertEqual(validate_receipt(receipt,request,'e'*64),receipt)
        for area,key,replacement in [('after','transactionId','0'*64),('linkage','rawRecordSha256','0'*64),
                                     ('linkage','simulated',1)]:
            bad=copy.deepcopy(receipt);bad[area][key]=replacement
            with self.assertRaises(ValueError):validate_receipt(bad,request,'e'*64)
    def test_submission_requires_fresh_request_and_native_locator(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'events.db';journal=Path(tmp)/'ops.db'
            with Store(source) as store:
                ingest_document(store,'a'*64,dict(session='session',batchId='1',dropped=0,
                    records=[dict(eventType=7,operation=2,sequence=1,policyVersion=12,processId=42,processCreateTime=987)],
                    nativeSources=[dict(schema='FalconProCollectorSource/v1',batchSha256='b'*64,recordIndex=0)]))
            event=events(source)['events'][0]
            with Operations(journal,source,'codex') as ops:
                decision=ops.assess(event['eventId'],event['evidenceSha256'],'suspicious',75,['bulk_overwrite'],['switch_to_enforce'],'test','1'*32)
                request=ops.propose(decision['recordId'],'switch_to_enforce','2'*32)
                payload=submission(ops,request['recordId'])
                self.assertEqual(payload['request'],request)
                self.assertEqual(payload['nativeSource']['recordIndex'],0)
                self.assertNotIn('command',payload)
                with self.assertRaises(ValueError):submission(ops,decision['recordId'])

    def test_no_json_from_model_can_be_substituted_for_the_bound_native_reply(self):
        request=dict(recordId='a'*64,eventId='b'*64,decisionId='c'*64,evidenceSha256='d'*64,simulated=True)
        value=dict(schema='FalconProNativeActionReceipt/v1',outcome='executed_verified',
            linkage=dict(requestId='0'*64,eventId='b'*64,decisionId='c'*64,evidenceSha256='d'*64,
                         deviceSha256='e'*64,action='switch_to_enforce',simulated=True),
            verificationProvenance='verified_locally_not_device_signed')
        with self.assertRaises(ValueError):validate_receipt(value,request,'e'*64)

if __name__=='__main__':unittest.main()
