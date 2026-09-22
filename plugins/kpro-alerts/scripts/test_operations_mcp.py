import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from kpro_alert_bridge import Store
from operations import status


class OperationsMcpTests(unittest.IsolatedAsyncioTestCase):
    async def test_event_to_assessment_and_unapproved_request_over_real_stdio(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, journal = Path(tmp)/'events.db', Path(tmp)/'ops.db'
            with Store(source) as store:
                store.ingest('private-device', 'session', dict(eventType=7, operation=2, sequence=1,
                    policyVersion=8, processId=11, processCreateTime=33, path='PRIVATE PATH'))
            env = {k:v for k,v in os.environ.items() if not k.startswith('KPRO_')}
            env.update(KPRO_ALERT_DATABASE=str(source), KPRO_OPERATIONS_DATABASE=str(journal), KPRO_ASSISTANT_CLIENT='zcode')
            parameters = StdioServerParameters(command=sys.executable,
                args=[str(Path(__file__).with_name('mcp_server.py'))],env=env)
            async with stdio_client(parameters) as (reader,writer):
                async with ClientSession(reader,writer) as client:
                    await client.initialize()
                    tools={item.name:item for item in (await client.list_tools()).tools}
                    for name in ('request_native_action','native_action_result','collect_native_action_result','diagnose_native_action'):
                        self.assertEqual(set(tools[name].inputSchema['properties']),{'request_id'})
                    self.assertTrue(tools['request_native_action'].annotations.destructiveHint)
                    self.assertTrue(tools['native_action_result'].annotations.readOnlyHint)
                    self.assertTrue(tools['diagnose_native_action'].annotations.readOnlyHint)
                    self.assertFalse(tools['collect_native_action_result'].annotations.readOnlyHint)
                    async def call(name,args):
                        reply=await client.call_tool(name,args)
                        return json.loads(next(c.text for c in reply.content if c.type=='text'))
                    capabilities=await call('integration_status',{})
                    self.assertEqual(capabilities.get('releaseScope'),'existing_driver_events_v1')
                    self.assertIs(capabilities.get('driverChangeRequired'),False)
                    self.assertIs(capabilities.get('policyMutationAvailable'),False)
                    self.assertIs(capabilities.get('aiActionExecutionAvailable'),False)
                    page=await call('operations_events',{'limit':10})
                    event=page['events'][0]
                    self.assertNotIn('PRIVATE', json.dumps(page))
                    args=dict(event_id=event['eventId'], evidence_sha256=event['evidenceSha256'], verdict='suspicious',
                        confidence=80, reason_codes=['bulk_overwrite'],recommended_actions=['terminate_process'],
                        model='test-model',request_key='a'*32)
                    decision=await call('assess_event',args)
                    self.assertEqual(decision,await call('assess_event',args))
                    request=await call('propose_action',dict(decision_id=decision['recordId'],action='terminate_process',request_key='b'*32))
                    self.assertEqual(request['executionState'],'not_executed')
                    self.assertEqual(request['approvalState'],'requires_native_confirmation')
                    self.assertFalse(request['executionAvailable'])
                    result=await call('collect_native_action_result',{'request_id':request['recordId']})
                    self.assertIs(result['executionVerified'],False)
            self.assertEqual(status(journal)['records'],2)
