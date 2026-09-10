import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class PersonalizedMcpTests(unittest.IsolatedAsyncioTestCase):
    async def test_local_event_to_contextual_advice_over_real_stdio(self):
        with tempfile.TemporaryDirectory() as directory:
            database=Path(directory)/'events.db'
            db=sqlite3.connect(database)
            try:
                db.execute('CREATE TABLE events(id,device,session,received,raw)')
                db.execute('INSERT INTO events VALUES(?,?,?,?,?)',('a'*64,'test','session','2026-09-09',
                    json.dumps({'eventType':7,'operation':8,'path':'PRIVATE','cmdline':'SECRET'})))
                db.commit()
            finally:
                db.close()
            allowed={'PATH','SYSTEMROOT','WINDIR','TEMP','TMP','HOME','USERPROFILE','LOCALAPPDATA'}
            env={k:v for k,v in os.environ.items() if k.upper() in allowed}
            env['KPRO_ALERT_DATABASE']=str(database)
            params=StdioServerParameters(command=sys.executable,
                args=[str(Path(__file__).with_name('mcp_server.py'))],env=env)
            async with stdio_client(params) as (reader,writer):
                async with ClientSession(reader,writer) as client:
                    await client.initialize()
                    events=await client.call_tool('local_alerts',{'limit':1})
                    payload=json.loads(next(c.text for c in events.content if c.type=='text'))
                    uid=payload['events'][0]['eventId']
                    result=await client.call_tool('alert_guidance',{
                        'alert_id':uid,'source':'local','profile':'business_critical',
                        'context':{'ongoing_damage':True,'backup_status':'missing',
                                   'shared_storage':True,'recent_activity':'build'}})
                    text=next(c.text for c in result.content if c.type=='text')
                    value=json.loads(text)
                    self.assertEqual(value['guidance']['urgency'],'urgent_review')
                    self.assertEqual(value['guidance']['automaticActionsPerformed'],[])
                    self.assertIn('terminate_process',value['guidance']['approvalRequiredActions'])
                    self.assertNotIn('PRIVATE',text)
                    self.assertNotIn('SECRET',text)


if __name__=='__main__':unittest.main()
