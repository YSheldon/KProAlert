import unittest
from unittest.mock import patch
import tempfile
from pathlib import Path
from notify import collect_alerts, collect_results, check, load_config


class NotifyTests(unittest.TestCase):
    def test_new_native_result_is_drafted_only_after_result_baseline(self):
        from notification_journal import NotificationJournal
        with tempfile.TemporaryDirectory() as directory:
            cfg={'state':str(Path(directory)/'notifications.db'),'source':{},
                 'operationsSource':{},'maxPages':1,'collectorHealth':None,
                 'knownSimulationIds':[],'profile':'home','context':{}}
            journal=NotificationJournal(cfg['state'])
            journal.baseline([],[])
            result=dict(recordId='a'*64,schema='FalconProNativeActionResult/v1',
                eventId='b'*64,evidenceSha256='c'*64,requestId='d'*64,decisionId='e'*64,
                action='switch_to_enforce',executionState='executed_verified',
                reportedOutcome='executed_verified',verificationProvenance='verified_locally_not_device_signed',
                beforePolicyVersion='100',targetPolicyVersion='101',afterPolicyVersion='101',simulated=False)
            with patch('notify.collect_alerts',return_value=([],0)), \
                 patch('notify.collect_results',return_value=([result],0)):
                self.assertTrue(check(cfg)['baselineRequired'])
                journal.baseline_results([])
                draft=[d for batch in check(cfg)['batches'] for d in batch['drafts']]
                self.assertEqual(len(draft),1)
                self.assertEqual(draft[0]['kind'],'result')
                self.assertEqual(draft[0]['recordId'],result['recordId'])
                self.assertFalse(draft[0]['deliveryConfirmed'])
                self.assertEqual(draft[0]['guidance']['profile'],'home')
                self.assertTrue(draft[0]['guidance']['questions'])
                self.assertEqual(check(cfg)['batches'],[])
            with patch('notify.collect_alerts',return_value=([],0)), \
                 patch('notify.collect_results',return_value=([],16)):
                failed=check(cfg)
                self.assertEqual(failed['faultCode'],16)
                self.assertTrue(failed['batches'])

    def test_result_pagination_requires_progress_and_reports_incomplete_coverage(self):
        calls=[]
        def reader(cli,base,table,limit,offset):
            calls.append(offset)
            return {'records':[],'hasMore':True,'nextOffset':offset+1}
        records,code=collect_results({'cli':'x','base':'b','table':'t'},2,reader)
        self.assertEqual((records,code),([],16))
        self.assertEqual(calls,[0])

    def test_operations_source_is_optional_but_must_be_explicit_when_present(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            base={'schema':'KProNotify/v1','state':str(root/'notifications.db'),
                  'source':{'cli':str(root/'lark.exe'),'base':'BASE','table':'ALERTS'},
                  'profile':'home','context':{},'knownSimulationIds':[],
                  'maxPages':1,'collectorHealth':None}
            config=root/'config.json'
            config.write_text(json.dumps(base),encoding='utf-8')
            self.assertNotIn('operationsSource',load_config(config))
            configured=dict(base,operationsSource={'cli':str(root/'lark.exe'),
                'base':'BASE','table':'OPERATIONS'})
            config.write_text(json.dumps(configured),encoding='utf-8')
            self.assertEqual(load_config(config)['operationsSource']['table'],'OPERATIONS')
            for value in ({'cli':'relative.exe','base':'BASE','table':'OPERATIONS'},
                          {'cli':str(root/'lark.exe'),'base':'BASE','table':'bad/path'}):
                config.write_text(json.dumps(dict(base,operationsSource=value)),encoding='utf-8')
                with self.assertRaises(ValueError):load_config(config)

    def test_conflicting_identity_is_not_silently_downgraded(self):
        pages=iter([
            {'alerts':[{'alertId':'a'*64,'eventType':0}], 'hasMore':True,'nextOffset':200},
            {'alerts':[{'alertId':'a'*64,'eventType':8}], 'hasMore':False}])
        alerts,code=collect_alerts({'cli':'x','base':'b','table':'t'},2,lambda *args:next(pages))
        self.assertEqual(code,1)
        self.assertEqual(alerts,[])

    def test_missing_cli_is_observable_source_fault(self):
        with tempfile.TemporaryDirectory() as directory:
            alerts,code=collect_alerts({'cli':str(Path(directory)/'missing.exe'),'base':'b','table':'t'},1)
            self.assertEqual(alerts,[])
            self.assertEqual(code,1)

    def test_check_journal_simulation_and_fault_transitions(self):
        from notification_journal import NotificationJournal
        with tempfile.TemporaryDirectory() as directory:
            cfg={'state':str(Path(directory)/'notifications.db'),'source':{},'maxPages':1,
                 'collectorHealth':None,'knownSimulationIds':['SIMULATED-'+'a'*64],
                 'profile':'office','context':{'ongoing_damage':True}}
            NotificationJournal(cfg['state']).baseline([],[])
            known={'alertId':'SIMULATED-'+'a'*64,'eventType':7,'simulated':True}
            spoof={'alertId':'SIMULATED-'+'b'*64,'eventType':7,'simulated':True}
            with patch('notify.collect_alerts',return_value=([known,spoof],0)):
                result=check(cfg)
                drafts=[d for b in result['batches'] for d in b['drafts']]
                self.assertEqual(len(drafts),1)
                self.assertEqual(drafts[0]['alertId'],spoof['alertId'])
                self.assertEqual(drafts[0]['guidance']['urgency'],'urgent_review')
                self.assertFalse(result['deliveryConfirmed'])
                self.assertEqual(check(cfg)['batches'],[])
            with patch('notify.collect_alerts',return_value=([],1)):
                self.assertTrue(check(cfg)['batches'])
                self.assertEqual(check(cfg)['batches'],[])
            with patch('notify.collect_alerts',return_value=([],0)):
                self.assertTrue(check(cfg)['batches'])
                self.assertEqual(check(cfg)['batches'],[])

    def test_bounded_pagination(self):
        calls=[]
        def reader(cli,base,table,limit,offset):
            calls.append(offset)
            return {'alerts':[{'alertId':'a'*64,'eventType':7}],
                    'hasMore':True,'nextOffset':offset+1}
        alerts,code=collect_alerts({'cli':'x','base':'b','table':'t'},2,reader)
        self.assertEqual(calls,[0,1])
        self.assertEqual(code,2)
        self.assertEqual(len(alerts),1)

    def test_failure_has_no_remote_error_text(self):
        def reader(*args,**kwargs): raise RuntimeError('private-token-value')
        result=collect_alerts({'cli':'x','base':'b','table':'t'},2,reader)
        self.assertEqual(result,([],1))
        self.assertNotIn('private-token-value',str(result))

    def test_nonadvancing_page_is_fault(self):
        def reader(*args,**kwargs):return {'alerts':[],'hasMore':True,'nextOffset':0}
        self.assertEqual(collect_alerts({'cli':'x','base':'b','table':'t'},2,reader),([],1))


if __name__=='__main__':unittest.main()
