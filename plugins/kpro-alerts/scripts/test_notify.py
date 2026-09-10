import unittest
from unittest.mock import patch
import tempfile
from pathlib import Path
from notify import collect_alerts, check


class NotifyTests(unittest.TestCase):
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
