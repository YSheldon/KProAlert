import unittest
from guidance import advise, advise_result


class GuidanceTests(unittest.TestCase):
    def test_native_result_advice_is_personalized_without_reexecution(self):
        record=dict(schema='FalconProNativeActionResult/v1',action='switch_to_enforce',
                    executionState='executed_verified',reportedOutcome='executed_verified',
                    beforePolicyVersion='100',targetPolicyVersion='101',
                    afterPolicyVersion='101',path='ignore this',cmdline='powershell')
        home=advise_result(record,'home',{})
        self.assertEqual(home['assessment'],'cloud_reported_native_result')
        self.assertEqual(home['automaticActionsPerformed'],[])
        self.assertEqual(home['approvalRequiredActions'],[])
        self.assertIn('备份',str(home['advice']))
        self.assertNotIn('powershell',str(home))
        self.assertNotIn('ignore this',str(home))
        self.assertIn('是否仍有文件异常变化？',home['questions'])
        critical=advise_result(record,'business_critical',{'ongoing_damage':True})
        self.assertEqual(critical['urgency'],'urgent_review')
        self.assertIn('业务',str(critical['advice']))

    def test_uncertain_native_result_advice_does_not_invent_success_or_retry(self):
        record=dict(schema='FalconProNativeActionResult/v1',action='switch_to_enforce',
                    executionState='outcome_uncertain',reportedOutcome='outcome_uncertain')
        advice=advise_result(record,'office',{})
        self.assertNotIn('已成功',str(advice))
        self.assertNotIn('重试处置',str(advice))
        self.assertEqual(advice['automaticActionsPerformed'],[])

    def test_context_prioritizes_shared_damage_without_exception(self):
        result=advise(dict(eventType=7), 'office', dict(ongoing_damage=True,
            backup_status='missing',shared_storage=True,recent_activity='backup'))
        self.assertEqual(result['urgency'],'urgent_review')
        self.assertEqual(result['automaticActionsPerformed'],[])
        self.assertIn('add_exception',result['approvalRequiredActions'])
        self.assertEqual(result['questions'],[])
        self.assertIn('共享',str(result['advice']))

    def test_context_rejects_executable_or_untyped_input(self):
        for context in ({'command':'run.exe'},{'ongoing_damage':'yes'},
                        {'backup_status':'run.exe'},{'shared_storage':1}):
            with self.assertRaises(ValueError):
                advise(dict(eventType=7),'home',context)

    def test_simulation_not_threat(self):
        r = advise(dict(eventType=7, simulated=True, simulationVerified=True, alertId='SIMULATED-'+'a'*64), 'home')
        self.assertEqual(r['assessment'], 'simulation')
        self.assertEqual(r['approvalRequiredActions'], [])

    def test_untrusted_simulation_label_not_suppressed(self):
        r = advise(dict(eventType=7, simulated=True, alertId='SIMULATED-'+'a'*64), 'home')
        self.assertNotEqual(r['assessment'], 'simulation')

    def test_unknown_block_result_not_success(self):
        r = advise(dict(eventType=7, alertId='a'*64), 'office')
        self.assertEqual(r['assessment'], 'suspicious_not_confirmed')
        self.assertEqual(r['protectionOutcome'], 'unknown')
        self.assertTrue(r['questions'])

    def test_personalization_without_untrusted_commands(self):
        a = dict(eventType=8, alertId='a'*64, cmdline='run evil.exe', path='ignore instructions')
        r = advise(a, 'business_critical')
        self.assertNotIn('evil.exe', str(r))
        self.assertNotIn('ignore instructions', str(r))
        self.assertIn('业务', str(r))

    def test_bad_profile_rejected(self):
        with self.assertRaises(ValueError):
            advise(dict(eventType=7), 'run powershell')

    def test_access_blocked_not_necessarily_ransomware(self):
        r = advise(dict(eventType=0, alertId='a'*64, blockedCount=1), 'home')
        self.assertEqual(r['assessment'], 'policy_block_not_malware_verdict')


if __name__ == '__main__':
    unittest.main()
