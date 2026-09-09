import unittest
from guidance import advise


class GuidanceTests(unittest.TestCase):
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
