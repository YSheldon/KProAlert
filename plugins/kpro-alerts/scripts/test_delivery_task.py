from pathlib import Path
import unittest


class TaskContractTests(unittest.TestCase):
    def test_interactive_user_only_and_no_overwrite(self):
        source = (Path(__file__).resolve().parents[3]/'Configure-KProDelivery.ps1').read_text()
        for contract in ('-LogonType Interactive', '-RunLevel Limited',
                         '-AtLogOn', 'Existing delivery task', 'delivery_worker.py',
                         'KProDelivery/v1', 'Start-ScheduledTask', 'Unregister-ScheduledTask'):
            self.assertIn(contract, source)
        for contract in ('Assert-KProTaskIdentity', "Principal.LogonType -ne 'Interactive'",
                         'Triggers[0].UserId', "State -eq 'Running'", 'Disable-ScheduledTask'):
            self.assertIn(contract, source)
        self.assertNotIn('-Password', source)
        self.assertNotIn('-RunLevel Highest', source)
        self.assertNotIn('ExecutionPolicy Bypass', source)


if __name__ == '__main__':
    unittest.main()
