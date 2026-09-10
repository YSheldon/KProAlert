import tempfile
import unittest
from pathlib import Path
from upgrade_state import Upgrade, plan_upgrade


def facts():
    return dict(version='1.2.0.267',manifestSha256='a'*64,policySha256='b'*64,
        runtimeSha256='c'*64,verified=True,policySnapshotVerified=True,
        recoveryPackageVerified=True,deliveryDrained=True,deviceId='d'*64)


class UpgradeTests(unittest.TestCase):
    def test_downgrade_and_unverified_policy_block(self):
        old=facts();new={**old,'version':'1.2.0.300','manifestSha256':'e'*64}
        self.assertEqual(plan_upgrade(old,new)['state'],'planned')
        with self.assertRaises(ValueError):plan_upgrade(new,old)
        with self.assertRaises(ValueError):plan_upgrade({**old,'policySnapshotVerified':False},new)
        with self.assertRaises(ValueError):plan_upgrade(old,{**new,'policySha256':'f'*64})

    def test_crash_after_intent_never_retries_automatically(self):
        with tempfile.TemporaryDirectory() as folder:
            with Upgrade(Path(folder)/'upgrade.db') as u:
                plan=plan_upgrade(facts(),{**facts(),'version':'1.2.0.300','manifestSha256':'e'*64})
                u.create(plan)
                u.begin('backup',approved=False)
                with self.assertRaises(ValueError):u.begin('backup',approved=False)
            with Upgrade(Path(folder)/'upgrade.db') as u:
                self.assertEqual(u.status()['state'],'backup_pending')
                with self.assertRaises(ValueError):u.begin('uninstall',approved=True)

    def test_receipts_and_approval_required(self):
        with tempfile.TemporaryDirectory() as folder:
            with Upgrade(Path(folder)/'upgrade.db') as u:
                u.create(plan_upgrade(facts(),{**facts(),'version':'1.2.0.300','manifestSha256':'e'*64}))
                u.begin('backup')
                with self.assertRaises(ValueError):u.complete('backup',{'ok':True})
                u.complete('backup',{'archiveVerified':True,'policyPreserved':True,'userDataPreserved':True})
                with self.assertRaises(ValueError):u.begin('uninstall')
                u.begin('uninstall',approved=True)
                u.complete('uninstall',{'productAuthorized':True,'serviceAbsent':True,'driverServiceAbsent':True})
                u.begin('install',approved=True)
                u.complete('install',{'serviceRunning':True,'driverRunning':True})
                u.begin('verify')
                u.complete('verify',{'policyVerified':True,'eventsVerified':True,'rebootRecoveryVerified':True})
                self.assertEqual(u.status()['state'],'complete')


if __name__=='__main__':unittest.main()
