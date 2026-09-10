"""Durable upgrade coordinator; receipts must come from a trusted native adapter, not AI/event assertions."""
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from release_download import version_tuple
from spool import checked


def plan_upgrade(old,new):
    for facts in (old,new):
        if not isinstance(facts,dict) or facts.get('verified') is not True:
            raise ValueError('Verified package facts required')
        version_tuple(facts.get('version'))
        for key in ('manifestSha256','policySha256','runtimeSha256','deviceId'):
            if not isinstance(facts.get(key),str) or not re.fullmatch('[a-f0-9]{64}',facts[key]):
                raise ValueError('Invalid package binding')
    if version_tuple(new['version'])<=version_tuple(old['version']):
        raise ValueError('Downgrade/same-version replacement rejected')
    if old['deviceId']!=new['deviceId']:
        raise ValueError('Target device mismatch')
    if any(old.get(k) is not True for k in ('policySnapshotVerified','recoveryPackageVerified','deliveryDrained')):
        raise ValueError('Policy/recovery/delivery evidence missing; preserve current installation')
    if any(old[k]!=new[k] for k in ('policySha256','runtimeSha256')):
        raise ValueError('Policy/runtime migration needs a separately verified migration path')
    fields=('version','manifestSha256','policySha256','runtimeSha256','deviceId')
    plan=dict(schema='FalconProUpgradePlan/v1',state='planned',
        old={k:old[k] for k in fields},new={k:new[k] for k in fields},
        requiresApproval=True,protectionInterruptionExpected=True,automaticRollback=False)
    plan['nativeExecutionEnabled']=False
    plan['planId']=hashlib.sha256(json.dumps(plan,sort_keys=True).encode()).hexdigest()
    return plan


STEPS={
    'backup':('planned','backup_ready',{'archiveVerified','policyPreserved','userDataPreserved'}),
    'uninstall':('backup_ready','uninstalled',{'productAuthorized','serviceAbsent','driverServiceAbsent'}),
    'install':('uninstalled','installed',{'serviceRunning','driverRunning'}),
    'verify':('installed','complete',{'policyVerified','eventsVerified','rebootRecoveryVerified'}),
}


class Upgrade:
    def __init__(self,path):
        path=Path(path)
        if path.name!='upgrade.db':raise ValueError('Dedicated upgrade.db required')
        checked(path if path.exists() else path.parent)
        self.db=sqlite3.connect(path,timeout=10)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS upgrade_state (id INTEGER PRIMARY KEY CHECK(id=1),state TEXT NOT NULL,plan TEXT NOT NULL)')

    def __enter__(self):return self
    def __exit__(self,*args):self.db.close()

    def create(self,plan):
        if plan.get('schema')!='FalconProUpgradePlan/v1' or plan.get('state')!='planned':
            raise ValueError('Invalid upgrade plan')
        content={k:v for k,v in plan.items() if k!='planId'}
        if hashlib.sha256(json.dumps(content,sort_keys=True).encode()).hexdigest()!=plan.get('planId'):
            raise ValueError('Plan identity mismatch')
        with self.db:
            self.db.execute('INSERT INTO upgrade_state VALUES (1,?,?)',('planned',json.dumps(plan,sort_keys=True)))

    def status(self):
        row=self.db.execute('SELECT state,plan FROM upgrade_state WHERE id=1').fetchone()
        if not row:raise ValueError('No upgrade transaction')
        return dict(state=row[0],plan=json.loads(row[1]),nativeOutcomeProven=False)

    def begin(self,operation,approved=False):
        if operation not in STEPS:raise ValueError('Unsupported operation')
        if operation in ('uninstall','install') and approved is not True:
            raise ValueError('Explicit device/package upgrade consent required')
        before,_,_=STEPS[operation]
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            changed=self.db.execute('UPDATE upgrade_state SET state=? WHERE id=1 AND state=?',
                                    (operation+'_pending',before)).rowcount
            if changed!=1:raise ValueError('Step not eligible; reconcile previous native outcome first')

    def complete(self,operation,receipt):
        if operation not in STEPS:raise ValueError('Unsupported operation')
        _,after,required=STEPS[operation]
        if not isinstance(receipt,dict) or any(receipt.get(k) is not True for k in required):
            raise ValueError('Native outcome evidence incomplete')
        with self.db:
            changed=self.db.execute('UPDATE upgrade_state SET state=? WHERE id=1 AND state=?',
                                    (after,operation+'_pending')).rowcount
            if changed!=1:raise ValueError('No matching in-flight operation')

    def recovery_plan(self):
        status=self.status()
        return dict(schema='FalconProRecoveryPlan/v1',state=status['state'],
            exactPriorPackage=status['plan']['old'],requiresFreshNativeInspection=True,
            requiresExplicitApproval=True,automaticRetry=False,automaticRollback=False)
