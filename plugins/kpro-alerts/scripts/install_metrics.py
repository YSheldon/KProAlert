"""Opt-in, transport-neutral metrics. No network, machine identity or automatic collection."""
import re
import secrets
import argparse
import json
from pathlib import Path
import time


KEYS={'schema','installationId','eventId','day','kind','version','architecture','osFamily','state','simulated'}
KINDS={'install_started','install_success','install_failure','status','uninstall',
       'upgrade_started','upgrade_success','upgrade_failure'}
STATES={'unknown','not_running','running_policy_unverified'}


def new_installation_id(*, consent=False):
    if type(consent) is not bool:
        raise ValueError('Explicit boolean consent required')
    return secrets.token_hex(16) if consent else None


def validate_event(event):
    if not isinstance(event,dict) or set(event)!=KEYS or event['schema']!='FalconProInstallMetrics/v1':
        raise ValueError('Unsupported metrics schema or fields')
    for key in ('installationId','eventId'):
        if not isinstance(event[key],str) or not re.fullmatch('[a-f0-9]{32}',event[key]):
            raise ValueError('Random opaque identifiers required')
    if type(event['day']) is not int or not 0<=event['day']<=200000:
        raise ValueError('UTC epoch day required')
    if type(event['simulated']) is not bool:
        raise ValueError('Explicit simulation marker required')
    for key, allowed in (('kind',KINDS),('state',STATES),('architecture',{'x86','x64','arm64'}),
                         ('osFamily',{'windows7','windows10','windows11','windows_server'})):
        if not isinstance(event[key],str) or event[key] not in allowed:
            raise ValueError('Unsupported metrics enum')
    if not isinstance(event['version'],str) or not re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,5}){3}',event['version']):
        raise ValueError('Numeric component version required')
    return dict(event)


def make_event(*, consent=False, installation_id=None, event_id=None, day=None,
               kind=None, version=None, architecture=None, os_family=None, state='unknown', simulated=False):
    if type(consent) is not bool:
        raise ValueError('Explicit boolean consent required')
    if not consent:
        return None
    return validate_event(dict(schema='FalconProInstallMetrics/v1',installationId=installation_id,
        eventId=event_id,day=day,kind=kind,version=version,architecture=architecture,
        osFamily=os_family,state=state,simulated=simulated))


def summarize(events, *, today, complete=False):
    if type(today) is not int or not 0<=today<=200000 or type(complete) is not bool:
        raise ValueError('Invalid statistics window')
    records={}
    for index, raw in enumerate(events):
        if index>=100000:
            raise ValueError('Statistics budget exceeded; use a bounded server aggregation')
        event=validate_event(raw)
        if event['simulated']:
            continue
        if event['day']>today:
            raise ValueError('Future observation requires clock investigation')
        key=(event['installationId'],event['eventId'])
        if key in records and records[key]!=event:
            raise ValueError('Conflicting duplicate metrics event')
        records[key]=event
    installed=set()
    observed={}
    removed={}
    versions={}
    for event in records.values():
        identity=event['installationId']
        if event['kind']=='install_success':
            installed.add(identity)
        if event['kind'] in ('status','install_success','upgrade_success'):
            observed[identity]=max(observed.get(identity,-1),event['day'])
            if today-29<=event['day']<=today:
                versions.setdefault(event['version'],set()).add(identity)
        if event['kind']=='uninstall':
            removed[identity]=max(removed.get(identity,-1),event['day'])
    active=lambda days: sum(1 for identity in installed
        if observed.get(identity,-1)>=today-days+1 and
        identity not in removed)
    return dict(schema='FalconProInstallStatistics/v1',sourceComplete=complete,
        scope='consenting reported installation IDs, not unique devices or people',
        successfulInstallations=len(installed),activeInstallations7d=active(7),
        activeInstallations30d=active(30),uniqueUsers=None,protectionVerified=False,
        reportedFailures=sum(e['kind']=='install_failure' for e in records.values()),
        reportedStarts=sum(e['kind']=='install_started' for e in records.values()),
        reportedUpgradeStarts=sum(e['kind']=='upgrade_started' for e in records.values()),
        reportedUpgradeSuccesses=sum(e['kind']=='upgrade_success' for e in records.values()),
        reportedUpgradeFailures=sum(e['kind']=='upgrade_failure' for e in records.values()),
        versionObservations30d={version:len(ids) for version,ids in sorted(versions.items())})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',required=True,help='authorized JSON array of exported metrics records')
    parser.add_argument('--complete',action='store_true',help='assert full authorized dataset, not a single page')
    args=parser.parse_args()
    path=Path(args.input)
    if path.stat().st_size>32*1024*1024:
        raise ValueError('Export exceeds local aggregation budget')
    data=json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(data,list):
        raise ValueError('Metrics record array required')
    print(json.dumps(summarize(data,today=int(time.time()//86400),complete=args.complete)))
