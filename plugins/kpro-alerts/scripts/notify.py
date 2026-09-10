"""Bounded notification preparation. Does not send messages or execute remediation."""
import argparse
import json
from pathlib import Path
import re

from feishu_reader import read
from guidance import advise, validate_context, PROFILES
from collector_health import read_health
from spool import checked


def collect_alerts(source, max_pages, reader=read):
    alerts,seen,offset=[],{},0
    for _ in range(max_pages):
        try:
            if reader is read and not checked(source['cli']).is_file():
                raise ValueError('authorized source CLI unavailable')
            page=reader(source['cli'],source['base'],source['table'],200,offset)
            if not isinstance(page,dict) or type(page.get('hasMore')) is not bool:
                raise ValueError('invalid page')
            rows=page.get('alerts')
            if not isinstance(rows,list) or len(rows)>200:
                raise ValueError('invalid rows')
            for row in rows:
                if not isinstance(row,dict) or not isinstance(row.get('alertId'),str):
                    raise ValueError('invalid alert')
                if not re.fullmatch(r'(?:SIMULATED-)?[a-f0-9]{64}',row['alertId']):
                    raise ValueError('invalid ID')
                if type(row.get('eventType')) is not int or not 0<=row['eventType']<=8:
                    raise ValueError('invalid type')
                uid=row['alertId']
                canonical=json.dumps(row,sort_keys=True,allow_nan=False)
                if uid in seen and seen[uid]!=canonical:
                    return [item for item in alerts if item['alertId']!=uid],1
                if uid not in seen:
                    seen[uid]=canonical;alerts.append(row)
            if not page['hasMore']:
                return alerts,0
            next_offset=page.get('nextOffset')
            if type(next_offset) is not int or next_offset<=offset:
                raise ValueError('pagination did not advance')
            offset=next_offset
        except Exception:
            return alerts,1
    return alerts,2


def load_config(path):
    path=checked(path)
    if path.stat().st_size>16384:
        raise ValueError('configuration too large')
    cfg=json.loads(path.read_text(encoding='utf-8-sig'))
    keys={'schema','state','source','profile','context','knownSimulationIds','maxPages','collectorHealth'}
    if not isinstance(cfg,dict) or cfg.keys()!=keys or cfg['schema']!='KProNotify/v1':
        raise ValueError('unsupported notification configuration')
    state=Path(cfg['state'])
    if not state.is_absolute() or state.name!='notifications.db':
        raise ValueError('absolute notifications.db required')
    checked(state if state.exists() else state.parent)
    if cfg['profile'] not in PROFILES:
        raise ValueError('unsupported profile')
    cfg['context']=validate_context(cfg['context'])
    if type(cfg['maxPages']) is not int or not 1<=cfg['maxPages']<=10:
        raise ValueError('maxPages must be 1..10')
    ids=cfg['knownSimulationIds']
    if not isinstance(ids,list) or len(ids)>200 or any(not isinstance(i,str) or not re.fullmatch(r'SIMULATED-[a-f0-9]{64}',i) for i in ids):
        raise ValueError('explicit known simulation IDs required')
    source=cfg['source']
    if not isinstance(source,dict) or source.keys()!={'cli','base','table'}:
        raise ValueError('invalid source')
    if not isinstance(source['cli'],str) or not Path(source['cli']).is_absolute():
        raise ValueError('explicit authorized CLI required')
    if any(not isinstance(source[k],str) or not re.fullmatch(r'[A-Za-z0-9]{1,128}',source[k]) for k in ('base','table')):
        raise ValueError('invalid source identity')
    if cfg['collectorHealth'] is not None and (not isinstance(cfg['collectorHealth'],str) or not Path(cfg['collectorHealth']).is_absolute()):
        raise ValueError('absolute health path required')
    return cfg


def check(cfg):
    from notification_journal import NotificationJournal
    journal=NotificationJournal(cfg['state'])
    if not journal.status()['initialized']:
        return {'error':'Notification baseline is not initialized','baselineRequired':True,
                'deliveryConfirmed':False,'automaticRemediation':False}
    alerts,code=collect_alerts(cfg['source'],cfg['maxPages'])
    if cfg['collectorHealth']:
        try:
            health=read_health(cfg['collectorHealth'])
            if not health['receiptFresh'] or health['stopped'] or health['status']!=0 or health['collectorDropped']:
                code|=8
        except Exception:
            code|=4
    batches=[]
    for start in range(0,len(alerts),200):
        batch=journal.prepare(alerts[start:start+200],cfg['knownSimulationIds'])
        if batch['drafts']:batches.append(batch)
    fault=journal.prepare([],[],{'active':bool(code),'code':code})
    if fault['drafts']:batches.append(fault)
    for batch in batches:
        for draft in batch['drafts']:
            if draft['kind']=='alert':
                draft['guidance']=advise(dict(draft['fields'],alertId=draft['alertId']),cfg['profile'],cfg['context'])
            else:
                draft['advice']=['告警采集状态发生变化，请检查数据源及本机采集器；这不是勒索检测结论，也不证明防护正常。']
    return {'schema':'KProNotificationCheck/v1','batches':batches,'faultCode':code,
            'sourceComplete':code&3==0,'collectorConfigured':bool(cfg['collectorHealth']),
            'profile':cfg['profile'],'context':cfg['context'],
            'deliveryConfirmed':False,'automaticRemediation':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('baseline','check','ack','uncertain','status'))
    parser.add_argument('--config',required=True)
    parser.add_argument('--token')
    parser.add_argument('--receipt')
    parser.add_argument('--after')
    args=parser.parse_args()
    if args.after and args.command!='status':
        raise ValueError('pending cursor is only valid for status')
    cfg=load_config(args.config)
    if args.command=='baseline':
        from notification_journal import NotificationJournal
        alerts,code=collect_alerts(cfg['source'],cfg['maxPages'])
        if code:raise ValueError('Complete source read required for baseline')
        result=NotificationJournal(cfg['state']).baseline(alerts,cfg['knownSimulationIds'])
    elif args.command=='check':
        result=check(cfg)
    else:
        from notification_journal import NotificationJournal
        journal=NotificationJournal(cfg['state'])
        if args.command!='status' and not args.token:raise ValueError('bound token required')
        if args.command=='ack':journal.ack(args.token,args.receipt)
        elif args.command=='uncertain':journal.mark_uncertain(args.token)
        result=journal.status(args.token,args.after)
    print(json.dumps(result,ensure_ascii=True,allow_nan=False))


if __name__=='__main__':
    try:main()
    except Exception:
        print(json.dumps({'error':'Notification check failed; inspect local configuration or journal',
                          'deliveryConfirmed':False,'automaticRemediation':False}))
        raise SystemExit(1)
