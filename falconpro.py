"""One entry for FalconPro setup, signed installation, upgrades, and opt-in metrics."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SCRIPTS=Path(__file__).resolve().parent/'plugins/kpro-alerts/scripts'
sys.path.insert(0,str(SCRIPTS))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    status=commands.add_parser('status')
    status.add_argument('--device-id',default=os.environ.get('KPRO_ENDPOINT_DEVICE_ID',''))
    setup=commands.add_parser('setup')
    setup.add_argument('--client',choices=['codex','grok','workbuddy','cursor','zcode'],required=True)
    setup.add_argument('--database')
    setup.add_argument('--cli')
    setup.add_argument('--base')
    setup.add_argument('--table')
    setup.add_argument('--operations-table')
    setup.add_argument('--collector-health')
    setup.add_argument('--device-id')
    setup.add_argument('--operations-database')
    setup.add_argument('--native-entry')
    setup.add_argument('--native-entry-sha256')
    setup.add_argument('--apply',action='store_true')
    setup.add_argument('--update',action='store_true', help='Explicitly migrate an existing kpro-alerts connector')
    for verb in ('install','upgrade'):
        command=commands.add_parser(verb)
        command.add_argument('--device-id',default=os.environ.get('KPRO_ENDPOINT_DEVICE_ID',''))
        command.add_argument('--destination')
        command.add_argument('--plan',help='Existing verified download plan; required for resume/rollback')
        command.add_argument('--apply',action='store_true')
        command.add_argument('--approve',action='store_true')
        command.add_argument('--resume',action='store_true')
        command.add_argument('--rollback',action='store_true')
        command.add_argument('--metrics-database')
    metrics=commands.add_parser('metrics')
    metrics.add_argument('--database',required=True)
    metrics.add_argument('action',choices=['enable','disable','status','prepare','ack','uncertain','recover','upload'])
    metrics.add_argument('--consent',action='store_true')
    metrics.add_argument('--simulation',action='store_true')
    metrics.add_argument('--event-id')
    metrics.add_argument('--receipt')
    metrics.add_argument('--after',type=int,default=0)
    metrics.add_argument('--cli')
    metrics.add_argument('--base')
    metrics.add_argument('--table')
    metrics.add_argument('--apply',action='store_true')
    statistics=commands.add_parser('statistics')
    statistics.add_argument('--input',required=True)
    statistics.add_argument('--complete',action='store_true')
    native_metrics=commands.add_parser('metrics-native',help='Read a verified native transaction into existing opt-in metrics')
    native_metrics.add_argument('--database',required=True)
    native_metrics.add_argument('--entry',required=True)
    native_metrics.add_argument('--entry-sha256',required=True)
    native_metrics.add_argument('--device-id',required=True)
    native_metrics.add_argument('--transaction',required=True)
    ops = commands.add_parser('operations', help='Evidence-bound AI operations and explicit summary upload')
    ops.add_argument('action', choices=['status','events','upload','reconcile'])
    ops.add_argument('--database', required=True)
    ops.add_argument('--source', required=True)
    ops.add_argument('--after', type=int, default=0)
    ops.add_argument('--limit', type=int, default=100)
    ops.add_argument('--cli')
    ops.add_argument('--base')
    ops.add_argument('--table')
    ops.add_argument('--record-id')
    ops.add_argument('--remote-record-id')
    ops.add_argument('--apply', action='store_true')
    args=parser.parse_args()
    if args.command=='operations':
        from operations import status, events
        if args.action=='status':return status(args.database)
        if args.action=='events':return events(args.source,args.after,args.limit)
        from operations_upload import upload, reconcile
        if args.action=='reconcile':
            if not args.apply:raise ValueError('Reconciliation changes local delivery state; --apply is required')
            return reconcile(args.database,args.source,args.cli,args.base,args.table,args.record_id,args.remote_record_id)
        return upload(args.database,args.source,args.cli,args.base,args.table,apply=args.apply,limit=args.limit)
    if args.command=='metrics-native':
        from native_observation import collect_native_observation
        from native_receipt_reader import read_receipt
        event=collect_native_observation(args.database,lambda:read_receipt(
            args.entry,args.entry_sha256,args.device_id,args.transaction))
        return dict(state='metrics_recorded' if event else 'metrics_disabled',
                    event=event,uploaded=False,installPerformed=False)
    if args.command=='status':
        from endpoint import probe
        return probe(args.device_id)
    if args.command=='metrics':
        if args.action=='upload':
            from metrics_upload import upload
            return upload(args.database,args.cli,args.base,args.table,apply=args.apply)
        arguments=['--database',args.database,args.action]
        if args.consent:arguments+=['--consent']
        if args.simulation:arguments+=['--simulation']
        if args.event_id:arguments+=['--event-id',args.event_id]
        if args.receipt:arguments+=['--receipt',args.receipt]
        if args.after:arguments+=['--after',str(args.after)]
        returncode=subprocess.call([sys.executable,str(SCRIPTS/'metrics_journal.py'),*arguments])
        raise SystemExit(returncode)
    if args.command=='statistics':
        arguments=['--input',args.input]+(['--complete'] if args.complete else [])
        returncode=subprocess.call([sys.executable,str(SCRIPTS/'install_metrics.py'),*arguments])
        raise SystemExit(returncode)
    if args.command=='setup':
        from assistant_setup import make_plan,register,migrate,backup_native_client_configuration
        value=make_plan(args.client,args.database,args.cli,args.base,args.table,
                        collector_health=args.collector_health,endpoint_device_id=args.device_id,
                        operations_database=args.operations_database,native_entry=args.native_entry,
                        native_entry_sha256=args.native_entry_sha256,operations_table=args.operations_table)
        if args.update and args.native_entry:
            raise ValueError('Migration preserves existing environment; export reviewed native configuration separately instead of overwriting it')
        if args.update and not args.apply:
            return {**value, 'state':'migration_requires_apply',
                    'installsDriver':False, 'automaticRemediation':False}
        if not args.apply:return value
        # Reuse native client interfaces, with a non-destructive Cursor merge.
        import importlib.metadata
        if importlib.metadata.version('mcp')!='1.30.0':raise ValueError('Install the pinned requirements first')
        if args.client=='cursor':
            from cursor_setup import configure
            return configure(value['server'], upgrade=args.update)
        if args.client=='zcode':
            from zcode_setup import configure
            return configure(value['server'], upgrade=args.update)
        if args.update:
            if args.client not in ('codex','workbuddy'):
                raise ValueError('Grok migration requires its actual AddMcpServer host tool')
            backup=backup_native_client_configuration(value)
            result=migrate(value)
            return {**result, 'backupCreated':True, 'backupPath':str(backup)}
        return register(value)
    from lifecycle import plan,read_json,apply
    if args.resume and args.rollback:raise ValueError('Choose either resume or rollback')
    if args.plan:
        value=read_json(Path(args.plan))
        if value.get('operation')!=args.command:raise ValueError('Plan operation differs')
    else:
        if args.resume or args.rollback:raise ValueError('Resume/recovery requires the original plan')
        destination=Path(args.destination) if args.destination else Path(tempfile.mkdtemp(prefix='FalconPro-'))/'release'
        value=plan(args.command,destination,args.device_id)
        if value.get('schema')!='FalconProLifecyclePlan/v2':return value
        plan_path=destination/'lifecycle-plan.json'
        with plan_path.open('x',encoding='utf-8') as stream:json.dump(value,stream,indent=2)
        if not args.apply:return {**value,'planPath':str(plan_path)}
    if not args.apply:return value
    journal=None
    try:
        if args.metrics_database:
            from metrics_journal import Journal
            if not Path(args.metrics_database).is_file():raise ValueError('Enable metrics separately with consent first')
            journal=Journal(args.metrics_database)
        return apply(value,approval=args.approve,mode='resume' if args.resume else 'rollback' if args.rollback else None,
                     metrics=journal)
    finally:
        if journal:journal.close()


if __name__=='__main__':
    try:
        response=main()
        print(json.dumps(response,ensure_ascii=True))
        if response.get('state')=='attention_required':raise SystemExit(1)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        print(json.dumps(dict(state='blocked',errorClass=type(exc).__name__,message=str(exc))))
        raise SystemExit(1)
