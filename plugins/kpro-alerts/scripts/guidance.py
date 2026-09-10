"""Deterministic advice context, not a malware verdict or automatic remediation."""
PROFILES = ('home', 'office', 'developer', 'business_critical')
EVENT_NAMES = (
    'AccessBlocked', 'AccessAudited', 'PolicyChanged', 'DriverHealthChanged',
    'ProcessTermination', 'RansomwareFormatMismatch', 'RansomwareSuspiciousRename',
    'RansomwareBehaviorDetected', 'RansomwareSuspiciousCreate')


def validate_context(context):
    context={} if context is None else context
    if not isinstance(context,dict) or context.keys()-{'ongoing_damage','backup_status','shared_storage','recent_activity'}:
        raise ValueError('unsupported context fields')
    for field in ('ongoing_damage','shared_storage'):
        if field in context and type(context[field]) is not bool:
            raise ValueError('context flag must be boolean')
    for field,allowed in (
        ('backup_status',('unknown','verified','missing')),
        ('recent_activity',('unknown','none','install_update','build','backup','bulk_copy'))):
        if field in context and context[field] not in allowed:
            raise ValueError('unsupported context value')
    return dict(context)


def advise(alert, profile, context=None):
    if profile not in PROFILES:
        raise ValueError('unsupported profile')
    context=validate_context(context)
    kind = alert.get('eventType')
    if type(kind) is not int or not 0 <= kind < len(EVENT_NAMES):
        raise ValueError('unsupported event type')
    if alert.get('simulated') is True and alert.get('simulationVerified') is True:
        return dict(assessment='simulation', approvalRequiredActions=[],
                    advice=['这是通信测试记录，不代表真实威胁，不执行处置。'])
    assessment = ('suspicious_not_confirmed' if kind >= 5 else
                  'policy_block_not_malware_verdict' if kind == 0 else 'operational_event')
    blocked = alert.get('blockedCount')
    outcome = 'some_operations_blocked' if type(blocked) is int and blocked > 0 else 'unknown'
    advice = [
        '保留告警时间和证据，不要因单条告警直接删除文件或添加放行例外。',
        '核实是否正在安装、更新、备份或开发构建；这些背景用于复核，不自动构成白名单。',
        '若文件仍持续异常变化，先暂停本人发起的可疑操作并联系安全人员；需要断网时先确认业务影响。',
        '使用现有可信安全软件扫描；不要下载陌生解密器、支付赎金或覆盖唯一的备份。',
        '阻断部分操作不等于没有损失。确认威胁停止后再从已验证、未受影响的备份恢复。']
    if alert.get('simulated') is True:
        advice.insert(0, '记录声称是模拟事件，但未由本机测试白名单确认；先核对来源，不按该标签自动忽略。')
    if kind < 5:
        advice = ['这条记录本身不是勒索定论。先核对策略、操作语义和组件运行状态。',
                  '进程终止事件必须结合实际结果码，不能仅凭事件类型认定终止成功。']
    extra = {
        'home': '优先检查个人文档和照片的可用备份，不要把备份盘接入仍在异常写入的机器。',
        'office': '联系单位 IT，提供告警 ID；共享盘和同步盘恢复先与管理员协调。',
        'developer': '保留构建工具版本及任务时间，区别正常产物改名和异常覆盖，避免放行整个开发目录。',
        'business_critical': '关键业务主机先通知值班负责人，确认故障切换与取证方案，避免直接重启或终止核心服务。'}
    if context.get('ongoing_damage') is True:
        advice.insert(0,'用户报告仍有持续异常变化：优先联系安全人员并评估隔离范围；不得未经确认终止进程或切断关键业务。')
    if context.get('shared_storage') is True:
        advice.append('涉及共享盘或同步盘：通知相应管理员核查其他终端，先确认影响范围再进行恢复或暂停同步。')
    if context.get('backup_status') == 'missing':
        advice.append('目前没有确认可恢复的备份：保留原盘与证据，不覆盖现有文件，不先执行恢复或清理。')
    elif context.get('backup_status') == 'verified':
        advice.append('已有经验证的备份仍需保持隔离；确认威胁停止后，先恢复到干净环境验证，再安排业务切换。')
    if context.get('recent_activity') not in (None,'none','unknown'):
        advice.append('近期正常任务只作为复核背景，不构成自动放行依据；对照任务时间、工具来源与告警行为后再决定。')
    questions=[]
    for field,question in (
        ('ongoing_damage','是否仍有文件异常变化？'),
        ('recent_activity','当时正在执行什么任务？'),
        ('backup_status','是否有离线且验证可恢复的备份？'),
        ('shared_storage','是否涉及共享盘或同步盘？')):
        if field not in context or context[field]=='unknown':
            questions.append(question)
    return dict(eventType=kind, eventName=EVENT_NAMES[kind], assessment=assessment,
        protectionOutcome=outcome, profile=profile, advice=advice + [extra[profile]],
        context=context,contextTrust='user_supplied_not_independently_verified',
        urgency='urgent_review' if context.get('ongoing_damage') is True else 'review',
        questions=questions,
        limitations=['仅依据当前告警摘要；未扫描样本或证明文件已安全。',
                     '没有动作结果字段时，阻断、终止、恢复状态均为未知。'],
        approvalRequiredActions=['isolate_network', 'terminate_process', 'quarantine_file',
                                 'delete_file', 'add_exception', 'restore_backup'],
        automaticActionsPerformed=[])
