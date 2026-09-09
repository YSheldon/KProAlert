"""Deterministic advice context, not a malware verdict or automatic remediation."""
PROFILES = ('home', 'office', 'developer', 'business_critical')
EVENT_NAMES = (
    'AccessBlocked', 'AccessAudited', 'PolicyChanged', 'DriverHealthChanged',
    'ProcessTermination', 'RansomwareFormatMismatch', 'RansomwareSuspiciousRename',
    'RansomwareBehaviorDetected', 'RansomwareSuspiciousCreate')


def advise(alert, profile):
    if profile not in PROFILES:
        raise ValueError('unsupported profile')
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
    return dict(eventType=kind, eventName=EVENT_NAMES[kind], assessment=assessment,
        protectionOutcome=outcome, profile=profile, advice=advice + [extra[profile]],
        questions=['是否仍有文件异常变化？', '当时正在执行什么任务？', '是否有离线且验证可恢复的备份？'],
        limitations=['仅依据当前告警摘要；未扫描样本或证明文件已安全。',
                     '没有动作结果字段时，阻断、终止、恢复状态均为未知。'],
        approvalRequiredActions=['isolate_network', 'terminate_process', 'quarantine_file',
                                 'delete_file', 'add_exception', 'restore_backup'],
        automaticActionsPerformed=[])
