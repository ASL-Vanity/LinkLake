import 'dart:convert';
import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'api_client.dart';

const remoteUpdateActions = <String>[
  'check',
  'download',
  'apply',
  'status',
  'recover',
  'rollback',
];

const _remoteUpdateConfirmations = <String, String>{
  'check': 'CHECK',
  'download': 'DOWNLOAD',
  'apply': 'UPDATE',
  'status': 'STATUS',
  'recover': 'RECOVER',
  'rollback': 'ROLLBACK',
};

String? remoteUpdateConfirmationPhrase(String action) =>
    _remoteUpdateConfirmations[action];

bool remoteUpdateTaskCanCancel(Map<String, dynamic> task) =>
    !const {'succeeded', 'failed', 'cancelled'}.contains(task['state']) &&
    task['state'] != 'cancel_requested' &&
    task['cancel_requested'] != true;

class RemoteUpdateManagementPage extends StatefulWidget {
  const RemoteUpdateManagementPage({
    super.key,
    required this.api,
    required this.clients,
    required this.serverUpdate,
    required this.tasks,
    required this.chinese,
    required this.onRefresh,
    required this.onError,
  });

  final LinkLakeApi api;
  final List<dynamic> clients;
  final Map<String, dynamic> serverUpdate;
  final List<dynamic> tasks;
  final bool chinese;
  final Future<void> Function() onRefresh;
  final ValueChanged<Object> onError;

  @override
  State<RemoteUpdateManagementPage> createState() =>
      _RemoteUpdateManagementPageState();
}

class _RemoteUpdateManagementPageState
    extends State<RemoteUpdateManagementPage> {
  String? _selectedClientId;
  String _selectedAction = 'check';
  bool _busy = false;

  String t(String chinese, String english) =>
      widget.chinese ? chinese : english;

  List<Map<String, dynamic>> get _enabledClients => widget.clients
      .whereType<Map>()
      .map((client) => Map<String, dynamic>.from(client))
      .where(
        (client) =>
            client['enabled'] != false &&
            (client['client_id']?.toString().isNotEmpty ?? false),
      )
      .toList(growable: false);

  String? get _effectiveClientId {
    final clients = _enabledClients;
    if (clients.any(
      (client) => client['client_id']?.toString() == _selectedClientId,
    )) {
      return _selectedClientId;
    }
    return clients.isEmpty ? null : clients.first['client_id']?.toString();
  }

  bool get _remoteAvailable =>
      widget.serverUpdate['remote_client_update_available'] == true;

  @override
  Widget build(BuildContext context) {
    final clients = _enabledClients;
    final selectedClientId = _effectiveClientId;
    final tasks =
        widget.tasks
            .whereType<Map>()
            .map((task) => Map<String, dynamic>.from(task))
            .toList(growable: false)
          ..sort(
            (left, right) => _integer(
              right['updated_unix_seconds'],
            ).compareTo(_integer(left['updated_unix_seconds'])),
          );
    return Padding(
      padding: const EdgeInsets.fromLTRB(24, 20, 24, 32),
      child: ListView(
        key: const Key('remote-update-page'),
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      t('更新管理', 'Update management'),
                      style: Theme.of(context).textTheme.headlineSmall,
                    ),
                    const SizedBox(height: 4),
                    Text(
                      t(
                        '查看服务端更新状态，并向已注册客户端下发受限的签名更新任务。',
                        'Inspect server update state and dispatch bounded signed update tasks to enrolled clients.',
                      ),
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
                  ],
                ),
              ),
              Chip(
                avatar: Icon(
                  _remoteAvailable ? Icons.verified_outlined : Icons.block,
                  size: 18,
                ),
                label: Text(
                  _remoteAvailable
                      ? t('远程任务已启用', 'Remote tasks enabled')
                      : t('远程任务不可用', 'Remote tasks unavailable'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          _serverUpdateCard(),
          const SizedBox(height: 16),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(18),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    t('创建客户端更新任务', 'Create client update task'),
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 4),
                  Text(
                    t(
                      '仅支持六种内置动作；不接受任意命令、脚本、下载地址或降级参数。',
                      'Only six built-in actions are accepted; arbitrary commands, scripts, URLs, and downgrade flags are rejected.',
                    ),
                  ),
                  const SizedBox(height: 16),
                  LayoutBuilder(
                    builder: (context, constraints) {
                      final horizontal = constraints.maxWidth >= 720;
                      final fields = [
                        DropdownButtonFormField<String>(
                          key: const Key('remote-update-client'),
                          initialValue: selectedClientId,
                          decoration: InputDecoration(
                            labelText: t('目标客户端', 'Target client'),
                          ),
                          items: [
                            for (final client in clients)
                              DropdownMenuItem(
                                value: client['client_id']?.toString(),
                                child: Text(
                                  '${client['name'] ?? client['client_id']}${client['online'] == true ? ' · ${t('在线', 'online')}' : ''}',
                                ),
                              ),
                          ],
                          onChanged: _busy
                              ? null
                              : (value) =>
                                    setState(() => _selectedClientId = value),
                        ),
                        DropdownButtonFormField<String>(
                          key: const Key('remote-update-action'),
                          initialValue: _selectedAction,
                          decoration: InputDecoration(
                            labelText: t('更新动作', 'Update action'),
                          ),
                          items: [
                            for (final action in remoteUpdateActions)
                              DropdownMenuItem(
                                key: Key('remote-update-action-$action'),
                                value: action,
                                child: Text(_actionLabel(action)),
                              ),
                          ],
                          onChanged: _busy
                              ? null
                              : (value) => setState(
                                  () => _selectedAction = value ?? 'check',
                                ),
                        ),
                      ];
                      if (horizontal) {
                        return Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Expanded(child: fields[0]),
                            const SizedBox(width: 14),
                            Expanded(child: fields[1]),
                          ],
                        );
                      }
                      return Column(
                        children: [
                          fields[0],
                          const SizedBox(height: 12),
                          fields[1],
                        ],
                      );
                    },
                  ),
                  const SizedBox(height: 14),
                  Wrap(
                    spacing: 10,
                    runSpacing: 8,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      FilledButton.icon(
                        key: const Key('remote-update-create'),
                        onPressed:
                            _busy ||
                                !_remoteAvailable ||
                                selectedClientId == null
                            ? null
                            : () => _createTask(selectedClientId),
                        icon: _busy
                            ? const SizedBox.square(
                                dimension: 16,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                ),
                              )
                            : const Icon(Icons.add_task),
                        label: Text(t('创建任务', 'Create task')),
                      ),
                      Text(
                        t(
                          '提交前必须准确输入该动作的确认词。',
                          'The exact action-specific confirmation phrase is required.',
                        ),
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 20),
          Row(
            children: [
              Expanded(
                child: Text(
                  t('客户端更新任务', 'Client update tasks'),
                  style: Theme.of(context).textTheme.titleLarge,
                ),
              ),
              Chip(label: Text('${tasks.length}')),
            ],
          ),
          const SizedBox(height: 10),
          if (tasks.isEmpty)
            Card(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Text(t('暂无客户端更新任务。', 'No client update tasks.')),
              ),
            )
          else
            for (final task in tasks) _taskCard(task),
        ],
      ),
    );
  }

  Widget _serverUpdateCard() {
    final build = widget.serverUpdate['build'] is Map
        ? Map<String, dynamic>.from(widget.serverUpdate['build'] as Map)
        : const <String, dynamic>{};
    final status = widget.serverUpdate['status'] is Map
        ? Map<String, dynamic>.from(widget.serverUpdate['status'] as Map)
        : const <String, dynamic>{};
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              t('服务端更新状态', 'Server update state'),
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 28,
              runSpacing: 12,
              children: [
                _summaryValue(
                  t('已安装版本', 'Installed version'),
                  build['version'],
                ),
                _summaryValue(t('目标平台', 'Target platform'), build['target']),
                _summaryValue(
                  t('状态', 'State'),
                  status['state'] ?? t('空闲', 'idle'),
                ),
                _summaryValue(
                  t('签名策略', 'Signature policy'),
                  widget.serverUpdate['signature_policy'],
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _summaryValue(String label, Object? value) => SizedBox(
    width: 190,
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: Theme.of(context).textTheme.labelMedium),
        const SizedBox(height: 3),
        Text(
          value?.toString().isNotEmpty == true ? value.toString() : '—',
          style: Theme.of(context).textTheme.titleSmall,
        ),
      ],
    ),
  );

  Widget _taskCard(Map<String, dynamic> task) {
    final taskId = task['task_id']?.toString() ?? '';
    final canCancel = remoteUpdateTaskCanCancel(task);
    return Card(
      key: Key('remote-update-task-$taskId'),
      margin: const EdgeInsets.only(bottom: 10),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 14, 12, 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    '${_clientName(task['target_client_id'])} · ${_actionLabel(task['action']?.toString() ?? '')}',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                ),
                Chip(label: Text(_stateLabel(task['state']?.toString() ?? ''))),
              ],
            ),
            const SizedBox(height: 6),
            Text(
              '${t('阶段', 'Stage')}: ${_stageLabel(task['stage']?.toString() ?? '')} · '
              '${t('请求者', 'Requested by')}: ${task['requested_by'] ?? '—'} · '
              '${t('更新时间', 'Updated')}: ${_formatTimestamp(task['updated_unix_seconds'])}',
            ),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                OutlinedButton.icon(
                  key: Key('remote-update-details-$taskId'),
                  onPressed: _busy || taskId.isEmpty
                      ? null
                      : () => _showTaskDetails(taskId),
                  icon: const Icon(Icons.receipt_long_outlined),
                  label: Text(t('详情', 'Details')),
                ),
                if (canCancel)
                  TextButton.icon(
                    key: Key('remote-update-cancel-$taskId'),
                    onPressed: _busy || taskId.isEmpty
                        ? null
                        : () => _cancelTask(taskId),
                    icon: const Icon(Icons.cancel_outlined),
                    label: Text(t('取消任务', 'Cancel task')),
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _createTask(String targetClientId) async {
    final phrase = remoteUpdateConfirmationPhrase(_selectedAction);
    if (phrase == null) return;
    final confirmed = await _confirmPhrase(
      phrase: phrase,
      title: t('确认创建更新任务', 'Confirm update task'),
      message: t(
        '将为 ${_clientName(targetClientId)} 创建“${_actionLabel(_selectedAction)}”任务。',
        'Create the “${_actionLabel(_selectedAction)}” task for ${_clientName(targetClientId)}.',
      ),
    );
    if (!confirmed || !mounted) return;
    await _withBusy(() async {
      await widget.api.postObject('/api/v1/updates/clients/tasks', {
        'target_client_id': targetClientId,
        'action': _selectedAction,
        'idempotency_key': _idempotencyKey(_selectedAction, targetClientId),
        'confirmation': phrase,
      });
      await widget.onRefresh();
      _message(t('客户端更新任务已创建。', 'Client update task created.'));
    });
  }

  Future<void> _cancelTask(String taskId) async {
    final confirmed = await _confirmPhrase(
      phrase: 'CANCEL',
      title: t('确认取消任务', 'Confirm task cancellation'),
      message: t(
        '客户端可能已开始执行；取消请求只会在安全边界内生效。',
        'The client may already be running the task; cancellation is honored only at safe boundaries.',
      ),
    );
    if (!confirmed || !mounted) return;
    await _withBusy(() async {
      await widget.api.postObject(
        '/api/v1/updates/clients/tasks/$taskId/cancel',
        const {'confirmation': 'CANCEL'},
      );
      await widget.onRefresh();
      _message(t('已请求取消更新任务。', 'Update task cancellation requested.'));
    });
  }

  Future<void> _showTaskDetails(String taskId) async {
    Map<String, dynamic> detail;
    try {
      detail = await widget.api.getObject(
        '/api/v1/updates/clients/tasks/$taskId',
      );
    } catch (error) {
      _reportError(error);
      return;
    }
    if (!mounted) return;
    final task = detail['task'] is Map
        ? Map<String, dynamic>.from(detail['task'] as Map)
        : const <String, dynamic>{};
    final events = detail['events'] is List
        ? List<dynamic>.from(detail['events'] as List)
        : const <dynamic>[];
    final cancel = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        key: const Key('remote-update-detail-dialog'),
        title: Text(t('更新任务详情', 'Update task details')),
        content: SizedBox(
          width: math.min(MediaQuery.sizeOf(context).width - 48, 760),
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SelectableText(taskId),
                const SizedBox(height: 12),
                _detailValue(
                  t('目标客户端', 'Target client'),
                  _clientName(task['target_client_id']),
                ),
                _detailValue(
                  t('动作', 'Action'),
                  _actionLabel(task['action']?.toString() ?? ''),
                ),
                _detailValue(
                  t('状态', 'State'),
                  _stateLabel(task['state']?.toString() ?? ''),
                ),
                _detailValue(
                  t('阶段', 'Stage'),
                  _stageLabel(task['stage']?.toString() ?? ''),
                ),
                _detailValue(
                  t('恢复状态', 'Recovery state'),
                  task['recovery_state'],
                ),
                _detailValue(t('尝试次数', 'Attempt'), task['attempt']),
                _detailValue(t('请求者', 'Requested by'), task['requested_by']),
                _detailValue(
                  t('创建时间', 'Created'),
                  _formatTimestamp(task['created_unix_seconds']),
                ),
                _detailValue(
                  t('更新时间', 'Updated'),
                  _formatTimestamp(task['updated_unix_seconds']),
                ),
                _detailValue(
                  t('完成时间', 'Completed'),
                  _formatTimestamp(task['completed_unix_seconds']),
                ),
                if (task['error_code'] != null)
                  _detailValue(t('错误代码', 'Error code'), task['error_code']),
                if (task['result'] != null)
                  _detailValue(
                    t('执行结果', 'Result'),
                    const JsonEncoder.withIndent('  ').convert(task['result']),
                  ),
                const SizedBox(height: 16),
                Text(
                  t('任务事件', 'Task events'),
                  style: Theme.of(context).textTheme.titleMedium,
                ),
                const SizedBox(height: 8),
                if (events.isEmpty)
                  Text(t('暂无任务事件。', 'No task events.'))
                else
                  for (final raw in events.whereType<Map>())
                    _eventTile(Map<String, dynamic>.from(raw)),
              ],
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: Text(t('关闭', 'Close')),
          ),
          if (remoteUpdateTaskCanCancel(task))
            FilledButton.tonalIcon(
              key: const Key('remote-update-detail-cancel'),
              onPressed: () => Navigator.pop(dialogContext, true),
              icon: const Icon(Icons.cancel_outlined),
              label: Text(t('取消任务', 'Cancel task')),
            ),
        ],
      ),
    );
    if (cancel == true && mounted) await _cancelTask(taskId);
  }

  Widget _detailValue(String label, Object? value) => Padding(
    padding: const EdgeInsets.only(bottom: 6),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 128,
          child: Text(label, style: Theme.of(context).textTheme.labelMedium),
        ),
        Expanded(child: SelectableText(value?.toString() ?? '—')),
      ],
    ),
  );

  Widget _eventTile(Map<String, dynamic> event) => Card.outlined(
    margin: const EdgeInsets.only(bottom: 8),
    child: ListTile(
      dense: true,
      leading: CircleAvatar(
        radius: 17,
        child: Text('#${event['sequence'] ?? '—'}'),
      ),
      title: Text(_eventLabel(event['kind']?.toString() ?? '')),
      subtitle: Text(
        '${_stateLabel(event['state']?.toString() ?? '')} · '
        '${_stageLabel(event['stage']?.toString() ?? '')}'
        '${event['error_code'] == null ? '' : ' · ${event['error_code']}'}',
      ),
      trailing: Text(_formatTimestamp(event['created_unix_seconds'])),
    ),
  );

  Future<bool> _confirmPhrase({
    required String phrase,
    required String title,
    required String message,
  }) async =>
      await showDialog<bool>(
        context: context,
        builder: (_) => _ExactConfirmationDialog(
          phrase: phrase,
          title: title,
          message: message,
          chinese: widget.chinese,
        ),
      ) ==
      true;

  Future<void> _withBusy(Future<void> Function() action) async {
    if (_busy) return;
    setState(() => _busy = true);
    try {
      await action();
    } catch (error) {
      _reportError(error);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _reportError(Object error) {
    widget.onError(error);
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(error.toString())));
  }

  void _message(String value) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(value)));
  }

  String _idempotencyKey(String action, String clientId) {
    final random = math.Random.secure().nextInt(0x7fffffff).toRadixString(16);
    return '$action:$clientId:${DateTime.now().microsecondsSinceEpoch}:$random';
  }

  String _clientName(Object? clientId) {
    final id = clientId?.toString() ?? '';
    for (final client in _enabledClients) {
      if (client['client_id']?.toString() == id) {
        return client['name']?.toString().isNotEmpty == true
            ? client['name'].toString()
            : id;
      }
    }
    return id.isEmpty ? '—' : id;
  }

  String _actionLabel(String action) => switch (action) {
    'check' => t('检查', 'Check'),
    'download' => t('下载', 'Download'),
    'apply' => t('安装', 'Apply'),
    'status' => t('状态', 'Status'),
    'recover' => t('恢复', 'Recover'),
    'rollback' => t('回滚', 'Rollback'),
    _ => action.isEmpty ? t('未知', 'Unknown') : action,
  };

  String _stateLabel(String state) => switch (state) {
    'queued' => t('排队中', 'Queued'),
    'claimed' => t('已领取', 'Claimed'),
    'running' => t('执行中', 'Running'),
    'cancel_requested' => t('正在取消', 'Cancel requested'),
    'succeeded' => t('成功', 'Succeeded'),
    'failed' => t('失败', 'Failed'),
    'cancelled' => t('已取消', 'Cancelled'),
    _ => state.isEmpty ? t('未知', 'Unknown') : state,
  };

  String _stageLabel(String stage) => switch (stage) {
    'queued' => t('排队', 'Queued'),
    'claimed' => t('已领取', 'Claimed'),
    'checking' => t('检查中', 'Checking'),
    'downloading' => t('下载中', 'Downloading'),
    'applying' => t('安装中', 'Applying'),
    'inspecting' => t('检查状态', 'Inspecting'),
    'recovering' => t('恢复中', 'Recovering'),
    'rolling_back' => t('回滚中', 'Rolling back'),
    'awaiting_restart' => t('等待重启', 'Awaiting restart'),
    'completed' => t('已完成', 'Completed'),
    'failed' => t('失败', 'Failed'),
    'cancelled' => t('已取消', 'Cancelled'),
    _ => stage.isEmpty ? t('未知', 'Unknown') : stage,
  };

  String _eventLabel(String kind) => switch (kind) {
    'created' => t('任务已创建', 'Created'),
    'idempotent_replay' => t('幂等重放', 'Idempotent replay'),
    'claimed' => t('任务已领取', 'Claimed'),
    'lease_renewed' => t('租约已续期', 'Lease renewed'),
    'stage_reported' => t('阶段已上报', 'Stage reported'),
    'cancel_requested' => t('已请求取消', 'Cancel requested'),
    'cancelled' => t('任务已取消', 'Cancelled'),
    'succeeded' => t('任务成功', 'Succeeded'),
    'failed' => t('任务失败', 'Failed'),
    'lease_expired_requeued' => t('租约过期并重新排队', 'Lease expired and requeued'),
    'lease_expired_failed_closed' => t(
      '租约过期并关闭失败',
      'Lease expired and failed closed',
    ),
    'restart_reconciled' => t('重启状态已协调', 'Restart reconciled'),
    _ => kind.isEmpty ? t('未知事件', 'Unknown event') : kind,
  };

  int _integer(Object? value) => switch (value) {
    int number => number,
    num number => number.toInt(),
    _ => int.tryParse(value?.toString() ?? '') ?? 0,
  };

  String _formatTimestamp(Object? value) {
    final seconds = _integer(value);
    if (seconds <= 0) return '—';
    return DateTime.fromMillisecondsSinceEpoch(
      seconds * 1000,
      isUtc: true,
    ).toLocal().toString().split('.').first;
  }
}

// 独立组件负责确认词输入框的生命周期，关闭弹窗时即可安全释放控制器。
class _ExactConfirmationDialog extends StatefulWidget {
  const _ExactConfirmationDialog({
    required this.phrase,
    required this.title,
    required this.message,
    required this.chinese,
  });

  final String phrase;
  final String title;
  final String message;
  final bool chinese;

  @override
  State<_ExactConfirmationDialog> createState() =>
      _ExactConfirmationDialogState();
}

class _ExactConfirmationDialogState extends State<_ExactConfirmationDialog> {
  final TextEditingController _controller = TextEditingController();
  bool _exact = false;

  String t(String chinese, String english) =>
      widget.chinese ? chinese : english;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text(widget.title),
    content: SizedBox(
      width: 480,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(widget.message),
          const SizedBox(height: 14),
          Text(
            t(
              '请输入确认词：${widget.phrase}',
              'Type the confirmation phrase: ${widget.phrase}',
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            key: const Key('remote-update-confirmation'),
            controller: _controller,
            autofocus: true,
            autocorrect: false,
            enableSuggestions: false,
            decoration: InputDecoration(hintText: widget.phrase),
            onChanged: (value) =>
                setState(() => _exact = value == widget.phrase),
          ),
        ],
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context, false),
        child: Text(t('取消', 'Cancel')),
      ),
      FilledButton(
        key: const Key('remote-update-confirm'),
        onPressed: _exact ? () => Navigator.pop(context, true) : null,
        child: Text(t('确认', 'Confirm')),
      ),
    ],
  );
}
