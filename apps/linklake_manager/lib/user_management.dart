import 'package:flutter/material.dart';

import 'api_client.dart';
import 'manager_identity.dart';
import 'rbac.dart';

class UserActionPolicy {
  const UserActionPolicy({
    required this.currentUsername,
    required this.currentSessionId,
    required this.enabledAdministratorCount,
  });

  final String currentUsername;
  final String? currentSessionId;
  final int enabledAdministratorCount;

  bool isCurrentUser(Map<String, dynamic> user) =>
      user['username']?.toString() == currentUsername;

  bool isLastEnabledAdministrator(Map<String, dynamic> user) =>
      user['enabled'] == true &&
      user['role'] == 'administrator' &&
      enabledAdministratorCount <= 1;

  bool canChangeRoleOrEnabled(Map<String, dynamic> user) =>
      !isCurrentUser(user) && !isLastEnabledAdministrator(user);

  bool canDelete(Map<String, dynamic> user) =>
      !isCurrentUser(user) && !isLastEnabledAdministrator(user);

  bool canResetPassword(Map<String, dynamic> user) => !isCurrentUser(user);

  bool canRevokeUserSessions(Map<String, dynamic> user) => !isCurrentUser(user);

  bool canRevokeSession(Map<String, dynamic> session) =>
      currentSessionId != null &&
      session['session_id'] != null &&
      session['session_id']?.toString() != currentSessionId;
}

class UserManagementPage extends StatefulWidget {
  const UserManagementPage({
    super.key,
    required this.api,
    required this.identity,
    required this.users,
    required this.sessions,
    required this.apiTokens,
    required this.capabilities,
    required this.chinese,
    required this.onRefresh,
    required this.onError,
  });

  final LinkLakeApi api;
  final Map<String, dynamic> identity;
  final List<dynamic> users;
  final List<dynamic> sessions;
  final List<dynamic> apiTokens;
  final RoleCapabilities capabilities;
  final bool chinese;
  final Future<void> Function() onRefresh;
  final ValueChanged<Object> onError;

  @override
  State<UserManagementPage> createState() => _UserManagementPageState();
}

class _UserManagementPageState extends State<UserManagementPage> {
  bool _working = false;

  String t(String chinese, String english) =>
      widget.chinese ? chinese : english;

  List<Map<String, dynamic>> get _users => widget.users
      .whereType<Map>()
      .map((value) => Map<String, dynamic>.from(value))
      .toList(growable: false);

  List<Map<String, dynamic>> get _sessions => widget.sessions
      .whereType<Map>()
      .map((value) => Map<String, dynamic>.from(value))
      .toList(growable: false);

  UserActionPolicy get _actionPolicy {
    final identity = ManagerIdentity.fromJson(widget.identity);
    return UserActionPolicy(
      currentUsername: identity.username,
      currentSessionId: identity.sessionId,
      enabledAdministratorCount: _users
          .where(
            (user) =>
                user['enabled'] == true && user['role'] == 'administrator',
          )
          .length,
    );
  }

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.all(24),
    child: ListView(
      children: [
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    t('用户与会话', 'Users and sessions'),
                    style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 3),
                  Text(
                    t(
                      '管理角色、启用状态、密码和交互式会话',
                      'Manage roles, enabled state, passwords, and interactive sessions',
                    ),
                  ),
                ],
              ),
            ),
            FilledButton.icon(
              key: const Key('create-user'),
              onPressed: _working || !widget.capabilities.canManageUsers
                  ? null
                  : () => _showUserEditor(),
              icon: const Icon(Icons.person_add_alt_1),
              label: Text(t('新建用户', 'New user')),
            ),
          ],
        ),
        const SizedBox(height: 16),
        _totpCard(),
        const SizedBox(height: 18),
        if (_users.isEmpty)
          _emptyCard(t('暂无用户', 'No users'))
        else
          for (final user in _users) _userCard(user),
        const SizedBox(height: 22),
        _apiTokenSection(),
        const SizedBox(height: 22),
        Text(
          t('活动会话', 'Active sessions'),
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        if (_sessions.isEmpty)
          _emptyCard(t('暂无活动会话', 'No active sessions'))
        else
          for (final session in _sessions) _sessionCard(session),
      ],
    ),
  );

  Widget _totpCard() {
    final enabled = widget.identity['totp_enabled'] == true;
    return Card(
      child: ListTile(
        leading: Icon(
          enabled ? Icons.verified_user_outlined : Icons.security_outlined,
        ),
        title: Text(t('双因素认证', 'Two-factor authentication')),
        subtitle: Text(
          enabled
              ? t(
                  '已启用，登录时需要动态验证码',
                  'Enabled; sign-in requires a verification code',
                )
              : t('未启用，当前仅使用密码登录', 'Disabled; password-only sign-in is active'),
        ),
        trailing: FilledButton.tonal(
          onPressed: _working || !widget.capabilities.canManageTotp
              ? null
              : _manageTotp,
          child: Text(enabled ? t('关闭', 'Disable') : t('设置', 'Set up')),
        ),
      ),
    );
  }

  Widget _userCard(Map<String, dynamic> user) {
    final enabled = user['enabled'] == true;
    final current = _actionPolicy.isCurrentUser(user);
    final protected = _actionPolicy.isLastEnabledAdministrator(user);
    final username = user['username']?.toString() ?? '-';
    return Card(
      key: Key('user-$username'),
      margin: const EdgeInsets.only(bottom: 10),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(
          children: [
            CircleAvatar(
              backgroundColor: enabled
                  ? Theme.of(context).colorScheme.primaryContainer
                  : Theme.of(context).colorScheme.surfaceContainerHighest,
              child: Icon(enabled ? Icons.person : Icons.person_off_outlined),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Wrap(
                    spacing: 8,
                    runSpacing: 6,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      Text(
                        user['display_name']?.toString() ?? username,
                        style: Theme.of(context).textTheme.titleMedium
                            ?.copyWith(fontWeight: FontWeight.w700),
                      ),
                      Chip(
                        visualDensity: VisualDensity.compact,
                        label: Text(user['role']?.toString() ?? 'auditor'),
                      ),
                      if (current)
                        Chip(
                          visualDensity: VisualDensity.compact,
                          label: Text(t('当前用户', 'Current user')),
                        ),
                      if (protected && !current)
                        Chip(
                          visualDensity: VisualDensity.compact,
                          label: Text(t('最后管理员', 'Last administrator')),
                        ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '$username · ${enabled ? t('已启用', 'Enabled') : t('已停用', 'Disabled')} '
                    '· ${t('会话', 'Sessions')}: ${user['active_sessions'] ?? 0}',
                  ),
                  if (user['must_change_password'] == true)
                    Text(
                      t(
                        '下次登录必须修改密码',
                        'Password change required at next sign-in',
                      ),
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.tertiary,
                      ),
                    ),
                ],
              ),
            ),
            PopupMenuButton<String>(
              key: Key('user-actions-$username'),
              enabled: !_working && widget.capabilities.canManageUsers,
              onSelected: (action) => switch (action) {
                'edit' => _showUserEditor(user),
                'password' => _resetPassword(user),
                'revoke' => _revokeUserSessions(user),
                'delete' => _deleteUser(user),
                _ => Future<void>.value(),
              },
              itemBuilder: (context) => [
                PopupMenuItem(
                  value: 'edit',
                  child: ListTile(
                    contentPadding: EdgeInsets.zero,
                    leading: const Icon(Icons.edit_outlined),
                    title: Text(t('编辑', 'Edit')),
                  ),
                ),
                PopupMenuItem(
                  value: 'password',
                  enabled: _actionPolicy.canResetPassword(user),
                  child: Tooltip(
                    message: current
                        ? t(
                            '不能从用户管理中重置当前账户的密码',
                            'The current account cannot be reset from user administration',
                          )
                        : '',
                    child: ListTile(
                      contentPadding: EdgeInsets.zero,
                      leading: const Icon(Icons.password_outlined),
                      title: Text(t('重置密码', 'Reset password')),
                    ),
                  ),
                ),
                PopupMenuItem(
                  value: 'revoke',
                  enabled: _actionPolicy.canRevokeUserSessions(user),
                  child: Tooltip(
                    message: current
                        ? t(
                            '当前账户必须通过退出登录结束当前会话',
                            'Use sign out to end the current account session',
                          )
                        : '',
                    child: ListTile(
                      contentPadding: EdgeInsets.zero,
                      leading: const Icon(Icons.phonelink_erase_outlined),
                      title: Text(t('撤销用户会话', 'Revoke user sessions')),
                    ),
                  ),
                ),
                PopupMenuItem(
                  value: 'delete',
                  enabled: _actionPolicy.canDelete(user),
                  child: Tooltip(
                    message: current
                        ? t('不能删除当前用户', 'The current user cannot be deleted')
                        : protected
                        ? t(
                            '不能删除最后一个已启用的管理员',
                            'The last enabled administrator cannot be deleted',
                          )
                        : '',
                    child: ListTile(
                      contentPadding: EdgeInsets.zero,
                      leading: const Icon(Icons.delete_outline),
                      title: Text(t('删除', 'Delete')),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _sessionCard(Map<String, dynamic> session) {
    final sessionId = session['session_id']?.toString() ?? '-';
    final current = !_actionPolicy.canRevokeSession(session);
    return Card(
      key: Key('session-$sessionId'),
      margin: const EdgeInsets.only(bottom: 10),
      child: ListTile(
        leading: Icon(
          current ? Icons.desktop_windows_outlined : Icons.devices_outlined,
        ),
        title: Text(
          '${session['username'] ?? '-'}${current ? ' · ${t('当前会话', 'Current session')}' : ''}',
        ),
        subtitle: Text(
          '${session['remote_addr'] ?? '-'} · '
          '${_formatTime(session['expires_unix_seconds'])}\n'
          '${session['user_agent'] ?? '-'}',
        ),
        isThreeLine: true,
        trailing: Tooltip(
          message: current
              ? t('当前会话必须通过退出登录结束', 'Use sign out to end the current session')
              : t('撤销会话', 'Revoke session'),
          child: IconButton(
            key: Key('revoke-session-$sessionId'),
            onPressed:
                _working || current || !widget.capabilities.canManageSessions
                ? null
                : () => _revokeSession(session),
            icon: const Icon(Icons.logout_outlined),
          ),
        ),
      ),
    );
  }

  Widget _apiTokenSection() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Row(
        children: [
          Expanded(
            child: Text(
              'API ${t('令牌', 'tokens')}',
              style: Theme.of(context).textTheme.titleMedium,
            ),
          ),
          FilledButton.icon(
            onPressed: _working || !widget.capabilities.canManageApiTokens
                ? null
                : _createApiToken,
            icon: const Icon(Icons.add),
            label: Text(t('新建令牌', 'New token')),
          ),
        ],
      ),
      const SizedBox(height: 8),
      if (widget.apiTokens.isEmpty) _emptyCard(t('暂无 API 令牌', 'No API tokens')),
      for (final raw in widget.apiTokens.whereType<Map>())
        Card(
          margin: const EdgeInsets.only(bottom: 10),
          child: ListTile(
            leading: const Icon(Icons.key_outlined),
            title: Text(raw['name']?.toString() ?? '-'),
            subtitle: Text(
              '${raw['scope']} · ${t('最后使用', 'Last used')}: '
              '${raw['last_used_unix_seconds'] == null ? t('从未', 'Never') : _formatTime(raw['last_used_unix_seconds'])}',
            ),
            trailing: IconButton(
              onPressed: _working || !widget.capabilities.canManageApiTokens
                  ? null
                  : () => _revokeApiToken(Map<String, dynamic>.from(raw)),
              icon: const Icon(Icons.delete_outline),
            ),
          ),
        ),
    ],
  );

  Future<void> _showUserEditor([Map<String, dynamic>? user]) async {
    if (!widget.capabilities.canManageUsers) return;
    final creating = user == null;
    final policy = _actionPolicy;
    final mutableRole = creating || policy.canChangeRoleOrEnabled(user);
    final username = TextEditingController(text: user?['username']?.toString());
    final displayName = TextEditingController(
      text: user?['display_name']?.toString(),
    );
    final password = TextEditingController();
    var role = user?['role']?.toString() ?? 'operator';
    var enabled = user?['enabled'] != false;
    var forcePasswordChange = true;
    var submitting = false;
    String? error;
    final saved = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => PopScope(
          canPop: !submitting,
          child: AlertDialog(
            title: Text(
              creating ? t('新建用户', 'New user') : t('编辑用户', 'Edit user'),
            ),
            content: SizedBox(
              width: 480,
              child: SingleChildScrollView(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    TextField(
                      controller: username,
                      enabled: creating && !submitting,
                      decoration: InputDecoration(
                        labelText: t('用户名', 'Username'),
                      ),
                    ),
                    const SizedBox(height: 10),
                    TextField(
                      controller: displayName,
                      enabled: !submitting,
                      decoration: InputDecoration(
                        labelText: t('显示名称', 'Display name'),
                      ),
                    ),
                    if (creating) ...[
                      const SizedBox(height: 10),
                      TextField(
                        controller: password,
                        enabled: !submitting,
                        obscureText: true,
                        decoration: InputDecoration(
                          labelText: t(
                            '密码（至少 12 位）',
                            'Password (12+ characters)',
                          ),
                        ),
                      ),
                    ],
                    const SizedBox(height: 10),
                    DropdownButtonFormField<String>(
                      initialValue: role,
                      items: const [
                        DropdownMenuItem(
                          value: 'administrator',
                          child: Text('administrator'),
                        ),
                        DropdownMenuItem(
                          value: 'operator',
                          child: Text('operator'),
                        ),
                        DropdownMenuItem(
                          value: 'auditor',
                          child: Text('auditor'),
                        ),
                      ],
                      onChanged: mutableRole && !submitting
                          ? (value) =>
                                setDialogState(() => role = value ?? role)
                          : null,
                      decoration: InputDecoration(labelText: t('角色', 'Role')),
                    ),
                    if (creating)
                      SwitchListTile(
                        contentPadding: EdgeInsets.zero,
                        value: forcePasswordChange,
                        onChanged: submitting
                            ? null
                            : (value) => setDialogState(
                                () => forcePasswordChange = value,
                              ),
                        title: Text(
                          t(
                            '下次登录强制修改密码',
                            'Require password change at next sign-in',
                          ),
                        ),
                      )
                    else
                      SwitchListTile(
                        key: const Key('edit-user-enabled'),
                        contentPadding: EdgeInsets.zero,
                        value: enabled,
                        onChanged: mutableRole && !submitting
                            ? (value) => setDialogState(() => enabled = value)
                            : null,
                        title: Text(t('启用用户', 'User enabled')),
                      ),
                    if (!mutableRole && !creating)
                      Text(
                        policy.isCurrentUser(user)
                            ? t(
                                '当前用户不能在此处停用或降权',
                                'The current user cannot be disabled or demoted here',
                              )
                            : t(
                                '最后一个已启用的管理员不能停用或降权',
                                'The last enabled administrator cannot be disabled or demoted',
                              ),
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                    if (error != null)
                      Padding(
                        padding: const EdgeInsets.only(top: 10),
                        child: Text(
                          error!,
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.error,
                          ),
                        ),
                      ),
                  ],
                ),
              ),
            ),
            actions: [
              TextButton(
                onPressed: submitting
                    ? null
                    : () => Navigator.pop(dialogContext, false),
                child: Text(t('取消', 'Cancel')),
              ),
              FilledButton(
                key: const Key('save-user'),
                onPressed: submitting
                    ? null
                    : () async {
                        try {
                          if (displayName.text.trim().isEmpty) {
                            throw FormatException(
                              t('请输入显示名称', 'Enter a display name'),
                            );
                          }
                          if (creating && password.text.length < 12) {
                            throw FormatException(
                              t(
                                '密码必须至少包含 12 个字符',
                                'Password must contain at least 12 characters',
                              ),
                            );
                          }
                          setDialogState(() {
                            submitting = true;
                            error = null;
                          });
                          if (creating) {
                            await widget.api.postObject('/api/v1/users', {
                              'username': username.text.trim(),
                              'display_name': displayName.text.trim(),
                              'role': role,
                              'password': password.text,
                              'force_password_change': forcePasswordChange,
                            });
                          } else {
                            await widget.api.putObject(
                              '/api/v1/users/${Uri.encodeComponent(username.text)}',
                              {
                                'display_name': displayName.text.trim(),
                                'role': role,
                                'enabled': enabled,
                              },
                            );
                          }
                          if (context.mounted) {
                            Navigator.pop(dialogContext, true);
                          }
                        } catch (value) {
                          if (!context.mounted) return;
                          setDialogState(() {
                            submitting = false;
                            error = value.toString();
                          });
                        }
                      },
                child: submitting
                    ? const SizedBox.square(
                        dimension: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : Text(t('保存', 'Save')),
              ),
            ],
          ),
        ),
      ),
    );
    await _disposeControllers([username, displayName, password]);
    if (saved == true) await _refreshAfterDialog();
  }

  Future<void> _resetPassword(Map<String, dynamic> user) async {
    if (!widget.capabilities.canManageUsers ||
        !_actionPolicy.canResetPassword(user)) {
      return;
    }
    final password = TextEditingController();
    var forcePasswordChange = true;
    var submitting = false;
    String? error;
    final reset = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => PopScope(
          canPop: !submitting,
          child: AlertDialog(
            title: Text(t('重置密码', 'Reset password')),
            content: SizedBox(
              width: 440,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  TextField(
                    controller: password,
                    enabled: !submitting,
                    obscureText: true,
                    decoration: InputDecoration(
                      labelText: t(
                        '新密码（至少 12 位）',
                        'New password (12+ characters)',
                      ),
                    ),
                  ),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    value: forcePasswordChange,
                    onChanged: submitting
                        ? null
                        : (value) =>
                              setDialogState(() => forcePasswordChange = value),
                    title: Text(
                      t(
                        '下次登录强制修改密码',
                        'Require password change at next sign-in',
                      ),
                    ),
                  ),
                  Text(
                    t(
                      '重置后该用户的所有现有会话都会被撤销。',
                      'Resetting also revokes every existing session for this user.',
                    ),
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                  if (error != null)
                    Text(
                      error!,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: submitting
                    ? null
                    : () => Navigator.pop(dialogContext, false),
                child: Text(t('取消', 'Cancel')),
              ),
              FilledButton(
                key: const Key('confirm-reset-password'),
                onPressed: submitting
                    ? null
                    : () async {
                        try {
                          if (password.text.length < 12) {
                            throw FormatException(
                              t(
                                '密码必须至少包含 12 个字符',
                                'Password must contain at least 12 characters',
                              ),
                            );
                          }
                          setDialogState(() {
                            submitting = true;
                            error = null;
                          });
                          await widget.api.post(
                            '/api/v1/users/${Uri.encodeComponent(user['username'].toString())}/reset-password',
                            {
                              'new_password': password.text,
                              'force_password_change': forcePasswordChange,
                            },
                          );
                          if (context.mounted) {
                            Navigator.pop(dialogContext, true);
                          }
                        } catch (value) {
                          if (!context.mounted) return;
                          setDialogState(() {
                            submitting = false;
                            error = value.toString();
                          });
                        }
                      },
                child: submitting
                    ? const SizedBox.square(
                        dimension: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : Text(t('重置密码', 'Reset password')),
              ),
            ],
          ),
        ),
      ),
    );
    await _disposeControllers([password]);
    if (reset == true) await _refreshAfterDialog();
  }

  Future<void> _revokeUserSessions(Map<String, dynamic> user) async {
    if (!widget.capabilities.canManageSessions ||
        !_actionPolicy.canRevokeUserSessions(user)) {
      return;
    }
    final confirmed = await _confirm(
      t(
        '撤销 ${user['username']} 的所有会话？',
        'Revoke every session for ${user['username']}?',
      ),
    );
    if (!confirmed) return;
    await _runAction(
      () => widget.api.post(
        '/api/v1/users/${Uri.encodeComponent(user['username'].toString())}/revoke-sessions',
      ),
    );
  }

  Future<void> _deleteUser(Map<String, dynamic> user) async {
    if (!widget.capabilities.canManageUsers || !_actionPolicy.canDelete(user)) {
      return;
    }
    final confirmed = await _confirm(
      t(
        '删除用户 ${user['username']}？此操作会同时撤销其会话。',
        'Delete ${user['username']} and revoke all of their sessions?',
      ),
    );
    if (!confirmed) return;
    await _runAction(
      () => widget.api.delete(
        '/api/v1/users/${Uri.encodeComponent(user['username'].toString())}',
      ),
    );
  }

  Future<void> _revokeSession(Map<String, dynamic> session) async {
    if (!widget.capabilities.canManageSessions ||
        !_actionPolicy.canRevokeSession(session)) {
      return;
    }
    final confirmed = await _confirm(t('撤销该会话？', 'Revoke this session?'));
    if (!confirmed) return;
    await _runAction(
      () => widget.api.delete(
        '/api/v1/sessions/${Uri.encodeComponent(session['session_id'].toString())}',
      ),
    );
  }

  Future<void> _manageTotp() async {
    if (!widget.capabilities.canManageTotp) return;
    final enabled = widget.identity['totp_enabled'] == true;
    final code = TextEditingController();
    String? secret;
    String? uri;
    String? error;
    if (!enabled) {
      try {
        final setup = await widget.api.postObject(
          '/api/v1/auth/totp/setup',
          {},
        );
        secret = setup['secret']?.toString();
        uri = setup['provisioning_uri']?.toString();
        if (secret == null || secret.isEmpty || uri == null || uri.isEmpty) {
          throw const LinkLakeApiException(
            500,
            'server did not return a TOTP setup secret',
            code: 'invalid_response',
          );
        }
      } catch (value) {
        if (mounted) widget.onError(value);
        code.dispose();
        return;
      }
    }
    if (!mounted) {
      code.dispose();
      return;
    }
    var submitting = false;
    final changed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => PopScope(
          canPop: !submitting,
          child: AlertDialog(
            title: Text(
              enabled
                  ? t('关闭双因素认证', 'Disable two-factor authentication')
                  : t('设置双因素认证', 'Set up two-factor authentication'),
            ),
            content: SizedBox(
              width: 520,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (!enabled) ...[
                    SelectableText('${t('设置密钥', 'Setup key')}: $secret'),
                    const SizedBox(height: 8),
                    SelectableText(uri ?? ''),
                    const SizedBox(height: 12),
                  ],
                  TextField(
                    controller: code,
                    enabled: !submitting,
                    autofocus: true,
                    keyboardType: TextInputType.number,
                    maxLength: 6,
                    decoration: InputDecoration(
                      labelText: t('动态验证码', 'Verification code'),
                      errorText: error,
                      counterText: '',
                    ),
                  ),
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: submitting
                    ? null
                    : () => Navigator.pop(dialogContext, false),
                child: Text(t('取消', 'Cancel')),
              ),
              FilledButton(
                onPressed: submitting
                    ? null
                    : () async {
                        try {
                          setDialogState(() {
                            submitting = true;
                            error = null;
                          });
                          await widget.api.post(
                            '/api/v1/auth/totp/${enabled ? 'disable' : 'enable'}',
                            {'code': code.text},
                          );
                          if (context.mounted) {
                            Navigator.pop(dialogContext, true);
                          }
                        } catch (value) {
                          if (!context.mounted) return;
                          setDialogState(() {
                            submitting = false;
                            error = value.toString();
                          });
                        }
                      },
                child: submitting
                    ? const SizedBox.square(
                        dimension: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : Text(enabled ? t('关闭', 'Disable') : t('启用', 'Enable')),
              ),
            ],
          ),
        ),
      ),
    );
    await _disposeControllers([code]);
    if (changed == true) await _refreshAfterDialog();
  }

  Future<void> _createApiToken() async {
    if (!widget.capabilities.canManageApiTokens) return;
    final name = TextEditingController();
    final days = TextEditingController();
    var scope = 'read';
    var submitting = false;
    String? error;
    final created = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => PopScope(
          canPop: !submitting,
          child: AlertDialog(
            title: Text(t('新建 API 令牌', 'New API token')),
            content: SizedBox(
              width: 460,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  TextField(
                    controller: name,
                    enabled: !submitting,
                    decoration: InputDecoration(labelText: t('名称', 'Name')),
                  ),
                  const SizedBox(height: 10),
                  DropdownButtonFormField<String>(
                    initialValue: scope,
                    items: const [
                      DropdownMenuItem(value: 'read', child: Text('read')),
                      DropdownMenuItem(value: 'write', child: Text('write')),
                      DropdownMenuItem(
                        value: 'administrator',
                        child: Text('administrator'),
                      ),
                    ],
                    onChanged: submitting
                        ? null
                        : (value) =>
                              setDialogState(() => scope = value ?? scope),
                    decoration: InputDecoration(labelText: t('权限范围', 'Scope')),
                  ),
                  const SizedBox(height: 10),
                  TextField(
                    controller: days,
                    enabled: !submitting,
                    keyboardType: TextInputType.number,
                    decoration: InputDecoration(
                      labelText: t('有效天数（可选）', 'Expiry days (optional)'),
                    ),
                  ),
                  if (error != null)
                    Text(
                      error!,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: submitting
                    ? null
                    : () => Navigator.pop(dialogContext),
                child: Text(t('取消', 'Cancel')),
              ),
              FilledButton(
                onPressed: submitting
                    ? null
                    : () async {
                        try {
                          final tokenName = name.text.trim();
                          if (tokenName.isEmpty) {
                            throw FormatException(
                              t('请输入令牌名称', 'Enter a token name'),
                            );
                          }
                          final expiryText = days.text.trim();
                          final expiryDays = expiryText.isEmpty
                              ? null
                              : int.tryParse(expiryText);
                          if (expiryText.isNotEmpty &&
                              (expiryDays == null || expiryDays <= 0)) {
                            throw FormatException(
                              t(
                                '有效天数必须是正整数',
                                'Expiry days must be a positive integer',
                              ),
                            );
                          }
                          setDialogState(() {
                            submitting = true;
                            error = null;
                          });
                          final value = await widget.api
                              .postObject('/api/v1/api-tokens', {
                                'name': tokenName,
                                'scope': scope,
                                'expires_unix_seconds': expiryDays == null
                                    ? null
                                    : DateTime.now().millisecondsSinceEpoch ~/
                                              1000 +
                                          expiryDays * 86400,
                              });
                          final token = value['token']?.toString() ?? '';
                          if (token.isEmpty) {
                            throw const LinkLakeApiException(
                              500,
                              'server did not return the one-time API token',
                              code: 'invalid_response',
                            );
                          }
                          if (context.mounted) {
                            Navigator.pop(dialogContext, value);
                          }
                        } catch (value) {
                          if (!context.mounted) return;
                          setDialogState(() {
                            submitting = false;
                            error = value.toString();
                          });
                        }
                      },
                child: submitting
                    ? const SizedBox.square(
                        dimension: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : Text(t('创建', 'Create')),
              ),
            ],
          ),
        ),
      ),
    );
    await _disposeControllers([name, days]);
    if (created == null || !mounted) return;
    final token = created['token']!.toString();
    await showDialog<void>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(t('请立即复制令牌', 'Copy this token now')),
        content: SelectableText(token),
        actions: [
          FilledButton(
            onPressed: () => Navigator.pop(context),
            child: Text(t('完成', 'Done')),
          ),
        ],
      ),
    );
    await _refreshAfterDialog();
  }

  Future<void> _revokeApiToken(Map<String, dynamic> token) async {
    if (!widget.capabilities.canManageApiTokens) return;
    final confirmed = await _confirm(
      t('撤销该 API 令牌？', 'Revoke this API token?'),
    );
    if (!confirmed) return;
    await _runAction(
      () => widget.api.delete(
        '/api/v1/api-tokens/${Uri.encodeComponent(token['id'].toString())}',
      ),
    );
  }

  Future<void> _runAction(Future<void> Function() action) async {
    if (_working || !mounted) return;
    setState(() => _working = true);
    try {
      await action();
      if (mounted) await widget.onRefresh();
    } catch (error) {
      if (mounted) widget.onError(error);
    } finally {
      if (mounted) setState(() => _working = false);
    }
  }

  Future<void> _refreshAfterDialog() async {
    if (!mounted) return;
    try {
      await widget.onRefresh();
    } catch (error) {
      if (mounted) widget.onError(error);
    }
  }

  Future<void> _disposeControllers(
    Iterable<TextEditingController> controllers,
  ) async {
    await Future<void>.delayed(const Duration(milliseconds: 350));
    for (final controller in controllers) {
      controller.dispose();
    }
  }

  Future<bool> _confirm(String message) async {
    if (!mounted) return false;
    return await showDialog<bool>(
          context: context,
          builder: (dialogContext) => AlertDialog(
            title: Text(t('确认操作', 'Confirm action')),
            content: Text(message),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(dialogContext, false),
                child: Text(t('取消', 'Cancel')),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(dialogContext, true),
                child: Text(t('确认', 'Confirm')),
              ),
            ],
          ),
        ) ??
        false;
  }

  Widget _emptyCard(String message) => Card(
    child: Padding(padding: const EdgeInsets.all(18), child: Text(message)),
  );

  String _formatTime(Object? value) {
    final seconds = int.tryParse(value?.toString() ?? '');
    if (seconds == null) return '-';
    final time = DateTime.fromMillisecondsSinceEpoch(seconds * 1000).toLocal();
    return time.toIso8601String().replaceFirst('T', ' ').split('.').first;
  }
}
