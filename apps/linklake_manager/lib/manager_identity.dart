import 'package:flutter/material.dart';

class ManagerIdentity {
  const ManagerIdentity({
    required this.username,
    required this.displayName,
    required this.role,
    required this.authenticationType,
    required this.sessionId,
    required this.expiresUnixSeconds,
  });

  factory ManagerIdentity.fromJson(Map<String, dynamic> value) =>
      ManagerIdentity(
        username: value['username']?.toString() ?? '-',
        displayName: value['display_name']?.toString() ?? '',
        role: value['role']?.toString() ?? 'auditor',
        authenticationType:
            value['authentication_type']?.toString() ?? 'unknown',
        sessionId: value['session_id']?.toString(),
        expiresUnixSeconds: int.tryParse(
          value['expires_unix_seconds']?.toString() ?? '',
        ),
      );

  final String username;
  final String displayName;
  final String role;
  final String authenticationType;
  final String? sessionId;
  final int? expiresUnixSeconds;

  String get primaryName => displayName.trim().isEmpty ? username : displayName;

  String roleLabel(bool chinese) => switch (role) {
    'administrator' => chinese ? '管理员' : 'Administrator',
    'operator' => chinese ? '操作员' : 'Operator',
    _ => chinese ? '审计员' : 'Auditor',
  };

  String authenticationLabel(bool chinese) => switch (authenticationType) {
    'session' ||
    'password' ||
    'password_session' => chinese ? '密码会话' : 'Password session',
    'api_token' || 'token' => chinese ? 'API 令牌' : 'API token',
    _ => chinese ? '未知认证' : 'Unknown authentication',
  };
}

class ManagerIdentityBadge extends StatelessWidget {
  const ManagerIdentityBadge({
    super.key,
    required this.identity,
    required this.chinese,
    this.compact = false,
  });

  final ManagerIdentity identity;
  final bool chinese;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final subtitle =
        '${identity.roleLabel(chinese)} · '
        '${identity.authenticationLabel(chinese)}';
    final expiry = identity.expiresUnixSeconds == null
        ? null
        : DateTime.fromMillisecondsSinceEpoch(
            identity.expiresUnixSeconds! * 1000,
          ).toLocal();
    return Tooltip(
      message: [
        '${chinese ? '用户名' : 'Username'}: ${identity.username}',
        subtitle,
        if (expiry != null)
          '${chinese ? '会话到期' : 'Session expires'}: '
              '${expiry.toIso8601String().replaceFirst('T', ' ').split('.').first}',
      ].join('\n'),
      child: Container(
        key: const Key('current-user-identity'),
        constraints: BoxConstraints(maxWidth: compact ? 156 : 260),
        padding: EdgeInsets.symmetric(
          horizontal: compact ? 8 : 11,
          vertical: 6,
        ),
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
            color: Theme.of(context).colorScheme.outlineVariant,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircleAvatar(
              radius: 14,
              backgroundColor: Theme.of(context).colorScheme.primaryContainer,
              child: Text(
                identity.username.isEmpty
                    ? '?'
                    : identity.username.characters.first.toUpperCase(),
                style: TextStyle(
                  color: Theme.of(context).colorScheme.onPrimaryContainer,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
            const SizedBox(width: 8),
            Flexible(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    identity.primaryName,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: Theme.of(context).textTheme.labelLarge?.copyWith(
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  if (!compact)
                    Text(
                      subtitle,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: Theme.of(context).textTheme.labelSmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                    ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
