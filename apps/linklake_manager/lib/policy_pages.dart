import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'api_client.dart';
import 'rbac.dart';

enum PolicyKind { tcp, udp, group, http, sni, secret, socks5, proxy }

enum PolicyFieldType { text, number, client, optionalClient, select, toggle }

class PolicyPartialSaveException implements Exception {
  const PolicyPartialSaveException(this.message, this.cause);

  final String message;
  final Object cause;

  @override
  String toString() => '$message\n$cause';
}

class PolicyField {
  const PolicyField(
    this.name,
    this.zh,
    this.en, {
    this.type = PolicyFieldType.text,
    this.required = false,
    this.defaultValue,
    this.min,
    this.max,
    this.options = const [],
    this.visibleWhen,
  });

  final String name;
  final String zh;
  final String en;
  final PolicyFieldType type;
  final bool required;
  final Object? defaultValue;
  final int? min;
  final int? max;
  final List<String> options;
  final (String, Object?)? visibleWhen;
}

extension PolicyKindInfo on PolicyKind {
  String get key => switch (this) {
    PolicyKind.tcp => 'tcp',
    PolicyKind.udp => 'udp',
    PolicyKind.group => 'group',
    PolicyKind.http => 'http',
    PolicyKind.sni => 'sni',
    PolicyKind.secret => 'secret',
    PolicyKind.socks5 => 'socks5',
    PolicyKind.proxy => 'proxy',
  };

  String get resource => switch (this) {
    PolicyKind.tcp => 'tcp-tunnels',
    PolicyKind.udp => 'udp-tunnels',
    PolicyKind.group => 'port-groups',
    PolicyKind.http => 'http-routes',
    PolicyKind.sni => 'sni-routes',
    PolicyKind.secret => 'secret-tunnels',
    PolicyKind.socks5 => 'socks5-proxies',
    PolicyKind.proxy => 'http-proxies',
  };

  String get collectionPath => '/api/v1/$resource';
  String itemPath(Object id) => '$collectionPath/$id';
  String enabledPath(Object id) => '${itemPath(id)}/enabled';

  String? get oneTimeCredentialField => switch (this) {
    PolicyKind.secret => 'access_key',
    PolicyKind.socks5 || PolicyKind.proxy => 'password',
    _ => null,
  };

  String title(bool zh) => switch (this) {
    PolicyKind.tcp => 'TCP',
    PolicyKind.udp => 'UDP',
    PolicyKind.group => zh ? '端口组' : 'Port Groups',
    PolicyKind.http => 'HTTP/HTTPS',
    PolicyKind.sni => 'TLS SNI',
    PolicyKind.secret => 'Secret',
    PolicyKind.socks5 => 'SOCKS5',
    PolicyKind.proxy => 'HTTP Proxy',
  };

  String subtitle(bool zh) => switch (this) {
    PolicyKind.tcp =>
      zh ? '面向公网 TCP 端口的可靠转发策略' : 'Reliable forwarding for public TCP ports',
    PolicyKind.udp =>
      zh
          ? '带会话追踪和超时控制的 UDP 转发'
          : 'UDP forwarding with session tracking and timeouts',
    PolicyKind.group =>
      zh ? '批量映射连续或离散的 TCP/UDP 端口' : 'Map ranges or lists of TCP/UDP ports',
    PolicyKind.http =>
      zh
          ? '基于域名的 HTTP 路由和自动 HTTPS'
          : 'Hostname routes with optional automatic HTTPS',
    PolicyKind.sni =>
      zh ? '不终止 TLS 的 SNI 透传路由' : 'TLS pass-through routing by SNI',
    PolicyKind.secret =>
      zh ? '使用一次性访问密钥的私密转发' : 'Private forwarding protected by an access key',
    PolicyKind.socks5 =>
      zh
          ? '支持 CONNECT 与可选 UDP ASSOCIATE 的 SOCKS5 代理'
          : 'SOCKS5 CONNECT with optional UDP ASSOCIATE',
    PolicyKind.proxy =>
      zh
          ? '支持普通请求和 CONNECT 的 HTTP 代理'
          : 'HTTP proxy for regular and CONNECT requests',
  };

  List<PolicyField> get fields => switch (this) {
    PolicyKind.tcp => const [
      PolicyField(
        'client_id',
        '客户端',
        'Client',
        type: PolicyFieldType.client,
        required: true,
      ),
      PolicyField('name', '名称', 'Name', required: true),
      PolicyField(
        'public_port',
        '公网端口',
        'Public port',
        type: PolicyFieldType.number,
        required: true,
        min: 1,
        max: 65535,
      ),
      PolicyField('target_addr', '目标地址', 'Target address', required: true),
      PolicyField(
        'max_connections',
        '最大连接数',
        'Maximum connections',
        type: PolicyFieldType.number,
        required: true,
        defaultValue: 64,
        min: 1,
        max: 1024,
      ),
      PolicyField(
        'bandwidth_limit_bps',
        '带宽上限（bps）',
        'Bandwidth limit (bps)',
        type: PolicyFieldType.number,
        min: 1024,
        max: 1000000000,
      ),
    ],
    PolicyKind.udp => const [
      PolicyField(
        'client_id',
        '客户端',
        'Client',
        type: PolicyFieldType.client,
        required: true,
      ),
      PolicyField('name', '名称', 'Name', required: true),
      PolicyField(
        'public_port',
        '公网端口',
        'Public port',
        type: PolicyFieldType.number,
        required: true,
        min: 1,
        max: 65535,
      ),
      PolicyField('target_addr', '目标地址', 'Target address', required: true),
      PolicyField(
        'max_sessions',
        '最大会话数',
        'Maximum sessions',
        type: PolicyFieldType.number,
        required: true,
        defaultValue: 256,
        min: 1,
        max: 4096,
      ),
      PolicyField(
        'session_idle_timeout_seconds',
        '会话空闲超时（秒）',
        'Idle timeout (seconds)',
        type: PolicyFieldType.number,
        required: true,
        defaultValue: 120,
        min: 30,
        max: 3600,
      ),
      PolicyField(
        'bandwidth_limit_bps',
        '带宽上限（bps）',
        'Bandwidth limit (bps)',
        type: PolicyFieldType.number,
        min: 1024,
        max: 1000000000,
      ),
    ],
    PolicyKind.group => const [
      PolicyField(
        'client_id',
        '客户端',
        'Client',
        type: PolicyFieldType.client,
        required: true,
      ),
      PolicyField('name', '名称', 'Name', required: true),
      PolicyField(
        'protocol',
        '协议',
        'Protocol',
        type: PolicyFieldType.select,
        required: true,
        defaultValue: 'tcp',
        options: ['tcp', 'udp'],
      ),
      PolicyField('public_ports', '公网端口表达式', 'Public ports', required: true),
      PolicyField('target_host', '目标主机', 'Target host', required: true),
      PolicyField('target_ports', '目标端口表达式', 'Target ports', required: true),
      PolicyField(
        'max_connections',
        '最大连接数',
        'Maximum connections',
        type: PolicyFieldType.number,
        defaultValue: 64,
        min: 1,
        max: 1024,
        visibleWhen: ('protocol', 'tcp'),
      ),
      PolicyField(
        'max_sessions',
        '最大会话数',
        'Maximum sessions',
        type: PolicyFieldType.number,
        defaultValue: 256,
        min: 1,
        max: 4096,
        visibleWhen: ('protocol', 'udp'),
      ),
      PolicyField(
        'session_idle_timeout_seconds',
        '会话空闲超时（秒）',
        'Idle timeout (seconds)',
        type: PolicyFieldType.number,
        defaultValue: 120,
        min: 30,
        max: 3600,
        visibleWhen: ('protocol', 'udp'),
      ),
      PolicyField(
        'bandwidth_limit_bps',
        '带宽上限（bps）',
        'Bandwidth limit (bps)',
        type: PolicyFieldType.number,
        min: 1024,
        max: 1000000000,
      ),
    ],
    PolicyKind.http => const [
      PolicyField(
        'client_id',
        '客户端',
        'Client',
        type: PolicyFieldType.client,
        required: true,
      ),
      PolicyField('name', '名称', 'Name', required: true),
      PolicyField('hostname', '主机名', 'Hostname', required: true),
      PolicyField('target_addr', '目标地址', 'Target address', required: true),
      PolicyField(
        'max_connections',
        '最大连接数',
        'Maximum connections',
        type: PolicyFieldType.number,
        required: true,
        defaultValue: 64,
        min: 1,
        max: 1024,
      ),
      PolicyField(
        'tls_mode',
        'TLS 模式',
        'TLS mode',
        type: PolicyFieldType.select,
        defaultValue: 'disabled',
        options: ['disabled', 'acme'],
      ),
      PolicyField(
        'redirect_http_to_https',
        'HTTP 重定向到 HTTPS',
        'Redirect HTTP to HTTPS',
        type: PolicyFieldType.toggle,
        defaultValue: false,
        visibleWhen: ('tls_mode', 'acme'),
      ),
    ],
    PolicyKind.sni => const [
      PolicyField(
        'client_id',
        '客户端',
        'Client',
        type: PolicyFieldType.client,
        required: true,
      ),
      PolicyField('name', '名称', 'Name', required: true),
      PolicyField('hostname', '主机名', 'Hostname', required: true),
      PolicyField('target_addr', '目标地址', 'Target address', required: true),
      PolicyField(
        'max_connections',
        '最大连接数',
        'Maximum connections',
        type: PolicyFieldType.number,
        required: true,
        defaultValue: 64,
        min: 1,
        max: 1024,
      ),
      PolicyField(
        'bandwidth_limit_bps',
        '带宽上限（bps）',
        'Bandwidth limit (bps)',
        type: PolicyFieldType.number,
        min: 1024,
        max: 1000000000,
      ),
    ],
    PolicyKind.secret => const [
      PolicyField(
        'provider_client_id',
        '提供方客户端',
        'Provider client',
        type: PolicyFieldType.client,
        required: true,
      ),
      PolicyField(
        'allowed_client_id',
        '允许访问的客户端',
        'Allowed visitor',
        type: PolicyFieldType.optionalClient,
      ),
      PolicyField('name', '名称', 'Name', required: true),
      PolicyField('target_addr', '目标地址', 'Target address', required: true),
      PolicyField(
        'max_connections',
        '最大连接数',
        'Maximum connections',
        type: PolicyFieldType.number,
        required: true,
        defaultValue: 32,
        min: 1,
        max: 1024,
      ),
      PolicyField(
        'bandwidth_limit_bps',
        '带宽上限（bps）',
        'Bandwidth limit (bps)',
        type: PolicyFieldType.number,
        min: 1024,
        max: 1000000000,
      ),
    ],
    PolicyKind.socks5 || PolicyKind.proxy => const [
      PolicyField(
        'client_id',
        '客户端',
        'Client',
        type: PolicyFieldType.client,
        required: true,
      ),
      PolicyField('name', '名称', 'Name', required: true),
      PolicyField(
        'public_port',
        '公网端口',
        'Public port',
        type: PolicyFieldType.number,
        required: true,
        min: 1,
        max: 65535,
      ),
      PolicyField('username', '代理用户名', 'Proxy username', required: true),
      PolicyField(
        'max_connections',
        '最大连接数',
        'Maximum connections',
        type: PolicyFieldType.number,
        required: true,
        defaultValue: 64,
        min: 1,
        max: 1024,
      ),
      PolicyField(
        'bandwidth_limit_bps',
        '带宽上限（bps）',
        'Bandwidth limit (bps)',
        type: PolicyFieldType.number,
        min: 1024,
        max: 1000000000,
      ),
    ],
  };
}

class PolicyPage extends StatefulWidget {
  const PolicyPage({
    super.key,
    required this.kind,
    required this.api,
    required this.policies,
    required this.clients,
    required this.capabilities,
    required this.chinese,
    required this.onRefresh,
    this.onTrafficControl,
  });

  final PolicyKind kind;
  final LinkLakeApi api;
  final List<dynamic> policies;
  final List<dynamic> clients;
  final RoleCapabilities capabilities;
  final bool chinese;
  final Future<void> Function() onRefresh;
  final Future<void> Function(String kind, Map<String, dynamic> policy)?
  onTrafficControl;

  @override
  State<PolicyPage> createState() => _PolicyPageState();
}

class _PolicyPageState extends State<PolicyPage> {
  bool _working = false;

  String t(String zh, String en) => widget.chinese ? zh : en;

  List<Map<String, dynamic>> get policies => widget.policies
      .whereType<Map>()
      .map((value) => Map<String, dynamic>.from(value))
      .toList(growable: false);

  @override
  Widget build(BuildContext context) {
    final values = policies;
    return Padding(
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
                      widget.kind.title(widget.chinese),
                      style: Theme.of(context).textTheme.headlineSmall
                          ?.copyWith(fontWeight: FontWeight.w700),
                    ),
                    const SizedBox(height: 3),
                    Text(widget.kind.subtitle(widget.chinese)),
                  ],
                ),
              ),
              if (widget.capabilities.canWritePolicies)
                FilledButton.icon(
                  key: Key('create-${widget.kind.key}'),
                  onPressed: _working || widget.clients.isEmpty
                      ? null
                      : () => _showEditor(),
                  icon: const Icon(Icons.add),
                  label: Text(t('新建', 'Create')),
                ),
            ],
          ),
          const SizedBox(height: 18),
          _PolicyInsights(
            kind: widget.kind,
            policies: values,
            chinese: widget.chinese,
          ),
          const SizedBox(height: 18),
          if (values.isEmpty)
            Card(
              child: Padding(
                padding: const EdgeInsets.all(28),
                child: Column(
                  children: [
                    const Icon(Icons.route_outlined, size: 42),
                    const SizedBox(height: 10),
                    Text(t('暂无策略', 'No policies')),
                    if (widget.capabilities.canWritePolicies &&
                        widget.clients.isEmpty)
                      Text(
                        t(
                          '需要先注册客户端才能创建策略',
                          'Enroll a client before creating a policy',
                        ),
                      ),
                  ],
                ),
              ),
            )
          else
            for (final policy in values) _policyCard(policy),
        ],
      ),
    );
  }

  Widget _policyCard(Map<String, dynamic> policy) {
    final enabled = policy['enabled'] != false;
    final online = _isOnline(policy);
    final tls = policy['tls'] is Map
        ? Map<String, dynamic>.from(policy['tls'] as Map)
        : const <String, dynamic>{};
    return Card(
      key: Key('policy-${widget.kind.key}-${policy['id']}'),
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Wrap(
              spacing: 8,
              runSpacing: 8,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                Text(
                  _title(policy),
                  style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
                ),
                Chip(
                  visualDensity: VisualDensity.compact,
                  label: Text(
                    enabled ? t('已启用', 'Enabled') : t('已停用', 'Disabled'),
                  ),
                ),
                Chip(
                  visualDensity: VisualDensity.compact,
                  avatar: Icon(
                    online ? Icons.check_circle : Icons.pause_circle,
                    color: online ? Colors.green : Colors.orange,
                    size: 18,
                  ),
                  label: Text(online ? t('在线', 'Online') : t('离线', 'Offline')),
                ),
              ],
            ),
            const SizedBox(height: 6),
            SelectableText(_endpoint(policy)),
            if (widget.kind == PolicyKind.socks5) ...[
              const SizedBox(height: 8),
              Text(
                _socks5CapabilityText(policy),
                key: Key('socks5-capabilities-${policy['id']}'),
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
            ],
            const SizedBox(height: 10),
            Wrap(
              spacing: 18,
              runSpacing: 6,
              children: [
                for (final stat in _stats(policy))
                  Text.rich(
                    TextSpan(
                      children: [
                        TextSpan(
                          text: '${stat.$1}: ',
                          style: const TextStyle(fontWeight: FontWeight.w600),
                        ),
                        TextSpan(text: stat.$2),
                      ],
                    ),
                  ),
              ],
            ),
            if (tls['last_error_message'] != null) ...[
              const SizedBox(height: 8),
              Text(
                tls['last_error_message'].toString(),
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
            ],
            if (widget.capabilities.canWritePolicies) ...[
              const Divider(height: 24),
              Wrap(
                spacing: 6,
                children: [
                  TextButton.icon(
                    key: Key('edit-${widget.kind.key}-${policy['id']}'),
                    onPressed: _working ? null : () => _showEditor(policy),
                    icon: const Icon(Icons.edit_outlined),
                    label: Text(t('编辑', 'Edit')),
                  ),
                  TextButton.icon(
                    key: Key('toggle-${widget.kind.key}-${policy['id']}'),
                    onPressed: _working ? null : () => _toggle(policy),
                    icon: Icon(enabled ? Icons.pause : Icons.play_arrow),
                    label: Text(
                      enabled ? t('停用', 'Disable') : t('启用', 'Enable'),
                    ),
                  ),
                  if (widget.kind == PolicyKind.http && tls['mode'] == 'acme')
                    PopupMenuButton<String>(
                      tooltip: t('证书操作', 'Certificate actions'),
                      onSelected: (action) => _certificate(policy, action),
                      itemBuilder: (_) => [
                        PopupMenuItem(
                          value: 'issue',
                          child: Text(t('签发证书', 'Issue certificate')),
                        ),
                        PopupMenuItem(
                          value: 'renew',
                          child: Text(t('续期证书', 'Renew certificate')),
                        ),
                      ],
                      child: Padding(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 12,
                          vertical: 8,
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const Icon(Icons.verified_user_outlined, size: 18),
                            const SizedBox(width: 8),
                            Text(t('证书', 'Certificate')),
                          ],
                        ),
                      ),
                    ),
                  if (widget.capabilities.canManageTrafficControl &&
                      widget.onTrafficControl != null &&
                      widget.kind != PolicyKind.secret)
                    TextButton.icon(
                      onPressed: () => widget.onTrafficControl!(
                        widget.kind == PolicyKind.proxy
                            ? 'http_proxy'
                            : widget.kind == PolicyKind.group
                            ? 'port_group'
                            : widget.kind.key,
                        policy,
                      ),
                      icon: const Icon(Icons.security_outlined),
                      label: Text(t('流量控制', 'Traffic control')),
                    ),
                  TextButton.icon(
                    key: Key('delete-${widget.kind.key}-${policy['id']}'),
                    onPressed: _working ? null : () => _delete(policy),
                    icon: const Icon(Icons.delete_outline),
                    label: Text(t('删除', 'Delete')),
                    style: TextButton.styleFrom(
                      foregroundColor: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }

  Future<void> _showEditor([Map<String, dynamic>? policy]) async {
    if (!widget.capabilities.canWritePolicies) return;
    final values = <String, Object?>{};
    for (final field in widget.kind.fields) {
      Object? value = policy?[field.name] ?? field.defaultValue;
      if (widget.kind == PolicyKind.http && field.name == 'tls_mode') {
        value = (policy?['tls'] as Map?)?['mode'] ?? field.defaultValue;
      }
      if (widget.kind == PolicyKind.http &&
          field.name == 'redirect_http_to_https') {
        value =
            (policy?['tls'] as Map?)?['redirect_http_to_https'] ??
            field.defaultValue;
      }
      if ((field.type == PolicyFieldType.client ||
              field.type == PolicyFieldType.optionalClient) &&
          value == null &&
          widget.clients.isNotEmpty &&
          field.type == PolicyFieldType.client) {
        value = (widget.clients.first as Map)['client_id']?.toString();
      }
      values[field.name] = value;
    }
    final result = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (_) => _PolicyEditorDialog(
        kind: widget.kind,
        chinese: widget.chinese,
        clients: widget.clients,
        initialValues: values,
        editing: policy != null,
      ),
    );
    if (result == null || !mounted) return;
    await _runAction(() async {
      final payload = Map<String, dynamic>.from(result);
      final tlsMode = payload.remove('tls_mode')?.toString();
      final redirect = payload.remove('redirect_http_to_https') == true;
      if (widget.kind == PolicyKind.group) {
        if (payload['protocol'] == 'tcp') {
          payload['max_sessions'] = null;
          payload['session_idle_timeout_seconds'] = null;
        } else {
          payload['max_connections'] = null;
        }
      }
      if (widget.kind == PolicyKind.secret &&
          payload['allowed_client_id'] == '') {
        payload['allowed_client_id'] = null;
      }
      Map<String, dynamic>? response;
      var primarySaved = false;
      try {
        response = policy == null
            ? await widget.api.postObject(widget.kind.collectionPath, payload)
            : await widget.api.putObject(
                widget.kind.itemPath(policy['id']),
                payload,
              );
        primarySaved = true;
        final policyId = policy?['id'] ?? response['id'];
        if (widget.kind == PolicyKind.http) {
          if (policyId == null) {
            throw const FormatException(
              'HTTP route response did not include a route id.',
            );
          }
          await widget.api.putObject('/api/v1/http-routes/$policyId/tls', {
            'mode': tlsMode ?? 'disabled',
            'redirect_http_to_https': tlsMode == 'acme' && redirect,
          });
        }
      } catch (error) {
        if (primarySaved) {
          await widget.onRefresh();
          throw PolicyPartialSaveException(
            t(
              '基础策略已保存，但后续 TLS 更新失败。请检查当前状态后重试 TLS 设置。',
              'The policy was saved, but the follow-up TLS update failed. Review the current state and retry the TLS settings.',
            ),
            error,
          );
        }
        rethrow;
      }
      if (policy == null) await _showCreatedCredentials(response);
      _message(
        policy == null
            ? t('策略已创建', 'Policy created')
            : t('策略已更新', 'Policy updated'),
      );
      await widget.onRefresh();
    });
  }

  Future<void> _showCreatedCredentials(Map<String, dynamic> response) async {
    final field = widget.kind.oneTimeCredentialField;
    final credential = field == null ? null : response[field];
    if (credential == null || !mounted) return;
    final username = response['username'];
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        title: Text(t('请立即保存凭据', 'Save these credentials now')),
        content: SizedBox(
          width: 480,
          child: SelectableText(
            '${username == null ? '' : '${t('用户名', 'Username')}: $username\n'}'
            '${field == 'access_key' ? t('访问密钥', 'Access key') : t('密码', 'Password')}: $credential\n\n'
            '${t('该凭据只显示一次，Manager 不会保存它。', 'This credential is shown only once and is not stored by Manager.')}',
          ),
        ),
        actions: [
          FilledButton(
            onPressed: () => Navigator.pop(context),
            child: Text(t('已保存', 'Saved')),
          ),
        ],
      ),
    );
  }

  Future<void> _toggle(Map<String, dynamic> policy) async {
    if (!widget.capabilities.canWritePolicies) return;
    await _runAction(() async {
      await widget.api.post(widget.kind.enabledPath(policy['id']), {
        'enabled': policy['enabled'] == false,
      });
      _message(
        policy['enabled'] == false
            ? t('策略已启用', 'Policy enabled')
            : t('策略已停用', 'Policy disabled'),
      );
      await widget.onRefresh();
    });
  }

  Future<void> _delete(Map<String, dynamic> policy) async {
    if (!widget.capabilities.canWritePolicies) return;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(t('删除策略？', 'Delete policy?')),
        content: Text(t('此操作无法撤销。', 'This action cannot be undone.')),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(t('取消', 'Cancel')),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(t('删除', 'Delete')),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await _runAction(() async {
      await widget.api.delete(widget.kind.itemPath(policy['id']));
      _message(t('策略已删除', 'Policy deleted'));
      await widget.onRefresh();
    });
  }

  Future<void> _certificate(Map<String, dynamic> policy, String action) async {
    if (!widget.capabilities.canWritePolicies) return;
    await _runAction(() async {
      await widget.api.post(
        '/api/v1/http-routes/${policy['id']}/certificate/$action',
      );
      _message(t('证书任务已提交', 'Certificate action queued'));
      await widget.onRefresh();
    });
  }

  Future<void> _runAction(Future<void> Function() action) async {
    if (_working) return;
    setState(() => _working = true);
    try {
      await action();
    } catch (error) {
      _message(_actionError(error), error: true);
    } finally {
      if (mounted) setState(() => _working = false);
    }
  }

  String _actionError(Object error) {
    if (error is LinkLakeApiException) {
      if (error.statusCode == 401) {
        return t('登录已失效，请重新登录。', 'Your session expired. Sign in again.');
      }
      if (error.statusCode == 403) {
        return t('当前角色无权执行此操作。', 'Your role cannot perform this action.');
      }
      if (error.code != null && error.code!.isNotEmpty) {
        return '${error.message} (${error.code})';
      }
    }
    return error.toString();
  }

  void _message(String value, {bool error = false}) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(value),
        backgroundColor: error ? Theme.of(context).colorScheme.error : null,
      ),
    );
  }

  String _title(Map<String, dynamic> policy) {
    final name = policy['name'] ?? '-';
    return switch (widget.kind) {
      PolicyKind.tcp => '$name · TCP :${policy['public_port']}',
      PolicyKind.udp => '$name · UDP :${policy['public_port']}',
      PolicyKind.group =>
        '$name · ${policy['protocol']?.toString().toUpperCase()} ${policy['public_ports']}',
      PolicyKind.http || PolicyKind.sni => '$name · ${policy['hostname']}',
      PolicyKind.secret => name.toString(),
      PolicyKind.socks5 => '$name · SOCKS5 :${policy['public_port']}',
      PolicyKind.proxy => '$name · HTTP :${policy['public_port']}',
    };
  }

  String _clientName(Object? id) {
    for (final raw in widget.clients.whereType<Map>()) {
      if (raw['client_id']?.toString() == id?.toString()) {
        return raw['name']?.toString() ?? id?.toString() ?? '-';
      }
    }
    return id?.toString() ?? '-';
  }

  String _endpoint(Map<String, dynamic> policy) => switch (widget.kind) {
    PolicyKind.group =>
      '${_clientName(policy['client_id'])} · :${policy['public_ports']} → ${policy['target_host']}:${policy['target_ports']}',
    PolicyKind.http =>
      '${((policy['tls'] as Map?)?['mode'] == 'acme') ? 'https' : 'http'}://${policy['hostname']} → ${_clientName(policy['client_id'])} · ${policy['target_addr']}',
    PolicyKind.secret =>
      '${_clientName(policy['provider_client_id'])} → ${policy['target_addr']}',
    PolicyKind.tcp || PolicyKind.udp || PolicyKind.sni =>
      '${_clientName(policy['client_id'])} → ${policy['target_addr']}',
    PolicyKind.socks5 || PolicyKind.proxy =>
      '${_clientName(policy['client_id'])} · ${policy['username']}@:${policy['public_port']}',
  };

  String _socks5CapabilityText(Map<String, dynamic> policy) {
    final capabilities = policy['capabilities'] is Map
        ? Map<String, dynamic>.from(policy['capabilities'] as Map)
        : const <String, dynamic>{};
    if (capabilities['udp_associate'] == true) {
      return t(
        'CONNECT 与 UDP ASSOCIATE 当前可用；BIND 与 UDP FRAG 按设计不受支持。',
        'CONNECT and UDP ASSOCIATE are available. BIND and UDP FRAG are intentionally unsupported.',
      );
    }
    return t(
      'CONNECT 当前可用；UDP relay 未启用，因此 UDP ASSOCIATE 不可用；BIND 与 UDP FRAG 按设计不受支持。',
      'CONNECT is available. UDP ASSOCIATE is unavailable because the UDP relay is disabled. BIND and UDP FRAG are intentionally unsupported.',
    );
  }

  List<(String, String)> _stats(
    Map<String, dynamic> policy,
  ) => switch (widget.kind) {
    PolicyKind.tcp => [
      (
        t('活动', 'Active'),
        '${policy['active_connections'] ?? 0}/${policy['max_connections'] ?? 0}',
      ),
      (t('拒绝', 'Rejected'), '${policy['rejected_connections'] ?? 0}'),
      (t('失败', 'Failed'), '${policy['failed_connections'] ?? 0}'),
      (
        t('流量', 'Traffic'),
        '${_formatBytes(policy['bytes_from_public'])} / ${_formatBytes(policy['bytes_to_public'])}',
      ),
    ],
    PolicyKind.udp => [
      (
        t('会话', 'Sessions'),
        '${policy['active_sessions'] ?? 0}/${policy['max_sessions'] ?? 0}',
      ),
      (t('丢包', 'Drops'), '${policy['dropped_packets'] ?? 0}'),
      (t('超时', 'Timeouts'), '${policy['attach_timeouts'] ?? 0}'),
      (
        t('流量', 'Traffic'),
        '${_formatBytes(policy['bytes_from_public'])} / ${_formatBytes(policy['bytes_to_public'])}',
      ),
    ],
    PolicyKind.group => [
      (
        t('映射', 'Mappings'),
        '${policy['online_mappings'] ?? 0}/${policy['mapping_count'] ?? 0}',
      ),
      (t('负载', 'Workload'), '${_workload(policy)}'),
      (
        t('流量', 'Traffic'),
        '${_formatBytes(policy['bytes_from_public'])} / ${_formatBytes(policy['bytes_to_public'])}',
      ),
    ],
    PolicyKind.http => [
      (
        t('活动', 'Active'),
        '${policy['active_connections'] ?? 0}/${policy['max_connections'] ?? 0}',
      ),
      (t('请求', 'Requests'), '${policy['requests_total'] ?? 0}'),
      (t('失败', 'Failed'), '${policy['failed_requests'] ?? 0}'),
      (
        t('证书', 'Certificate'),
        '${(policy['tls'] as Map?)?['status'] ?? 'disabled'}',
      ),
    ],
    PolicyKind.sni => [
      (t('活动', 'Active'), '${policy['active_connections'] ?? 0}'),
      (t('连接', 'Connections'), '${policy['connections_total'] ?? 0}'),
      ('Unknown SNI', '${policy['unknown_sni'] ?? 0}'),
      (
        t('流量', 'Traffic'),
        '${_formatBytes(policy['bytes_from_public'])} / ${_formatBytes(policy['bytes_to_public'])}',
      ),
    ],
    PolicyKind.secret => [
      (
        t('活动', 'Active'),
        '${policy['active_connections'] ?? 0}/${policy['max_connections'] ?? 0}',
      ),
      (t('连接', 'Connections'), '${policy['connections_total'] ?? 0}'),
      (t('拒绝', 'Rejected'), '${policy['rejected_connections'] ?? 0}'),
      (
        t('流量', 'Traffic'),
        '${_formatBytes(policy['bytes_from_visitor'])} / ${_formatBytes(policy['bytes_to_visitor'])}',
      ),
    ],
    PolicyKind.socks5 => [
      (t('活动', 'Active'), '${policy['active_connections'] ?? 0}'),
      (t('请求', 'Requests'), '${policy['requests_total'] ?? 0}'),
      ('UDP', '${policy['udp_active_associations'] ?? 0}'),
      (t('失败', 'Failed'), '${_errors(policy)}'),
    ],
    PolicyKind.proxy => [
      (t('活动', 'Active'), '${policy['active_connections'] ?? 0}'),
      (t('请求', 'Requests'), '${policy['requests_total'] ?? 0}'),
      ('CONNECT', '${policy['connect_requests'] ?? 0}'),
      (t('失败', 'Failed'), '${_errors(policy)}'),
    ],
  };

  bool _isOnline(Map<String, dynamic> policy) {
    if (policy['online'] is bool) return policy['online'] == true;
    if (policy['enabled'] == false) return false;
    if (widget.kind == PolicyKind.group) {
      return (policy['online_mappings'] as num? ?? 0) > 0;
    }
    return (policy['active_connections'] as num? ?? 0) > 0 ||
        (policy['active_sessions'] as num? ?? 0) > 0 ||
        (policy['requests_total'] as num? ?? 0) > 0;
  }

  num _workload(Map<String, dynamic> value) =>
      (value['active_connections'] as num? ?? 0) +
      (value['active_sessions'] as num? ?? 0) +
      (widget.kind == PolicyKind.socks5
          ? (value['udp_active_associations'] as num? ?? 0)
          : 0);

  num _errors(Map<String, dynamic> value) =>
      (value['authentication_failures'] as num? ?? 0) +
      (value['connect_failures'] as num? ?? 0) +
      (value['malformed_requests'] as num? ?? 0);

  String _formatBytes(Object? raw) {
    var value = (raw as num? ?? 0).toDouble();
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    var unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit++;
    }
    return '${value.toStringAsFixed(unit == 0 ? 0 : 1)} ${units[unit]}';
  }
}

class _PolicyEditorDialog extends StatefulWidget {
  const _PolicyEditorDialog({
    required this.kind,
    required this.chinese,
    required this.clients,
    required this.initialValues,
    required this.editing,
  });

  final PolicyKind kind;
  final bool chinese;
  final List<dynamic> clients;
  final Map<String, Object?> initialValues;
  final bool editing;

  @override
  State<_PolicyEditorDialog> createState() => _PolicyEditorDialogState();
}

class _PolicyEditorDialogState extends State<_PolicyEditorDialog> {
  final _formKey = GlobalKey<FormState>();
  final Map<String, TextEditingController> _controllers = {};
  late Map<String, Object?> _values;

  String t(String zh, String en) => widget.chinese ? zh : en;

  @override
  void initState() {
    super.initState();
    _values = Map<String, Object?>.from(widget.initialValues);
    for (final field in widget.kind.fields) {
      if (field.type == PolicyFieldType.text ||
          field.type == PolicyFieldType.number) {
        _controllers[field.name] = TextEditingController(
          text: _values[field.name]?.toString() ?? '',
        );
      }
    }
  }

  @override
  void dispose() {
    for (final controller in _controllers.values) {
      controller.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text(
      widget.editing
          ? t(
              '编辑 ${widget.kind.title(true)}',
              'Edit ${widget.kind.title(false)}',
            )
          : t(
              '新建 ${widget.kind.title(true)}',
              'Create ${widget.kind.title(false)}',
            ),
    ),
    content: SizedBox(
      width: math.min(MediaQuery.sizeOf(context).width - 48, 620),
      child: Form(
        key: _formKey,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              for (final field in widget.kind.fields)
                if (_visible(field)) ...[
                  _field(field),
                  const SizedBox(height: 12),
                ],
            ],
          ),
        ),
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: Text(t('取消', 'Cancel')),
      ),
      FilledButton(
        key: const Key('save-policy'),
        onPressed: _save,
        child: Text(t('保存', 'Save')),
      ),
    ],
  );

  bool _visible(PolicyField field) {
    final condition = field.visibleWhen;
    return condition == null || _values[condition.$1] == condition.$2;
  }

  Widget _field(PolicyField field) {
    final label = t(field.zh, field.en);
    if (field.type == PolicyFieldType.client ||
        field.type == PolicyFieldType.optionalClient) {
      final ids = widget.clients
          .whereType<Map>()
          .map((value) => value['client_id']?.toString())
          .whereType<String>()
          .toSet();
      final current = _values[field.name]?.toString();
      return DropdownButtonFormField<String>(
        key: Key('field-${field.name}'),
        initialValue:
            current == null || (!ids.contains(current) && current.isNotEmpty)
            ? (field.type == PolicyFieldType.optionalClient ? '' : null)
            : current,
        decoration: InputDecoration(labelText: label),
        items: [
          if (field.type == PolicyFieldType.optionalClient)
            DropdownMenuItem(value: '', child: Text(t('任意客户端', 'Any client'))),
          for (final raw in widget.clients.whereType<Map>())
            DropdownMenuItem(
              value: raw['client_id']?.toString(),
              child: Text('${raw['name'] ?? raw['client_id']}'),
            ),
        ],
        validator: field.required
            ? (value) =>
                  value == null || value.isEmpty ? t('必填', 'Required') : null
            : null,
        onChanged: (value) => _values[field.name] = value,
      );
    }
    if (field.type == PolicyFieldType.select) {
      return DropdownButtonFormField<String>(
        key: Key('field-${field.name}'),
        initialValue: _values[field.name]?.toString(),
        decoration: InputDecoration(labelText: label),
        items: [
          for (final option in field.options)
            DropdownMenuItem(value: option, child: Text(option.toUpperCase())),
        ],
        onChanged: (value) => setState(() => _values[field.name] = value),
      );
    }
    if (field.type == PolicyFieldType.toggle) {
      return SwitchListTile(
        key: Key('field-${field.name}'),
        contentPadding: EdgeInsets.zero,
        title: Text(label),
        value: _values[field.name] == true,
        onChanged: (value) => setState(() => _values[field.name] = value),
      );
    }
    return TextFormField(
      key: Key('field-${field.name}'),
      controller: _controllers[field.name],
      keyboardType: field.type == PolicyFieldType.number
          ? TextInputType.number
          : TextInputType.text,
      decoration: InputDecoration(labelText: label),
      validator: (value) {
        final text = value?.trim() ?? '';
        if (field.required && text.isEmpty) return t('必填', 'Required');
        if (text.isNotEmpty && field.type == PolicyFieldType.number) {
          final number = int.tryParse(text);
          if (number == null) return t('请输入整数', 'Enter an integer');
          if (field.min != null && number < field.min!) return '≥ ${field.min}';
          if (field.max != null && number > field.max!) return '≤ ${field.max}';
        }
        return null;
      },
    );
  }

  void _save() {
    if (!_formKey.currentState!.validate()) return;
    final result = <String, dynamic>{};
    for (final field in widget.kind.fields) {
      if (!_visible(field)) continue;
      if (field.type == PolicyFieldType.text ||
          field.type == PolicyFieldType.number) {
        final text = _controllers[field.name]!.text.trim();
        result[field.name] = field.type == PolicyFieldType.number
            ? (text.isEmpty ? null : int.parse(text))
            : text;
      } else {
        result[field.name] = _values[field.name];
      }
    }
    Navigator.pop(context, result);
  }
}

class _PolicyInsights extends StatelessWidget {
  const _PolicyInsights({
    required this.kind,
    required this.policies,
    required this.chinese,
  });

  final PolicyKind kind;
  final List<Map<String, dynamic>> policies;
  final bool chinese;

  String t(String zh, String en) => chinese ? zh : en;

  @override
  Widget build(BuildContext context) {
    final enabled = policies.where((value) => value['enabled'] != false).length;
    final online = policies.where(_online).length;
    final workload = policies.fold<num>(
      0,
      (sum, value) => sum + _workload(value),
    );
    final traffic = policies.fold<num>(
      0,
      (sum, value) => sum + _traffic(value),
    );
    final maxTraffic = policies.fold<num>(
      1,
      (maxValue, value) => math.max(maxValue, _traffic(value)),
    );
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Wrap(
              spacing: 24,
              runSpacing: 12,
              children: [
                _kpi(context, '${policies.length}', t('策略', 'Policies')),
                _kpi(context, '$enabled', t('已启用', 'Enabled')),
                _kpi(context, '$online', t('在线', 'Online')),
                _kpi(context, '$workload', t('活动负载', 'Workload')),
                _kpi(context, _formatBytes(traffic), t('总流量', 'Total traffic')),
              ],
            ),
            const SizedBox(height: 16),
            Text(
              t('状态与流量', 'Status and traffic'),
              style: Theme.of(context).textTheme.titleSmall,
            ),
            const SizedBox(height: 10),
            Row(
              children: [
                Expanded(
                  child: _statusBar(
                    context,
                    online,
                    Colors.green,
                    t('在线', 'Online'),
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: _statusBar(
                    context,
                    math.max(0, enabled - online),
                    Colors.orange,
                    t('离线', 'Offline'),
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: _statusBar(
                    context,
                    math.max(0, policies.length - enabled),
                    Colors.grey,
                    t('停用', 'Disabled'),
                  ),
                ),
              ],
            ),
            if (policies.isNotEmpty) ...[
              const SizedBox(height: 14),
              for (final policy in policies.take(8))
                Padding(
                  padding: const EdgeInsets.only(top: 6),
                  child: Row(
                    children: [
                      SizedBox(
                        width: 130,
                        child: Text(policy['name']?.toString() ?? '-'),
                      ),
                      Expanded(
                        child: LinearProgressIndicator(
                          value: (_traffic(policy) / maxTraffic)
                              .clamp(0, 1)
                              .toDouble(),
                          minHeight: 8,
                        ),
                      ),
                      const SizedBox(width: 10),
                      SizedBox(
                        width: 76,
                        child: Text(
                          _formatBytes(_traffic(policy)),
                          textAlign: TextAlign.end,
                        ),
                      ),
                    ],
                  ),
                ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _kpi(BuildContext context, String value, String label) => SizedBox(
    width: 110,
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          value,
          style: Theme.of(
            context,
          ).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w700),
        ),
        Text(label),
      ],
    ),
  );

  Widget _statusBar(
    BuildContext context,
    int value,
    Color color,
    String label,
  ) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Container(
        height: 10,
        decoration: BoxDecoration(
          color: color.withValues(alpha: value == 0 ? 0.18 : 0.9),
          borderRadius: BorderRadius.circular(5),
        ),
      ),
      const SizedBox(height: 4),
      Text('$label · $value', style: Theme.of(context).textTheme.labelSmall),
    ],
  );

  bool _online(Map<String, dynamic> value) {
    if (value['enabled'] == false) return false;
    if (value['online'] is bool) return value['online'] == true;
    return _workload(value) > 0 || (value['online_mappings'] as num? ?? 0) > 0;
  }

  num _workload(Map<String, dynamic> value) =>
      (value['active_connections'] as num? ?? 0) +
      (value['active_sessions'] as num? ?? 0) +
      (kind == PolicyKind.socks5
          ? (value['udp_active_associations'] as num? ?? 0)
          : 0);

  num _traffic(Map<String, dynamic> value) {
    if (kind == PolicyKind.secret) {
      return (value['bytes_from_visitor'] as num? ?? 0) +
          (value['bytes_to_visitor'] as num? ?? 0);
    }
    return (value['bytes_from_public'] as num? ?? 0) +
        (value['bytes_to_public'] as num? ?? 0);
  }

  String _formatBytes(num raw) {
    var value = raw.toDouble();
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    var unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit++;
    }
    return '${value.toStringAsFixed(unit == 0 ? 0 : 1)} ${units[unit]}';
  }
}
