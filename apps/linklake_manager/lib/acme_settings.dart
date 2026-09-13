import 'package:flutter/material.dart';

import 'api_client.dart';

/// 只交换 ACME 配置与凭据就绪状态，不接收或显示密钥材料。
class AcmeSettingsPage extends StatefulWidget {
  const AcmeSettingsPage({
    super.key,
    required this.api,
    required this.chinese,
    required this.editable,
  });
  final LinkLakeApi api;
  final bool chinese;
  final bool editable;

  @override
  State<AcmeSettingsPage> createState() => _AcmeSettingsPageState();
}

class _AcmeSettingsPageState extends State<AcmeSettingsPage> {
  static const directories = {
    'staging': 'https://acme-staging-v02.api.letsencrypt.org/directory',
    'production': 'https://acme-v02.api.letsencrypt.org/directory',
  };
  final _form = GlobalKey<FormState>();
  final _directory = TextEditingController();
  final _email = TextEditingController();
  final _days = TextEditingController();
  Map<String, dynamic>? _config;
  bool _enabled = false, _terms = false, _busy = false;
  String _environment = 'staging', _challenge = 'http-01';
  String? _error;
  String t(String zh, String en) => widget.chinese ? zh : en;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _directory.dispose();
    _email.dispose();
    _days.dispose();
    super.dispose();
  }

  void _apply(Map<String, dynamic> config) {
    _config = config;
    _enabled = config['enabled'] == true;
    _terms = config['terms_accepted'] == true;
    _environment =
        ['staging', 'production', 'custom'].contains(config['environment'])
        ? config['environment'] as String
        : 'custom';
    _challenge = config['challenge_type'] == 'dns-01' ? 'dns-01' : 'http-01';
    _directory.text = config['directory_url']?.toString() ?? '';
    _email.text = config['contact_email']?.toString() ?? '';
    _days.text = (config['renew_before_days'] ?? 30).toString();
  }

  Future<void> _load() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final value = await widget.api.getObject('/api/v1/acme/config');
      if (mounted) setState(() => _apply(value));
    } catch (_) {
      if (mounted) {
        setState(
          () => _error = t(
            '无法读取 ACME 设置，请重试。',
            'Could not load ACME settings. Retry.',
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _save() async {
    if (!widget.editable || _busy || !_form.currentState!.validate()) return;
    if (_enabled && !_terms) {
      setState(
        () => _error = t(
          '启用前请接受证书机构服务条款。',
          'Accept the certificate authority terms before enabling ACME.',
        ),
      );
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final value = await widget.api.putObject('/api/v1/acme/config', {
        'enabled': _enabled,
        'environment': _environment,
        'directory_url': _directory.text.trim(),
        'contact_email': _email.text.trim(),
        'terms_accepted': _terms,
        'challenge_type': _challenge,
        'renew_before_days': int.parse(_days.text.trim()),
      });
      if (!mounted) return;
      setState(() => _apply(value));
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(t('ACME 设置已保存。', 'ACME settings saved.'))),
      );
    } catch (_) {
      if (mounted) {
        setState(
          () => _error = t(
            '保存失败，请检查配置、权限和服务端凭据状态。',
            'Save failed. Check settings, permissions and server credential readiness.',
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final edit = widget.editable && !_busy;
    final keyReady = _config?['material_key_configured'];
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        Text(
          t('ACME 证书设置', 'ACME certificate settings'),
          style: Theme.of(context).textTheme.headlineSmall,
        ),
        const SizedBox(height: 12),
        if (_busy) const LinearProgressIndicator(),
        if (_error != null)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 12),
            child: Text(
              _error!,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ),
        if (_config == null)
          Align(
            alignment: Alignment.centerLeft,
            child: OutlinedButton(
              onPressed: _busy ? null : _load,
              child: Text(t('重试', 'Retry')),
            ),
          ),
        if (_config != null)
          Align(
            alignment: Alignment.topLeft,
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 780),
              child: Form(
                key: _form,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(
                      _config!['account_registered'] == true
                          ? t('ACME 账户已注册', 'ACME account registered')
                          : t('ACME 账户尚未注册', 'ACME account not registered'),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      keyReady == true
                          ? t(
                              '证书材料密钥：就绪或当前后端无需配置',
                              'Certificate material key: ready or not required by this backend',
                            )
                          : keyReady == false
                          ? t(
                              '证书材料密钥：未配置',
                              'Certificate material key: not configured',
                            )
                          : t(
                              '证书材料密钥：服务器未提供状态',
                              'Certificate material key: status unavailable from this server',
                            ),
                    ),
                    Text(
                      _config!['cloudflare_token_configured'] == true
                          ? t(
                              'Cloudflare 凭据：已配置',
                              'Cloudflare token: configured',
                            )
                          : t(
                              'Cloudflare 凭据：未配置或状态未知',
                              'Cloudflare token: not configured or status unavailable',
                            ),
                    ),
                    SwitchListTile(
                      contentPadding: EdgeInsets.zero,
                      title: Text(
                        t(
                          '启用自动证书管理',
                          'Enable automatic certificate management',
                        ),
                      ),
                      value: _enabled,
                      onChanged: edit
                          ? (value) => setState(() => _enabled = value)
                          : null,
                    ),
                    DropdownButtonFormField<String>(
                      initialValue: _environment,
                      decoration: InputDecoration(
                        labelText: t('环境', 'Environment'),
                      ),
                      items: [
                        for (final value in ['staging', 'production', 'custom'])
                          DropdownMenuItem(
                            value: value,
                            child: Text(switch (value) {
                              'staging' => t('测试环境', 'Staging'),
                              'production' => t('正式环境', 'Production'),
                              _ => t('自定义目录', 'Custom directory'),
                            }),
                          ),
                      ],
                      onChanged: edit
                          ? (value) => setState(() {
                              _environment = value!;
                              if (directories.containsKey(value)) {
                                _directory.text = directories[value]!;
                              }
                            })
                          : null,
                    ),
                    const SizedBox(height: 16),
                    TextFormField(
                      controller: _directory,
                      enabled: edit,
                      readOnly: _environment != 'custom',
                      decoration: InputDecoration(
                        labelText: t('目录 URL', 'Directory URL'),
                      ),
                      validator: (value) {
                        final uri = Uri.tryParse(value?.trim() ?? '');
                        return uri == null ||
                                uri.scheme != 'https' ||
                                uri.host.isEmpty ||
                                uri.userInfo.isNotEmpty
                            ? t('请输入有效的 HTTPS URL', 'Enter a valid HTTPS URL')
                            : null;
                      },
                    ),
                    const SizedBox(height: 16),
                    DropdownButtonFormField<String>(
                      initialValue: _challenge,
                      decoration: InputDecoration(
                        labelText: t('验证方式', 'Validation method'),
                      ),
                      items: const [
                        DropdownMenuItem(
                          value: 'http-01',
                          child: Text('HTTP-01'),
                        ),
                        DropdownMenuItem(
                          value: 'dns-01',
                          child: Text('DNS-01'),
                        ),
                      ],
                      onChanged: edit
                          ? (value) => setState(() => _challenge = value!)
                          : null,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      t(
                        'HTTP-01 需要公网 80 端口；DNS-01 支持通配符证书，需要服务端配置 Cloudflare 凭据。',
                        'HTTP-01 requires public port 80. DNS-01 supports wildcard certificates and requires a configured Cloudflare token.',
                      ),
                    ),
                    const SizedBox(height: 16),
                    TextFormField(
                      controller: _email,
                      enabled: edit,
                      keyboardType: TextInputType.emailAddress,
                      decoration: InputDecoration(
                        labelText: t('联系邮箱', 'Contact email'),
                      ),
                      validator: (value) {
                        final email = value?.trim() ?? '';
                        return (_enabled && email.isEmpty) ||
                                (email.isNotEmpty &&
                                    !RegExp(
                                      r'^[^\s@]+@[^\s@]+\.[^\s@]+$',
                                    ).hasMatch(email))
                            ? t('请输入有效的邮箱', 'Enter a valid email address')
                            : null;
                      },
                    ),
                    const SizedBox(height: 16),
                    TextFormField(
                      controller: _days,
                      enabled: edit,
                      keyboardType: TextInputType.number,
                      decoration: InputDecoration(
                        labelText: t(
                          '提前续期天数（7–60）',
                          'Renew before expiry (7–60 days)',
                        ),
                      ),
                      validator: (value) {
                        final days = int.tryParse(value?.trim() ?? '');
                        return days == null || days < 7 || days > 60
                            ? t('请输入 7–60 的整数', 'Enter an integer from 7 to 60')
                            : null;
                      },
                    ),
                    CheckboxListTile(
                      contentPadding: EdgeInsets.zero,
                      title: Text(
                        t(
                          '我同意证书颁发机构的服务条款',
                          'I accept the certificate authority terms of service',
                        ),
                      ),
                      value: _terms,
                      onChanged: edit
                          ? (value) => setState(() => _terms = value == true)
                          : null,
                    ),
                    Align(
                      alignment: Alignment.centerLeft,
                      child: FilledButton(
                        onPressed: edit ? _save : null,
                        child: Text(t('保存 ACME 设置', 'Save ACME settings')),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
      ],
    );
  }
}
