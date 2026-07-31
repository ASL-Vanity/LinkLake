import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';

import 'api_client.dart';

void main() {
  runApp(const LinkLakeManagerApp());
}

class LinkLakeManagerApp extends StatefulWidget {
  const LinkLakeManagerApp({super.key});

  @override
  State<LinkLakeManagerApp> createState() => _LinkLakeManagerAppState();
}

class _LinkLakeManagerAppState extends State<LinkLakeManagerApp> {
  bool _chinese = true;

  @override
  Widget build(BuildContext context) {
    final scheme = ColorScheme.fromSeed(
      seedColor: const Color(0xFF168AAD),
      brightness: Brightness.light,
    );
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'LinkLake Manager',
      theme: ThemeData(
        colorScheme: scheme,
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xFFF3F8FA),
        cardTheme: const CardThemeData(
          elevation: 0,
          margin: EdgeInsets.zero,
        ),
      ),
      home: LoginPage(
        chinese: _chinese,
        onLanguageChanged: (value) => setState(() => _chinese = value),
      ),
    );
  }
}

class LoginPage extends StatefulWidget {
  const LoginPage({
    super.key,
    required this.chinese,
    required this.onLanguageChanged,
  });

  final bool chinese;
  final ValueChanged<bool> onLanguageChanged;

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final _server = TextEditingController(text: 'https://linklake.odelake.com');
  final _username = TextEditingController(text: 'admin');
  final _password = TextEditingController();
  bool _busy = false;
  String? _error;

  String t(String zh, String en) => widget.chinese ? zh : en;

  Future<void> _login() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    final api = LinkLakeApiClient(_server.text.trim());
    try {
      final result = await api.login(_username.text.trim(), _password.text);
      if (!mounted) return;
      if (result['password_change_required'] == true) {
        final changed = await _forcePasswordChange(api);
        if (!changed) {
          api.close();
          return;
        }
      }
      if (!mounted) return;
      await Navigator.of(context).pushReplacement(
        MaterialPageRoute(
          builder: (_) => DashboardPage(
            api: api,
            chinese: widget.chinese,
            onLanguageChanged: widget.onLanguageChanged,
          ),
        ),
      );
    } catch (error) {
      api.close();
      if (mounted) setState(() => _error = error.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<bool> _forcePasswordChange(LinkLakeApiClient api) async {
    final controller = TextEditingController();
    String? error;
    final result = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: Text(t('首次登录必须修改密码', 'Password change required')),
          content: SizedBox(
            width: 420,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: controller,
                  obscureText: true,
                  autofocus: true,
                  decoration: InputDecoration(
                    labelText: t('新密码（至少 12 位）', 'New password (12+ characters)'),
                    errorText: error,
                  ),
                ),
              ],
            ),
          ),
          actions: [
            FilledButton(
              onPressed: () async {
                try {
                  await api.changePassword(controller.text);
                  if (context.mounted) Navigator.pop(context, true);
                } catch (value) {
                  setDialogState(() => error = value.toString());
                }
              },
              child: Text(t('保存', 'Save')),
            ),
          ],
        ),
      ),
    );
    controller.dispose();
    return result == true;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(
        children: [
          const Positioned.fill(child: _LakeBackground()),
          Align(
            alignment: Alignment.topRight,
            child: Padding(
              padding: const EdgeInsets.all(20),
              child: TextButton.icon(
                onPressed: () => widget.onLanguageChanged(!widget.chinese),
                icon: const Icon(Icons.language),
                label: Text(widget.chinese ? 'English' : '中文'),
              ),
            ),
          ),
          Center(
            child: Card(
              child: Container(
                width: 460,
                padding: const EdgeInsets.all(32),
                child: AutofillGroup(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      const _BrandMark(size: 72),
                      const SizedBox(height: 14),
                      Text(
                        'LinkLake',
                        textAlign: TextAlign.center,
                        style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                              fontWeight: FontWeight.w700,
                              color: const Color(0xFF075985),
                            ),
                      ),
                      Text(
                        t('跨平台网络服务管理客户端', 'Cross-platform network service manager'),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 28),
                      TextField(
                        controller: _server,
                        autofillHints: const [AutofillHints.url],
                        decoration: InputDecoration(
                          labelText: t('服务端地址', 'Server URL'),
                          prefixIcon: const Icon(Icons.cloud_outlined),
                        ),
                      ),
                      const SizedBox(height: 14),
                      TextField(
                        controller: _username,
                        autofillHints: const [AutofillHints.username],
                        decoration: InputDecoration(
                          labelText: t('用户名', 'Username'),
                          prefixIcon: const Icon(Icons.person_outline),
                        ),
                      ),
                      const SizedBox(height: 14),
                      TextField(
                        controller: _password,
                        obscureText: true,
                        autofillHints: const [AutofillHints.password],
                        onSubmitted: (_) => _busy ? null : _login(),
                        decoration: InputDecoration(
                          labelText: t('密码', 'Password'),
                          prefixIcon: const Icon(Icons.lock_outline),
                        ),
                      ),
                      if (_error != null) ...[
                        const SizedBox(height: 12),
                        Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
                      ],
                      const SizedBox(height: 22),
                      FilledButton.icon(
                        onPressed: _busy ? null : _login,
                        icon: _busy
                            ? const SizedBox.square(
                                dimension: 18,
                                child: CircularProgressIndicator(strokeWidth: 2),
                              )
                            : const Icon(Icons.login),
                        label: Text(t('登录', 'Sign in')),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class DashboardPage extends StatefulWidget {
  const DashboardPage({
    super.key,
    required this.api,
    required this.chinese,
    required this.onLanguageChanged,
  });

  final LinkLakeApiClient api;
  final bool chinese;
  final ValueChanged<bool> onLanguageChanged;

  @override
  State<DashboardPage> createState() => _DashboardPageState();
}

class _DashboardPageState extends State<DashboardPage> {
  int _page = 0;
  late bool _chinese;
  bool _busy = true;
  String? _error;
  Timer? _timer;
  Map<String, dynamic> _status = {};
  Map<String, dynamic> _metrics = {};
  List<dynamic> _clients = [];
  List<dynamic> _p2p = [];
  List<dynamic> _audit = [];
  final Map<String, List<dynamic>> _resources = {};

  bool get zh => _chinese;
  String t(String chinese, String english) => zh ? chinese : english;

  @override
  void initState() {
    super.initState();
    _chinese = widget.chinese;
    _refresh();
    _timer = Timer.periodic(const Duration(seconds: 10), (_) => _refresh(silent: true));
  }

  @override
  void dispose() {
    _timer?.cancel();
    widget.api.close();
    super.dispose();
  }

  Future<void> _refresh({bool silent = false}) async {
    if (!silent) setState(() => _busy = true);
    try {
      final values = await Future.wait<dynamic>([
        widget.api.getObject('/api/v1/status'),
        widget.api.getObject('/api/v1/metrics'),
        widget.api.getList('/api/v1/clients'),
        widget.api.getList('/api/v1/p2p/nodes'),
        widget.api.getList('/api/v1/audit?limit=50'),
        widget.api.getList('/api/v1/tcp-tunnels'),
        widget.api.getList('/api/v1/udp-tunnels'),
        widget.api.getList('/api/v1/http-routes'),
        widget.api.getList('/api/v1/sni-routes'),
        widget.api.getList('/api/v1/secret-tunnels'),
        widget.api.getList('/api/v1/socks5-proxies'),
        widget.api.getList('/api/v1/http-proxies'),
        widget.api.getList('/api/v1/port-groups'),
      ]);
      if (!mounted) return;
      setState(() {
        _status = values[0];
        _metrics = values[1];
        _clients = values[2];
        _p2p = values[3];
        _audit = values[4];
        _resources
          ..['tcp'] = values[5]
          ..['udp'] = values[6]
          ..['http'] = values[7]
          ..['sni'] = values[8]
          ..['secret'] = values[9]
          ..['socks5'] = values[10]
          ..['proxy'] = values[11]
          ..['group'] = values[12];
        _error = null;
      });
    } catch (error) {
      if (mounted) setState(() => _error = error.toString());
    } finally {
      if (mounted && !silent) setState(() => _busy = false);
    }
  }

  Future<void> _logout() async {
    await widget.api.logout();
    if (!mounted) return;
    await Navigator.of(context).pushReplacement(
      MaterialPageRoute(
        builder: (_) => LoginPage(
          chinese: zh,
          onLanguageChanged: widget.onLanguageChanged,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final destinations = [
      (Icons.dashboard_outlined, t('概览', 'Overview')),
      (Icons.devices_outlined, t('客户端', 'Clients')),
      (Icons.swap_horiz, t('服务', 'Services')),
      (Icons.hub_outlined, 'P2P'),
      (Icons.receipt_long_outlined, t('审计', 'Audit')),
    ];
    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            const _BrandMark(size: 34),
            const SizedBox(width: 10),
            const Text('LinkLake Manager'),
            const SizedBox(width: 12),
            if (_status['instance_id'] != null)
              Text(
                _status['instance_id'].toString().substring(0, 8),
                style: Theme.of(context).textTheme.labelSmall,
              ),
          ],
        ),
        actions: [
          IconButton(onPressed: _refresh, tooltip: t('刷新', 'Refresh'), icon: const Icon(Icons.refresh)),
          TextButton.icon(
            onPressed: () {
              setState(() => _chinese = !_chinese);
              widget.onLanguageChanged(_chinese);
            },
            icon: const Icon(Icons.language),
            label: Text(zh ? 'English' : '中文'),
          ),
          IconButton(onPressed: _logout, tooltip: t('退出', 'Sign out'), icon: const Icon(Icons.logout)),
          const SizedBox(width: 8),
        ],
      ),
      body: Row(
        children: [
          NavigationRail(
            selectedIndex: _page,
            labelType: NavigationRailLabelType.all,
            onDestinationSelected: (value) => setState(() => _page = value),
            destinations: [
              for (final item in destinations)
                NavigationRailDestination(icon: Icon(item.$1), label: Text(item.$2)),
            ],
          ),
          const VerticalDivider(width: 1),
          Expanded(
            child: _busy
                ? const Center(child: CircularProgressIndicator())
                : Column(
                    children: [
                      if (_error != null)
                        MaterialBanner(
                          content: Text(_error!),
                          actions: [TextButton(onPressed: _refresh, child: Text(t('重试', 'Retry')))],
                        ),
                      Expanded(child: _currentPage()),
                    ],
                  ),
          ),
        ],
      ),
    );
  }

  Widget _currentPage() => switch (_page) {
        0 => _overview(),
        1 => _clientsPage(),
        2 => _servicesPage(),
        3 => _p2pPage(),
        _ => _auditPage(),
      };

  Widget _overview() {
    final cards = <(String, String, IconData)>[
      (t('在线客户端', 'Clients'), '${_status['clients'] ?? 0}', Icons.devices),
      (t('TCP 连接', 'TCP connections'), '${_metrics['tcp_active_connections'] ?? 0}', Icons.swap_horiz),
      (t('UDP 会话', 'UDP sessions'), '${_metrics['udp_active_sessions'] ?? 0}', Icons.bolt),
      (t('HTTP 请求', 'HTTP requests'), '${_metrics['http_requests_total'] ?? 0}', Icons.http),
      (t('P2P 直连', 'P2P direct'), '${_metrics['p2p_direct_connections_total'] ?? 0}', Icons.hub),
      (t('中继回退', 'Relay fallback'), '${_metrics['p2p_relay_fallbacks_total'] ?? 0}', Icons.cloud_sync),
      (t('托管证书', 'Certificates'), '${_metrics['certificates_active'] ?? 0}', Icons.verified_user),
      (t('运行时间', 'Uptime'), _duration(_metrics['uptime_seconds']), Icons.timer_outlined),
    ];
    return _pagePadding(
      ListView(
        children: [
          _pageTitle(t('运行概览', 'Runtime overview'), t('服务状态、连接与安全指标', 'Service health, connections, and security metrics')),
          const SizedBox(height: 18),
          LayoutBuilder(
            builder: (context, constraints) {
              final width = constraints.maxWidth > 1000 ? (constraints.maxWidth - 48) / 4 : (constraints.maxWidth - 16) / 2;
              return Wrap(
                spacing: 16,
                runSpacing: 16,
                children: [for (final card in cards) SizedBox(width: width, child: _metricCard(card))],
              );
            },
          ),
          const SizedBox(height: 20),
          _jsonPanel(t('完整指标', 'Full metrics'), _metrics),
        ],
      ),
    );
  }

  Widget _clientsPage() => _pagePadding(
        ListView(
          children: [
            _pageTitle(t('已注册客户端', 'Enrolled clients'), t('配置模式、同步状态和最近心跳', 'Configuration mode, sync status, and heartbeat')),
            const SizedBox(height: 16),
            for (final raw in _clients)
              _recordCard(raw as Map<String, dynamic>, titleKeys: const ['name', 'client_id'], stateKey: 'online'),
          ],
        ),
      );

  Widget _servicesPage() {
    const labels = {
      'tcp': 'TCP',
      'udp': 'UDP',
      'http': 'HTTP/HTTPS',
      'sni': 'TLS SNI',
      'secret': 'Secret',
      'socks5': 'SOCKS5',
      'proxy': 'HTTP Proxy',
      'group': 'Port Group',
    };
    return _pagePadding(
      ListView(
        children: [
          Row(
            children: [
              Expanded(child: _pageTitle(t('服务与转发策略', 'Services and forwarding policies'), t('查看全部协议；可新建 TCP/UDP 策略', 'Inspect every protocol and create TCP/UDP policies'))),
              FilledButton.icon(
                onPressed: _clients.isEmpty ? null : _showCreateTunnel,
                icon: const Icon(Icons.add),
                label: Text(t('新建 TCP/UDP', 'New TCP/UDP')),
              ),
            ],
          ),
          const SizedBox(height: 16),
          for (final entry in labels.entries) ...[
            Text(entry.value, style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            if ((_resources[entry.key] ?? []).isEmpty)
              _emptyCard(t('暂无策略', 'No policies'))
            else
              for (final raw in _resources[entry.key]!)
                _recordCard(raw as Map<String, dynamic>, titleKeys: const ['name', 'hostname', 'id'], stateKey: 'online'),
            const SizedBox(height: 18),
          ],
        ],
      ),
    );
  }

  Widget _p2pPage() => _pagePadding(
        ListView(
          children: [
            _pageTitle('P2P', t('UDP 打洞、TCP Noise、NAT 映射和候选地址', 'UDP hole punching, TCP Noise, NAT mapping, and candidates')),
            const SizedBox(height: 16),
            if (_p2p.isEmpty) _emptyCard(t('暂无 P2P 节点', 'No P2P nodes')),
            for (final raw in _p2p) _p2pCard(raw as Map<String, dynamic>),
          ],
        ),
      );

  Widget _auditPage() => _pagePadding(
        ListView(
          children: [
            _pageTitle(t('审计日志', 'Audit log'), t('最近 50 条管理和网络事件', 'Latest 50 management and network events')),
            const SizedBox(height: 16),
            for (final raw in _audit) _recordCard(raw as Map<String, dynamic>, titleKeys: const ['event_type', 'action', 'id']),
          ],
        ),
      );

  Future<void> _showCreateTunnel() async {
    String protocol = 'tcp';
    String clientId = (_clients.first as Map<String, dynamic>)['client_id'].toString();
    final name = TextEditingController();
    final port = TextEditingController(text: '32000');
    final target = TextEditingController(text: '127.0.0.1:2333');
    String? error;
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: Text(t('新建转发策略', 'Create forwarding policy')),
          content: SizedBox(
            width: 520,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                DropdownButtonFormField<String>(
                  initialValue: protocol,
                  items: const [DropdownMenuItem(value: 'tcp', child: Text('TCP')), DropdownMenuItem(value: 'udp', child: Text('UDP'))],
                  onChanged: (value) => setDialogState(() => protocol = value ?? 'tcp'),
                  decoration: InputDecoration(labelText: t('协议', 'Protocol')),
                ),
                const SizedBox(height: 12),
                DropdownButtonFormField<String>(
                  initialValue: clientId,
                  items: [
                    for (final raw in _clients)
                      DropdownMenuItem(
                        value: (raw as Map<String, dynamic>)['client_id'].toString(),
                        child: Text('${raw['name'] ?? raw['client_id']}'),
                      ),
                  ],
                  onChanged: (value) => setDialogState(() => clientId = value ?? clientId),
                  decoration: InputDecoration(labelText: t('客户端', 'Client')),
                ),
                const SizedBox(height: 12),
                TextField(controller: name, decoration: InputDecoration(labelText: t('名称', 'Name'))),
                const SizedBox(height: 12),
                TextField(controller: port, keyboardType: TextInputType.number, decoration: InputDecoration(labelText: t('公网端口', 'Public port'))),
                const SizedBox(height: 12),
                TextField(controller: target, decoration: InputDecoration(labelText: t('目标地址', 'Target address'))),
                if (error != null) Padding(padding: const EdgeInsets.only(top: 12), child: Text(error!, style: TextStyle(color: Theme.of(context).colorScheme.error))),
              ],
            ),
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(dialogContext), child: Text(t('取消', 'Cancel'))),
            FilledButton(
              onPressed: () async {
                try {
                  final parsedPort = int.parse(port.text);
                  final path = protocol == 'tcp' ? '/api/v1/tcp-tunnels' : '/api/v1/udp-tunnels';
                  final body = <String, dynamic>{
                    'client_id': clientId,
                    'name': name.text.trim(),
                    'public_port': parsedPort,
                    'target_addr': target.text.trim(),
                    if (protocol == 'tcp') 'max_connections': 64 else 'max_sessions': 256,
                  };
                  await widget.api.postObject(path, body);
                  if (dialogContext.mounted) Navigator.pop(dialogContext);
                  await _refresh();
                } catch (value) {
                  setDialogState(() => error = value.toString());
                }
              },
              child: Text(t('创建', 'Create')),
            ),
          ],
        ),
      ),
    );
    name.dispose();
    port.dispose();
    target.dispose();
  }

  Widget _p2pCard(Map<String, dynamic> value) {
    final candidates = (value['candidates'] as List? ?? []).map((raw) {
      final candidate = raw as Map<String, dynamic>;
      if (candidate['transport'] != 'iroh_quic') return 'TCP Noise: ${candidate['endpoint']}';
      try {
        final address = jsonDecode(candidate['endpoint'].toString()) as Map<String, dynamic>;
        final network = address['network'] as Map<String, dynamic>? ?? {};
        return 'Iroh QUIC: ${(address['direct_addresses'] as List? ?? []).join(', ')}\n'
            'NAT: ${network['mapping_behavior'] ?? 'unknown'} | port map: ${network['port_mapping'] ?? false}\n'
            'relay: ${address['relay_url'] ?? '-'}';
      } catch (_) {
        return 'Iroh QUIC: ${candidate['endpoint']}';
      }
    }).join('\n\n');
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Card(
        child: ListTile(
          leading: Icon(value['fresh'] == true ? Icons.hub : Icons.hub_outlined, color: value['fresh'] == true ? Colors.green : Colors.orange),
          title: Text(value['client_id']?.toString() ?? 'P2P'),
          subtitle: SelectableText('$candidates\n${t('更新时间', 'Age')}: ${value['age_seconds'] ?? '-'}s'),
          isThreeLine: true,
        ),
      ),
    );
  }

  Widget _recordCard(Map<String, dynamic> value, {required List<String> titleKeys, String? stateKey}) {
    final title = titleKeys.map((key) => value[key]).firstWhere((item) => item != null, orElse: () => '-').toString();
    final online = stateKey == null ? null : value[stateKey] == true;
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Card(
        child: ListTile(
          leading: online == null ? const Icon(Icons.article_outlined) : Icon(online ? Icons.check_circle : Icons.pause_circle, color: online ? Colors.green : Colors.orange),
          title: Text(title),
          subtitle: SelectableText(const JsonEncoder.withIndent('  ').convert(value)),
        ),
      ),
    );
  }

  Widget _metricCard((String, String, IconData) value) => Card(
        child: Padding(
          padding: const EdgeInsets.all(18),
          child: Row(
            children: [
              CircleAvatar(child: Icon(value.$3)),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(value.$2, style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w700)),
                    Text(value.$1),
                  ],
                ),
              ),
            ],
          ),
        ),
      );

  Widget _jsonPanel(String title, Map<String, dynamic> value) => Card(
        child: ExpansionTile(
          title: Text(title),
          children: [
            Padding(
              padding: const EdgeInsets.all(16),
              child: Align(alignment: Alignment.centerLeft, child: SelectableText(const JsonEncoder.withIndent('  ').convert(value))),
            ),
          ],
        ),
      );

  Widget _emptyCard(String value) => Card(child: Padding(padding: const EdgeInsets.all(18), child: Text(value)));

  Widget _pagePadding(Widget child) => Padding(padding: const EdgeInsets.all(24), child: child);

  Widget _pageTitle(String title, String subtitle) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w700)),
          const SizedBox(height: 3),
          Text(subtitle),
        ],
      );

  String _duration(dynamic value) {
    final seconds = int.tryParse(value?.toString() ?? '') ?? 0;
    final duration = Duration(seconds: seconds);
    return '${duration.inDays}d ${duration.inHours.remainder(24)}h ${duration.inMinutes.remainder(60)}m';
  }
}

class _BrandMark extends StatelessWidget {
  const _BrandMark({required this.size});

  final double size;

  @override
  Widget build(BuildContext context) => Container(
        width: size,
        height: size,
        decoration: BoxDecoration(
          gradient: const LinearGradient(colors: [Color(0xFF0EA5E9), Color(0xFF0F766E)], begin: Alignment.topLeft, end: Alignment.bottomRight),
          borderRadius: BorderRadius.circular(size * .28),
          boxShadow: const [BoxShadow(color: Color(0x330E7490), blurRadius: 18, offset: Offset(0, 8))],
        ),
        child: Icon(Icons.waves_rounded, color: Colors.white, size: size * .62),
      );
}

class _LakeBackground extends StatelessWidget {
  const _LakeBackground();

  @override
  Widget build(BuildContext context) => DecoratedBox(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            colors: [Color(0xFFE0F2FE), Color(0xFFF0FDFA), Color(0xFFF8FAFC)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
        ),
      );
}
