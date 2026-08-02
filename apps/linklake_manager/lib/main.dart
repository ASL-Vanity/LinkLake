import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'api_client.dart';
import 'desktop_lifecycle.dart';
import 'manager_settings.dart';
import 'policy_pages.dart';
import 'rbac.dart';
import 'server_profiles.dart';
import 'version.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final repository = ManagerSettingsStore();
  var settings = await repository.load();
  final lifecycle = DesktopLifecycleController(
    adapter: NativeDesktopPlatformAdapter(),
    repository: repository,
  );
  try {
    settings = await lifecycle.initialize(settings);
  } catch (error) {
    stderr.writeln('Desktop lifecycle initialization failed: $error');
  }
  runApp(
    LinkLakeManagerApp(
      initialSettings: settings,
      settingsRepository: repository,
      desktopLifecycle: lifecycle,
    ),
  );
}

// 集中维护客户端更新命令，避免界面按钮与命令行协议发生偏差。
List<String> clientUpdateArguments(String action) => switch (action) {
  'check' => ['check-update'],
  'download' => ['update', 'download'],
  'apply' => ['update', 'apply', '--yes'],
  'rollback' => ['update', 'rollback', '--yes'],
  _ => ['update', 'status'],
};

class LinkLakeManagerApp extends StatefulWidget {
  const LinkLakeManagerApp({
    super.key,
    this.initialSettings = const ManagerSettings(),
    this.settingsRepository,
    this.desktopLifecycle,
  });

  final ManagerSettings initialSettings;
  final ManagerSettingsRepository? settingsRepository;
  final DesktopLifecycleController? desktopLifecycle;

  @override
  State<LinkLakeManagerApp> createState() => _LinkLakeManagerAppState();
}

class _LinkLakeManagerAppState extends State<LinkLakeManagerApp> {
  late ManagerSettings _settings;
  late ManagerSettingsRepository _repository;

  @override
  void initState() {
    super.initState();
    _settings = widget.initialSettings;
    _repository =
        widget.settingsRepository ?? MemoryManagerSettingsStore(_settings);
  }

  Future<void> _updateSettings(ManagerSettings value) async {
    var saved = value;
    if (widget.desktopLifecycle != null) {
      saved = await widget.desktopLifecycle!.updateSettings(value);
    } else {
      await _repository.save(value);
    }
    if (mounted) setState(() => _settings = saved);
  }

  @override
  Widget build(BuildContext context) {
    final scheme = ColorScheme.fromSeed(seedColor: const Color(0xFF168AAD));
    final darkScheme = ColorScheme.fromSeed(
      seedColor: const Color(0xFF38BDF8),
      brightness: Brightness.dark,
    );
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'LinkLake Manager',
      theme: ThemeData(
        colorScheme: scheme,
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xFFF3F8FA),
        cardTheme: const CardThemeData(elevation: 0, margin: EdgeInsets.zero),
      ),
      darkTheme: ThemeData(
        colorScheme: darkScheme,
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xFF06131D),
        cardTheme: const CardThemeData(elevation: 0, margin: EdgeInsets.zero),
      ),
      themeMode: _settings.themeMode,
      home: LoginPage(
        chinese: _settings.chinese,
        onLanguageChanged: (value) =>
            _updateSettings(_settings.copyWith(chinese: value)),
        themeMode: _settings.themeMode,
        onThemeChanged: (value) =>
            _updateSettings(_settings.copyWith(themeMode: value)),
        initialServerUrl: _settings.lastServerUrl,
        onServerChanged: (value) =>
            _updateSettings(_settings.copyWith(lastServerUrl: value)),
        settings: _settings,
        onSettingsChanged: _updateSettings,
        desktopLifecycle: widget.desktopLifecycle,
      ),
    );
  }
}

class LoginPage extends StatefulWidget {
  const LoginPage({
    super.key,
    required this.chinese,
    required this.onLanguageChanged,
    required this.themeMode,
    required this.onThemeChanged,
    this.initialServerUrl = 'https://link.odelake.com',
    this.onServerChanged,
    this.settings = const ManagerSettings(),
    this.onSettingsChanged,
    this.desktopLifecycle,
  });

  final bool chinese;
  final ValueChanged<bool> onLanguageChanged;
  final ThemeMode themeMode;
  final ValueChanged<ThemeMode> onThemeChanged;
  final String initialServerUrl;
  final ValueChanged<String>? onServerChanged;
  final ManagerSettings settings;
  final Future<void> Function(ManagerSettings)? onSettingsChanged;
  final DesktopLifecycleController? desktopLifecycle;

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  late final TextEditingController _server;
  final _username = TextEditingController(text: 'admin');
  final _password = TextEditingController();
  final _totp = TextEditingController();
  bool _busy = false;
  bool _totpRequired = false;
  String? _error;
  List<ServerProfile> _profiles = const [];

  @override
  void initState() {
    super.initState();
    _server = TextEditingController(text: widget.initialServerUrl);
    _loadProfiles();
  }

  Future<void> _loadProfiles() async {
    final profiles = await ServerProfileStore.load();
    if (!mounted) return;
    setState(() => _profiles = profiles);
    if (profiles.isNotEmpty && _server.text.trim().isEmpty) {
      _server.text = profiles.first.url;
    }
  }

  Future<void> _manageProfiles() async {
    final profiles = [..._profiles];
    final name = TextEditingController();
    final url = TextEditingController(text: 'https://');
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: Text(t('服务端列表', 'Server profiles')),
          content: SizedBox(
            width: 520,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                for (final profile in profiles)
                  ListTile(
                    leading: const Icon(Icons.cloud_outlined),
                    title: Text(profile.name),
                    subtitle: Text(profile.url),
                    onTap: () {
                      _server.text = profile.url;
                      Navigator.pop(dialogContext);
                    },
                    trailing: IconButton(
                      icon: const Icon(Icons.delete_outline),
                      onPressed: () =>
                          setDialogState(() => profiles.remove(profile)),
                    ),
                  ),
                const Divider(),
                TextField(
                  controller: name,
                  decoration: InputDecoration(labelText: t('名称', 'Name')),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: url,
                  decoration: InputDecoration(
                    labelText: t('服务端地址', 'Server URL'),
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: Text(t('完成', 'Done')),
            ),
            FilledButton.icon(
              onPressed: () {
                final profileName = name.text.trim();
                final profileUrl = url.text.trim().replaceAll(
                  RegExp(r'/+$'),
                  '',
                );
                if (profileName.isEmpty || !profileUrl.startsWith('http')) {
                  return;
                }
                setDialogState(() {
                  profiles.removeWhere((value) => value.name == profileName);
                  profiles.add(
                    ServerProfile(name: profileName, url: profileUrl),
                  );
                  name.clear();
                  url.text = 'https://';
                });
              },
              icon: const Icon(Icons.add),
              label: Text(t('添加', 'Add')),
            ),
          ],
        ),
      ),
    );
    name.dispose();
    url.dispose();
    await ServerProfileStore.save(profiles);
    if (mounted) setState(() => _profiles = profiles);
  }

  String t(String zh, String en) => widget.chinese ? zh : en;

  Future<void> _login() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    final serverUrl = _server.text.trim().replaceAll(RegExp(r'/+$'), '');
    widget.onServerChanged?.call(serverUrl);
    final api = LinkLakeApiClient(serverUrl);
    try {
      final result = await api.login(
        _username.text.trim(),
        _password.text,
        totpCode: _totpRequired ? _totp.text : null,
      );
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
            themeMode: widget.themeMode,
            onThemeChanged: widget.onThemeChanged,
            initialIdentity: result,
            settings: widget.settings.copyWith(lastServerUrl: serverUrl),
            onSettingsChanged: widget.onSettingsChanged,
            desktopLifecycle: widget.desktopLifecycle,
          ),
        ),
      );
    } on LinkLakeApiException catch (error) {
      api.close();
      if (mounted) {
        setState(() {
          if (error.code == 'totp_required') {
            _totpRequired = true;
            _error = t(
              '请输入身份验证器中的 6 位动态验证码。',
              'Enter the 6-digit code from your authenticator app.',
            );
          } else {
            _error = error.toString();
          }
        });
      }
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
                    labelText: t(
                      '新密码（至少 12 位）',
                      'New password (12+ characters)',
                    ),
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
  void dispose() {
    _server.dispose();
    _username.dispose();
    _password.dispose();
    _totp.dispose();
    super.dispose();
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
                        style: Theme.of(context).textTheme.headlineMedium
                            ?.copyWith(
                              fontWeight: FontWeight.w700,
                              color: const Color(0xFF075985),
                            ),
                      ),
                      Text(
                        t(
                          '跨平台网络服务管理客户端',
                          'Cross-platform network service manager',
                        ),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 28),
                      if (_profiles.isNotEmpty) ...[
                        DropdownButtonFormField<String>(
                          initialValue:
                              _profiles.any(
                                (value) => value.url == _server.text,
                              )
                              ? _server.text
                              : null,
                          items: [
                            for (final profile in _profiles)
                              DropdownMenuItem(
                                value: profile.url,
                                child: Text(profile.name),
                              ),
                          ],
                          onChanged: (value) {
                            if (value != null) _server.text = value;
                          },
                          decoration: InputDecoration(
                            labelText: t('服务端配置', 'Server profile'),
                            prefixIcon: const Icon(Icons.dns_outlined),
                            suffixIcon: IconButton(
                              onPressed: _manageProfiles,
                              icon: const Icon(Icons.settings_outlined),
                            ),
                          ),
                        ),
                        const SizedBox(height: 14),
                      ],
                      TextField(
                        controller: _server,
                        autofillHints: const [AutofillHints.url],
                        decoration: InputDecoration(
                          labelText: t('服务端地址', 'Server URL'),
                          prefixIcon: const Icon(Icons.cloud_outlined),
                        ),
                      ),
                      if (_totpRequired) ...[
                        const SizedBox(height: 14),
                        TextField(
                          controller: _totp,
                          keyboardType: TextInputType.number,
                          autofillHints: const [AutofillHints.oneTimeCode],
                          maxLength: 6,
                          onSubmitted: (_) => _busy ? null : _login(),
                          decoration: InputDecoration(
                            labelText: t('动态验证码', 'Verification code'),
                            prefixIcon: const Icon(Icons.security_outlined),
                            counterText: '',
                          ),
                        ),
                      ],
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
                        Text(
                          _error!,
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.error,
                          ),
                        ),
                      ],
                      const SizedBox(height: 22),
                      FilledButton.icon(
                        onPressed: _busy ? null : _login,
                        icon: _busy
                            ? const SizedBox.square(
                                dimension: 18,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                ),
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
    required this.themeMode,
    required this.onThemeChanged,
    this.initialIdentity = const {},
    this.settings = const ManagerSettings(),
    this.onSettingsChanged,
    this.desktopLifecycle,
  });

  final LinkLakeApi api;
  final bool chinese;
  final ValueChanged<bool> onLanguageChanged;
  final ThemeMode themeMode;
  final ValueChanged<ThemeMode> onThemeChanged;
  final Map<String, dynamic> initialIdentity;
  final ManagerSettings settings;
  final Future<void> Function(ManagerSettings)? onSettingsChanged;
  final DesktopLifecycleController? desktopLifecycle;

  @override
  State<DashboardPage> createState() => _DashboardPageState();
}

class _DashboardPageState extends State<DashboardPage> {
  String _page = 'overview';
  late bool _chinese;
  late ManagerSettings _settings;
  bool _busy = true;
  bool _refreshing = false;
  String? _error;
  Timer? _timer;
  Map<String, dynamic> _status = {};
  Map<String, dynamic> _metrics = {};
  List<dynamic> _clients = [];
  List<dynamic> _p2p = [];
  List<dynamic> _audit = [];
  List<dynamic> _alerts = [];
  List<dynamic> _alertRules = [];
  List<dynamic> _users = [];
  List<dynamic> _sessions = [];
  List<dynamic> _apiTokens = [];
  Map<String, dynamic> _identity = {};
  Map<String, dynamic> _fleet = {};
  Map<String, dynamic> _diagnostics = {};
  String? _latestRelease;
  bool? _updateAvailable;
  bool _clientUpdateBusy = false;
  final Map<String, List<dynamic>> _resources = {};

  bool get zh => _chinese;
  String t(String chinese, String english) => zh ? chinese : english;
  ManagementRole get _role => ManagementRole.parse(_identity['role']);
  RoleCapabilities get _capabilities => RoleCapabilities(_role);

  @override
  void initState() {
    super.initState();
    _chinese = widget.chinese;
    _settings = widget.settings;
    _identity = Map<String, dynamic>.from(widget.initialIdentity);
    _refresh();
    _timer = Timer.periodic(
      const Duration(seconds: 10),
      (_) => _refresh(silent: true),
    );
  }

  @override
  void didUpdateWidget(covariant DashboardPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.settings != widget.settings) _settings = widget.settings;
  }

  @override
  void dispose() {
    _timer?.cancel();
    widget.api.close();
    super.dispose();
  }

  Future<void> _refresh({bool silent = false}) async {
    if (_refreshing) return;
    _refreshing = true;
    if (!silent) setState(() => _busy = true);
    try {
      final identity = await widget.api.getObject('/api/v1/auth/me');
      final role = ManagementRole.parse(identity['role']);
      final results = await Future.wait(
        dashboardRequestPlan(role).map((request) async {
          try {
            final value = request.object
                ? await widget.api.getObject(request.path)
                : await widget.api.getList(request.path);
            return (request.key, value, null as Object?);
          } on LinkLakeApiException catch (error) {
            if (error.statusCode == 403) {
              final unavailable = request.object
                  ? <String, dynamic>{}
                  : <dynamic>[];
              return (request.key, unavailable, null as Object?);
            }
            return (request.key, null, error as Object?);
          } catch (error) {
            return (request.key, null, error as Object?);
          }
        }),
      );
      if (!mounted) return;
      final failures = results
          .where((result) => result.$3 != null)
          .map((result) => '${result.$1}: ${result.$3}')
          .toList();
      setState(() {
        _identity = identity;
        if (role != ManagementRole.administrator) {
          _users = [];
          _sessions = [];
          _apiTokens = [];
          _fleet = {};
        }
        if (!visibleDestinationIds(role).contains(_page)) _page = 'overview';
        for (final result in results) {
          if (result.$2 != null) _applyDashboardValue(result.$1, result.$2!);
        }
        _error = failures.isEmpty
            ? null
            : '${t('部分数据刷新失败', 'Some data could not be refreshed')}: ${failures.join('; ')}';
      });
    } catch (error) {
      if (mounted) setState(() => _error = _refreshError(error));
    } finally {
      _refreshing = false;
      if (mounted && !silent) setState(() => _busy = false);
    }
  }

  String _refreshError(Object error) {
    if (error is LinkLakeApiException) {
      if (error.statusCode == 401) {
        return t(
          '登录已失效，请退出后重新登录。',
          'Your session expired. Sign out and sign in again.',
        );
      }
      if (error.statusCode == 403) {
        return t('当前角色无法刷新此页面。', 'Your role cannot refresh this page.');
      }
    }
    return error.toString();
  }

  void _applyDashboardValue(String key, Object value) {
    switch (key) {
      case 'status':
        _status = Map<String, dynamic>.from(value as Map);
      case 'metrics':
        _metrics = Map<String, dynamic>.from(value as Map);
      case 'clients':
        _clients = value as List<dynamic>;
      case 'p2p':
        _p2p = value as List<dynamic>;
      case 'audit':
        _audit = value as List<dynamic>;
      case 'alerts':
        _alerts = value as List<dynamic>;
      case 'alertRules':
        _alertRules = value as List<dynamic>;
      case 'users':
        _users = value as List<dynamic>;
      case 'sessions':
        _sessions = value as List<dynamic>;
      case 'apiTokens':
        _apiTokens = value as List<dynamic>;
      case 'fleet':
        _fleet = Map<String, dynamic>.from(value as Map);
      default:
        _resources[key] = value as List<dynamic>;
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
          themeMode: _settings.themeMode,
          onThemeChanged: widget.onThemeChanged,
          initialServerUrl: _settings.lastServerUrl,
          settings: _settings,
          onSettingsChanged: widget.onSettingsChanged,
          desktopLifecycle: widget.desktopLifecycle,
        ),
      ),
    );
  }

  Future<void> _toggleLanguage() async {
    final updated = _settings.copyWith(chinese: !zh);
    await _applyDashboardSettings(updated);
  }

  Future<void> _changeTheme(ThemeMode value) async {
    final updated = _settings.copyWith(themeMode: value);
    await _applyDashboardSettings(updated);
  }

  Future<void> _applyDashboardSettings(ManagerSettings updated) async {
    try {
      if (widget.onSettingsChanged case final onChanged?) {
        await onChanged(updated);
      } else {
        if (updated.chinese != _settings.chinese) {
          widget.onLanguageChanged(updated.chinese);
        }
        if (updated.themeMode != _settings.themeMode) {
          widget.onThemeChanged(updated.themeMode);
        }
      }
      if (!mounted) return;
      setState(() {
        _settings = updated;
        _chinese = updated.chinese;
      });
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(error.toString())));
      }
    }
  }

  Future<void> _showManagerSettings() async {
    final desktopCapabilities =
        widget.desktopLifecycle?.capabilities ??
        const DesktopCapabilities.none();
    var language = _settings.chinese;
    var theme = _settings.themeMode;
    var closeToTray = desktopCapabilities.tray && _settings.closeToTray;
    var launchAtStartup =
        desktopCapabilities.launchAtStartup && _settings.launchAtStartup;
    var rememberWindow =
        desktopCapabilities.windowLifecycle && _settings.rememberWindow;
    final updated = await showDialog<ManagerSettings>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: Text(t('Manager 设置', 'Manager settings')),
          content: SizedBox(
            width: math.min(MediaQuery.sizeOf(context).width - 48, 540),
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  DropdownButtonFormField<bool>(
                    initialValue: language,
                    decoration: InputDecoration(labelText: t('语言', 'Language')),
                    items: const [
                      DropdownMenuItem(value: true, child: Text('中文')),
                      DropdownMenuItem(value: false, child: Text('English')),
                    ],
                    onChanged: (value) =>
                        setDialogState(() => language = value ?? true),
                  ),
                  const SizedBox(height: 12),
                  DropdownButtonFormField<ThemeMode>(
                    initialValue: theme,
                    decoration: InputDecoration(labelText: t('主题', 'Theme')),
                    items: [
                      DropdownMenuItem(
                        value: ThemeMode.system,
                        child: Text(t('跟随系统', 'System')),
                      ),
                      DropdownMenuItem(
                        value: ThemeMode.light,
                        child: Text(t('浅色', 'Light')),
                      ),
                      DropdownMenuItem(
                        value: ThemeMode.dark,
                        child: Text(t('深色', 'Dark')),
                      ),
                    ],
                    onChanged: (value) =>
                        setDialogState(() => theme = value ?? ThemeMode.system),
                  ),
                  const SizedBox(height: 12),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    value: closeToTray,
                    onChanged: desktopCapabilities.tray
                        ? (value) => setDialogState(() => closeToTray = value)
                        : null,
                    title: Text(
                      t('关闭窗口后驻留托盘', 'Keep running in tray when closed'),
                    ),
                    subtitle: Text(
                      desktopCapabilities.tray
                          ? t(
                              '托盘左键恢复窗口，右键菜单可退出',
                              'Left-click restores; use the tray menu to exit',
                            )
                          : t(
                              '当前平台或运行环境不支持系统托盘',
                              'The system tray is unavailable on this platform or runtime',
                            ),
                    ),
                  ),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    value: rememberWindow,
                    onChanged: desktopCapabilities.windowLifecycle
                        ? (value) =>
                              setDialogState(() => rememberWindow = value)
                        : null,
                    title: Text(
                      t('记住窗口位置和大小', 'Remember window position and size'),
                    ),
                  ),
                  SwitchListTile(
                    key: const Key('launch-at-startup'),
                    contentPadding: EdgeInsets.zero,
                    value: launchAtStartup,
                    onChanged: desktopCapabilities.launchAtStartup
                        ? (value) =>
                              setDialogState(() => launchAtStartup = value)
                        : null,
                    title: Text(t('开机自启动', 'Launch at startup')),
                    subtitle: Text(
                      !desktopCapabilities.launchAtStartup
                          ? t(
                              Platform.isMacOS
                                  ? '当前 macOS 工程未集成 LaunchAtLogin，功能已禁用'
                                  : '当前平台不支持开机自启',
                              Platform.isMacOS
                                  ? 'This macOS build does not integrate LaunchAtLogin, so the setting is disabled'
                                  : 'Launch at startup is unavailable on this platform',
                            )
                          : Platform.isLinux
                          ? t(
                              '取决于桌面环境的自启动和托盘支持',
                              'Depends on desktop autostart and tray support',
                            )
                          : t(
                              '登录 Windows 后自动启动',
                              'Start automatically after Windows sign-in',
                            ),
                    ),
                  ),
                  const SizedBox(height: 8),
                  Align(
                    alignment: Alignment.centerLeft,
                    child: SelectableText(
                      '${t('当前服务端', 'Current server')}: ${_settings.lastServerUrl}',
                    ),
                  ),
                ],
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: Text(t('取消', 'Cancel')),
            ),
            FilledButton(
              key: const Key('save-manager-settings'),
              onPressed: () => Navigator.pop(
                dialogContext,
                _settings.copyWith(
                  chinese: language,
                  themeMode: theme,
                  closeToTray: closeToTray,
                  launchAtStartup: launchAtStartup,
                  rememberWindow: rememberWindow,
                ),
              ),
              child: Text(t('保存', 'Save')),
            ),
          ],
        ),
      ),
    );
    if (updated == null || !mounted) return;
    await _applyDashboardSettings(updated);
  }

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final narrow = constraints.maxWidth < 900;
        final destinations = _dashboardDestinations();
        final selectedIndex = math.max(
          0,
          destinations.indexWhere((item) => item.$1 == _page),
        );
        final content = _busy
            ? const Center(child: CircularProgressIndicator())
            : Column(
                children: [
                  if (_error != null)
                    MaterialBanner(
                      content: Text(_error!),
                      actions: [
                        TextButton(
                          onPressed: _refresh,
                          child: Text(t('重试', 'Retry')),
                        ),
                      ],
                    ),
                  Expanded(child: _currentPage()),
                ],
              );
        return Scaffold(
          drawer: narrow
              ? Drawer(
                  child: SafeArea(
                    child: ListView(
                      children: [
                        const DrawerHeader(
                          child: Column(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              _BrandMark(size: 54),
                              SizedBox(height: 8),
                              Text('LinkLake Manager'),
                            ],
                          ),
                        ),
                        for (final destination in destinations)
                          ListTile(
                            key: Key('nav-${destination.$1}'),
                            selected: destination.$1 == _page,
                            leading: Icon(destination.$2),
                            title: Text(destination.$3),
                            onTap: () {
                              setState(() => _page = destination.$1);
                              Navigator.pop(context);
                            },
                          ),
                      ],
                    ),
                  ),
                )
              : null,
          appBar: AppBar(
            title: Row(
              children: [
                const _BrandMark(size: 34),
                const SizedBox(width: 10),
                Flexible(child: Text(narrow ? 'LinkLake' : 'LinkLake Manager')),
                if (!narrow && _status['instance_id'] != null) ...[
                  const SizedBox(width: 12),
                  Text(
                    _status['instance_id'].toString().substring(0, 8),
                    style: Theme.of(context).textTheme.labelSmall,
                  ),
                ],
              ],
            ),
            actions: [
              IconButton(
                onPressed: _refresh,
                tooltip: t('刷新', 'Refresh'),
                icon: const Icon(Icons.refresh),
              ),
              if (!narrow)
                TextButton.icon(
                  onPressed: _toggleLanguage,
                  icon: const Icon(Icons.language),
                  label: Text(zh ? 'English' : '中文'),
                ),
              if (!narrow)
                PopupMenuButton<ThemeMode>(
                  tooltip: t('外观', 'Appearance'),
                  initialValue: _settings.themeMode,
                  onSelected: _changeTheme,
                  itemBuilder: (_) => [
                    PopupMenuItem(
                      value: ThemeMode.system,
                      child: Text(t('跟随系统', 'System')),
                    ),
                    PopupMenuItem(
                      value: ThemeMode.light,
                      child: Text(t('浅色', 'Light')),
                    ),
                    PopupMenuItem(
                      value: ThemeMode.dark,
                      child: Text(t('深色', 'Dark')),
                    ),
                  ],
                  icon: const Icon(Icons.palette_outlined),
                ),
              IconButton(
                key: const Key('manager-settings'),
                onPressed: _showManagerSettings,
                tooltip: t('设置', 'Settings'),
                icon: const Icon(Icons.settings_outlined),
              ),
              if (narrow)
                PopupMenuButton<String>(
                  onSelected: (value) {
                    if (value == 'language') _toggleLanguage();
                    if (value == 'theme') {
                      _changeTheme(
                        _settings.themeMode == ThemeMode.dark
                            ? ThemeMode.light
                            : ThemeMode.dark,
                      );
                    }
                    if (value == 'logout') _logout();
                  },
                  itemBuilder: (_) => [
                    PopupMenuItem(
                      value: 'language',
                      child: Text(zh ? 'English' : '中文'),
                    ),
                    PopupMenuItem(
                      value: 'theme',
                      child: Text(t('切换明暗主题', 'Toggle light/dark')),
                    ),
                    PopupMenuItem(
                      value: 'logout',
                      child: Text(t('退出登录', 'Sign out')),
                    ),
                  ],
                )
              else
                IconButton(
                  onPressed: _logout,
                  tooltip: t('退出', 'Sign out'),
                  icon: const Icon(Icons.logout),
                ),
              const SizedBox(width: 4),
            ],
          ),
          body: Row(
            children: [
              if (!narrow) ...[
                SizedBox(
                  width: 176,
                  child: ListView.builder(
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    itemCount: destinations.length,
                    itemBuilder: (context, index) {
                      final item = destinations[index];
                      return ListTile(
                        key: Key('nav-${item.$1}'),
                        dense: true,
                        selected: index == selectedIndex,
                        leading: Icon(item.$2),
                        title: Text(item.$3),
                        onTap: () => setState(() => _page = item.$1),
                      );
                    },
                  ),
                ),
                const VerticalDivider(width: 1),
              ],
              Expanded(child: content),
            ],
          ),
        );
      },
    );
  }

  List<(String, IconData, String)> _dashboardDestinations() {
    final labels = <String, (IconData, String)>{
      'overview': (Icons.dashboard_outlined, t('概览', 'Overview')),
      'clients': (Icons.devices_outlined, t('客户端', 'Clients')),
      'tcp': (Icons.swap_horiz, 'TCP'),
      'udp': (Icons.bolt_outlined, 'UDP'),
      'group': (Icons.view_week_outlined, t('端口组', 'Port Groups')),
      'http': (Icons.http, 'HTTP/HTTPS'),
      'sni': (Icons.lock_outline, 'TLS SNI'),
      'secret': (Icons.key_outlined, 'Secret'),
      'socks5': (Icons.route_outlined, 'SOCKS5'),
      'proxy': (Icons.language_outlined, 'HTTP Proxy'),
      'p2p': (Icons.hub_outlined, 'P2P'),
      'fleet': (Icons.cloud_sync_outlined, t('多云', 'Multi-cloud')),
      'alerts': (Icons.warning_amber_outlined, t('告警', 'Alerts')),
      'users': (Icons.manage_accounts_outlined, t('用户', 'Users')),
      'diagnostics': (Icons.build_outlined, t('诊断', 'Diagnostics')),
      'audit': (Icons.receipt_long_outlined, t('审计', 'Audit')),
    };
    return [
      for (final id in visibleDestinationIds(_role))
        (id, labels[id]!.$1, labels[id]!.$2),
    ];
  }

  Widget _currentPage() => switch (_page) {
    'overview' => _overview(),
    'clients' => _clientsPage(),
    'tcp' => _policyPage(PolicyKind.tcp),
    'udp' => _policyPage(PolicyKind.udp),
    'group' => _policyPage(PolicyKind.group),
    'http' => _policyPage(PolicyKind.http),
    'sni' => _policyPage(PolicyKind.sni),
    'secret' => _policyPage(PolicyKind.secret),
    'socks5' => _policyPage(PolicyKind.socks5),
    'proxy' => _policyPage(PolicyKind.proxy),
    'p2p' => _p2pPage(),
    'fleet' when _capabilities.canViewFleet => _fleetPage(),
    'alerts' => _alertsPage(),
    'users' when _capabilities.canManageUsers => _usersPage(),
    'diagnostics' => _diagnosticsPage(),
    _ => _auditPage(),
  };

  Widget _overview() {
    final cards = <(String, String, IconData)>[
      (t('在线客户端', 'Clients'), '${_status['clients'] ?? 0}', Icons.devices),
      (
        t('TCP 连接', 'TCP connections'),
        '${_metrics['tcp_active_connections'] ?? 0}',
        Icons.swap_horiz,
      ),
      (
        t('UDP 会话', 'UDP sessions'),
        '${_metrics['udp_active_sessions'] ?? 0}',
        Icons.bolt,
      ),
      (
        t('HTTP 请求', 'HTTP requests'),
        '${_metrics['http_requests_total'] ?? 0}',
        Icons.http,
      ),
      (
        t('P2P 直连', 'P2P direct'),
        '${_metrics['p2p_direct_connections_total'] ?? 0}',
        Icons.hub,
      ),
      (
        t('中继回退', 'Relay fallback'),
        '${_metrics['p2p_relay_fallbacks_total'] ?? 0}',
        Icons.cloud_sync,
      ),
      (
        t('托管证书', 'Certificates'),
        '${_metrics['certificates_active'] ?? 0}',
        Icons.verified_user,
      ),
      (
        t('运行时间', 'Uptime'),
        _duration(_metrics['uptime_seconds']),
        Icons.timer_outlined,
      ),
    ];
    return _pagePadding(
      ListView(
        children: [
          _pageTitle(
            t('运行概览', 'Runtime overview'),
            t(
              '服务状态、连接与安全指标',
              'Service health, connections, and security metrics',
            ),
          ),
          const SizedBox(height: 18),
          LayoutBuilder(
            builder: (context, constraints) {
              final width = constraints.maxWidth > 1000
                  ? (constraints.maxWidth - 48) / 4
                  : (constraints.maxWidth - 16) / 2;
              return Wrap(
                spacing: 16,
                runSpacing: 16,
                children: [
                  for (final card in cards)
                    SizedBox(width: width, child: _metricCard(card)),
                ],
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
        _pageTitle(
          t('已注册客户端', 'Enrolled clients'),
          t('配置模式、同步状态和最近心跳', 'Configuration mode, sync status, and heartbeat'),
        ),
        const SizedBox(height: 16),
        for (final raw in _clients)
          _recordCard(
            raw as Map<String, dynamic>,
            titleKeys: const ['name', 'client_id'],
            stateKey: 'online',
          ),
      ],
    ),
  );

  Widget _policyPage(PolicyKind kind) => PolicyPage(
    key: ValueKey('policy-page-${kind.key}'),
    kind: kind,
    api: widget.api,
    policies: _resources[kind.key] ?? const [],
    clients: _clients,
    capabilities: _capabilities,
    chinese: zh,
    onRefresh: () => _refresh(silent: true),
    onTrafficControl: _showTrafficControl,
  );

  Widget _p2pPage() => _pagePadding(
    ListView(
      children: [
        _pageTitle(
          'P2P',
          t(
            'UDP 打洞、TCP Noise、NAT 映射和候选地址',
            'UDP hole punching, TCP Noise, NAT mapping, and candidates',
          ),
        ),
        const SizedBox(height: 16),
        if (_p2p.isEmpty) _emptyCard(t('暂无 P2P 节点', 'No P2P nodes')),
        for (final raw in _p2p) _p2pCard(raw as Map<String, dynamic>),
      ],
    ),
  );

  Widget _alertsPage() => _pagePadding(
    ListView(
      children: [
        Row(
          children: [
            Expanded(
              child: _pageTitle(
                t('告警管理', 'Alert management'),
                t(
                  '持久化规则、活动事件和通知通道',
                  'Persistent rules, active events, and notification channels',
                ),
              ),
            ),
            if (_capabilities.canManageAlerts)
              FilledButton.icon(
                onPressed: () => _showAlertRule(),
                icon: const Icon(Icons.add),
                label: Text(t('新建规则', 'New rule')),
              ),
          ],
        ),
        const SizedBox(height: 16),
        Text(
          t('活动告警', 'Active alerts'),
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        if (_alerts.isEmpty) _emptyCard(t('当前没有活动告警', 'No active alerts')),
        for (final raw in _alerts)
          _recordCard(
            raw as Map<String, dynamic>,
            titleKeys: const ['rule_name', 'subject'],
            stateKey: 'active',
          ),
        const SizedBox(height: 20),
        Text(
          t('告警规则', 'Alert rules'),
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        if (_alertRules.isEmpty) _emptyCard(t('暂无规则', 'No rules')),
        for (final raw in _alertRules)
          Card(
            margin: const EdgeInsets.only(bottom: 10),
            child: ListTile(
              leading: Icon(
                (raw as Map<String, dynamic>)['severity'] == 'critical'
                    ? Icons.error_outline
                    : Icons.warning_amber_outlined,
              ),
              title: Text('${raw['name']} · ${raw['metric']}'),
              subtitle: Text(
                '${raw['comparator']} ${raw['threshold']} · ${raw['evaluation_window_seconds']}s · ${raw['target'] ?? '*'}',
              ),
              trailing: _capabilities.canManageAlerts
                  ? Wrap(
                      spacing: 4,
                      children: [
                        IconButton(
                          onPressed: () => _showAlertRule(raw),
                          icon: const Icon(Icons.edit_outlined),
                        ),
                        IconButton(
                          onPressed: () => _deleteAlertRule(raw),
                          icon: const Icon(Icons.delete_outline),
                        ),
                      ],
                    )
                  : null,
            ),
          ),
      ],
    ),
  );

  Future<void> _showAlertRule([Map<String, dynamic>? rule]) async {
    if (!_capabilities.canManageAlerts) return;
    final name = TextEditingController(text: rule?['name']?.toString() ?? '');
    final threshold = TextEditingController(
      text: rule?['threshold']?.toString() ?? '1',
    );
    final target = TextEditingController(
      text: rule?['target']?.toString() ?? '',
    );
    final window = TextEditingController(
      text: rule?['evaluation_window_seconds']?.toString() ?? '300',
    );
    final cooldown = TextEditingController(
      text: rule?['cooldown_seconds']?.toString() ?? '900',
    );
    var metric = rule?['metric']?.toString() ?? 'client_offline';
    var comparator = rule?['comparator']?.toString() ?? 'greater_or_equal';
    var severity = rule?['severity']?.toString() ?? 'warning';
    var enabled = rule?['enabled'] != false;
    var webhook = rule?['notify_webhook'] == true;
    var email = rule?['notify_email'] == true;
    String? error;
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: Text(
            rule == null
                ? t('新建告警规则', 'New alert rule')
                : t('编辑告警规则', 'Edit alert rule'),
          ),
          content: SizedBox(
            width: 560,
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  TextField(
                    controller: name,
                    decoration: InputDecoration(labelText: t('名称', 'Name')),
                  ),
                  const SizedBox(height: 10),
                  DropdownButtonFormField<String>(
                    initialValue: metric,
                    items: const [
                      DropdownMenuItem(
                        value: 'client_offline',
                        child: Text('client_offline'),
                      ),
                      DropdownMenuItem(
                        value: 'policy_unavailable',
                        child: Text('policy_unavailable'),
                      ),
                      DropdownMenuItem(
                        value: 'authentication_failures',
                        child: Text('authentication_failures'),
                      ),
                      DropdownMenuItem(
                        value: 'traffic_bytes_per_second',
                        child: Text('traffic_bytes_per_second'),
                      ),
                      DropdownMenuItem(
                        value: 'active_connections',
                        child: Text('active_connections'),
                      ),
                      DropdownMenuItem(
                        value: 'certificate_days_remaining',
                        child: Text('certificate_days_remaining'),
                      ),
                    ],
                    onChanged: (value) =>
                        setDialogState(() => metric = value ?? metric),
                    decoration: InputDecoration(labelText: t('指标', 'Metric')),
                  ),
                  const SizedBox(height: 10),
                  Row(
                    children: [
                      Expanded(
                        child: DropdownButtonFormField<String>(
                          initialValue: comparator,
                          items: const [
                            DropdownMenuItem(
                              value: 'greater_or_equal',
                              child: Text('≥'),
                            ),
                            DropdownMenuItem(
                              value: 'less_or_equal',
                              child: Text('≤'),
                            ),
                          ],
                          onChanged: (value) => setDialogState(
                            () => comparator = value ?? comparator,
                          ),
                          decoration: InputDecoration(
                            labelText: t('比较', 'Comparator'),
                          ),
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: TextField(
                          controller: threshold,
                          keyboardType: TextInputType.number,
                          decoration: InputDecoration(
                            labelText: t('阈值', 'Threshold'),
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  TextField(
                    controller: target,
                    decoration: InputDecoration(
                      labelText: t('目标（可选）', 'Target (optional)'),
                    ),
                  ),
                  const SizedBox(height: 10),
                  Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: window,
                          keyboardType: TextInputType.number,
                          decoration: InputDecoration(
                            labelText: t('评估窗口（秒）', 'Window (seconds)'),
                          ),
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: TextField(
                          controller: cooldown,
                          keyboardType: TextInputType.number,
                          decoration: InputDecoration(
                            labelText: t('冷却（秒）', 'Cooldown (seconds)'),
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  DropdownButtonFormField<String>(
                    initialValue: severity,
                    items: const [
                      DropdownMenuItem(value: 'info', child: Text('info')),
                      DropdownMenuItem(
                        value: 'warning',
                        child: Text('warning'),
                      ),
                      DropdownMenuItem(
                        value: 'critical',
                        child: Text('critical'),
                      ),
                    ],
                    onChanged: (value) =>
                        setDialogState(() => severity = value ?? severity),
                    decoration: InputDecoration(labelText: t('级别', 'Severity')),
                  ),
                  CheckboxListTile(
                    value: enabled,
                    onChanged: (value) =>
                        setDialogState(() => enabled = value ?? true),
                    title: Text(t('启用', 'Enabled')),
                  ),
                  CheckboxListTile(
                    value: webhook,
                    onChanged: (value) =>
                        setDialogState(() => webhook = value ?? false),
                    title: const Text('Webhook'),
                  ),
                  CheckboxListTile(
                    value: email,
                    onChanged: (value) =>
                        setDialogState(() => email = value ?? false),
                    title: const Text('Email'),
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
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: Text(t('取消', 'Cancel')),
            ),
            FilledButton(
              onPressed: () async {
                try {
                  final body = <String, dynamic>{
                    'name': name.text.trim(),
                    'metric': metric,
                    'comparator': comparator,
                    'threshold': double.parse(threshold.text),
                    'target': target.text.trim().isEmpty
                        ? null
                        : target.text.trim(),
                    'evaluation_window_seconds': int.parse(window.text),
                    'cooldown_seconds': int.parse(cooldown.text),
                    'severity': severity,
                    'notify_webhook': webhook,
                    'notify_email': email,
                    'enabled': enabled,
                  };
                  if (rule == null) {
                    await widget.api.postObject('/api/v1/alerts/rules', body);
                  } else {
                    await widget.api.putObject(
                      '/api/v1/alerts/rules/${rule['id']}',
                      body,
                    );
                  }
                  if (dialogContext.mounted) Navigator.pop(dialogContext);
                  await _refresh(silent: true);
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
    for (final controller in [name, threshold, target, window, cooldown]) {
      controller.dispose();
    }
  }

  Future<void> _deleteAlertRule(Map<String, dynamic> rule) async {
    if (!_capabilities.canManageAlerts) return;
    final confirmed = await _confirmDestructive(
      t('删除告警规则？', 'Delete alert rule?'),
    );
    if (!confirmed) return;
    try {
      await widget.api.delete('/api/v1/alerts/rules/${rule['id']}');
      await _refresh(silent: true);
    } catch (error) {
      if (mounted) setState(() => _error = error.toString());
    }
  }

  Widget _usersPage() => _pagePadding(
    ListView(
      children: [
        Row(
          children: [
            Expanded(
              child: _pageTitle(
                t('用户与会话', 'Users and sessions'),
                t('角色、登录状态和活动会话', 'Roles, sign-in state, and active sessions'),
              ),
            ),
            FilledButton.icon(
              onPressed: _showCreateUser,
              icon: const Icon(Icons.person_add_alt_1),
              label: Text(t('新建用户', 'New user')),
            ),
          ],
        ),
        const SizedBox(height: 16),
        Card(
          child: ListTile(
            leading: Icon(
              _identity['totp_enabled'] == true
                  ? Icons.verified_user_outlined
                  : Icons.security_outlined,
            ),
            title: Text(t('双因素认证', 'Two-factor authentication')),
            subtitle: Text(
              _identity['totp_enabled'] == true
                  ? t(
                      '已启用，登录时需要动态验证码',
                      'Enabled; sign-in requires a verification code',
                    )
                  : t(
                      '未启用，当前仅使用密码登录',
                      'Disabled; password-only sign-in is active',
                    ),
            ),
            trailing: FilledButton.tonal(
              onPressed: _manageTotp,
              child: Text(
                _identity['totp_enabled'] == true
                    ? t('关闭', 'Disable')
                    : t('设置', 'Set up'),
              ),
            ),
          ),
        ),
        const SizedBox(height: 20),
        for (final raw in _users)
          _recordCard(
            raw as Map<String, dynamic>,
            titleKeys: const ['username', 'display_name'],
            stateKey: 'enabled',
          ),
        const SizedBox(height: 20),
        Row(
          children: [
            Expanded(
              child: Text(
                t('API 令牌', 'API tokens'),
                style: Theme.of(context).textTheme.titleMedium,
              ),
            ),
            FilledButton.icon(
              onPressed: _createApiToken,
              icon: const Icon(Icons.add),
              label: Text(t('新建令牌', 'New token')),
            ),
          ],
        ),
        const SizedBox(height: 8),
        if (_apiTokens.isEmpty) _emptyCard(t('暂无 API 令牌', 'No API tokens')),
        for (final raw in _apiTokens)
          Card(
            margin: const EdgeInsets.only(bottom: 10),
            child: ListTile(
              leading: const Icon(Icons.key_outlined),
              title: Text(
                (raw as Map<String, dynamic>)['name']?.toString() ?? '-',
              ),
              subtitle: Text(
                '${raw['scope']} · ${t('最后使用', 'Last used')}: ${raw['last_used_unix_seconds'] ?? t('从未', 'Never')}',
              ),
              trailing: IconButton(
                onPressed: () => _revokeApiToken(raw),
                icon: const Icon(Icons.delete_outline),
              ),
            ),
          ),
        const SizedBox(height: 20),
        Text(
          t('活动会话', 'Active sessions'),
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        for (final raw in _sessions)
          _recordCard(
            raw as Map<String, dynamic>,
            titleKeys: const ['username', 'session_id'],
          ),
      ],
    ),
  );

  Future<void> _manageTotp() async {
    if (!_capabilities.canManageTotp) return;
    final enabled = _identity['totp_enabled'] == true;
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
      } catch (value) {
        if (mounted) setState(() => _error = value.toString());
        code.dispose();
        return;
      }
    }
    if (!mounted) {
      code.dispose();
      return;
    }
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
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
              onPressed: () => Navigator.pop(dialogContext),
              child: Text(t('取消', 'Cancel')),
            ),
            FilledButton(
              onPressed: () async {
                try {
                  await widget.api.post(
                    '/api/v1/auth/totp/${enabled ? 'disable' : 'enable'}',
                    {'code': code.text},
                  );
                  if (dialogContext.mounted) Navigator.pop(dialogContext);
                  await _refresh(silent: true);
                } catch (value) {
                  setDialogState(() => error = value.toString());
                }
              },
              child: Text(enabled ? t('关闭', 'Disable') : t('启用', 'Enable')),
            ),
          ],
        ),
      ),
    );
    code.dispose();
  }

  Future<void> _createApiToken() async {
    if (!_capabilities.canManageApiTokens) return;
    final name = TextEditingController();
    final days = TextEditingController();
    var scope = 'read';
    String? error;
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: Text(t('新建 API 令牌', 'New API token')),
          content: SizedBox(
            width: 460,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: name,
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
                  onChanged: (value) =>
                      setDialogState(() => scope = value ?? scope),
                  decoration: InputDecoration(labelText: t('权限范围', 'Scope')),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: days,
                  keyboardType: TextInputType.number,
                  decoration: InputDecoration(
                    labelText: t('有效天数（可选）', 'Expiry days (optional)'),
                  ),
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
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: Text(t('取消', 'Cancel')),
            ),
            FilledButton(
              onPressed: () async {
                try {
                  final expiryDays = int.tryParse(days.text);
                  final created = await widget.api
                      .postObject('/api/v1/api-tokens', {
                        'name': name.text.trim(),
                        'scope': scope,
                        'expires_unix_seconds': expiryDays == null
                            ? null
                            : DateTime.now().millisecondsSinceEpoch ~/ 1000 +
                                  expiryDays * 86400,
                      });
                  if (!dialogContext.mounted) return;
                  Navigator.pop(dialogContext);
                  await showDialog<void>(
                    context: context,
                    builder: (context) => AlertDialog(
                      title: Text(t('请立即复制令牌', 'Copy this token now')),
                      content: SelectableText(
                        created['token']?.toString() ?? '',
                      ),
                      actions: [
                        FilledButton(
                          onPressed: () => Navigator.pop(context),
                          child: Text(t('完成', 'Done')),
                        ),
                      ],
                    ),
                  );
                  await _refresh(silent: true);
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
    days.dispose();
  }

  Future<void> _revokeApiToken(Map<String, dynamic> token) async {
    if (!_capabilities.canManageApiTokens) return;
    final confirmed = await _confirmDestructive(
      t('撤销 API 令牌？', 'Revoke API token?'),
    );
    if (!confirmed) return;
    try {
      await widget.api.delete('/api/v1/api-tokens/${token['id']}');
      await _refresh(silent: true);
    } catch (error) {
      if (mounted) setState(() => _error = error.toString());
    }
  }

  Future<void> _showCreateUser() async {
    if (!_capabilities.canManageUsers) return;
    final username = TextEditingController();
    final displayName = TextEditingController();
    final password = TextEditingController();
    var role = 'operator';
    String? error;
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: Text(t('新建用户', 'New user')),
          content: SizedBox(
            width: 460,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: username,
                  decoration: InputDecoration(labelText: t('用户名', 'Username')),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: displayName,
                  decoration: InputDecoration(
                    labelText: t('显示名称', 'Display name'),
                  ),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: password,
                  obscureText: true,
                  decoration: InputDecoration(
                    labelText: t('密码（至少 12 位）', 'Password (12+ characters)'),
                  ),
                ),
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
                    DropdownMenuItem(value: 'auditor', child: Text('auditor')),
                  ],
                  onChanged: (value) =>
                      setDialogState(() => role = value ?? role),
                  decoration: InputDecoration(labelText: t('角色', 'Role')),
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
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: Text(t('取消', 'Cancel')),
            ),
            FilledButton(
              onPressed: () async {
                try {
                  await widget.api.postObject('/api/v1/users', {
                    'username': username.text.trim(),
                    'display_name': displayName.text.trim(),
                    'role': role,
                    'password': password.text,
                    'force_password_change': true,
                  });
                  if (dialogContext.mounted) Navigator.pop(dialogContext);
                  await _refresh(silent: true);
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
    username.dispose();
    displayName.dispose();
    password.dispose();
  }

  Widget _diagnosticsPage() => _pagePadding(
    ListView(
      children: [
        Row(
          children: [
            Expanded(
              child: _pageTitle(
                t('连接与配置诊断', 'Connection and configuration diagnostics'),
                t(
                  '检查管理 API、延迟、版本和本地环境',
                  'Check management API, latency, version, and local environment',
                ),
              ),
            ),
            FilledButton.icon(
              onPressed: _runDiagnostics,
              icon: const Icon(Icons.play_arrow),
              label: Text(t('开始诊断', 'Run diagnostics')),
            ),
          ],
        ),
        const SizedBox(height: 16),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            OutlinedButton.icon(
              onPressed: _showLocalDiagnose,
              icon: const Icon(Icons.fact_check_outlined),
              label: Text(t('诊断本地配置', 'Diagnose local config')),
            ),
            OutlinedButton.icon(
              onPressed: _showServiceInstall,
              icon: const Icon(Icons.install_desktop_outlined),
              label: Text(t('安装客户端服务', 'Install client service')),
            ),
            OutlinedButton.icon(
              onPressed: () => _runServiceAction('status'),
              icon: const Icon(Icons.info_outline),
              label: Text(t('服务状态', 'Service status')),
            ),
            OutlinedButton.icon(
              onPressed: () => _runServiceAction('restart'),
              icon: const Icon(Icons.restart_alt),
              label: Text(t('重启服务', 'Restart service')),
            ),
            OutlinedButton.icon(
              onPressed: _showLocalLogs,
              icon: const Icon(Icons.description_outlined),
              label: Text(t('查看本地日志', 'View local logs')),
            ),
            OutlinedButton.icon(
              onPressed: _clientUpdateBusy
                  ? null
                  : () => _runClientUpdate('check'),
              icon: const Icon(Icons.manage_search_outlined),
              label: Text(t('检查客户端更新', 'Check client update')),
            ),
            OutlinedButton.icon(
              onPressed: _clientUpdateBusy
                  ? null
                  : () => _runClientUpdate('download'),
              icon: const Icon(Icons.download_for_offline_outlined),
              label: Text(t('下载并验证', 'Download and verify')),
            ),
            FilledButton.icon(
              onPressed: _clientUpdateBusy
                  ? null
                  : () => _confirmClientUpdate('apply'),
              icon: const Icon(Icons.system_update_alt),
              label: Text(t('安装客户端更新', 'Install client update')),
            ),
            OutlinedButton.icon(
              onPressed: _clientUpdateBusy
                  ? null
                  : () => _confirmClientUpdate('rollback'),
              icon: const Icon(Icons.settings_backup_restore),
              label: Text(t('回滚客户端', 'Rollback client')),
            ),
            OutlinedButton.icon(
              onPressed: _clientUpdateBusy
                  ? null
                  : () => _runClientUpdate('status'),
              icon: const Icon(Icons.fact_check_outlined),
              label: Text(t('更新状态', 'Update status')),
            ),
          ],
        ),
        const SizedBox(height: 16),
        if (_diagnostics.isEmpty)
          _emptyCard(t('尚未运行诊断', 'Diagnostics have not run yet'))
        else
          _jsonPanel(t('诊断结果', 'Diagnostic results'), _diagnostics),
        const SizedBox(height: 16),
        _jsonPanel(t('版本信息', 'Version information'), {
          'manager_version': managerVersion,
          'release_version': managerReleaseVersion,
          'latest_release': _latestRelease ?? t('尚未检查', 'Not checked'),
          'update_available': _updateAvailable,
          'server': widget.api.baseUri.toString(),
          'platform': Platform.operatingSystem,
          'platform_version': Platform.operatingSystemVersion,
        }),
      ],
    ),
  );

  Future<void> _runDiagnostics() async {
    final started = DateTime.now();
    try {
      final health = await widget.api.getObject('/api/v1/health');
      final status = await widget.api.getObject('/api/v1/status');
      final channels = await widget.api.getObject('/api/v1/alerts/channels');
      final releaseClient = HttpClient()
        ..connectionTimeout = const Duration(seconds: 10);
      try {
        final request = await releaseClient.getUrl(
          Uri.parse(
            'https://api.github.com/repos/ASL-Vanity/LinkLake/releases?per_page=30',
          ),
        );
        request.headers.set(
          HttpHeaders.userAgentHeader,
          'LinkLake-Manager/$managerVersion',
        );
        final response = await request.close().timeout(
          const Duration(seconds: 15),
        );
        if (response.statusCode < 200 || response.statusCode >= 300) {
          throw HttpException(
            'GitHub releases returned HTTP ${response.statusCode}',
          );
        }
        final decoded = jsonDecode(await utf8.decoder.bind(response).join());
        if (decoded is List) {
          _latestRelease = selectLatestReleaseTag(
            decoded,
            managerReleaseVersion,
          );
          _updateAvailable = _latestRelease == null
              ? null
              : isReleaseNewer(_latestRelease!, managerReleaseVersion);
        }
      } finally {
        releaseClient.close(force: true);
      }
      if (!mounted) return;
      setState(
        () => _diagnostics = {
          'ok': true,
          'latency_ms': DateTime.now().difference(started).inMilliseconds,
          'health': health,
          'status': status,
          'notifications': channels,
          'client_count': _clients.length,
          'policy_count': _resources.values.fold<int>(
            0,
            (total, values) => total + values.length,
          ),
          'timestamp': DateTime.now().toIso8601String(),
        },
      );
    } catch (error) {
      if (mounted) {
        setState(
          () => _diagnostics = {
            'ok': false,
            'error': error.toString(),
            'latency_ms': DateTime.now().difference(started).inMilliseconds,
          },
        );
      }
    }
  }

  Widget _fleetPage() {
    final peers = (_fleet['peers'] as List? ?? const []);
    final preferred = _fleet['preferred_peer_id']?.toString();
    final conflicts = (_fleet['conflicts'] as List? ?? const []);
    return _pagePadding(
      ListView(
        children: [
          Row(
            children: [
              Expanded(
                child: _pageTitle(
                  t('多云集中管理', 'Multi-cloud management'),
                  t(
                    '服务端健康、延迟、流量、首选入口和故障切换顺序',
                    'Server health, latency, traffic, preferred entry, and failover order',
                  ),
                ),
              ),
              FilledButton.icon(
                onPressed: () => _showFleetPeer(),
                icon: const Icon(Icons.add),
                label: Text(t('添加服务端', 'Add server')),
              ),
            ],
          ),
          const SizedBox(height: 16),
          if (conflicts.isNotEmpty)
            for (final conflict in conflicts)
              Card(
                color: Theme.of(context).colorScheme.errorContainer,
                margin: const EdgeInsets.only(bottom: 8),
                child: ListTile(
                  leading: const Icon(Icons.warning_amber_outlined),
                  title: Text(t('部署冲突', 'Placement conflict')),
                  subtitle: Text(conflict.toString()),
                ),
              ),
          if (peers.isEmpty)
            _emptyCard(t('尚未配置多云服务端', 'No multi-cloud servers configured')),
          for (final raw in peers)
            Card(
              margin: const EdgeInsets.only(bottom: 10),
              child: ListTile(
                leading: Icon(
                  (raw as Map<String, dynamic>)['online'] == true
                      ? Icons.cloud_done_outlined
                      : Icons.cloud_off_outlined,
                ),
                title: Text(
                  '${raw['name']}${raw['id']?.toString() == preferred ? ' · ${t('首选', 'Preferred')}' : ''}',
                ),
                subtitle: Text(
                  '${raw['region']} · ${raw['url']}\n${t('延迟', 'Latency')}: ${raw['latency_millis'] ?? '-'} ms · ${t('优先级', 'Priority')}: ${raw['priority']} · ${t('权重', 'Weight')}: ${raw['weight']}\n${raw['error'] ?? t('在线', 'Online')}',
                ),
                isThreeLine: true,
                trailing: Wrap(
                  spacing: 4,
                  children: [
                    IconButton(
                      onPressed: () => _showFleetPeer(raw),
                      icon: const Icon(Icons.edit_outlined),
                    ),
                    IconButton(
                      onPressed: () => _deleteFleetPeer(raw),
                      icon: const Icon(Icons.delete_outline),
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }

  Future<void> _showFleetPeer([Map<String, dynamic>? peer]) async {
    if (!_capabilities.canManageFleet) return;
    final name = TextEditingController(text: peer?['name']?.toString() ?? '');
    final url = TextEditingController(
      text: peer?['url']?.toString() ?? 'https://',
    );
    final region = TextEditingController(
      text: peer?['region']?.toString() ?? '',
    );
    final tokenEnv = TextEditingController(
      text: peer?['token_env']?.toString() ?? 'LINKLAKE_FLEET_TOKEN',
    );
    final priority = TextEditingController(
      text: peer?['priority']?.toString() ?? '100',
    );
    final weight = TextEditingController(
      text: peer?['weight']?.toString() ?? '100',
    );
    var enabled = peer?['enabled'] != false;
    String? error;
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: Text(
            peer == null ? t('添加服务端', 'Add server') : t('编辑服务端', 'Edit server'),
          ),
          content: SizedBox(
            width: 520,
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  TextField(
                    controller: name,
                    decoration: InputDecoration(labelText: t('名称', 'Name')),
                  ),
                  const SizedBox(height: 10),
                  TextField(
                    controller: url,
                    decoration: const InputDecoration(labelText: 'URL'),
                  ),
                  const SizedBox(height: 10),
                  TextField(
                    controller: region,
                    decoration: InputDecoration(labelText: t('地域', 'Region')),
                  ),
                  const SizedBox(height: 10),
                  TextField(
                    controller: tokenEnv,
                    decoration: InputDecoration(
                      labelText: t('令牌环境变量', 'Token environment variable'),
                      helperText: t(
                        '令牌本身不会写入数据库',
                        'The token itself is not stored in the database',
                      ),
                    ),
                  ),
                  const SizedBox(height: 10),
                  Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: priority,
                          keyboardType: TextInputType.number,
                          decoration: InputDecoration(
                            labelText: t('优先级', 'Priority'),
                          ),
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: TextField(
                          controller: weight,
                          keyboardType: TextInputType.number,
                          decoration: InputDecoration(
                            labelText: t('权重', 'Weight'),
                          ),
                        ),
                      ),
                    ],
                  ),
                  CheckboxListTile(
                    value: enabled,
                    onChanged: (value) =>
                        setDialogState(() => enabled = value ?? true),
                    title: Text(t('启用', 'Enabled')),
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
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: Text(t('取消', 'Cancel')),
            ),
            FilledButton(
              onPressed: () async {
                try {
                  final body = {
                    'name': name.text.trim(),
                    'url': url.text.trim(),
                    'region': region.text.trim(),
                    'token_env': tokenEnv.text.trim(),
                    'priority': int.parse(priority.text),
                    'weight': int.parse(weight.text),
                    'enabled': enabled,
                  };
                  if (peer == null) {
                    await widget.api.postObject('/api/v1/fleet/peers', body);
                  } else {
                    await widget.api.putObject(
                      '/api/v1/fleet/peers/${peer['id']}',
                      body,
                    );
                  }
                  if (dialogContext.mounted) Navigator.pop(dialogContext);
                  await _refresh(silent: true);
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
    for (final controller in [name, url, region, tokenEnv, priority, weight]) {
      controller.dispose();
    }
  }

  Future<void> _deleteFleetPeer(Map<String, dynamic> peer) async {
    if (!_capabilities.canManageFleet) return;
    final confirmed = await _confirmDestructive(
      t('删除多云节点？', 'Delete fleet peer?'),
    );
    if (!confirmed) return;
    try {
      await widget.api.delete('/api/v1/fleet/peers/${peer['id']}');
      await _refresh(silent: true);
    } catch (error) {
      if (mounted) setState(() => _error = error.toString());
    }
  }

  Future<bool> _confirmDestructive(String title) async =>
      await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: Text(title),
          content: Text(t('此操作无法撤销。', 'This action cannot be undone.')),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: Text(t('取消', 'Cancel')),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: Text(t('确认', 'Confirm')),
            ),
          ],
        ),
      ) ??
      false;

  String _clientBinary() {
    final directory = File(Platform.resolvedExecutable).parent.path;
    final name = Platform.isWindows ? 'linklake-client.exe' : 'linklake-client';
    final bundled = File('$directory${Platform.pathSeparator}$name');
    if (bundled.existsSync()) return bundled.path;
    if (Platform.isMacOS) {
      final resources = File(
        '${Directory(directory).parent.path}${Platform.pathSeparator}Resources${Platform.pathSeparator}$name',
      );
      if (resources.existsSync()) return resources.path;
    }
    return name;
  }

  Future<ProcessResult> _runClient(List<String> arguments) =>
      Process.run(_clientBinary(), arguments);

  Future<String?> _askConfigPath(String title) async {
    final controller = TextEditingController(
      text: Platform.isWindows
          ? r'C:\ProgramData\LinkLake\client.toml'
          : '/etc/linklake/client.toml',
    );
    final result = await showDialog<String>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text(title),
        content: SizedBox(
          width: 520,
          child: TextField(
            controller: controller,
            decoration: InputDecoration(
              labelText: t('配置文件路径', 'Configuration file path'),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: Text(t('取消', 'Cancel')),
          ),
          FilledButton(
            onPressed: () =>
                Navigator.pop(dialogContext, controller.text.trim()),
            child: Text(t('继续', 'Continue')),
          ),
        ],
      ),
    );
    controller.dispose();
    return result;
  }

  Future<void> _showLocalDiagnose() async {
    final path = await _askConfigPath(
      t('诊断本地配置', 'Diagnose local configuration'),
    );
    if (path == null || path.isEmpty) return;
    final result = await _runClient(['diagnose', '--config', path]);
    if (!mounted) return;
    setState(
      () => _diagnostics['local_client'] = {
        'exit_code': result.exitCode,
        'stdout': result.stdout.toString(),
        'stderr': result.stderr.toString(),
      },
    );
  }

  Future<void> _showServiceInstall() async {
    final path = await _askConfigPath(t('安装客户端服务', 'Install client service'));
    if (path == null || path.isEmpty) return;
    final result = await _runClient([
      'service',
      'install',
      '--config',
      path,
      '--silent',
    ]);
    if (!mounted) return;
    setState(
      () => _diagnostics['service_install'] = {
        'exit_code': result.exitCode,
        'stdout': result.stdout.toString(),
        'stderr': result.stderr.toString(),
        'note': t(
          '安装系统服务通常需要以管理员/root 身份运行 Manager。',
          'Installing a system service usually requires running Manager as administrator/root.',
        ),
      },
    );
  }

  Future<void> _runServiceAction(String action) async {
    final result = await _runClient(['service', action]);
    if (!mounted) return;
    setState(
      () => _diagnostics['service_$action'] = {
        'exit_code': result.exitCode,
        'stdout': result.stdout.toString(),
        'stderr': result.stderr.toString(),
      },
    );
  }

  Future<void> _showLocalLogs() async {
    final result = await _runClient(['logs', '--lines', '200']);
    if (!mounted) return;
    setState(
      () => _diagnostics['local_logs'] = {
        'exit_code': result.exitCode,
        'stdout': result.stdout.toString(),
        'stderr': result.stderr.toString(),
      },
    );
  }

  Future<void> _confirmClientUpdate(String action) async {
    final rollback = action == 'rollback';
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text(
          rollback
              ? t('确认回滚客户端', 'Confirm client rollback')
              : t('确认安装客户端更新', 'Confirm client update'),
        ),
        content: Text(
          rollback
              ? t(
                  '将使用最后一份经过校验的客户端备份。更新帮助进程会停止匹配的系统服务、原子替换程序并重新启动服务。',
                  'The last verified client backup will be used. The update helper stops the matching service, atomically replaces the binary, and restarts the service.',
                )
              : t(
                  '将从官方 GitHub Release 下载程序，校验 GitHub 摘要、SHA-256 文件、平台、版本和归档内容，然后创建备份并原子替换。失败时会自动恢复。',
                  'The client is downloaded from the official GitHub release and validated against GitHub metadata, the SHA-256 file, platform, version, and archive contents. A backup is created and restored automatically on failure.',
                ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: Text(t('取消', 'Cancel')),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: Text(rollback ? t('回滚', 'Rollback') : t('安装', 'Install')),
          ),
        ],
      ),
    );
    if (confirmed == true) await _runClientUpdate(action);
  }

  Future<void> _runClientUpdate(String action) async {
    setState(() => _clientUpdateBusy = true);
    try {
      final arguments = clientUpdateArguments(action);
      final result = await _runClient(arguments);
      Map<String, dynamic>? followUp;
      if ((action == 'apply' || action == 'rollback') && result.exitCode == 0) {
        await Future<void>.delayed(const Duration(seconds: 3));
        final status = await _runClient(['update', 'status']);
        followUp = {
          'exit_code': status.exitCode,
          'stdout': status.stdout.toString(),
          'stderr': status.stderr.toString(),
        };
      }
      if (!mounted) return;
      setState(
        () => _diagnostics['client_update'] = {
          'action': action,
          'exit_code': result.exitCode,
          'stdout': result.stdout.toString(),
          'stderr': result.stderr.toString(),
          'status_after_schedule': followUp,
          'administrator_note': t(
            '替换系统安装目录中的客户端通常需要以管理员/root 身份运行 Manager。',
            'Replacing a client in a system installation usually requires running Manager as administrator/root.',
          ),
        },
      );
    } finally {
      if (mounted) setState(() => _clientUpdateBusy = false);
    }
  }

  Widget _auditPage() => _pagePadding(
    ListView(
      children: [
        _pageTitle(
          t('审计日志', 'Audit log'),
          t('最近 50 条管理和网络事件', 'Latest 50 management and network events'),
        ),
        const SizedBox(height: 16),
        for (final raw in _audit)
          _recordCard(
            raw as Map<String, dynamic>,
            titleKeys: const ['event_type', 'action', 'id'],
          ),
      ],
    ),
  );

  // Kept for compatibility with older integration tests; the v0.8 UI uses
  // the schema-driven protocol editors in policy_pages.dart.
  // ignore: unused_element
  Future<void> _showCreateTunnel() async {
    String protocol = 'tcp';
    String clientId = (_clients.first as Map<String, dynamic>)['client_id']
        .toString();
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
                  items: const [
                    DropdownMenuItem(value: 'tcp', child: Text('TCP')),
                    DropdownMenuItem(value: 'udp', child: Text('UDP')),
                  ],
                  onChanged: (value) =>
                      setDialogState(() => protocol = value ?? 'tcp'),
                  decoration: InputDecoration(labelText: t('协议', 'Protocol')),
                ),
                const SizedBox(height: 12),
                DropdownButtonFormField<String>(
                  initialValue: clientId,
                  items: [
                    for (final raw in _clients)
                      DropdownMenuItem(
                        value: (raw as Map<String, dynamic>)['client_id']
                            .toString(),
                        child: Text('${raw['name'] ?? raw['client_id']}'),
                      ),
                  ],
                  onChanged: (value) =>
                      setDialogState(() => clientId = value ?? clientId),
                  decoration: InputDecoration(labelText: t('客户端', 'Client')),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: name,
                  decoration: InputDecoration(labelText: t('名称', 'Name')),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: port,
                  keyboardType: TextInputType.number,
                  decoration: InputDecoration(
                    labelText: t('公网端口', 'Public port'),
                  ),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: target,
                  decoration: InputDecoration(
                    labelText: t('目标地址', 'Target address'),
                  ),
                ),
                if (error != null)
                  Padding(
                    padding: const EdgeInsets.only(top: 12),
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
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: Text(t('取消', 'Cancel')),
            ),
            FilledButton(
              onPressed: () async {
                try {
                  final parsedPort = int.parse(port.text);
                  final path = protocol == 'tcp'
                      ? '/api/v1/tcp-tunnels'
                      : '/api/v1/udp-tunnels';
                  final body = <String, dynamic>{
                    'client_id': clientId,
                    'name': name.text.trim(),
                    'public_port': parsedPort,
                    'target_addr': target.text.trim(),
                    if (protocol == 'tcp')
                      'max_connections': 64
                    else
                      'max_sessions': 256,
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

  Future<void> _showTrafficControl(
    String kind,
    Map<String, dynamic> policy,
  ) async {
    if (!_capabilities.canManageTrafficControl) return;
    final path = '/api/v1/traffic-controls/$kind/${policy['id']}';
    Map<String, dynamic>? current;
    try {
      current = await widget.api.getObject(path);
    } on LinkLakeApiException catch (error) {
      if (error.statusCode != 404) rethrow;
    }
    if (!mounted) return;

    final allowed = TextEditingController(
      text: ((current?['allowed_cidrs'] as List?) ?? const []).join('\n'),
    );
    final denied = TextEditingController(
      text: ((current?['denied_cidrs'] as List?) ?? const []).join('\n'),
    );
    final rate = TextEditingController(
      text: current?['max_connections_per_minute']?.toString() ?? '',
    );
    final quota = TextEditingController(
      text: current?['daily_quota_bytes'] == null
          ? ''
          : ((current!['daily_quota_bytes'] as num) / 1048576)
                .toStringAsFixed(2)
                .replaceFirst(RegExp(r'\.00$'), ''),
    );
    final weekdays = TextEditingController(
      text: ((current?['active_weekdays_utc'] as List?) ?? const []).join(','),
    );
    String minuteText(dynamic value) {
      if (value == null) return '';
      final minute = (value as num).toInt();
      return '${(minute ~/ 60).toString().padLeft(2, '0')}:${(minute % 60).toString().padLeft(2, '0')}';
    }

    final start = TextEditingController(
      text: minuteText(current?['start_minute_utc']),
    );
    final end = TextEditingController(
      text: minuteText(current?['end_minute_utc']),
    );
    var enabled = current?['enabled'] != false;
    String? error;
    bool saved = false;

    List<String> splitValues(String value) => value
        .split(RegExp(r'[\s,]+'))
        .map((item) => item.trim())
        .where((item) => item.isNotEmpty)
        .toList();
    int? optionalInt(String value) {
      final text = value.trim();
      return text.isEmpty ? null : int.parse(text);
    }

    int? parseMinute(String value) {
      final text = value.trim();
      if (text.isEmpty) return null;
      final match = RegExp(r'^(\d{1,2}):(\d{2})$').firstMatch(text);
      if (match == null) throw const FormatException('invalid time');
      final hour = int.parse(match.group(1)!);
      final minute = int.parse(match.group(2)!);
      if (hour > 23 || minute > 59) {
        throw const FormatException('invalid time');
      }
      return hour * 60 + minute;
    }

    await showDialog<void>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: Text(
            '${t('流量控制', 'Traffic control')} · ${policy['name'] ?? policy['hostname'] ?? policy['id']}',
          ),
          content: SizedBox(
            width: 620,
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    value: enabled,
                    onChanged: (value) => setDialogState(() => enabled = value),
                    title: Text(t('启用限制', 'Enable controls')),
                  ),
                  TextField(
                    controller: allowed,
                    minLines: 2,
                    maxLines: 4,
                    decoration: InputDecoration(
                      labelText: t('允许 CIDR（每行一个）', 'Allowed CIDRs'),
                      hintText: '10.0.0.0/8',
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: denied,
                    minLines: 2,
                    maxLines: 4,
                    decoration: InputDecoration(
                      labelText: t('拒绝 CIDR（每行一个）', 'Denied CIDRs'),
                      hintText: '198.51.100.0/24',
                    ),
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: rate,
                          keyboardType: TextInputType.number,
                          decoration: InputDecoration(
                            labelText: t('每分钟新连接上限', 'New connections/minute'),
                          ),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: TextField(
                          controller: quota,
                          keyboardType: const TextInputType.numberWithOptions(
                            decimal: true,
                          ),
                          decoration: InputDecoration(
                            labelText: t('每日流量配额 MiB', 'Daily quota MiB'),
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: weekdays,
                    decoration: InputDecoration(
                      labelText: t('UTC 星期（周一=0，逗号分隔）', 'UTC weekdays (Mon=0)'),
                      hintText: '0,1,2,3,4',
                    ),
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: start,
                          decoration: InputDecoration(
                            labelText: t('UTC 开始时间', 'UTC start'),
                            hintText: '09:00',
                          ),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: TextField(
                          controller: end,
                          decoration: InputDecoration(
                            labelText: t('UTC 结束时间', 'UTC end'),
                            hintText: '18:00',
                          ),
                        ),
                      ),
                    ],
                  ),
                  if (current?['used_today_bytes'] != null)
                    Padding(
                      padding: const EdgeInsets.only(top: 12),
                      child: Align(
                        alignment: Alignment.centerLeft,
                        child: Text(
                          '${t('今日已用', 'Used today')}: ${current!['used_today_bytes']} bytes',
                        ),
                      ),
                    ),
                  if (error != null)
                    Padding(
                      padding: const EdgeInsets.only(top: 12),
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
            if (current != null)
              TextButton(
                onPressed: () async {
                  await widget.api.delete(path);
                  if (dialogContext.mounted) Navigator.pop(dialogContext);
                },
                child: Text(t('清除限制', 'Clear controls')),
              ),
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: Text(t('取消', 'Cancel')),
            ),
            FilledButton(
              onPressed: () async {
                try {
                  final startMinute = parseMinute(start.text);
                  final endMinute = parseMinute(end.text);
                  if ((startMinute == null) != (endMinute == null)) {
                    throw FormatException(
                      t('开始和结束时间必须同时填写', 'Enter both start and end'),
                    );
                  }
                  final quotaText = quota.text.trim();
                  await widget.api.putObject(path, {
                    'allowed_cidrs': splitValues(allowed.text),
                    'denied_cidrs': splitValues(denied.text),
                    'max_connections_per_minute': optionalInt(rate.text),
                    'daily_quota_bytes': quotaText.isEmpty
                        ? null
                        : (double.parse(quotaText) * 1048576).round(),
                    'active_weekdays_utc': splitValues(
                      weekdays.text,
                    ).map(int.parse).toList(),
                    'start_minute_utc': startMinute,
                    'end_minute_utc': endMinute,
                    'enabled': enabled,
                  });
                  saved = true;
                  if (dialogContext.mounted) Navigator.pop(dialogContext);
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
    allowed.dispose();
    denied.dispose();
    rate.dispose();
    quota.dispose();
    weekdays.dispose();
    start.dispose();
    end.dispose();
    if (saved && mounted) await _refresh(silent: true);
  }

  Widget _p2pCard(Map<String, dynamic> value) {
    final candidates = (value['candidates'] as List? ?? [])
        .map((raw) {
          final candidate = raw as Map<String, dynamic>;
          if (candidate['transport'] != 'iroh_quic') {
            return 'TCP Noise: ${candidate['endpoint']}';
          }
          try {
            final address =
                jsonDecode(candidate['endpoint'].toString())
                    as Map<String, dynamic>;
            final network = address['network'] as Map<String, dynamic>? ?? {};
            return 'Iroh QUIC: ${(address['direct_addresses'] as List? ?? []).join(', ')}\n'
                'NAT: ${network['mapping_behavior'] ?? 'unknown'} | port map: ${network['port_mapping'] ?? false}\n'
                'relay: ${address['relay_url'] ?? '-'}';
          } catch (_) {
            return 'Iroh QUIC: ${candidate['endpoint']}';
          }
        })
        .join('\n\n');
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Card(
        child: ListTile(
          leading: Icon(
            value['fresh'] == true ? Icons.hub : Icons.hub_outlined,
            color: value['fresh'] == true ? Colors.green : Colors.orange,
          ),
          title: Text(value['client_id']?.toString() ?? 'P2P'),
          subtitle: SelectableText(
            '$candidates\n${t('更新时间', 'Age')}: ${value['age_seconds'] ?? '-'}s',
          ),
          isThreeLine: true,
        ),
      ),
    );
  }

  Widget _recordCard(
    Map<String, dynamic> value, {
    required List<String> titleKeys,
    String? stateKey,
    Widget? trailing,
  }) {
    final title = titleKeys
        .map((key) => value[key])
        .firstWhere((item) => item != null, orElse: () => '-')
        .toString();
    final online = stateKey == null ? null : value[stateKey] == true;
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Card(
        child: ListTile(
          leading: online == null
              ? const Icon(Icons.article_outlined)
              : Icon(
                  online ? Icons.check_circle : Icons.pause_circle,
                  color: online ? Colors.green : Colors.orange,
                ),
          title: Text(title),
          subtitle: SelectableText(
            const JsonEncoder.withIndent('  ').convert(value),
          ),
          trailing: trailing,
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
                Text(
                  value.$2,
                  style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
                ),
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
          child: Align(
            alignment: Alignment.centerLeft,
            child: SelectableText(
              const JsonEncoder.withIndent('  ').convert(value),
            ),
          ),
        ),
      ],
    ),
  );

  Widget _emptyCard(String value) => Card(
    child: Padding(padding: const EdgeInsets.all(18), child: Text(value)),
  );

  Widget _pagePadding(Widget child) =>
      Padding(padding: const EdgeInsets.all(24), child: child);

  Widget _pageTitle(String title, String subtitle) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Text(
        title,
        style: Theme.of(
          context,
        ).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w700),
      ),
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
      gradient: const LinearGradient(
        colors: [Color(0xFF0EA5E9), Color(0xFF0F766E)],
        begin: Alignment.topLeft,
        end: Alignment.bottomRight,
      ),
      borderRadius: BorderRadius.circular(size * .28),
      boxShadow: const [
        BoxShadow(
          color: Color(0x330E7490),
          blurRadius: 18,
          offset: Offset(0, 8),
        ),
      ],
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
