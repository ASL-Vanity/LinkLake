import 'package:linklake_manager/api_client.dart';
import 'package:linklake_manager/desktop_lifecycle.dart';
import 'package:linklake_manager/manager_settings.dart';

class FakeLinkLakeApi implements LinkLakeApi {
  FakeLinkLakeApi({this.role = 'administrator'});

  String role;
  final List<String> calls = [];
  final List<(String, Map<String, dynamic>)> posts = [];
  final List<(String, Map<String, dynamic>)> puts = [];
  final List<String> deletes = [];
  final Map<String, Map<String, dynamic>> objectResponses = {};
  final Map<String, List<dynamic>> listResponses = {};
  final Map<String, Object> failures = {};

  @override
  Uri get baseUri => Uri.parse('https://example.test');

  @override
  bool get authenticated => true;

  Never _failure(String path) => throw failures[path]!;

  @override
  Future<Map<String, dynamic>> getObject(String path) async {
    calls.add(path);
    if (failures.containsKey(path)) _failure(path);
    if (path == '/api/v1/auth/me') {
      return {'username': 'tester', 'role': role, 'totp_enabled': false};
    }
    return Map<String, dynamic>.from(objectResponses[path] ?? const {});
  }

  @override
  Future<List<dynamic>> getList(String path) async {
    calls.add(path);
    if (failures.containsKey(path)) _failure(path);
    return List<dynamic>.from(listResponses[path] ?? const []);
  }

  @override
  Future<Map<String, dynamic>> postObject(
    String path,
    Map<String, dynamic> body,
  ) async {
    posts.add((path, Map<String, dynamic>.from(body)));
    if (failures.containsKey(path)) _failure(path);
    return Map<String, dynamic>.from(
      objectResponses[path] ?? {'id': 'created'},
    );
  }

  @override
  Future<Map<String, dynamic>> putObject(
    String path,
    Map<String, dynamic> body,
  ) async {
    puts.add((path, Map<String, dynamic>.from(body)));
    if (failures.containsKey(path)) _failure(path);
    return Map<String, dynamic>.from(objectResponses[path] ?? const {});
  }

  @override
  Future<void> post(String path, [Map<String, dynamic>? body]) async {
    posts.add((path, Map<String, dynamic>.from(body ?? const {})));
    if (failures.containsKey(path)) _failure(path);
  }

  @override
  Future<void> delete(String path) async {
    deletes.add(path);
    if (failures.containsKey(path)) _failure(path);
  }

  @override
  Future<String> getText(String path) async {
    calls.add(path);
    if (failures.containsKey(path)) _failure(path);
    return '{}';
  }

  @override
  Future<Map<String, dynamic>> login(
    String username,
    String password, {
    String? totpCode,
  }) async => {'username': username, 'role': role};

  @override
  Future<void> changePassword(String password) async {}

  @override
  Future<void> logout() async {}

  @override
  void close() {}
}

class FakeDesktopAdapter implements DesktopPlatformAdapter {
  FakeDesktopAdapter({
    this.capabilities = const DesktopCapabilities(
      windowLifecycle: true,
      tray: true,
      launchAtStartup: true,
    ),
  });

  @override
  final DesktopCapabilities capabilities;
  bool prevented = false;
  bool hidden = false;
  bool shown = false;
  bool destroyed = false;
  bool trayDestroyed = false;
  bool startup = false;
  int trayInstalls = 0;
  WindowPreferences window = const WindowPreferences(
    x: 10,
    y: 20,
    width: 1000,
    height: 700,
  );

  @override
  Future<void> initialize(WindowPreferences window) async {
    this.window = window;
  }

  @override
  Future<void> setPreventClose(bool value) async => prevented = value;

  @override
  Future<void> showWindow() async => shown = true;

  @override
  Future<void> hideWindow() async => hidden = true;

  @override
  Future<void> destroyWindow() async => destroyed = true;

  @override
  Future<WindowPreferences> readWindowPreferences() async => window;

  @override
  Future<void> installTray({required bool chinese}) async => trayInstalls++;

  @override
  Future<void> destroyTray() async => trayDestroyed = true;

  @override
  Future<void> setLaunchAtStartup(bool enabled) async => startup = enabled;

  @override
  Future<bool> isLaunchAtStartupEnabled() async => startup;
}
