import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

class WindowPreferences {
  const WindowPreferences({
    this.x,
    this.y,
    this.width = 1280,
    this.height = 820,
    this.maximized = false,
  });

  final double? x;
  final double? y;
  final double width;
  final double height;
  final bool maximized;

  Map<String, dynamic> toJson() => {
    'x': x,
    'y': y,
    'width': width,
    'height': height,
    'maximized': maximized,
  };

  static WindowPreferences fromJson(Object? value) {
    if (value is! Map) return const WindowPreferences();
    final map = Map<String, dynamic>.from(value);
    double? number(String key) => (map[key] as num?)?.toDouble();
    return WindowPreferences(
      x: number('x'),
      y: number('y'),
      width: number('width')?.clamp(760, 3840) ?? 1280,
      height: number('height')?.clamp(560, 2160) ?? 820,
      maximized: map['maximized'] == true,
    );
  }
}

class ManagerSettings {
  const ManagerSettings({
    this.chinese = true,
    this.themeMode = ThemeMode.system,
    this.lastServerUrl = 'https://link.odelake.com',
    this.closeToTray = true,
    this.launchAtStartup = false,
    this.rememberWindow = true,
    this.window = const WindowPreferences(),
  });

  final bool chinese;
  final ThemeMode themeMode;
  final String lastServerUrl;
  final bool closeToTray;
  final bool launchAtStartup;
  final bool rememberWindow;
  final WindowPreferences window;

  ManagerSettings copyWith({
    bool? chinese,
    ThemeMode? themeMode,
    String? lastServerUrl,
    bool? closeToTray,
    bool? launchAtStartup,
    bool? rememberWindow,
    WindowPreferences? window,
  }) => ManagerSettings(
    chinese: chinese ?? this.chinese,
    themeMode: themeMode ?? this.themeMode,
    lastServerUrl: lastServerUrl ?? this.lastServerUrl,
    closeToTray: closeToTray ?? this.closeToTray,
    launchAtStartup: launchAtStartup ?? this.launchAtStartup,
    rememberWindow: rememberWindow ?? this.rememberWindow,
    window: window ?? this.window,
  );

  Map<String, dynamic> toJson() => {
    'language': chinese ? 'zh' : 'en',
    'theme': themeMode.name,
    'last_server_url': lastServerUrl,
    'close_to_tray': closeToTray,
    'launch_at_startup': launchAtStartup,
    'remember_window': rememberWindow,
    'window': window.toJson(),
  };

  static ManagerSettings fromJson(Object? value) {
    if (value is! Map) return const ManagerSettings();
    final map = Map<String, dynamic>.from(value);
    final theme = switch (map['theme']) {
      'light' => ThemeMode.light,
      'dark' => ThemeMode.dark,
      _ => ThemeMode.system,
    };
    final server = map['last_server_url']?.toString().trim() ?? '';
    return ManagerSettings(
      chinese: map['language'] != 'en',
      themeMode: theme,
      lastServerUrl: server.startsWith('http')
          ? server
          : 'https://link.odelake.com',
      closeToTray: map['close_to_tray'] != false,
      launchAtStartup: map['launch_at_startup'] == true,
      rememberWindow: map['remember_window'] != false,
      window: WindowPreferences.fromJson(map['window']),
    );
  }
}

abstract interface class ManagerSettingsRepository {
  Future<ManagerSettings> load();
  Future<void> save(ManagerSettings settings);
}

class ManagerSettingsStore implements ManagerSettingsRepository {
  ManagerSettingsStore({String? path}) : _overridePath = path;

  final String? _overridePath;

  @override
  Future<ManagerSettings> load() async {
    final file = File(_path());
    final primary = await _loadFile(file);
    if (primary != null) return primary;
    return await _loadFile(File('${file.path}.bak')) ?? const ManagerSettings();
  }

  @override
  Future<void> save(ManagerSettings settings) async {
    final file = File(_path());
    await file.parent.create(recursive: true);
    final temporary = File('${file.path}.tmp');
    final backup = File('${file.path}.bak');
    final backupTemporary = File('${backup.path}.tmp');
    await _deleteIfPresent(temporary);
    await _deleteIfPresent(backupTemporary);
    try {
      final encoded = const JsonEncoder.withIndent(
        '  ',
      ).convert(settings.toJson());
      await temporary.writeAsString(encoded, flush: true);
      jsonDecode(await temporary.readAsString());

      if (await _loadFile(file) != null) {
        await file.copy(backupTemporary.path);
        await backupTemporary.rename(backup.path);
      }
      await temporary.rename(file.path);
    } finally {
      await _deleteIfPresent(temporary);
      await _deleteIfPresent(backupTemporary);
    }
  }

  Future<ManagerSettings?> _loadFile(File file) async {
    if (!await file.exists()) return null;
    try {
      final value = jsonDecode(await file.readAsString());
      if (value is! Map) return null;
      return ManagerSettings.fromJson(value);
    } catch (_) {
      return null;
    }
  }

  Future<void> _deleteIfPresent(File file) async {
    if (await file.exists()) await file.delete();
  }

  String _path() {
    if (_overridePath case final path?) return path;
    final environment = Platform.environment;
    if (Platform.isWindows) {
      final root =
          environment['APPDATA'] ??
          environment['LOCALAPPDATA'] ??
          Directory.current.path;
      return '$root${Platform.pathSeparator}LinkLake${Platform.pathSeparator}manager-settings.json';
    }
    final home = environment['HOME'] ?? Directory.current.path;
    if (Platform.isMacOS) {
      return '$home/Library/Application Support/LinkLake/manager-settings.json';
    }
    return '$home/.config/linklake/manager-settings.json';
  }
}

class MemoryManagerSettingsStore implements ManagerSettingsRepository {
  MemoryManagerSettingsStore([this.value = const ManagerSettings()]);

  ManagerSettings value;

  @override
  Future<ManagerSettings> load() async => value;

  @override
  Future<void> save(ManagerSettings settings) async => value = settings;
}
