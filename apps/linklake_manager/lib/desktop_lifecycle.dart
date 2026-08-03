import 'dart:async';
import 'dart:io';
import 'dart:ui';

import 'package:flutter/material.dart';
import 'package:launch_at_startup/launch_at_startup.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

import 'manager_settings.dart';

class DesktopCapabilities {
  const DesktopCapabilities({
    required this.windowLifecycle,
    required this.tray,
    required this.launchAtStartup,
  });

  const DesktopCapabilities.none()
    : windowLifecycle = false,
      tray = false,
      launchAtStartup = false;

  final bool windowLifecycle;
  final bool tray;
  final bool launchAtStartup;

  DesktopCapabilities copyWith({
    bool? windowLifecycle,
    bool? tray,
    bool? launchAtStartup,
  }) => DesktopCapabilities(
    windowLifecycle: windowLifecycle ?? this.windowLifecycle,
    tray: tray ?? this.tray,
    launchAtStartup: launchAtStartup ?? this.launchAtStartup,
  );
}

abstract interface class DesktopPlatformAdapter {
  DesktopCapabilities get capabilities;
  Future<void> initialize(WindowPreferences window);
  Future<void> setPreventClose(bool value);
  Future<void> showWindow();
  Future<void> hideWindow();
  Future<void> destroyWindow();
  Future<WindowPreferences> readWindowPreferences();
  Future<void> installTray({required bool chinese});
  Future<void> destroyTray();
  Future<void> setLaunchAtStartup(bool enabled);
  Future<bool> isLaunchAtStartupEnabled();
}

class NativeDesktopPlatformAdapter implements DesktopPlatformAdapter {
  @override
  DesktopCapabilities get capabilities {
    if (Platform.isWindows) {
      return const DesktopCapabilities(
        windowLifecycle: true,
        tray: true,
        launchAtStartup: true,
      );
    }
    if (Platform.isLinux) {
      return const DesktopCapabilities(
        windowLifecycle: true,
        tray: true,
        launchAtStartup: true,
      );
    }
    if (Platform.isMacOS) {
      return const DesktopCapabilities(
        windowLifecycle: true,
        tray: true,
        launchAtStartup: true,
      );
    }
    return const DesktopCapabilities.none();
  }

  @override
  Future<void> initialize(WindowPreferences window) async {
    await windowManager.ensureInitialized();
    final options = WindowOptions(
      size: Size(window.width, window.height),
      minimumSize: const Size(760, 560),
      center: window.x == null || window.y == null,
      title: 'LinkLake Manager',
    );
    await windowManager.waitUntilReadyToShow(options, () async {
      if (window.x != null && window.y != null) {
        await windowManager.setPosition(Offset(window.x!, window.y!));
      }
      if (window.maximized) await windowManager.maximize();
      await windowManager.show();
      await windowManager.focus();
    });
  }

  @override
  Future<void> setPreventClose(bool value) =>
      windowManager.setPreventClose(value);

  @override
  Future<void> showWindow() async {
    await windowManager.show();
    if (await windowManager.isMinimized()) await windowManager.restore();
    await windowManager.focus();
  }

  @override
  Future<void> hideWindow() => windowManager.hide();

  @override
  Future<void> destroyWindow() => windowManager.destroy();

  @override
  Future<WindowPreferences> readWindowPreferences() async {
    final bounds = await windowManager.getBounds();
    return WindowPreferences(
      x: bounds.left,
      y: bounds.top,
      width: bounds.width,
      height: bounds.height,
      maximized: await windowManager.isMaximized(),
    );
  }

  @override
  Future<void> installTray({required bool chinese}) async {
    final icon = Platform.isWindows ? 'assets/tray.ico' : 'assets/tray.png';
    await trayManager.setIcon(icon);
    await trayManager.setToolTip('LinkLake Manager');
    await trayManager.setContextMenu(
      Menu(
        items: [
          MenuItem(
            key: 'show_window',
            label: chinese ? '打开 LinkLake Manager' : 'Open LinkLake Manager',
          ),
          MenuItem.separator(),
          MenuItem(key: 'exit_app', label: chinese ? '退出' : 'Exit'),
        ],
      ),
    );
  }

  @override
  Future<void> destroyTray() => trayManager.destroy();

  Future<void> _setupLaunchAtStartup() async {
    final package = await PackageInfo.fromPlatform();
    launchAtStartup.setup(
      appName: package.appName,
      appPath: Platform.resolvedExecutable,
      packageName: package.packageName,
    );
  }

  @override
  Future<void> setLaunchAtStartup(bool enabled) async {
    await _setupLaunchAtStartup();
    if (enabled) {
      await launchAtStartup.enable();
    } else {
      await launchAtStartup.disable();
    }
  }

  @override
  Future<bool> isLaunchAtStartupEnabled() async {
    await _setupLaunchAtStartup();
    return launchAtStartup.isEnabled();
  }
}

class DesktopLifecycleController with WindowListener, TrayListener {
  DesktopLifecycleController({
    required this.adapter,
    required this.repository,
    this.registerPluginListeners = true,
  });

  final DesktopPlatformAdapter adapter;
  final ManagerSettingsRepository repository;
  final bool registerPluginListeners;
  ManagerSettings _settings = const ManagerSettings();
  late DesktopCapabilities _capabilities = adapter.capabilities;
  bool _initialized = false;
  bool _exiting = false;
  bool _trayInstalled = false;

  bool get initialized => _initialized;
  ManagerSettings get settings => _settings;
  DesktopCapabilities get capabilities => _capabilities;

  Future<ManagerSettings> initialize(ManagerSettings settings) async {
    _settings = _normalizeSettings(settings);
    if (!_capabilities.windowLifecycle) {
      if (_settings != settings) await repository.save(_settings);
      return _settings;
    }
    await adapter.initialize(_settings.window);
    await adapter.setPreventClose(true);
    if (_capabilities.tray) {
      try {
        await adapter.installTray(chinese: _settings.chinese);
        _trayInstalled = true;
      } catch (_) {
        _capabilities = _capabilities.copyWith(tray: false);
        _settings = _normalizeSettings(_settings);
      }
    }
    if (registerPluginListeners) {
      windowManager.addListener(this);
      if (_trayInstalled) trayManager.addListener(this);
    }
    _initialized = true;
    if (_capabilities.launchAtStartup) {
      try {
        final actual = await adapter.isLaunchAtStartupEnabled();
        if (actual != _settings.launchAtStartup) {
          _settings = _settings.copyWith(launchAtStartup: actual);
        }
      } catch (_) {
        _capabilities = _capabilities.copyWith(launchAtStartup: false);
        _settings = _normalizeSettings(_settings);
      }
    }
    if (_settings != settings) await repository.save(_settings);
    return _settings;
  }

  Future<ManagerSettings> updateSettings(ManagerSettings settings) async {
    final normalized = _normalizeSettings(settings);
    final languageChanged = normalized.chinese != _settings.chinese;
    final startupChanged =
        normalized.launchAtStartup != _settings.launchAtStartup;
    if (_initialized && languageChanged && _trayInstalled) {
      await adapter.installTray(chinese: normalized.chinese);
    }
    if (_initialized && startupChanged && _capabilities.launchAtStartup) {
      await adapter.setLaunchAtStartup(normalized.launchAtStartup);
    }
    await repository.save(normalized);
    _settings = normalized;
    return normalized;
  }

  Future<void> handleWindowClose() async {
    if (_exiting) return;
    if (_settings.rememberWindow) await _saveWindowPreferences();
    if (_settings.closeToTray && _trayInstalled) {
      await adapter.hideWindow();
    } else {
      await exitApplication();
    }
  }

  Future<void> showWindow() => adapter.showWindow();

  Future<void> exitApplication() async {
    if (_exiting) return;
    _exiting = true;
    if (_settings.rememberWindow) await _saveWindowPreferences();
    if (_initialized && registerPluginListeners) {
      windowManager.removeListener(this);
      if (_trayInstalled) trayManager.removeListener(this);
    }
    if (_trayInstalled) await adapter.destroyTray();
    await adapter.setPreventClose(false);
    await adapter.destroyWindow();
  }

  Future<void> _saveWindowPreferences() async {
    try {
      final window = await adapter.readWindowPreferences();
      _settings = _settings.copyWith(window: window);
      await repository.save(_settings);
    } catch (_) {}
  }

  @override
  void onWindowClose() => unawaited(handleWindowClose());

  @override
  void onTrayIconMouseDown() => unawaited(showWindow());

  @override
  void onTrayIconRightMouseDown() => unawaited(trayManager.popUpContextMenu());

  @override
  void onTrayMenuItemClick(MenuItem menuItem) {
    if (menuItem.key == 'show_window') unawaited(showWindow());
    if (menuItem.key == 'exit_app') unawaited(exitApplication());
  }

  ManagerSettings _normalizeSettings(
    ManagerSettings settings,
  ) => settings.copyWith(
    closeToTray: _capabilities.tray && settings.closeToTray,
    launchAtStartup: _capabilities.launchAtStartup && settings.launchAtStartup,
    rememberWindow: _capabilities.windowLifecycle && settings.rememberWindow,
  );
}
