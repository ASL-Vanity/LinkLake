import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/desktop_lifecycle.dart';
import 'package:linklake_manager/manager_settings.dart';

import 'fakes.dart';

void main() {
  test(
    'manager settings persist language theme server and window preferences',
    () async {
      final directory = await Directory.systemTemp.createTemp(
        'linklake-manager-',
      );
      addTearDown(() => directory.delete(recursive: true));
      final store = ManagerSettingsStore(
        path: '${directory.path}/settings.json',
      );
      const settings = ManagerSettings(
        chinese: false,
        themeMode: ThemeMode.dark,
        lastServerUrl: 'https://manager.example.com',
        closeToTray: false,
        launchAtStartup: true,
        rememberWindow: true,
        window: WindowPreferences(
          x: 42,
          y: 84,
          width: 1440,
          height: 900,
          maximized: true,
        ),
      );
      await store.save(settings);
      final loaded = await store.load();

      expect(loaded.chinese, isFalse);
      expect(loaded.themeMode, ThemeMode.dark);
      expect(loaded.lastServerUrl, 'https://manager.example.com');
      expect(loaded.closeToTray, isFalse);
      expect(loaded.launchAtStartup, isTrue);
      expect(loaded.window.x, 42);
      expect(loaded.window.height, 900);
      expect(loaded.window.maximized, isTrue);
    },
  );

  test('corrupt preferences fall back safely', () async {
    final directory = await Directory.systemTemp.createTemp(
      'linklake-manager-',
    );
    addTearDown(() => directory.delete(recursive: true));
    final path = '${directory.path}/settings.json';
    await File(path).writeAsString('{broken');
    final loaded = await ManagerSettingsStore(path: path).load();
    expect(loaded.chinese, isTrue);
    expect(loaded.themeMode, ThemeMode.system);
    expect(loaded.closeToTray, isTrue);
  });

  test(
    'corrupt primary preferences fall back to the last valid backup',
    () async {
      final directory = await Directory.systemTemp.createTemp(
        'linklake-manager-',
      );
      addTearDown(() => directory.delete(recursive: true));
      final path = '${directory.path}/settings.json';
      final store = ManagerSettingsStore(path: path);
      await store.save(
        const ManagerSettings(lastServerUrl: 'https://first.example.com'),
      );
      await store.save(
        const ManagerSettings(lastServerUrl: 'https://second.example.com'),
      );
      await File(path).writeAsString('{broken', flush: true);

      final loaded = await store.load();
      expect(loaded.lastServerUrl, 'https://first.example.com');
    },
  );

  test('settings file never serializes authentication secrets', () async {
    final directory = await Directory.systemTemp.createTemp(
      'linklake-manager-',
    );
    addTearDown(() => directory.delete(recursive: true));
    final path = '${directory.path}/settings.json';
    await ManagerSettingsStore(
      path: path,
    ).save(const ManagerSettings(lastServerUrl: 'https://manager.example.com'));

    final text = await File(path).readAsString();
    for (final forbidden in ['password', 'cookie', 'totp', 'token']) {
      expect(text.toLowerCase(), isNot(contains(forbidden)));
    }
    expect(await File('$path.tmp').exists(), isFalse);
  });

  test('Manager update schema and status path survive restart', () async {
    final directory = await Directory.systemTemp.createTemp(
      'linklake-manager-',
    );
    addTearDown(() => directory.delete(recursive: true));
    final path = '${directory.path}/settings.json';
    final store = ManagerSettingsStore(path: path);
    const protocol = <String, dynamic>{
      'schema_version': 2,
      'state': 'scheduled',
      'operation': 'apply',
      'manager_process_id': 4242,
      'manager_process_identity': '4242:1785700000',
      'requires_manager_exit': true,
    };
    await store.save(
      const ManagerSettings(
        managerUpdate: ManagerUpdateUiState(
          statusPath: r'C:\state\manager-status.json',
          protocol: protocol,
        ),
      ),
    );

    final loaded = await store.load();
    expect(loaded.managerUpdate.statusPath, r'C:\state\manager-status.json');
    expect(loaded.managerUpdate.protocol, protocol);
    expect(loaded.managerUpdate.state, 'scheduled');
  });

  test(
    'desktop close-to-tray and explicit exit are independently testable',
    () async {
      final adapter = FakeDesktopAdapter();
      final repository = MemoryManagerSettingsStore();
      final controller = DesktopLifecycleController(
        adapter: adapter,
        repository: repository,
        registerPluginListeners: false,
      );
      await controller.initialize(const ManagerSettings(closeToTray: true));
      await controller.handleWindowClose();
      expect(adapter.hidden, isTrue);
      expect(adapter.destroyed, isFalse);
      expect(repository.value.window.width, 1280);

      await controller.exitApplication();
      expect(adapter.trayDestroyed, isTrue);
      expect(adapter.destroyed, isTrue);
      expect(adapter.prevented, isFalse);
    },
  );

  test('desktop settings update controls startup and tray language', () async {
    final adapter = FakeDesktopAdapter();
    final repository = MemoryManagerSettingsStore();
    final controller = DesktopLifecycleController(
      adapter: adapter,
      repository: repository,
      registerPluginListeners: false,
    );
    await controller.initialize(const ManagerSettings());
    await controller.updateSettings(
      const ManagerSettings(chinese: false, launchAtStartup: true),
    );
    expect(adapter.startup, isTrue);
    expect(adapter.trayInstalls, 2);
    expect(repository.value.chinese, isFalse);
  });

  test('close without tray performs a real application exit', () async {
    final adapter = FakeDesktopAdapter();
    final controller = DesktopLifecycleController(
      adapter: adapter,
      repository: MemoryManagerSettingsStore(),
      registerPluginListeners: false,
    );
    await controller.initialize(const ManagerSettings(closeToTray: false));
    await controller.handleWindowClose();
    expect(adapter.hidden, isFalse);
    expect(adapter.destroyed, isTrue);
  });

  test(
    'unsupported desktop capabilities are forced off and close exits',
    () async {
      final adapter = FakeDesktopAdapter(
        capabilities: const DesktopCapabilities(
          windowLifecycle: true,
          tray: false,
          launchAtStartup: false,
        ),
      );
      final repository = MemoryManagerSettingsStore();
      final controller = DesktopLifecycleController(
        adapter: adapter,
        repository: repository,
        registerPluginListeners: false,
      );
      final settings = await controller.initialize(
        const ManagerSettings(closeToTray: true, launchAtStartup: true),
      );

      expect(settings.closeToTray, isFalse);
      expect(settings.launchAtStartup, isFalse);
      await controller.handleWindowClose();
      expect(adapter.hidden, isFalse);
      expect(adapter.destroyed, isTrue);
    },
  );
}
