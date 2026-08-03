import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/main.dart';
import 'package:linklake_manager/manager_settings.dart';
import 'package:linklake_manager/rbac.dart';

import 'fakes.dart';

void main() {
  test('role parsing and capabilities default to least privilege', () {
    expect(ManagementRole.parse('administrator'), ManagementRole.administrator);
    expect(ManagementRole.parse('operator'), ManagementRole.operator);
    expect(ManagementRole.parse('auditor'), ManagementRole.auditor);
    expect(ManagementRole.parse('future-role'), ManagementRole.auditor);

    expect(
      RoleCapabilities(ManagementRole.administrator).canManageUsers,
      isTrue,
    );
    expect(RoleCapabilities(ManagementRole.operator).canWritePolicies, isTrue);
    expect(RoleCapabilities(ManagementRole.operator).canManageUsers, isFalse);
    expect(RoleCapabilities(ManagementRole.auditor).canWritePolicies, isFalse);
  });

  test('request plans omit administrator-only endpoints for non-admins', () {
    final restricted = {
      '/api/v1/users',
      '/api/v1/sessions',
      '/api/v1/api-tokens',
      '/api/v1/fleet/overview',
    };
    for (final role in [ManagementRole.operator, ManagementRole.auditor]) {
      final paths = dashboardRequestPlan(
        role,
      ).map((value) => value.path).toSet();
      expect(paths.intersection(restricted), isEmpty);
    }
    final adminPaths = dashboardRequestPlan(
      ManagementRole.administrator,
    ).map((value) => value.path).toSet();
    expect(adminPaths.containsAll(restricted), isTrue);
  });

  for (final role in ['administrator', 'operator', 'auditor']) {
    testWidgets('$role uses role-aware navigation and API requests', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(1440, 1000);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final api = FakeLinkLakeApi(role: role);
      await tester.pumpWidget(
        MaterialApp(
          home: DashboardPage(
            api: api,
            chinese: false,
            onLanguageChanged: (_) {},
            themeMode: ThemeMode.system,
            onThemeChanged: (_) {},
            initialIdentity: {'role': role},
            settings: const ManagerSettings(chinese: false),
          ),
        ),
      );
      await tester.pumpAndSettle();

      final isAdmin = role == 'administrator';
      expect(
        find.byKey(const Key('nav-users')),
        isAdmin ? findsOneWidget : findsNothing,
      );
      expect(
        find.byKey(const Key('nav-fleet')),
        isAdmin ? findsOneWidget : findsNothing,
      );
      expect(api.calls.contains('/api/v1/users'), isAdmin);
      expect(api.calls.contains('/api/v1/sessions'), isAdmin);
      expect(api.calls.contains('/api/v1/api-tokens'), isAdmin);
      expect(api.calls.contains('/api/v1/fleet/overview'), isAdmin);

      await tester.tap(find.byKey(const Key('nav-tcp')));
      await tester.pumpAndSettle();
      expect(
        find.byKey(const Key('create-tcp')),
        role == 'auditor' ? findsNothing : findsOneWidget,
      );
    });
  }

  testWidgets('narrow dashboard uses a drawer without overflow', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(520, 720);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeLinkLakeApi(role: 'operator');
    await tester.pumpWidget(
      MaterialApp(
        home: DashboardPage(
          api: api,
          chinese: true,
          onLanguageChanged: (_) {},
          themeMode: ThemeMode.system,
          onThemeChanged: (_) {},
          initialIdentity: const {'role': 'operator'},
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.byType(Drawer), findsNothing);
    expect(find.byType(NavigationRail), findsNothing);
    expect(tester.takeException(), isNull);
    await tester.tap(find.byTooltip('Open navigation menu'));
    await tester.pumpAndSettle();
    expect(find.byType(Drawer), findsOneWidget);
    expect(find.byKey(const Key('nav-tcp')), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('unknown roles render with auditor permissions', (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeLinkLakeApi(role: 'future-role');
    await tester.pumpWidget(
      MaterialApp(
        home: DashboardPage(
          api: api,
          chinese: false,
          onLanguageChanged: (_) {},
          themeMode: ThemeMode.system,
          onThemeChanged: (_) {},
          initialIdentity: const {'role': 'future-role'},
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('nav-users')), findsNothing);
    expect(api.calls, isNot(contains('/api/v1/users')));
    await tester.tap(find.byKey(const Key('nav-tcp')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('create-tcp')), findsNothing);
  });

  testWidgets('one noncritical request failure preserves the rest of refresh', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeLinkLakeApi(role: 'operator');
    api.listResponses['/api/v1/clients'] = const [
      {'client_id': 'client-1', 'name': 'Healthy client', 'online': true},
    ];
    api.failures['/api/v1/tcp-tunnels'] = const FormatException(
      'tcp unavailable',
    );
    await tester.pumpWidget(
      MaterialApp(
        home: DashboardPage(
          api: api,
          chinese: false,
          onLanguageChanged: (_) {},
          themeMode: ThemeMode.system,
          onThemeChanged: (_) {},
          initialIdentity: const {'role': 'operator'},
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(
      find.textContaining('Some data could not be refreshed'),
      findsOneWidget,
    );
    await tester.tap(find.byKey(const Key('nav-clients')));
    await tester.pumpAndSettle();
    expect(find.text('Healthy client'), findsOneWidget);
  });

  testWidgets('role downgrade removes privileged navigation immediately', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeLinkLakeApi();
    await tester.pumpWidget(
      MaterialApp(
        home: DashboardPage(
          api: api,
          chinese: false,
          onLanguageChanged: (_) {},
          themeMode: ThemeMode.system,
          onThemeChanged: (_) {},
          initialIdentity: const {'role': 'administrator'},
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('nav-users')), findsOneWidget);

    api.role = 'auditor';
    await tester.tap(find.byTooltip('Refresh'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('nav-users')), findsNothing);
    expect(find.byKey(const Key('nav-fleet')), findsNothing);
  });
}
