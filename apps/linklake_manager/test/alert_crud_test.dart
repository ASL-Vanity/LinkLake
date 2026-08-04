import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/main.dart';
import 'package:linklake_manager/manager_settings.dart';

import 'fakes.dart';

Future<void> pumpDashboard(
  WidgetTester tester,
  FakeLinkLakeApi api, {
  String role = 'administrator',
}) async {
  tester.view.physicalSize = const Size(1440, 1000);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
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
  await tester.tap(find.byKey(const Key('nav-alerts')));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets(
    'administrator creates an SLO alert rule with the exact API body',
    (tester) async {
      final api = FakeLinkLakeApi();
      await pumpDashboard(tester, api);

      await tester.tap(find.byKey(const Key('new-alert-rule')));
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byKey(const Key('alert-rule-name')),
        'Fast budget burn',
      );
      await tester.tap(find.byKey(const Key('alert-rule-metric')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('slo_fast_burn_rate').last);
      await tester.enterText(
        find.byKey(const Key('alert-rule-threshold')),
        '14.4',
      );
      await tester.enterText(
        find.byKey(const Key('alert-rule-target')),
        'global',
      );
      await tester.tap(find.byKey(const Key('save-alert-rule')));
      await tester.pumpAndSettle();

      expect(api.posts, hasLength(1));
      expect(api.posts.single.$1, '/api/v1/alerts/rules');
      expect(api.posts.single.$2, containsPair('metric', 'slo_fast_burn_rate'));
      expect(api.posts.single.$2, containsPair('threshold', 14.4));
      expect(api.posts.single.$2, containsPair('target', 'global'));
    },
  );

  testWidgets('administrator updates and deletes an existing alert rule', (
    tester,
  ) async {
    final api = FakeLinkLakeApi();
    api.listResponses['/api/v1/alerts/rules'] = const [
      {
        'id': 'rule-1',
        'name': 'Slow budget burn',
        'metric': 'slo_slow_burn_rate',
        'comparator': 'greater_or_equal',
        'threshold': 6.0,
        'target': 'global',
        'evaluation_window_seconds': 21600,
        'cooldown_seconds': 21600,
        'severity': 'warning',
        'notify_webhook': true,
        'notify_email': true,
        'enabled': true,
      },
    ];
    await pumpDashboard(tester, api);

    await tester.tap(find.byKey(const Key('edit-alert-rule-1')));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.byKey(const Key('alert-rule-name')),
      'Updated slow budget burn',
    );
    await tester.tap(find.byKey(const Key('save-alert-rule')));
    await tester.pumpAndSettle();
    expect(api.puts, hasLength(1));
    expect(api.puts.single.$1, '/api/v1/alerts/rules/rule-1');
    expect(
      api.puts.single.$2,
      containsPair('name', 'Updated slow budget burn'),
    );

    await tester.tap(find.byKey(const Key('delete-alert-rule-1')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Confirm'));
    await tester.pumpAndSettle();
    expect(api.deletes, contains('/api/v1/alerts/rules/rule-1'));
  });

  testWidgets('auditor can inspect alerts but cannot mutate rules', (
    tester,
  ) async {
    final api = FakeLinkLakeApi(role: 'auditor');
    api.listResponses['/api/v1/alerts/rules'] = const [
      {
        'id': 'rule-1',
        'name': 'Read only rule',
        'metric': 'slo_fast_burn_rate',
        'comparator': 'greater_or_equal',
        'threshold': 14.4,
        'evaluation_window_seconds': 300,
        'cooldown_seconds': 3600,
        'severity': 'critical',
        'enabled': true,
      },
    ];
    await pumpDashboard(tester, api, role: 'auditor');
    expect(find.textContaining('Read only rule'), findsOneWidget);
    expect(find.byKey(const Key('new-alert-rule')), findsNothing);
    expect(find.byKey(const Key('edit-alert-rule-1')), findsNothing);
    expect(find.byKey(const Key('delete-alert-rule-1')), findsNothing);
    expect(api.posts, isEmpty);
    expect(api.puts, isEmpty);
    expect(api.deletes, isEmpty);
  });
}
