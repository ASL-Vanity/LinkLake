import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/main.dart';
import 'package:linklake_manager/manager_settings.dart';

import 'fakes.dart';

void main() {
  for (final chinese in [false, true]) {
    testWidgets(
      'HA remains readable and read-only (${chinese ? 'zh narrow' : 'en desktop'})',
      (tester) async {
        tester.view.physicalSize = Size(chinese ? 520 : 1400, 900);
        tester.view.devicePixelRatio = 1;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);
        final api = FakeLinkLakeApi(role: 'auditor');
        api.objectResponses['/api/v1/ha/overview'] = {
          'mode': 'postgres_ha',
          'local_is_leader': false,
          'current_leader': {
            'instance_id': 'leader-instance-1234567890',
            'fencing_token': 9,
            'lease_remaining_seconds': 20,
            'lease_until_unix_seconds': 1789200000,
          },
          'members': [],
          'job_leases': [],
          'port_ownership': [],
          'target_health': {
            'healthy': 0,
            'total': 1,
            'targets': [
              {
                'target_key': 'edge-target',
                'effective_healthy': false,
                'member_alive': true,
                'control_channel_healthy': false,
                'application_healthy': true,
                'last_probe_unix_seconds': 1789199900,
                'has_error': true,
              },
            ],
          },
          'recent_events': [
            {
              'code': 'leader_lost',
              'severity': 'warning',
              'message': 'Lease expired',
              'at_unix_seconds': 1789199900,
            },
          ],
        };
        await tester.pumpWidget(
          MaterialApp(
            home: DashboardPage(
              api: api,
              chinese: chinese,
              onLanguageChanged: (_) {},
              themeMode: ThemeMode.system,
              onThemeChanged: (_) {},
              initialIdentity: const {'role': 'auditor'},
              settings: ManagerSettings(chinese: chinese),
            ),
          ),
        );
        await tester.pumpAndSettle();
        if (chinese) {
          await tester.tap(find.byTooltip('Open navigation menu'));
          await tester.pumpAndSettle();
        }
        await tester.scrollUntilVisible(
          find.byKey(const Key('nav-ha')),
          150,
          scrollable: find.byType(Scrollable).first,
        );
        await tester.pumpAndSettle();
        await tester.tap(find.byKey(const Key('nav-ha')));
        await tester.pumpAndSettle();
        expect(find.text('PostgreSQL HA'), findsOneWidget);
        expect(find.text(chinese ? 'HA 管理' : 'HA management'), findsWidgets);
        expect(tester.takeException(), isNull);

        final pageScroll = find
            .descendant(
              of: find.byType(ListView).last,
              matching: find.byType(Scrollable),
            )
            .first;
        await tester.scrollUntilVisible(
          find.text('edge-target'),
          250,
          scrollable: pageScroll,
        );
        await tester.pumpAndSettle();
        expect(
          find.textContaining(
            chinese ? '健康 / 异常 / 健康' : 'healthy / unhealthy / healthy',
          ),
          findsOneWidget,
        );
        final event = find.text(chinese ? 'Leader 已丢失' : 'Leadership lost');
        await tester.scrollUntilVisible(event, 150, scrollable: pageScroll);
        await tester.pumpAndSettle();
        expect(event, findsOneWidget);
        expect(tester.takeException(), isNull);
        expect(api.puts, isEmpty);
        expect(api.posts, isEmpty);
        expect(api.deletes, isEmpty);
      },
    );
  }
}
