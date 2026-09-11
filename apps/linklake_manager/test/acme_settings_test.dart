import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/acme_settings.dart';

import 'fakes.dart';

void main() {
  FakeLinkLakeApi configuredApi() => FakeLinkLakeApi()
    ..objectResponses['/api/v1/acme/config'] = {
      'enabled': true,
      'environment': 'staging',
      'directory_url': 'https://acme-staging-v02.api.letsencrypt.org/directory',
      'contact_email': 'admin@example.test',
      'terms_accepted': true,
      'challenge_type': 'dns-01',
      'renew_before_days': 30,
      'material_key_configured': true,
      'cloudflare_token_configured': true,
      'account_registered': true,
    };

  testWidgets('saving keeps DNS-01 and excludes credential readiness fields', (tester) async {
    final api = configuredApi();
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: AcmeSettingsPage(api: api, chinese: false, editable: true))));
    await tester.pumpAndSettle();
    expect(find.text('DNS-01'), findsOneWidget);
    expect(find.text('Cloudflare token: configured'), findsOneWidget);
    final save = find.text('Save ACME settings');
    await tester.ensureVisible(save);
    await tester.tap(save);
    await tester.pumpAndSettle();
    expect(api.puts, hasLength(1));
    expect(api.puts.single.$2['challenge_type'], 'dns-01');
    expect(api.puts.single.$2.keys, unorderedEquals(['enabled', 'environment', 'directory_url', 'contact_email', 'terms_accepted', 'challenge_type', 'renew_before_days']));
  });

  testWidgets('auditor can inspect readiness but cannot save', (tester) async {
    final api = configuredApi();
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: AcmeSettingsPage(api: api, chinese: false, editable: false))));
    await tester.pumpAndSettle();
    expect(tester.widget<FilledButton>(find.byType(FilledButton)).onPressed, isNull);
    expect(api.puts, isEmpty);
  });

  testWidgets('legacy missing key status is not reported ready', (tester) async {
    final api = configuredApi();
    api.objectResponses['/api/v1/acme/config']!.remove('material_key_configured');
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: AcmeSettingsPage(api: api, chinese: false, editable: true))));
    await tester.pumpAndSettle();
    expect(find.text('Certificate material key: status unavailable from this server'), findsOneWidget);
  });
}
