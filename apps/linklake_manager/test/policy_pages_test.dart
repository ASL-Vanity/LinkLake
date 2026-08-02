import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/policy_pages.dart';
import 'package:linklake_manager/rbac.dart';

import 'fakes.dart';

const client = {'client_id': 'client-1', 'name': 'Edge client'};

Widget policyHarness({
  required FakeLinkLakeApi api,
  required PolicyKind kind,
  List<dynamic> policies = const [],
  ManagementRole role = ManagementRole.administrator,
  Future<void> Function()? onRefresh,
}) => MaterialApp(
  home: Scaffold(
    body: PolicyPage(
      kind: kind,
      api: api,
      policies: policies,
      clients: const [client],
      capabilities: RoleCapabilities(role),
      chinese: false,
      onRefresh: onRefresh ?? () async {},
    ),
  ),
);

void main() {
  test('eight protocol schemas and CRUD paths match server contracts', () {
    final expectedFields = <PolicyKind, Set<String>>{
      PolicyKind.tcp: {
        'client_id',
        'name',
        'public_port',
        'target_addr',
        'max_connections',
        'bandwidth_limit_bps',
      },
      PolicyKind.udp: {
        'client_id',
        'name',
        'public_port',
        'target_addr',
        'max_sessions',
        'session_idle_timeout_seconds',
        'bandwidth_limit_bps',
      },
      PolicyKind.group: {
        'client_id',
        'name',
        'protocol',
        'public_ports',
        'target_host',
        'target_ports',
        'max_connections',
        'max_sessions',
        'session_idle_timeout_seconds',
        'bandwidth_limit_bps',
      },
      PolicyKind.http: {
        'client_id',
        'name',
        'hostname',
        'target_addr',
        'max_connections',
        'tls_mode',
        'redirect_http_to_https',
      },
      PolicyKind.sni: {
        'client_id',
        'name',
        'hostname',
        'target_addr',
        'max_connections',
        'bandwidth_limit_bps',
      },
      PolicyKind.secret: {
        'provider_client_id',
        'allowed_client_id',
        'name',
        'target_addr',
        'max_connections',
        'bandwidth_limit_bps',
      },
      PolicyKind.socks5: {
        'client_id',
        'name',
        'public_port',
        'username',
        'max_connections',
        'bandwidth_limit_bps',
      },
      PolicyKind.proxy: {
        'client_id',
        'name',
        'public_port',
        'username',
        'max_connections',
        'bandwidth_limit_bps',
      },
    };
    final expectedResources = <PolicyKind, String>{
      PolicyKind.tcp: 'tcp-tunnels',
      PolicyKind.udp: 'udp-tunnels',
      PolicyKind.group: 'port-groups',
      PolicyKind.http: 'http-routes',
      PolicyKind.sni: 'sni-routes',
      PolicyKind.secret: 'secret-tunnels',
      PolicyKind.socks5: 'socks5-proxies',
      PolicyKind.proxy: 'http-proxies',
    };

    for (final kind in PolicyKind.values) {
      expect(
        kind.fields.map((field) => field.name).toSet(),
        expectedFields[kind],
      );
      expect(kind.collectionPath, '/api/v1/${expectedResources[kind]}');
      expect(kind.itemPath('id-1'), '${kind.collectionPath}/id-1');
      expect(kind.enabledPath('id-1'), '${kind.collectionPath}/id-1/enabled');
    }
    expect(PolicyKind.secret.oneTimeCredentialField, 'access_key');
    expect(PolicyKind.socks5.oneTimeCredentialField, 'password');
    expect(PolicyKind.proxy.oneTimeCredentialField, 'password');
    expect(PolicyKind.tcp.oneTimeCredentialField, isNull);
  });

  testWidgets('TCP create uses the WebUI-compatible payload', (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeLinkLakeApi();
    var refreshes = 0;
    await tester.pumpWidget(
      policyHarness(
        api: api,
        kind: PolicyKind.tcp,
        onRefresh: () async => refreshes++,
      ),
    );
    await tester.tap(find.byKey(const Key('create-tcp')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('field-name')), 'ssh');
    await tester.enterText(find.byKey(const Key('field-public_port')), '32022');
    await tester.enterText(
      find.byKey(const Key('field-target_addr')),
      '127.0.0.1:22',
    );
    await tester.tap(find.byKey(const Key('save-policy')));
    await tester.pumpAndSettle();

    expect(api.posts, hasLength(1));
    expect(api.posts.single.$1, '/api/v1/tcp-tunnels');
    expect(api.posts.single.$2, {
      'client_id': 'client-1',
      'name': 'ssh',
      'public_port': 32022,
      'target_addr': '127.0.0.1:22',
      'max_connections': 64,
      'bandwidth_limit_bps': null,
    });
    expect(refreshes, 1);
  });

  testWidgets('HTTP save performs route and TLS updates', (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeLinkLakeApi();
    api.objectResponses['/api/v1/http-routes'] = {'id': 'route-1'};
    await tester.pumpWidget(policyHarness(api: api, kind: PolicyKind.http));
    await tester.tap(find.byKey(const Key('create-http')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('field-name')), 'site');
    await tester.enterText(
      find.byKey(const Key('field-hostname')),
      'app.example.com',
    );
    await tester.enterText(
      find.byKey(const Key('field-target_addr')),
      '127.0.0.1:8080',
    );
    await tester.tap(find.byKey(const Key('field-tls_mode')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('ACME').last);
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('field-redirect_http_to_https')));
    await tester.tap(find.byKey(const Key('save-policy')));
    await tester.pumpAndSettle();

    expect(api.posts.single.$1, '/api/v1/http-routes');
    expect(api.puts.single.$1, '/api/v1/http-routes/route-1/tls');
    expect(api.puts.single.$2, {
      'mode': 'acme',
      'redirect_http_to_https': true,
    });
  });

  testWidgets('HTTP partial TLS failure refreshes and reports partial save', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeLinkLakeApi();
    api.objectResponses['/api/v1/http-routes'] = {'id': 'route-1'};
    api.failures['/api/v1/http-routes/route-1/tls'] = const FormatException(
      'tls unavailable',
    );
    var refreshes = 0;
    await tester.pumpWidget(
      policyHarness(
        api: api,
        kind: PolicyKind.http,
        onRefresh: () async => refreshes++,
      ),
    );
    await tester.tap(find.byKey(const Key('create-http')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('field-name')), 'site');
    await tester.enterText(
      find.byKey(const Key('field-hostname')),
      'app.example.com',
    );
    await tester.enterText(
      find.byKey(const Key('field-target_addr')),
      '127.0.0.1:8080',
    );
    await tester.tap(find.byKey(const Key('save-policy')));
    await tester.pumpAndSettle();

    expect(refreshes, 1);
    expect(find.textContaining('follow-up TLS update failed'), findsOneWidget);
  });

  testWidgets('secret creation presents a non-persistent one-time credential', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeLinkLakeApi();
    api.objectResponses['/api/v1/secret-tunnels'] = {
      'id': 'secret-1',
      'access_key': 'one-time-key',
    };
    await tester.pumpWidget(policyHarness(api: api, kind: PolicyKind.secret));
    await tester.tap(find.byKey(const Key('create-secret')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('field-name')), 'private');
    await tester.enterText(
      find.byKey(const Key('field-target_addr')),
      '127.0.0.1:22',
    );
    await tester.tap(find.byKey(const Key('save-policy')));
    await tester.pumpAndSettle();

    expect(find.textContaining('one-time-key'), findsOneWidget);
    expect(find.textContaining('not stored by Manager'), findsOneWidget);
    expect(api.posts.single.$2, isNot(contains('access_key')));
  });

  testWidgets('policy toggle and confirmed delete update CRUD state', (
    tester,
  ) async {
    final api = FakeLinkLakeApi();
    const policy = {
      'id': 'tcp-1',
      'client_id': 'client-1',
      'name': 'ssh',
      'public_port': 32022,
      'target_addr': '127.0.0.1:22',
      'max_connections': 64,
      'enabled': true,
      'online': true,
    };
    await tester.pumpWidget(
      policyHarness(api: api, kind: PolicyKind.tcp, policies: const [policy]),
    );
    await tester.tap(find.byKey(const Key('toggle-tcp-tcp-1')));
    await tester.pumpAndSettle();
    expect(api.posts.single.$1, '/api/v1/tcp-tunnels/tcp-1/enabled');
    expect(api.posts.single.$2, {'enabled': false});

    await tester.tap(find.byKey(const Key('delete-tcp-tcp-1')));
    await tester.pumpAndSettle();
    expect(api.deletes, isEmpty);
    await tester.tap(find.text('Delete').last);
    await tester.pumpAndSettle();
    expect(api.deletes, ['/api/v1/tcp-tunnels/tcp-1']);
  });

  testWidgets('auditor sees data but no mutation controls', (tester) async {
    final api = FakeLinkLakeApi(role: 'auditor');
    await tester.pumpWidget(
      policyHarness(
        api: api,
        kind: PolicyKind.socks5,
        role: ManagementRole.auditor,
        policies: const [
          {
            'id': 'proxy-1',
            'name': 'readonly',
            'client_id': 'client-1',
            'public_port': 32100,
            'username': 'viewer',
            'enabled': true,
          },
        ],
      ),
    );
    expect(find.textContaining('readonly'), findsWidgets);
    expect(find.byKey(const Key('create-socks5')), findsNothing);
    expect(find.byKey(const Key('edit-socks5-proxy-1')), findsNothing);
    expect(find.byKey(const Key('delete-socks5-proxy-1')), findsNothing);
  });

  testWidgets('API failures surface as local error feedback', (tester) async {
    final api = FakeLinkLakeApi();
    api.failures['/api/v1/tcp-tunnels/tcp-1/enabled'] = const FormatException(
      'controlled failure',
    );
    await tester.pumpWidget(
      policyHarness(
        api: api,
        kind: PolicyKind.tcp,
        policies: const [
          {
            'id': 'tcp-1',
            'client_id': 'client-1',
            'name': 'broken',
            'public_port': 32001,
            'target_addr': '127.0.0.1:1',
            'enabled': true,
          },
        ],
      ),
    );
    await tester.tap(find.byKey(const Key('toggle-tcp-tcp-1')));
    await tester.pumpAndSettle();
    expect(find.textContaining('controlled failure'), findsOneWidget);
  });
}
