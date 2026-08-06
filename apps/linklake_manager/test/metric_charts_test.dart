import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/metric_charts.dart';

import 'fakes.dart';

void main() {
  test('history endpoints and policy protocol mapping match the server', () {
    expect(
      metricsHistoryPath(protocol: 'tcp', range: MetricsRange.twelveHours),
      '/api/v1/metrics/history?range=12h&protocol=tcp',
    );
    expect(
      policyMetricsHistoryPath(
        kind: 'http',
        policyId: 'policy-1',
        range: MetricsRange.thirtyDays,
      ),
      '/api/v1/metrics/policies/http/policy-1/history?range=30d',
    );
    expect(historyProtocolForPolicyKey('http'), 'web');
    expect(historyProtocolForPolicyKey('sni'), 'web');
    expect(historyProtocolForPolicyKey('socks5'), 'proxy');
    expect(historyProtocolForPolicyKey('group'), 'total');
  });

  test('client snapshot derives availability platform and config state', () {
    final snapshot = ClientInsightSnapshot.fromClients(const [
      {
        'enabled': true,
        'last_seen_unix_seconds': 990,
        'platform': 'windows',
        'config_mode': 'server_managed',
        'config_sync_status': 'applied',
      },
      {
        'enabled': true,
        'last_seen_unix_seconds': 100,
        'platform': 'linux',
        'config_mode': 'local',
        'config_sync_status': 'conflict',
      },
      {'enabled': false, 'platform': 'windows', 'config_mode': 'report_only'},
    ], nowUnixSeconds: 1000);
    expect(snapshot.total, 3);
    expect(snapshot.online, 1);
    expect(snapshot.offline, 1);
    expect(snapshot.disabled, 1);
    expect(snapshot.configurationIssues, 1);
    expect(snapshot.platforms, {'windows': 2, 'linux': 1});
    expect(snapshot.configModes['server_managed'], 1);
  });

  testWidgets('history panel renders points and switches all five ranges', (
    tester,
  ) async {
    final api = FakeLinkLakeApi();
    for (final range in MetricsRange.values) {
      api.objectResponses[metricsHistoryPath(protocol: 'tcp', range: range)] =
          _history(range.key, 1024 * (range.index + 1));
    }
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: MetricsHistoryPanel(
            api: api,
            protocol: 'tcp',
            chinese: false,
            title: 'TCP history',
            subtitle: 'Traffic and sessions',
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('metrics-chart-tcp')), findsOneWidget);
    expect(find.textContaining('Inbound 1.0 KiB/s'), findsOneWidget);
    for (final range in MetricsRange.values.skip(1)) {
      await tester.tap(find.byKey(Key('metrics-range-tcp-${range.key}')));
      await tester.pumpAndSettle();
      expect(
        api.calls,
        contains(metricsHistoryPath(protocol: 'tcp', range: range)),
      );
    }
  });

  testWidgets('last selected range wins when an older request finishes later', (
    tester,
  ) async {
    final api = ControlledHistoryApi();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: MetricsHistoryPanel(
            api: api,
            protocol: 'total',
            chinese: false,
            title: 'History',
            subtitle: 'Last click wins',
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.byKey(const Key('metrics-range-total-12h')));
    await tester.pump();
    await tester.tap(find.byKey(const Key('metrics-range-total-1d')));
    await tester.pump();

    api.complete('1d', _history('1d', 2048));
    await tester.pumpAndSettle();
    expect(find.textContaining('Inbound 2.0 KiB/s'), findsOneWidget);

    api.complete('12h', _history('12h', 1024));
    await tester.pumpAndSettle();
    expect(find.textContaining('Inbound 2.0 KiB/s'), findsOneWidget);
    expect(find.textContaining('Inbound 1.0 KiB/s'), findsNothing);
  });
}

Map<String, dynamic> _history(String range, num inbound) => {
  'protocol': 'tcp',
  'range': range,
  'sample_interval_seconds': 5,
  'step_seconds': 15,
  'points': [
    {
      'timestamp_unix_seconds': 1000,
      'inbound_bps': inbound,
      'outbound_bps': inbound / 2,
      'active_connections': 2,
      'active_sessions': 1,
      'requests_per_second': 3,
      'errors_per_second': 0,
    },
    {
      'timestamp_unix_seconds': 1015,
      'inbound_bps': inbound,
      'outbound_bps': inbound / 2,
      'active_connections': 3,
      'active_sessions': 1,
      'requests_per_second': 4,
      'errors_per_second': 0,
    },
  ],
};

class ControlledHistoryApi extends FakeLinkLakeApi {
  final Map<String, Completer<Map<String, dynamic>>> _pending = {};

  @override
  Future<Map<String, dynamic>> getObject(String path) async {
    calls.add(path);
    final uri = Uri.parse(path);
    final range = uri.queryParameters['range'] ?? '1h';
    if (range == '1h') return _history('1h', 512);
    return (_pending[range] ??= Completer<Map<String, dynamic>>()).future;
  }

  void complete(String range, Map<String, dynamic> value) {
    _pending[range]!.complete(value);
  }
}
