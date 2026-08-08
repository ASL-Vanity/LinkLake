import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/remote_update_management.dart';

import 'fakes.dart';

const clientId = '11111111-1111-4111-8111-111111111111';
const taskId = '22222222-2222-4222-8222-222222222222';

Widget updateHarness({
  required FakeLinkLakeApi api,
  Key? key,
  List<dynamic> tasks = const [],
  Future<void> Function()? onRefresh,
}) => MaterialApp(
  home: Scaffold(
    body: RemoteUpdateManagementPage(
      key: key,
      api: api,
      clients: const [
        {
          'client_id': clientId,
          'name': 'Edge client',
          'enabled': true,
          'online': true,
        },
      ],
      serverUpdate: const {
        'remote_client_update_available': true,
        'signature_policy': 'production',
        'build': {'version': '1.1.0', 'target': 'windows-x86_64'},
        'status': {'state': 'idle'},
      },
      tasks: tasks,
      chinese: false,
      onRefresh: onRefresh ?? () async {},
      onError: (_) {},
    ),
  ),
);

void main() {
  test('remote update actions use exact action-specific confirmations', () {
    expect(remoteUpdateConfirmationPhrase('check'), 'CHECK');
    expect(remoteUpdateConfirmationPhrase('download'), 'DOWNLOAD');
    expect(remoteUpdateConfirmationPhrase('apply'), 'UPDATE');
    expect(remoteUpdateConfirmationPhrase('status'), 'STATUS');
    expect(remoteUpdateConfirmationPhrase('recover'), 'RECOVER');
    expect(remoteUpdateConfirmationPhrase('rollback'), 'ROLLBACK');
    expect(remoteUpdateConfirmationPhrase('unknown'), isNull);
  });

  test('only active remote update tasks can be cancelled', () {
    expect(remoteUpdateTaskCanCancel({'state': 'queued'}), isTrue);
    expect(remoteUpdateTaskCanCancel({'state': 'running'}), isTrue);
    expect(
      remoteUpdateTaskCanCancel({'state': 'running', 'cancel_requested': true}),
      isFalse,
    );
    for (final state in [
      'cancel_requested',
      'succeeded',
      'failed',
      'cancelled',
    ]) {
      expect(remoteUpdateTaskCanCancel({'state': state}), isFalse);
    }
  });

  for (final entry in const {
    'check': 'CHECK',
    'download': 'DOWNLOAD',
    'apply': 'UPDATE',
    'status': 'STATUS',
    'recover': 'RECOVER',
    'rollback': 'ROLLBACK',
  }.entries) {
    testWidgets('administrator creates ${entry.key} remote update task', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(1200, 1000);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final api = FakeLinkLakeApi();
      var refreshes = 0;
      await tester.pumpWidget(
        updateHarness(
          key: ValueKey(entry.key),
          api: api,
          onRefresh: () async => refreshes++,
        ),
      );
      await tester.tap(find.byKey(const Key('remote-update-action')));
      await tester.pumpAndSettle();
      final actionLabel = switch (entry.key) {
        'check' => 'Check',
        'download' => 'Download',
        'apply' => 'Apply',
        'status' => 'Status',
        'recover' => 'Recover',
        _ => 'Rollback',
      };
      await tester.tap(find.text(actionLabel).last);
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('remote-update-create')));
      await tester.pumpAndSettle();

      expect(
        tester
            .widget<FilledButton>(
              find.byKey(const Key('remote-update-confirm')),
            )
            .onPressed,
        isNull,
      );
      await tester.enterText(
        find.byKey(const Key('remote-update-confirmation')),
        entry.value,
      );
      await tester.pump();
      await tester.tap(find.byKey(const Key('remote-update-confirm')));
      await tester.pumpAndSettle();

      expect(api.posts, hasLength(1));
      expect(api.posts.single.$1, '/api/v1/updates/clients/tasks');
      expect(api.posts.single.$2['target_client_id'], clientId);
      expect(api.posts.single.$2['action'], entry.key);
      expect(api.posts.single.$2['confirmation'], entry.value);
      expect(
        api.posts.single.$2['idempotency_key'].toString(),
        startsWith('${entry.key}:$clientId:'),
      );
      expect(
        api.posts.single.$2['idempotency_key'].toString().length,
        lessThanOrEqualTo(128),
      );
      expect(refreshes, 1);
    });
  }

  testWidgets('task details render events and cancellation requires CANCEL', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1200, 1000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = FakeLinkLakeApi();
    const task = {
      'task_id': taskId,
      'target_client_id': clientId,
      'action': 'download',
      'state': 'running',
      'stage': 'downloading',
      'recovery_state': 'none',
      'requested_by': 'admin',
      'attempt': 1,
      'cancel_requested': false,
      'created_unix_seconds': 1786118400,
      'updated_unix_seconds': 1786118460,
    };
    api.objectResponses['/api/v1/updates/clients/tasks/$taskId'] = const {
      'task': task,
      'events': [
        {
          'sequence': 1,
          'kind': 'created',
          'state': 'queued',
          'stage': 'queued',
          'recovery_state': 'none',
          'created_unix_seconds': 1786118400,
        },
        {
          'sequence': 2,
          'kind': 'stage_reported',
          'state': 'running',
          'stage': 'downloading',
          'recovery_state': 'none',
          'created_unix_seconds': 1786118460,
        },
      ],
    };
    await tester.pumpWidget(updateHarness(api: api, tasks: const [task]));

    await tester.tap(find.byKey(const Key('remote-update-details-$taskId')));
    await tester.pumpAndSettle();
    expect(
      find.byKey(const Key('remote-update-detail-dialog')),
      findsOneWidget,
    );
    expect(find.text('Stage reported'), findsOneWidget);
    expect(find.textContaining(taskId), findsOneWidget);

    await tester.tap(find.byKey(const Key('remote-update-detail-cancel')));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.byKey(const Key('remote-update-confirmation')),
      'CANCEL',
    );
    await tester.pump();
    await tester.tap(find.byKey(const Key('remote-update-confirm')));
    await tester.pumpAndSettle();

    expect(api.posts, hasLength(1));
    expect(api.posts.single.$1, '/api/v1/updates/clients/tasks/$taskId/cancel');
    expect(api.posts.single.$2, const {'confirmation': 'CANCEL'});
  });
}
