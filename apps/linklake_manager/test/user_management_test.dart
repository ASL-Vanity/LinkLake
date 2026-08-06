import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/rbac.dart';
import 'package:linklake_manager/user_management.dart';

import 'fakes.dart';

const currentUser = <String, dynamic>{
  'username': 'admin',
  'display_name': 'Administrator',
  'role': 'administrator',
  'enabled': true,
  'active_sessions': 1,
};
const operatorUser = <String, dynamic>{
  'username': 'operator',
  'display_name': 'Operator',
  'role': 'operator',
  'enabled': true,
  'active_sessions': 1,
  'must_change_password': false,
};
const identity = <String, dynamic>{
  'username': 'admin',
  'role': 'administrator',
  'session_id': 'current-session',
  'authentication_type': 'password_session',
  'totp_enabled': false,
};

void main() {
  test(
    'action policy protects current user last admin and current session',
    () {
      const policy = UserActionPolicy(
        currentUsername: 'admin',
        currentSessionId: 'current-session',
        enabledAdministratorCount: 1,
      );
      expect(policy.canDelete(currentUser), isFalse);
      expect(policy.canChangeRoleOrEnabled(currentUser), isFalse);
      expect(policy.canResetPassword(currentUser), isFalse);
      expect(policy.canRevokeUserSessions(currentUser), isFalse);
      expect(
        policy.canRevokeSession(const {'session_id': 'current-session'}),
        isFalse,
      );
      expect(policy.canDelete(operatorUser), isTrue);
      expect(
        policy.canRevokeSession(const {'session_id': 'other-session'}),
        isTrue,
      );
      const unidentified = UserActionPolicy(
        currentUsername: 'admin',
        currentSessionId: null,
        enabledAdministratorCount: 1,
      );
      expect(
        unidentified.canRevokeSession(const {'session_id': 'other-session'}),
        isFalse,
      );
    },
  );

  testWidgets('administrator edits and disables a supported user', (
    tester,
  ) async {
    final api = FakeLinkLakeApi();
    await _pumpPage(tester, api);

    await tester.tap(find.byKey(const Key('user-actions-operator')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Edit').last);
    await tester.pumpAndSettle();
    await tester.enterText(
      find.widgetWithText(TextField, 'Display name'),
      'Operations Team',
    );
    await tester.tap(find.byKey(const Key('edit-user-enabled')));
    await tester.tap(find.byKey(const Key('save-user')));
    await tester.pumpAndSettle();

    expect(api.puts, hasLength(1));
    expect(api.puts.single.$1, '/api/v1/users/operator');
    expect(api.puts.single.$2, {
      'display_name': 'Operations Team',
      'role': 'operator',
      'enabled': false,
    });
  });

  testWidgets('administrator creates and deletes users with server contracts', (
    tester,
  ) async {
    final api = FakeLinkLakeApi();
    await _pumpPage(tester, api);

    await tester.tap(find.byKey(const Key('create-user')));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.widgetWithText(TextField, 'Username'),
      'new-user',
    );
    await tester.enterText(
      find.widgetWithText(TextField, 'Display name'),
      'New User',
    );
    await tester.enterText(
      find.widgetWithText(TextField, 'Password (12+ characters)'),
      'safe-password-123',
    );
    await tester.tap(find.byKey(const Key('save-user')));
    await tester.pumpAndSettle();

    expect(api.posts.first.$1, '/api/v1/users');
    expect(api.posts.first.$2, {
      'username': 'new-user',
      'display_name': 'New User',
      'role': 'operator',
      'password': 'safe-password-123',
      'force_password_change': true,
    });

    await tester.tap(find.byKey(const Key('user-actions-operator')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Delete').last);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Confirm').last);
    await tester.pumpAndSettle();
    expect(api.deletes, contains('/api/v1/users/operator'));
  });

  testWidgets('password reset and user session revocation use real endpoints', (
    tester,
  ) async {
    final api = FakeLinkLakeApi();
    await _pumpPage(tester, api);

    await tester.tap(find.byKey(const Key('user-actions-operator')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Reset password').last);
    await tester.pumpAndSettle();
    await tester.enterText(
      find.widgetWithText(TextField, 'New password (12+ characters)'),
      'safe-password-123',
    );
    await tester.tap(find.byKey(const Key('confirm-reset-password')));
    await tester.pumpAndSettle();

    expect(api.posts.last.$1, '/api/v1/users/operator/reset-password');
    expect(api.posts.last.$2, {
      'new_password': 'safe-password-123',
      'force_password_change': true,
    });

    await tester.tap(find.byKey(const Key('user-actions-operator')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Revoke user sessions').last);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Confirm').last);
    await tester.pumpAndSettle();
    expect(api.posts.last.$1, '/api/v1/users/operator/revoke-sessions');
  });

  testWidgets(
    'current session is disabled while another session is revocable',
    (tester) async {
      final api = FakeLinkLakeApi();
      await _pumpPage(tester, api);

      final current = tester.widget<IconButton>(
        find.byKey(const Key('revoke-session-current-session')),
      );
      expect(current.onPressed, isNull);

      await tester.tap(find.byKey(const Key('revoke-session-other-session')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Confirm').last);
      await tester.pumpAndSettle();
      expect(api.deletes, contains('/api/v1/sessions/other-session'));
    },
  );
}

Future<void> _pumpPage(WidgetTester tester, FakeLinkLakeApi api) async {
  tester.view.physicalSize = const Size(1280, 1000);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(
    MaterialApp(
      home: Scaffold(
        body: UserManagementPage(
          api: api,
          identity: identity,
          users: const [currentUser, operatorUser],
          sessions: const [
            {
              'session_id': 'current-session',
              'username': 'admin',
              'expires_unix_seconds': 2000000000,
            },
            {
              'session_id': 'other-session',
              'username': 'operator',
              'expires_unix_seconds': 2000000000,
            },
          ],
          apiTokens: const [],
          capabilities: const RoleCapabilities(ManagementRole.administrator),
          chinese: false,
          onRefresh: () async {},
          onError: (error) => fail(error.toString()),
        ),
      ),
    ),
  );
  await tester.pumpAndSettle();
}
