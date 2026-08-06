import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/manager_identity.dart';
import 'package:linklake_manager/manager_theme.dart';

void main() {
  test('three material themes use distinct surfaces and geometry', () {
    final themes = ManagerThemeStyle.values
        .map((style) => buildManagerTheme(style, Brightness.light))
        .toList();
    expect(
      themes.map((theme) => theme.scaffoldBackgroundColor).toSet(),
      hasLength(3),
    );
    final shapes = themes
        .map((theme) => theme.cardTheme.shape.toString())
        .toSet();
    expect(shapes, hasLength(3));
  });

  testWidgets('identity badge exposes user role and authentication type', (
    tester,
  ) async {
    const identity = ManagerIdentity(
      username: 'admin',
      displayName: 'Lake Admin',
      role: 'administrator',
      authenticationType: 'password_session',
      sessionId: 'session-1',
      expiresUnixSeconds: 2000000000,
    );
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: ManagerIdentityBadge(identity: identity, chinese: false),
        ),
      ),
    );

    expect(find.byKey(const Key('current-user-identity')), findsOneWidget);
    expect(find.text('Lake Admin'), findsOneWidget);
    expect(find.text('Administrator · Password session'), findsOneWidget);
  });
}
