import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/manager_identity.dart';
import 'package:linklake_manager/manager_theme.dart';

void main() {
  test('five material themes use distinct surfaces and geometry', () {
    final themes = ManagerThemeStyle.values
        .map((style) => buildManagerTheme(style, Brightness.light))
        .toList();
    expect(
      themes.map((theme) => theme.scaffoldBackgroundColor).toSet(),
      hasLength(5),
    );
    final shapes = themes
        .map((theme) => theme.cardTheme.shape.toString())
        .toSet();
    expect(shapes, hasLength(5));
  });

  test('high contrast themes exceed the enhanced text contrast threshold', () {
    for (final brightness in Brightness.values) {
      final theme = buildManagerTheme(
        ManagerThemeStyle.highContrast,
        brightness,
      );
      expect(
        _contrastRatio(theme.colorScheme.onSurface, theme.colorScheme.surface),
        greaterThanOrEqualTo(7),
      );
      expect(
        _contrastRatio(theme.colorScheme.onPrimary, theme.colorScheme.primary),
        greaterThanOrEqualTo(7),
      );
      final shape = theme.cardTheme.shape! as RoundedRectangleBorder;
      expect(shape.side.width, greaterThanOrEqualTo(2));
    }
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

double _contrastRatio(Color first, Color second) {
  final lighter = first.computeLuminance() > second.computeLuminance()
      ? first.computeLuminance()
      : second.computeLuminance();
  final darker = first.computeLuminance() > second.computeLuminance()
      ? second.computeLuminance()
      : first.computeLuminance();
  return (lighter + 0.05) / (darker + 0.05);
}
