import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/main.dart';
import 'package:linklake_manager/version.dart';

void main() {
  testWidgets('shows the LinkLake login screen', (tester) async {
    await tester.pumpWidget(const LinkLakeManagerApp());

    expect(find.text('LinkLake'), findsOneWidget);
    expect(find.text('登录'), findsOneWidget);
  });

  test('manager and distribution versions stay aligned with manifests', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    final workspace = File('../../Cargo.toml').readAsStringSync();
    expect(pubspec, contains('version: $managerVersion'));
    expect(workspace, contains('version = "$managerReleaseVersion"'));
  });

  test('release comparison follows semantic version precedence', () {
    expect(isReleaseNewer('v0.6.0', '0.6.0-rc.2'), isTrue);
    expect(isReleaseNewer('v0.7.0-rc.1', '0.6.0'), isTrue);
    expect(isReleaseNewer('v0.6.0-rc.1', '0.6.0-rc.2'), isFalse);
    expect(isReleaseNewer('not-a-version', '0.6.0'), isFalse);
  });

  test('release selection respects stable and prerelease channels', () {
    final releases = [
      {'tag_name': 'v0.8.0-rc.1', 'prerelease': false, 'draft': false},
      {'tag_name': 'v0.7.0-rc.1', 'prerelease': true, 'draft': false},
      {'tag_name': 'v0.6.0', 'prerelease': false, 'draft': false},
      {'tag_name': 'v9.0.0', 'prerelease': false, 'draft': true},
    ];
    expect(selectLatestReleaseTag(releases, '0.6.0'), 'v0.6.0');
    expect(selectLatestReleaseTag(releases, '0.6.0-rc.2'), 'v0.8.0-rc.1');
  });

  test('client update actions use the safe updater command contract', () {
    expect(clientUpdateArguments('check'), ['check-update']);
    expect(clientUpdateArguments('download'), ['update', 'download']);
    expect(clientUpdateArguments('apply'), ['update', 'apply', '--yes']);
    expect(clientUpdateArguments('rollback'), ['update', 'rollback', '--yes']);
    expect(clientUpdateArguments('status'), ['update', 'status']);
  });
}
