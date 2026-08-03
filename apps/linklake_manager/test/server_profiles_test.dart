import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/server_profiles.dart';

void main() {
  test('server profiles use atomic replacement and backup fallback', () async {
    final directory = await Directory.systemTemp.createTemp(
      'linklake-profiles-',
    );
    addTearDown(() => directory.delete(recursive: true));
    final path = '${directory.path}/profiles.json';

    await ServerProfileStore.save(const [
      ServerProfile(name: 'First', url: 'https://first.example.com'),
    ], path: path);
    await ServerProfileStore.save(const [
      ServerProfile(name: 'Second', url: 'https://second.example.com'),
    ], path: path);
    await File(path).writeAsString('{broken', flush: true);

    final loaded = await ServerProfileStore.load(path: path);
    expect(loaded, hasLength(1));
    expect(loaded.single.name, 'First');
    expect(loaded.single.url, 'https://first.example.com');
    expect(await File('$path.tmp').exists(), isFalse);
  });
}
