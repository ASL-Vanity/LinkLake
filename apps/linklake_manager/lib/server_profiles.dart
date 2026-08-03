import 'dart:convert';
import 'dart:io';

class ServerProfile {
  const ServerProfile({required this.name, required this.url});

  final String name;
  final String url;

  Map<String, dynamic> toJson() => {'name': name, 'url': url};

  static ServerProfile fromJson(Map<String, dynamic> value) => ServerProfile(
    name: value['name']?.toString() ?? '',
    url: value['url']?.toString() ?? '',
  );
}

class ServerProfileStore {
  static Future<List<ServerProfile>> load({String? path}) async {
    final file = File(path ?? _path());
    final backup = File('${file.path}.bak');
    final primaryProfiles = await _loadFile(file);
    if (primaryProfiles != null) return primaryProfiles;
    final backupProfiles = await _loadFile(backup);
    if (backupProfiles != null) return backupProfiles;
    if (!await file.exists() && !await backup.exists()) {
      return const [
        ServerProfile(name: 'LinkLake', url: 'https://link.odelake.com'),
      ];
    }
    return const [];
  }

  static Future<void> save(List<ServerProfile> profiles, {String? path}) async {
    final file = File(path ?? _path());
    await file.parent.create(recursive: true);
    final temporary = File('${file.path}.tmp');
    final backup = File('${file.path}.bak');
    final backupTemporary = File('${backup.path}.tmp');
    await _deleteIfPresent(temporary);
    await _deleteIfPresent(backupTemporary);
    try {
      final encoded = const JsonEncoder.withIndent(
        '  ',
      ).convert(profiles.map((value) => value.toJson()).toList());
      await temporary.writeAsString(encoded, flush: true);
      jsonDecode(await temporary.readAsString());
      if (await _loadFile(file) != null) {
        await file.copy(backupTemporary.path);
        await backupTemporary.rename(backup.path);
      }
      await temporary.rename(file.path);
    } finally {
      await _deleteIfPresent(temporary);
      await _deleteIfPresent(backupTemporary);
    }
  }

  static Future<List<ServerProfile>?> _loadFile(File file) async {
    if (!await file.exists()) return null;
    try {
      final decoded = jsonDecode(await file.readAsString());
      if (decoded is! List) return null;
      return decoded
          .whereType<Map>()
          .map(
            (value) => ServerProfile.fromJson(Map<String, dynamic>.from(value)),
          )
          .where((value) => value.name.isNotEmpty && value.url.isNotEmpty)
          .toList(growable: false);
    } catch (_) {
      return null;
    }
  }

  static Future<void> _deleteIfPresent(File file) async {
    if (await file.exists()) await file.delete();
  }

  static String _path() {
    final environment = Platform.environment;
    if (Platform.isWindows) {
      final root =
          environment['APPDATA'] ??
          environment['LOCALAPPDATA'] ??
          Directory.current.path;
      return '$root${Platform.pathSeparator}LinkLake${Platform.pathSeparator}manager-servers.json';
    }
    final home = environment['HOME'] ?? Directory.current.path;
    if (Platform.isMacOS) {
      return '$home/Library/Application Support/LinkLake/manager-servers.json';
    }
    return '$home/.config/linklake/manager-servers.json';
  }
}
