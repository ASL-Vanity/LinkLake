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
  static Future<List<ServerProfile>> load() async {
    final file = File(_path());
    if (!await file.exists()) {
      return const [
        ServerProfile(name: 'LinkLake', url: 'https://link.odelake.com'),
      ];
    }
    try {
      final decoded = jsonDecode(await file.readAsString());
      if (decoded is! List) return const [];
      return decoded
          .whereType<Map>()
          .map(
            (value) => ServerProfile.fromJson(Map<String, dynamic>.from(value)),
          )
          .where((value) => value.name.isNotEmpty && value.url.isNotEmpty)
          .toList(growable: false);
    } catch (_) {
      return const [];
    }
  }

  static Future<void> save(List<ServerProfile> profiles) async {
    final file = File(_path());
    await file.parent.create(recursive: true);
    final temporary = File('${file.path}.tmp');
    await temporary.writeAsString(
      const JsonEncoder.withIndent(
        '  ',
      ).convert(profiles.map((value) => value.toJson()).toList()),
      flush: true,
    );
    if (await file.exists()) await file.delete();
    await temporary.rename(file.path);
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
