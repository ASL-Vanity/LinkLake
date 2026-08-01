// LinkLake Manager 的应用版本与发行版本。
// 发布构建可以用 --dart-define 覆盖；默认值必须与 pubspec.yaml 和 Cargo.toml 保持一致。
const managerVersion = String.fromEnvironment(
  'LINKLAKE_MANAGER_VERSION',
  defaultValue: '0.6.0+3',
);

const managerReleaseVersion = String.fromEnvironment(
  'LINKLAKE_RELEASE_VERSION',
  defaultValue: '0.6.0-rc.3',
);

bool isReleaseNewer(String latest, String current) {
  final latestVersion = _ReleaseVersion.tryParse(latest);
  final currentVersion = _ReleaseVersion.tryParse(current);
  if (latestVersion == null || currentVersion == null) return false;
  return latestVersion.compareTo(currentVersion) > 0;
}

String? selectLatestReleaseTag(Iterable<Object?> releases, String current) {
  final currentVersion = _ReleaseVersion.tryParse(current);
  if (currentVersion == null) return null;
  final includePrerelease = currentVersion.prerelease.isNotEmpty;
  String? selectedTag;
  _ReleaseVersion? selectedVersion;
  for (final value in releases) {
    if (value is! Map) continue;
    if (value['draft'] == true) continue;
    final tag = value['tag_name']?.toString();
    final version = tag == null ? null : _ReleaseVersion.tryParse(tag);
    if (version == null) continue;
    if (!includePrerelease &&
        (value['prerelease'] == true || version.prerelease.isNotEmpty)) {
      continue;
    }
    if (selectedVersion == null || version.compareTo(selectedVersion) > 0) {
      selectedTag = tag;
      selectedVersion = version;
    }
  }
  return selectedTag;
}

class _ReleaseVersion implements Comparable<_ReleaseVersion> {
  const _ReleaseVersion(this.major, this.minor, this.patch, this.prerelease);

  final int major;
  final int minor;
  final int patch;
  final List<String> prerelease;

  static _ReleaseVersion? tryParse(String value) {
    final match = RegExp(
      r'^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$',
    ).firstMatch(value.trim());
    if (match == null) return null;
    return _ReleaseVersion(
      int.parse(match.group(1)!),
      int.parse(match.group(2)!),
      int.parse(match.group(3)!),
      match.group(4)?.split('.') ?? const [],
    );
  }

  @override
  int compareTo(_ReleaseVersion other) {
    for (final pair in [
      (major, other.major),
      (minor, other.minor),
      (patch, other.patch),
    ]) {
      final result = pair.$1.compareTo(pair.$2);
      if (result != 0) return result;
    }
    if (prerelease.isEmpty && other.prerelease.isNotEmpty) return 1;
    if (prerelease.isNotEmpty && other.prerelease.isEmpty) return -1;
    for (
      var index = 0;
      index < prerelease.length && index < other.prerelease.length;
      index++
    ) {
      final left = int.tryParse(prerelease[index]);
      final right = int.tryParse(other.prerelease[index]);
      final result = switch ((left, right)) {
        (final int left, final int right) => left.compareTo(right),
        (final int _, null) => -1,
        (null, final int _) => 1,
        _ => prerelease[index].compareTo(other.prerelease[index]),
      };
      if (result != 0) return result;
    }
    return prerelease.length.compareTo(other.prerelease.length);
  }
}
