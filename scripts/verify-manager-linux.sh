#!/usr/bin/env sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
output_directory="${1:-$project_root/dist}"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$project_root/Cargo.toml" | head -n 1)"
archive="$output_directory/linklake-manager-$version-linux-x86_64.tar.gz"
checksum="$archive.sha256"
test -f "$archive"
test -f "$checksum"
(cd "$output_directory" && sha256sum -c "$(basename "$checksum")")
entries="$(tar -tzf "$archive" | sed 's#^[^/]*/##')"
for entry in linklake_manager linklake-client lib/libflutter_linux_gtk.so data/icudtl.dat data/flutter_assets/AssetManifest.bin README.md README.en.md MANAGER_README.md LICENSE NOTICE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.html TRADEMARKS.md release.json; do
  printf '%s\n' "$entries" | grep -Fx "$entry" >/dev/null || { echo "Missing archive entry: $entry" >&2; exit 1; }
done
printf '%s\n' "$entries" | grep -Fx 'linklake-client' >/dev/null
verify_root="$(mktemp -d)"
trap 'rm -rf -- "$verify_root"' EXIT
tar -xzf "$archive" -C "$verify_root"
package_root="$(find "$verify_root" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
"$package_root/linklake-client" --version | grep -F "$version" | grep -F 'target=linux-x86_64' >/dev/null
grep -F '"commit"' "$package_root/release.json" >/dev/null
echo "Verified $archive"
