#!/usr/bin/env sh
set -eu

project_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
output_directory="${1:-$project_root/dist}"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$project_root/Cargo.toml" | head -n 1)"
archive="$(find "$output_directory" -maxdepth 1 -name "linklake-$version-macos-*.tar.gz" -print | head -n 1)"
test -n "$archive"
(cd "$output_directory" && shasum -a 256 -c "$(basename "$archive").sha256")
entries="$(tar -tzf "$archive" | sed 's#^[^/]*/##')"
for entry in bin/linklake-server bin/linklake-client launchd/com.linklake.server.plist launchd/com.linklake.client.plist launchd/install-macos.sh README.md README.en.md CHANGELOG.md LICENSE NOTICE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.html TRADEMARKS.md release.json; do
  printf '%s\n' "$entries" | grep -Fx "$entry" >/dev/null || { echo "Missing archive entry: $entry" >&2; exit 1; }
done
verify_root="$(mktemp -d)"
trap 'rm -rf -- "$verify_root"' EXIT
tar -xzf "$archive" -C "$verify_root"
package_root="$(find "$verify_root" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
"$package_root/bin/linklake-server" --version | grep -F "$version" | grep -F 'target=macos-' >/dev/null
"$package_root/bin/linklake-client" --version | grep -F "$version" | grep -F 'target=macos-' >/dev/null
grep -F '"commit"' "$package_root/release.json" >/dev/null
case "${LINKLAKE_MACOS_SIGNING_REQUIRED:-false}" in
  1|true|TRUE|yes|YES)
    for binary in "$package_root/bin/linklake-server" "$package_root/bin/linklake-client"; do
      codesign --verify --strict --verbose=2 "$binary"
      spctl --assess --type execute --verbose=4 "$binary"
    done
    ;;
esac
echo "Verified $archive"
