#!/usr/bin/env sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
output_directory="${1:-$project_root/dist}"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$project_root/Cargo.toml" | head -n 1)"
archive="$(find "$output_directory" -maxdepth 1 -name "linklake-manager-$version-macos-*.tar.gz" -print | head -n 1)"
test -n "$archive"
(cd "$output_directory" && shasum -a 256 -c "$(basename "$archive").sha256")
entries="$(tar -tzf "$archive" | sed 's#^[^/]*/##')"
printf '%s\n' "$entries" | grep -E '\.app/Contents/Info\.plist$' >/dev/null
printf '%s\n' "$entries" | grep -E '\.app/Contents/MacOS/[^/]+$' >/dev/null
printf '%s\n' "$entries" | grep -E '\.app/Contents/Resources/linklake-client$' >/dev/null
for entry in README.md README.en.md MANAGER_README.md LICENSE NOTICE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.html TRADEMARKS.md release.json; do
  printf '%s\n' "$entries" | grep -Fx "$entry" >/dev/null || { echo "Missing archive entry: $entry" >&2; exit 1; }
done
verify_root="$(mktemp -d)"
trap 'rm -rf -- "$verify_root"' EXIT
tar -xzf "$archive" -C "$verify_root"
client="$(find "$verify_root" -path '*.app/Contents/Resources/linklake-client' -type f | head -n 1)"
"$client" --version | grep -F "$version" | grep -F 'target=macos-' >/dev/null
release="$(find "$verify_root" -name release.json -maxdepth 3 -type f | head -n 1)"
grep -F '"commit"' "$release" >/dev/null
echo "Verified $archive"
