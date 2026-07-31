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
for entry in README.md README.en.md MANAGER_README.md LICENSE NOTICE release.json; do
  printf '%s\n' "$entries" | grep -Fx "$entry" >/dev/null || { echo "Missing archive entry: $entry" >&2; exit 1; }
done
echo "Verified $archive"
