#!/usr/bin/env sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
manager_root="$project_root/apps/linklake_manager"
output_directory="${1:-$project_root/dist}"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$project_root/Cargo.toml" | head -n 1)"
manager_version="$(sed -n 's/^version:[[:space:]]*\([^[:space:]]*\)/\1/p' "$manager_root/pubspec.yaml" | head -n 1)"
test -n "$version"
test -n "$manager_version"
architecture="$(uname -m)"
package_name="linklake-manager-$version-macos-$architecture"
stage="$output_directory/$package_name"
archive="$output_directory/$package_name.tar.gz"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$project_root" log -1 --format=%ct 2>/dev/null || date +%s)}"
flutter_bin="${FLUTTER:-flutter}"

cd "$manager_root"
cargo build --release -p linklake-client --locked --manifest-path "$project_root/Cargo.toml"
"$flutter_bin" pub get
"$flutter_bin" build macos --release \
  --dart-define="LINKLAKE_MANAGER_VERSION=$manager_version" \
  --dart-define="LINKLAKE_RELEASE_VERSION=$version"
bundle="$(find "$manager_root/build/macos/Build/Products/Release" -maxdepth 1 -type d -name '*.app' -print | head -n 1)"
test -n "$bundle"
cp "$project_root/target/release/linklake-client" "$bundle/Contents/Resources/linklake-client"
chmod 0755 "$bundle/Contents/Resources/linklake-client"
codesign --force --deep --sign - "$bundle"
codesign --verify --deep --strict "$bundle"

rm -rf -- "$stage"
rm -f -- "$archive" "$archive.sha256"
install -d "$stage"
cp -a "$bundle" "$stage/"
cp "$project_root/README.md" "$project_root/README.en.md" "$project_root/LICENSE" "$project_root/NOTICE" \
  "$project_root/THIRD_PARTY_NOTICES.md" "$project_root/THIRD_PARTY_LICENSES.html" \
  "$project_root/TRADEMARKS.md" "$stage/"
cp "$manager_root/README.md" "$stage/MANAGER_README.md"
printf '{"product":"LinkLake Manager","component":"manager","version":"%s","target":"macos-%s","built_unix_seconds":%s}\n' \
  "$version" "$architecture" "$source_date_epoch" >"$stage/release.json"
find "$stage" -exec touch -t "$(date -r "$source_date_epoch" +%Y%m%d%H%M.%S)" {} +
tar -C "$output_directory" -czf "$archive" "$package_name"
(cd "$output_directory" && shasum -a 256 "$(basename "$archive")" >"$(basename "$archive").sha256")
echo "Created $archive"
