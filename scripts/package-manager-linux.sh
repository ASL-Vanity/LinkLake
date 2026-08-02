#!/usr/bin/env sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
manager_root="$project_root/apps/linklake_manager"
output_directory="${1:-$project_root/dist}"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$project_root/Cargo.toml" | head -n 1)"
manager_version="$(sed -n 's/^version:[[:space:]]*\([^[:space:]]*\)/\1/p' "$manager_root/pubspec.yaml" | head -n 1)"
test -n "$version"
test -n "$manager_version"
package_name="linklake-manager-$version-linux-x86_64"
stage="$output_directory/$package_name"
archive="$output_directory/$package_name.tar.gz"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$project_root" log -1 --format=%ct 2>/dev/null || date +%s)}"
flutter_bin="${FLUTTER:-flutter}"
cargo_bin="${CARGO:-cargo}"
if [ -x "$HOME/.cargo/bin/cargo" ]; then
  cargo_bin="$HOME/.cargo/bin/cargo"
fi

cd "$manager_root"
"$cargo_bin" build --release -p linklake-client --locked --manifest-path "$project_root/Cargo.toml"
"$flutter_bin" pub get
"$flutter_bin" build linux --release \
  --dart-define="LINKLAKE_MANAGER_VERSION=$manager_version" \
  --dart-define="LINKLAKE_RELEASE_VERSION=$version"
bundle="$manager_root/build/linux/x64/release/bundle"
test -x "$bundle/linklake_manager"

rm -rf -- "$stage"
rm -f -- "$archive" "$archive.sha256"
install -d "$stage"
cp -a "$bundle/." "$stage/"
cp "$project_root/target/release/linklake-client" "$stage/linklake-client"
cp "$project_root/README.md" "$project_root/README.en.md" "$project_root/LICENSE" "$project_root/NOTICE" \
  "$project_root/THIRD_PARTY_NOTICES.md" "$project_root/THIRD_PARTY_LICENSES.html" \
  "$project_root/TRADEMARKS.md" "$stage/"
cp "$manager_root/README.md" "$stage/MANAGER_README.md"
printf '{"product":"LinkLake Manager","component":"manager","version":"%s","target":"linux-x86_64","built_unix_seconds":%s}\n' \
  "$version" "$source_date_epoch" >"$stage/release.json"
find "$stage" -exec touch -d "@$source_date_epoch" {} +
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
  -C "$output_directory" -cf - "$package_name" | gzip -n >"$archive"
(cd "$output_directory" && sha256sum "$(basename "$archive")" >"$(basename "$archive").sha256")
echo "Created $archive"
