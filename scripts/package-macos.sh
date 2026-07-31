#!/usr/bin/env sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
output_directory="${1:-$project_root/dist}"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$project_root/Cargo.toml" | head -n 1)"
architecture="$(uname -m)"
package_name="linklake-$version-macos-$architecture"
stage="$output_directory/$package_name"
archive="$output_directory/$package_name.tar.gz"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$project_root" log -1 --format=%ct 2>/dev/null || date +%s)}"

cd "$project_root"
cargo build --release --workspace --locked
rm -rf -- "$stage"
rm -f -- "$archive" "$archive.sha256"
install -d "$stage/bin" "$stage/launchd" "$stage/examples"
install -m 0755 target/release/linklake-server "$stage/bin/linklake-server"
install -m 0755 target/release/linklake-client "$stage/bin/linklake-client"
install -m 0644 packaging/launchd/com.linklake.server.plist "$stage/launchd/"
install -m 0644 packaging/launchd/com.linklake.client.plist "$stage/launchd/"
install -m 0644 packaging/systemd/server.env.example "$stage/launchd/server.env.example"
install -m 0755 packaging/launchd/install-macos.sh "$stage/launchd/"
cp examples/* "$stage/examples/"
cp README.md README.en.md CHANGELOG.md LICENSE NOTICE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.html TRADEMARKS.md "$stage/"
printf '{"product":"LinkLake","version":"%s","target":"macos-%s","built_unix_seconds":%s}\n' \
  "$version" "$architecture" "$source_date_epoch" >"$stage/release.json"
find "$stage" -exec touch -t "$(date -r "$source_date_epoch" +%Y%m%d%H%M.%S)" {} +
tar -C "$output_directory" -czf "$archive" "$package_name"
(cd "$output_directory" && shasum -a 256 "$(basename "$archive")" >"$(basename "$archive").sha256")
echo "Created $archive"
