#!/usr/bin/env sh
set -eu

project_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
output_directory="${1:-$project_root/dist}"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$project_root/Cargo.toml" | head -n 1)"
architecture="$(uname -m)"
package_name="linklake-$version-macos-$architecture"
stage="$output_directory/$package_name"
archive="$output_directory/$package_name.tar.gz"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$project_root" log -1 --format=%ct 2>/dev/null || date +%s)}"
commit="$(git -C "$project_root" rev-parse --short=12 HEAD)"
export LINKLAKE_GIT_COMMIT="$commit"

cd "$project_root"
cargo build --release --workspace --locked
rm -rf -- "$stage"
rm -f -- "$archive" "$archive.sha256"
install -d "$stage/bin" "$stage/launchd" "$stage/examples"
install -m 0755 target/release/linklake-server "$stage/bin/linklake-server"
install -m 0755 target/release/linklake-client "$stage/bin/linklake-client"
install -m 0644 packaging/launchd/com.linklake.server.plist "$stage/launchd/"
install -m 0644 packaging/launchd/com.linklake.update-resume.plist "$stage/launchd/"
install -m 0644 packaging/launchd/com.linklake.client.plist "$stage/launchd/"
install -m 0644 packaging/systemd/server.env.example "$stage/launchd/server.env.example"
install -m 0755 packaging/launchd/install-macos.sh "$stage/launchd/"
cp examples/* "$stage/examples/"
cp README.md README.en.md CHANGELOG.md LICENSE NOTICE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.html TRADEMARKS.md "$stage/"
printf '{"product":"LinkLake","version":"%s","target":"macos-%s","built_unix_seconds":%s,"commit":"%s"}\n' \
  "$version" "$architecture" "$source_date_epoch" "$commit" >"$stage/release.json"

signing_required="${LINKLAKE_MACOS_SIGNING_REQUIRED:-false}"
signing_active="${LINKLAKE_MACOS_SIGNING_ACTIVE:-false}"
case "$signing_required" in 1|true|TRUE|yes|YES) signing_required=true;; *) signing_required=false;; esac
case "$signing_active" in 1|true|TRUE|yes|YES) signing_active=true;; *) signing_active=false;; esac
if [ "$signing_required" = true ] && [ "$signing_active" != true ]; then
  echo 'macOS production signing is required but the temporary signing context is inactive.' >&2
  exit 1
fi
if [ "$signing_active" = true ]; then
  test -n "${LINKLAKE_MACOS_SIGNING_IDENTITY:-}"
  test -f "${LINKLAKE_MACOS_KEYCHAIN_PATH:-}"
  for binary in "$stage/bin/linklake-server" "$stage/bin/linklake-client"; do
    codesign --force --timestamp --options runtime \
      --sign "$LINKLAKE_MACOS_SIGNING_IDENTITY" \
      --keychain "$LINKLAKE_MACOS_KEYCHAIN_PATH" "$binary"
    codesign --verify --strict --verbose=2 "$binary"
  done
  notary_dir="$(mktemp -d)"
  trap 'rm -rf -- "$notary_dir"' EXIT HUP INT TERM
  notary_archive="$notary_dir/$package_name.zip"
  ditto -c -k --keepParent "$stage" "$notary_archive"
  sh "$project_root/scripts/notarize-macos-artifact.sh" "$notary_archive"
fi

find "$stage" -exec touch -t "$(date -r "$source_date_epoch" +%Y%m%d%H%M.%S)" {} +
tar -C "$output_directory" -czf "$archive" "$package_name"
(cd "$output_directory" && shasum -a 256 "$(basename "$archive")" >"$(basename "$archive").sha256")
echo "Created $archive"
