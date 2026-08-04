#!/usr/bin/env sh
set -eu

project_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
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
commit="$(git -C "$project_root" rev-parse --short=12 HEAD)"
export LINKLAKE_GIT_COMMIT="$commit"

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
  sign_macos_code() {
    codesign --force --timestamp --options runtime \
      --sign "$LINKLAKE_MACOS_SIGNING_IDENTITY" \
      --keychain "$LINKLAKE_MACOS_KEYCHAIN_PATH" "$1"
  }
  if [ -d "$bundle/Contents/Frameworks" ]; then
    find "$bundle/Contents/Frameworks" -depth -type f | while IFS= read -r item; do
      if file "$item" | grep -q 'Mach-O'; then sign_macos_code "$item"; fi
    done
    find "$bundle/Contents/Frameworks" -depth -type d \( -name '*.framework' -o -name '*.xpc' -o -name '*.app' \) | \
      while IFS= read -r item; do sign_macos_code "$item"; done
  fi
  sign_macos_code "$bundle/Contents/Resources/linklake-client"
  codesign --force --timestamp --options runtime \
    --entitlements "$manager_root/macos/Runner/Release.entitlements" \
    --sign "$LINKLAKE_MACOS_SIGNING_IDENTITY" \
    --keychain "$LINKLAKE_MACOS_KEYCHAIN_PATH" "$bundle"
  codesign --verify --deep --strict --verbose=2 "$bundle"
  notary_dir="$(mktemp -d)"
  trap 'rm -rf -- "$notary_dir"' EXIT HUP INT TERM
  notary_archive="$notary_dir/$package_name.zip"
  ditto -c -k --keepParent "$bundle" "$notary_archive"
  sh "$project_root/scripts/notarize-macos-artifact.sh" "$notary_archive" "$bundle"
else
  codesign --force --deep --sign - "$bundle"
  codesign --verify --deep --strict "$bundle"
fi

rm -rf -- "$stage"
rm -f -- "$archive" "$archive.sha256"
install -d "$stage"
cp -a "$bundle" "$stage/"
cp "$project_root/README.md" "$project_root/README.en.md" "$project_root/LICENSE" "$project_root/NOTICE" \
  "$project_root/THIRD_PARTY_NOTICES.md" "$project_root/THIRD_PARTY_LICENSES.html" \
  "$project_root/TRADEMARKS.md" "$stage/"
cp "$manager_root/README.md" "$stage/MANAGER_README.md"
printf '{"product":"LinkLake Manager","component":"manager","version":"%s","target":"macos-%s","built_unix_seconds":%s,"commit":"%s"}\n' \
  "$version" "$architecture" "$source_date_epoch" "$commit" >"$stage/release.json"
find "$stage" -exec touch -t "$(date -r "$source_date_epoch" +%Y%m%d%H%M.%S)" {} +
tar -C "$output_directory" -czf "$archive" "$package_name"
(cd "$output_directory" && shasum -a 256 "$(basename "$archive")" >"$(basename "$archive").sha256")
echo "Created $archive"
