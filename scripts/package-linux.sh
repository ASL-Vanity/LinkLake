#!/usr/bin/env sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
output_directory="${1:-$project_root/dist}"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$project_root/Cargo.toml" | head -n 1)"
if [ -z "$version" ]; then
  echo "Could not read the workspace version." >&2
  exit 1
fi
package_name="linklake-$version-linux-x86_64"
stage="$output_directory/$package_name"
archive="$output_directory/$package_name.tar.gz"
source_date_epoch="${SOURCE_DATE_EPOCH:-}"
if [ -z "$source_date_epoch" ]; then
  source_date_epoch="$(git -C "$project_root" log -1 --format=%ct 2>/dev/null || date +%s)"
fi
cargo_bin="${CARGO:-cargo}"
commit="$(git -C "$project_root" rev-parse --short=12 HEAD)"
export LINKLAKE_GIT_COMMIT="$commit"
if [ -x "$HOME/.cargo/bin/cargo" ]; then
  cargo_bin="$HOME/.cargo/bin/cargo"
fi

cd "$project_root"
"$cargo_bin" build --release --workspace --locked
rm -rf -- "$stage"
rm -f -- "$archive" "$archive.sha256"
install -d "$stage/bin" "$stage/systemd" "$stage/iroh-relay" "$stage/examples"
install -m 0755 target/release/linklake-server "$stage/bin/linklake-server"
install -m 0755 target/release/linklake-client "$stage/bin/linklake-client"
install -m 0644 packaging/systemd/linklake-server.service "$stage/systemd/"
install -m 0644 packaging/systemd/linklake-client.service "$stage/systemd/"
install -m 0600 packaging/systemd/server.env.example "$stage/systemd/"
install -m 0755 packaging/systemd/install-linux.sh "$stage/systemd/"
install -m 0644 packaging/iroh-relay/config.toml.example "$stage/iroh-relay/"
install -m 0644 packaging/iroh-relay/linklake-iroh-relay.service "$stage/iroh-relay/"
install -m 0644 packaging/iroh-relay/nginx-location.conf.example "$stage/iroh-relay/"
install -m 0644 packaging/iroh-relay/nginx-server.conf.example "$stage/iroh-relay/"
install -m 0755 packaging/iroh-relay/install.sh "$stage/iroh-relay/"
cp examples/* "$stage/examples/"
cp README.md README.en.md CHANGELOG.md LICENSE NOTICE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.html TRADEMARKS.md "$stage/"
cat >"$stage/release.json" <<EOF
{"product":"LinkLake","version":"$version","target":"linux-x86_64","built_unix_seconds":$source_date_epoch,"commit":"$commit"}
EOF
find "$stage" -exec touch -d "@$source_date_epoch" {} +
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
  -C "$output_directory" -cf - "$package_name" | gzip -n >"$archive"
(cd "$output_directory" && sha256sum "$(basename "$archive")" >"$(basename "$archive").sha256")
echo "Created $archive"
