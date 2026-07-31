#!/usr/bin/env sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
output_directory="${1:-$project_root/dist}"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$project_root/Cargo.toml" | head -n 1)"
archive="$output_directory/linklake-$version-linux-x86_64.tar.gz"
checksum="$archive.sha256"

test -f "$archive"
test -f "$checksum"
(cd "$output_directory" && sha256sum -c "$(basename "$checksum")")

required='bin/linklake-server
bin/linklake-client
systemd/linklake-server.service
systemd/linklake-client.service
systemd/server.env.example
systemd/install-linux.sh
iroh-relay/config.toml.example
iroh-relay/linklake-iroh-relay.service
iroh-relay/nginx-location.conf.example
iroh-relay/nginx-server.conf.example
iroh-relay/install.sh
README.md
README.en.md
CHANGELOG.md
LICENSE
NOTICE
THIRD_PARTY_NOTICES.md
THIRD_PARTY_LICENSES.html
TRADEMARKS.md
release.json'

entries="$(tar -tzf "$archive" | sed 's#^[^/]*/##')"
printf '%s\n' "$required" | while IFS= read -r entry; do
  printf '%s\n' "$entries" | grep -Fx "$entry" >/dev/null || {
    echo "Missing archive entry: $entry" >&2
    exit 1
  }
done

echo "Verified $archive"
