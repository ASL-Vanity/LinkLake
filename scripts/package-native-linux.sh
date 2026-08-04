#!/usr/bin/env sh
set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
out="${1:-$root/dist}"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -n 1)"
rpm_version="${version%%-*}"
if [ "$rpm_version" = "$version" ]; then
  rpm_release=1
else
  rpm_release="0.$(printf '%s' "${version#*-}" | tr '-' '.')"
fi
arch="$(uname -m)"
case "$arch" in x86_64) deb_arch=amd64; rpm_arch=x86_64;; aarch64) deb_arch=arm64; rpm_arch=aarch64;; *) echo "Unsupported architecture: $arch" >&2; exit 1;; esac

cd "$root"
binary_dir="${LINKLAKE_BINARY_DIR:-$root/target/release}"
if [ -z "${LINKLAKE_BINARY_DIR:-}" ]; then
  cargo build --release --locked -p linklake-server -p linklake-client
fi
test -x "$binary_dir/linklake-server"
test -x "$binary_dir/linklake-client"
mkdir -p "$out"
stage="$(mktemp -d)"
trap 'rm -rf -- "$stage"' EXIT

install -d "$stage/usr/local/bin" "$stage/lib/systemd/system" "$stage/etc/linklake" \
  "$stage/var/lib/linklake" "$stage/var/log/linklake" \
  "$stage/var/lib/linklake-client" "$stage/var/log/linklake-client"
install -m 0755 "$binary_dir/linklake-server" "$stage/usr/local/bin/"
install -m 0755 "$binary_dir/linklake-client" "$stage/usr/local/bin/"
install -m 0644 packaging/systemd/linklake-server.service "$stage/lib/systemd/system/"
install -m 0644 packaging/systemd/linklake-client.service "$stage/lib/systemd/system/"
install -m 0600 packaging/systemd/server.env.example "$stage/etc/linklake/server.env.example"
install -m 0600 examples/linklake-client.toml "$stage/etc/linklake/client.toml.example"

if command -v dpkg-deb >/dev/null 2>&1; then
  install -d "$stage/DEBIAN"
  cat >"$stage/DEBIAN/control" <<EOF
Package: linklake
Version: $version
Section: net
Priority: optional
Architecture: $deb_arch
Maintainer: LinkLake Contributors
Depends: ca-certificates
Description: Cross-platform secure tunnel server and client
EOF
  cat >"$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
getent group linklake >/dev/null || addgroup --system linklake
getent passwd linklake >/dev/null || adduser --system --ingroup linklake --home /var/lib/linklake --no-create-home linklake
chown -R linklake:linklake /var/lib/linklake /var/log/linklake /var/lib/linklake-client /var/log/linklake-client
systemctl daemon-reload >/dev/null 2>&1 || true
EOF
  chmod 0755 "$stage/DEBIAN/postinst"
  dpkg-deb --build --root-owner-group "$stage" "$out/linklake_${version}_${deb_arch}.deb"
  rm -rf "$stage/DEBIAN"
fi

if command -v rpmbuild >/dev/null 2>&1; then
  top="$(mktemp -d)"
  mkdir -p "$top/BUILD" "$top/RPMS" "$top/SOURCES" "$top/SPECS" "$top/SRPMS"
  tar -C "$stage" -czf "$top/SOURCES/linklake-root.tar.gz" .
  cat >"$top/SPECS/linklake.spec" <<EOF
Name: linklake
Version: $rpm_version
Release: $rpm_release%{?dist}
Summary: Cross-platform secure tunnel server and client
License: Apache-2.0
BuildArch: $rpm_arch
Source0: linklake-root.tar.gz
%description
LinkLake secure tunnel server and client.
%prep
%build
%install
mkdir -p %{buildroot}
tar -xzf %{SOURCE0} -C %{buildroot}
%post
getent group linklake >/dev/null || groupadd --system linklake
getent passwd linklake >/dev/null || useradd --system --gid linklake --home-dir /var/lib/linklake --shell /sbin/nologin linklake
chown -R linklake:linklake /var/lib/linklake /var/log/linklake /var/lib/linklake-client /var/log/linklake-client
systemctl daemon-reload >/dev/null 2>&1 || true
%files
/usr/local/bin/linklake-server
/usr/local/bin/linklake-client
/lib/systemd/system/linklake-server.service
/lib/systemd/system/linklake-client.service
%config(noreplace) /etc/linklake/server.env.example
%config(noreplace) /etc/linklake/client.toml.example
%dir /var/lib/linklake
%dir /var/log/linklake
%dir /var/lib/linklake-client
%dir /var/log/linklake-client
EOF
  rpmbuild --define "_topdir $top" -bb "$top/SPECS/linklake.spec"
  find "$top/RPMS" -name '*.rpm' -exec cp {} "$out/" \;
  rm -rf -- "$top"
fi

for package in "$out"/linklake_"$version"_"$deb_arch".deb "$out"/linklake-"$rpm_version"-"$rpm_release"*."$rpm_arch".rpm; do
  if [ -f "$package" ]; then
    (cd "$out" && sha256sum "$(basename "$package")" >"$(basename "$package").sha256")
  fi
done

echo "Native packages created in $out"
