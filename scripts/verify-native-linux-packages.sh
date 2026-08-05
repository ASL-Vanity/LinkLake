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

verify_checksum() {
  package="$1"
  test -f "$package.sha256"
  (cd "$out" && sha256sum -c "$(basename "$package.sha256")")
}

verified=0

if command -v dpkg-deb >/dev/null 2>&1; then
  deb="$(find "$out" -maxdepth 1 -name "linklake_${version}_*.deb" -print -quit)"
  test -n "$deb"
  verify_checksum "$deb"
  test "$(dpkg-deb -f "$deb" Package)" = linklake
  test "$(dpkg-deb -f "$deb" Version)" = "$version"
  deb_entries="$(dpkg-deb -c "$deb" | sed 's#^.* \./#/#')"
  for entry in \
    /usr/local/bin/linklake-server \
    /usr/local/bin/linklake-client \
    /lib/systemd/system/linklake-server.service \
    /lib/systemd/system/linklake-update-resume.service \
    /lib/systemd/system/linklake-client.service \
    /etc/linklake/server.env.example \
    /etc/linklake/client.toml.example; do
    printf '%s\n' "$deb_entries" | grep -Fx "$entry" >/dev/null || {
      echo "Missing DEB entry: $entry" >&2
      exit 1
    }
  done
  if printf '%s\n' "$deb_entries" | grep -Fx '/etc/linklake/server.env' >/dev/null || \
    printf '%s\n' "$deb_entries" | grep -Fx '/etc/linklake/client.toml' >/dev/null; then
    echo 'DEB must create mutable runtime configuration in postinst rather than package it as a replaceable payload.' >&2
    exit 1
  fi
  control_root="$(mktemp -d)"
  dpkg-deb -e "$deb" "$control_root"
  grep -Fx '/etc/linklake/server.env.example' "$control_root/conffiles" >/dev/null
  grep -Fx '/etc/linklake/client.toml.example' "$control_root/conffiles" >/dev/null
  grep -F 'if [ ! -e /etc/linklake/server.env ] && [ ! -L /etc/linklake/server.env ]; then' "$control_root/postinst" >/dev/null
  grep -F 'install -o root -g root -m 0600 /etc/linklake/server.env.example /etc/linklake/server.env' "$control_root/postinst" >/dev/null
  grep -F 'if [ ! -e /etc/linklake/client.toml ] && [ ! -L /etc/linklake/client.toml ]; then' "$control_root/postinst" >/dev/null
  grep -F 'install -o linklake -g linklake -m 0600 /etc/linklake/client.toml.example /etc/linklake/client.toml' "$control_root/postinst" >/dev/null
  rm -rf -- "$control_root"
  verified=$((verified + 1))
fi

if command -v rpm >/dev/null 2>&1; then
  rpm_package="$(find "$out" -maxdepth 1 -name "linklake-${rpm_version}-${rpm_release}*.rpm" -print -quit)"
  test -n "$rpm_package"
  verify_checksum "$rpm_package"
  test "$(rpm -qp --qf '%{NAME}' "$rpm_package")" = linklake
  test "$(rpm -qp --qf '%{VERSION}' "$rpm_package")" = "$rpm_version"
  case "$(rpm -qp --qf '%{RELEASE}' "$rpm_package")" in
    "$rpm_release"|"$rpm_release".*) ;;
    *) echo "Unexpected RPM release" >&2; exit 1;;
  esac
  rpm_entries="$(rpm -qpl "$rpm_package")"
  for entry in \
    /usr/local/bin/linklake-server \
    /usr/local/bin/linklake-client \
    /lib/systemd/system/linklake-server.service \
    /lib/systemd/system/linklake-update-resume.service \
    /lib/systemd/system/linklake-client.service \
    /etc/linklake/server.env.example \
    /etc/linklake/client.toml.example; do
    printf '%s\n' "$rpm_entries" | grep -Fx "$entry" >/dev/null || {
      echo "Missing RPM entry: $entry" >&2
      exit 1
    }
  done
  if printf '%s\n' "$rpm_entries" | grep -Fx '/etc/linklake/server.env' >/dev/null || \
    printf '%s\n' "$rpm_entries" | grep -Fx '/etc/linklake/client.toml' >/dev/null; then
    echo 'RPM must create mutable runtime configuration in %post rather than package it as a replaceable payload.' >&2
    exit 1
  fi
  rpm -qpc "$rpm_package" | grep -Fx '/etc/linklake/server.env.example' >/dev/null
  rpm -qpc "$rpm_package" | grep -Fx '/etc/linklake/client.toml.example' >/dev/null
  rpm -qp --scripts "$rpm_package" | grep -F 'if [ ! -e /etc/linklake/server.env ] && [ ! -L /etc/linklake/server.env ]; then' >/dev/null
  rpm -qp --scripts "$rpm_package" | grep -F 'install -o root -g root -m 0600 /etc/linklake/server.env.example /etc/linklake/server.env' >/dev/null
  rpm -qp --scripts "$rpm_package" | grep -F 'if [ ! -e /etc/linklake/client.toml ] && [ ! -L /etc/linklake/client.toml ]; then' >/dev/null
  rpm -qp --scripts "$rpm_package" | grep -F 'install -o linklake -g linklake -m 0600 /etc/linklake/client.toml.example /etc/linklake/client.toml' >/dev/null
  verified=$((verified + 1))
fi

test "$verified" -gt 0
echo "Verified native Linux packages for LinkLake $version"
