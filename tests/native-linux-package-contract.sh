#!/usr/bin/env sh
set -eu

# 在容器内运行：
#   Debian：安装 systemd 后执行 `sh tests/native-linux-package-contract.sh deb`
#   Fedora：安装 rpm-build systemd 后执行 `sh tests/native-linux-package-contract.sh rpm`
# 测试使用临时 fixture 和 stub 二进制，不会修改工作树，也不会启动 systemd 服务。

mode="${1:-}"
case "$mode" in
  deb|rpm) ;;
  *) echo "Usage: $0 deb|rpm" >&2; exit 2 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo 'Run this native package contract test as root inside a disposable container.' >&2
  exit 1
fi

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
test_root="$(mktemp -d)"
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

case "$mode" in
  deb)
    require_command dpkg-deb
    require_command dpkg
    ;;
  rpm)
    require_command rpmbuild
    require_command rpm
    ;;
esac
require_command systemd-analyze
require_command stat

create_fixture() {
  fixture="$1"
  version="$2"
  template_marker="$3"
  mkdir -p "$fixture/scripts" "$fixture/packaging/systemd" "$fixture/examples" "$fixture/bin"
  cp "$root/scripts/package-native-linux.sh" "$fixture/scripts/package-native-linux.sh"
  cp "$root/scripts/verify-native-linux-packages.sh" "$fixture/scripts/verify-native-linux-packages.sh"
  cp "$root/packaging/systemd/linklake-server.service" "$fixture/packaging/systemd/"
  cp "$root/packaging/systemd/linklake-update-resume.service" "$fixture/packaging/systemd/"
  cp "$root/packaging/systemd/linklake-client.service" "$fixture/packaging/systemd/"
  cp "$root/packaging/systemd/server.env.example" "$fixture/packaging/systemd/server.env.example"
  cp "$root/examples/linklake-client.toml" "$fixture/examples/linklake-client.toml"
  printf '\n# native-package-contract-template=%s\n' "$template_marker" >>"$fixture/packaging/systemd/server.env.example"
  printf '\n# native-package-contract-template=%s\n' "$template_marker" >>"$fixture/examples/linklake-client.toml"
  cat >"$fixture/Cargo.toml" <<EOF
[workspace.package]
version = "$version"
EOF
  for binary in linklake-server linklake-client; do
    cat >"$fixture/bin/$binary" <<'EOF'
#!/usr/bin/env sh
exit 0
EOF
    chmod 0755 "$fixture/bin/$binary"
  done
}

build_fixture_package() {
  fixture="$1"
  out="$2"
  mkdir -p "$out"
  LINKLAKE_BINARY_DIR="$fixture/bin" sh "$fixture/scripts/package-native-linux.sh" "$out"
  sh "$fixture/scripts/verify-native-linux-packages.sh" "$out"
}

assert_owner_mode() {
  path="$1"
  expected="$2"
  actual="$(stat -c '%u:%g:%a' "$path")"
  test "$actual" = "$expected" || {
    echo "Unexpected ownership or mode for $path: $actual (expected $expected)" >&2
    exit 1
  }
}

assert_unit_contract() {
  test -f /lib/systemd/system/linklake-server.service
  test -f /lib/systemd/system/linklake-update-resume.service
  test -f /lib/systemd/system/linklake-client.service
  grep -Fx 'Requires=linklake-update-resume.service' /lib/systemd/system/linklake-server.service >/dev/null
  grep -Fx 'After=network-online.target linklake-update-resume.service' /lib/systemd/system/linklake-server.service >/dev/null
  grep -Fx 'EnvironmentFile=/etc/linklake/server.env' /lib/systemd/system/linklake-server.service >/dev/null
  grep -Fx 'Before=linklake-server.service' /lib/systemd/system/linklake-update-resume.service >/dev/null
  grep -Fx 'ConditionPathExists=/var/lib/linklake-updater/server/active.json' /lib/systemd/system/linklake-update-resume.service >/dev/null
  grep -F 'ExecStart=/usr/local/bin/linklake-server update recover --yes' /lib/systemd/system/linklake-update-resume.service >/dev/null
  grep -F 'ExecStart=/usr/local/bin/linklake-client run --config /etc/linklake/client.toml' /lib/systemd/system/linklake-client.service >/dev/null
  systemd-analyze verify \
    /lib/systemd/system/linklake-server.service \
    /lib/systemd/system/linklake-update-resume.service \
    /lib/systemd/system/linklake-client.service
}

assert_new_installation_ready() {
  getent passwd linklake >/dev/null
  test -f /etc/linklake/server.env
  test -f /etc/linklake/client.toml
  cmp /etc/linklake/server.env.example /etc/linklake/server.env
  cmp /etc/linklake/client.toml.example /etc/linklake/client.toml
  assert_owner_mode /etc/linklake/server.env '0:0:600'
  assert_owner_mode /etc/linklake/client.toml "$(id -u linklake):$(id -g linklake):600"
  assert_owner_mode /var/lib/linklake-updater '0:0:700'
  assert_owner_mode /var/lib/linklake-updater/server '0:0:700'
  assert_unit_contract
}

assert_operator_configuration_is_preserved() {
  server_before="$test_root/operator-server.env"
  client_before="$test_root/operator-client.toml"
  cat >/etc/linklake/server.env <<'EOF'
LINKLAKE_DATA_DIR=/srv/linklake-operator
LINKLAKE_OPERATOR_MARKER=keep-this-server-configuration
EOF
  cat >/etc/linklake/client.toml <<'EOF'
# keep-this-client-configuration
server = "operator.example.invalid:32100"
EOF
  chmod 0600 /etc/linklake/server.env /etc/linklake/client.toml
  cp /etc/linklake/server.env "$server_before"
  cp /etc/linklake/client.toml "$client_before"
  upgrade_package "$package_v2"
  cmp "$server_before" /etc/linklake/server.env
  cmp "$client_before" /etc/linklake/client.toml

  retained_server="$test_root/retained-server.env"
  retained_client="$test_root/retained-client.toml"
  printf 'LINKLAKE_OPERATOR_SYMLINK=server\n' >"$retained_server"
  printf '# LINKLAKE_OPERATOR_SYMLINK=client\n' >"$retained_client"
  rm -f /etc/linklake/server.env /etc/linklake/client.toml
  ln -s "$retained_server" /etc/linklake/server.env
  ln -s "$retained_client" /etc/linklake/client.toml
  upgrade_package "$package_v2"
  test -L /etc/linklake/server.env
  test -L /etc/linklake/client.toml
  cmp "$retained_server" /etc/linklake/server.env
  cmp "$retained_client" /etc/linklake/client.toml
}

fixture_v1="$test_root/fixture-v1"
fixture_v2="$test_root/fixture-v2"
out_v1="$test_root/out-v1"
out_v2="$test_root/out-v2"
create_fixture "$fixture_v1" '1.0.0' 'v1'
create_fixture "$fixture_v2" '1.0.1' 'v2'
build_fixture_package "$fixture_v1" "$out_v1"
build_fixture_package "$fixture_v2" "$out_v2"

case "$mode" in
  deb)
    package_v1="$(find "$out_v1" -maxdepth 1 -name 'linklake_1.0.0_*.deb' -print -quit)"
    package_v2="$(find "$out_v2" -maxdepth 1 -name 'linklake_1.0.1_*.deb' -print -quit)"
    test -n "$package_v1" && test -n "$package_v2"
    entries="$(dpkg-deb -c "$package_v1" | sed 's#^.* \./#/#')"
    for entry in \
      /usr/local/bin/linklake-server \
      /usr/local/bin/linklake-client \
      /lib/systemd/system/linklake-server.service \
      /lib/systemd/system/linklake-update-resume.service \
      /lib/systemd/system/linklake-client.service \
      /etc/linklake/server.env.example \
      /etc/linklake/client.toml.example; do
      printf '%s\n' "$entries" | grep -Fx "$entry" >/dev/null
    done
    ! printf '%s\n' "$entries" | grep -Fx '/etc/linklake/server.env' >/dev/null
    ! printf '%s\n' "$entries" | grep -Fx '/etc/linklake/client.toml' >/dev/null
    install_package() { dpkg -i "$1" >/dev/null; }
    upgrade_package() { dpkg --force-confold -i "$1" >/dev/null; }
    ;;
  rpm)
    package_v1="$(find "$out_v1" -maxdepth 1 -name 'linklake-1.0.0-1*.rpm' -print -quit)"
    package_v2="$(find "$out_v2" -maxdepth 1 -name 'linklake-1.0.1-1*.rpm' -print -quit)"
    test -n "$package_v1" && test -n "$package_v2"
    entries="$(rpm -qpl "$package_v1")"
    for entry in \
      /usr/local/bin/linklake-server \
      /usr/local/bin/linklake-client \
      /lib/systemd/system/linklake-server.service \
      /lib/systemd/system/linklake-update-resume.service \
      /lib/systemd/system/linklake-client.service \
      /etc/linklake/server.env.example \
      /etc/linklake/client.toml.example; do
      printf '%s\n' "$entries" | grep -Fx "$entry" >/dev/null
    done
    ! printf '%s\n' "$entries" | grep -Fx '/etc/linklake/server.env' >/dev/null
    ! printf '%s\n' "$entries" | grep -Fx '/etc/linklake/client.toml' >/dev/null
    install_package() { rpm -ivh --nosignature "$1" >/dev/null; }
    upgrade_package() { rpm -Uvh --replacepkgs --nosignature "$1" >/dev/null; }
    ;;
esac

install_package "$package_v1"
assert_new_installation_ready
assert_operator_configuration_is_preserved

echo "Native Linux $mode package install and upgrade contract passed."
