#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ -z "$1" ]; then
  echo "用法: $0 <version> [build-root]" >&2
  exit 64
fi
version="$1"
case "$version" in
  *[!0-9A-Za-z.+-]*|'')
    echo "无效的版本号: $version" >&2
    exit 64
    ;;
esac
build_root="${2:-/root/linklake-build-$version}"
binary="$build_root/target/release/linklake-server"
installed=/usr/local/bin/linklake-server
environment=/etc/linklake/server.env
stamp="$(date -u +%Y%m%d-%H%M%S)"
old_binary="$installed.pre-$version-$stamp"
old_environment="$environment.pre-$version-$stamp"
rollback_required=0

test -x "$binary"
test -f "$environment"
cp -a "$installed" "$old_binary"
cp -a "$environment" "$old_environment"

rollback() {
  status=$?
  if [ "$rollback_required" -eq 1 ]; then
    systemctl stop linklake-server.service >/dev/null 2>&1 || true
    install -m 0755 "$old_binary" "$installed"
    cp -a "$old_environment" "$environment"
    systemctl start linklake-server.service >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap rollback ERR

if ! grep -q '^LINKLAKE_MANAGEMENT_TOKEN=' "$environment"; then
  token="$(head -c 48 /dev/urandom | base64 | tr -d '\n=/+')"
  printf '\nLINKLAKE_MANAGEMENT_TOKEN=%s\n' "$token" >>"$environment"
  chmod 0600 "$environment"
fi

rollback_required=1
systemctl stop linklake-server.service
install -m 0755 "$binary" "$installed"
systemctl start linklake-server.service

healthy=0
for _ in $(seq 1 45); do
  if curl -ksSf --max-time 3 https://127.0.0.1:32100/api/v1/health >/tmp/linklake-health.json; then
    healthy=1
    break
  fi
  sleep 1
done
test "$healthy" -eq 1
rollback_required=0
trap - ERR

cat /tmp/linklake-health.json
python3 -c "import sqlite3; c=sqlite3.connect('/var/lib/linklake/linklake.sqlite3'); print('schema_version='+str(c.execute('pragma user_version').fetchone()[0]))"
find /var/lib/linklake -maxdepth 1 -type f -name 'linklake.sqlite3.pre-migration-*' -printf 'migration_backup=%f\n' | tail -n 5
printf 'old_binary=%s\nold_environment=%s\n' "$old_binary" "$old_environment"
