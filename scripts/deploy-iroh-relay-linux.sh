#!/usr/bin/env bash
set -euo pipefail

relay_hostname="${1:?usage: deploy-iroh-relay-linux.sh HOSTNAME CERTIFICATE_DIRECTORY [PACKAGE_ROOT] [NGINX_LISTEN]}"
certificate_directory="${2:?certificate directory is required}"
package_root="${3:-/root/linklake-iroh-relay}"
nginx_listen="${4:-127.0.0.1:34443 ssl proxy_protocol}"
relay_root="$package_root/packaging/iroh-relay"
nginx_available=/etc/nginx/sites-available/linklake-iroh-relay.conf
nginx_enabled=/etc/nginx/sites-enabled/linklake-iroh-relay.conf
stamp="$(date -u +%Y%m%d-%H%M%S)"
backup="$nginx_available.pre-$stamp"
rollback_required=0

if [[ "$EUID" -ne 0 ]]; then
  echo "请使用 root 运行此脚本。" >&2
  exit 1
fi

test -f "$certificate_directory/fullchain.pem"
test -f "$certificate_directory/privkey.pem"
test -f "$relay_root/config.toml.example"
test -f "$relay_root/linklake-iroh-relay.service"
test -f "$relay_root/nginx-server.conf.example"

rollback() {
  status=$?
  if [[ "$rollback_required" -eq 1 ]]; then
    rm -f "$nginx_enabled"
    if [[ -f "$backup" ]]; then
      mv -f "$backup" "$nginx_available"
      ln -sfn "$nginx_available" "$nginx_enabled"
    fi
    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap rollback ERR

(cd "$package_root" && bash packaging/iroh-relay/install.sh)
install -m 0640 -o root -g linklake "$certificate_directory/fullchain.pem" /etc/linklake/iroh-relay/fullchain.pem
install -m 0640 -o root -g linklake "$certificate_directory/privkey.pem" /etc/linklake/iroh-relay/privkey.pem

if [[ -f "$nginx_available" ]]; then
  cp -a "$nginx_available" "$backup"
fi
rollback_required=1
sed \
  -e "s|__RELAY_HOSTNAME__|$relay_hostname|g" \
  -e "s|__NGINX_LISTEN__|$nginx_listen|g" \
  "$relay_root/nginx-server.conf.example" >"$nginx_available"
ln -sfn "$nginx_available" "$nginx_enabled"
nginx -t
systemctl reload nginx
systemctl enable --now linklake-iroh-relay.service
healthy=0
for _ in $(seq 1 20); do
  if systemctl is-active --quiet linklake-iroh-relay.service \
    && ss -lntup | grep -Eq ':(3340|3341)[[:space:]]' \
    && ss -lnup | grep -Eq ':7842[[:space:]]'; then
    healthy=1
    break
  fi
  sleep 1
done
test "$healthy" -eq 1

rollback_required=0
trap - ERR
printf 'iroh_relay_hostname=%s\n' "$relay_hostname"
systemctl --no-pager --full status linklake-iroh-relay.service | sed -n '1,12p'
ss -lntup | grep -E ':(3340|3341|7842)[[:space:]]'
