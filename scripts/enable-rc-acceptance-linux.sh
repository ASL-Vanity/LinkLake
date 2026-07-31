#!/usr/bin/env bash
set -euo pipefail

environment=/etc/linklake/server.env
stream_config=/etc/nginx/stream-conf.d/linklake-443.conf
secure_http_config=/etc/nginx/sites-enabled/linklake-canary-http.conf
firewall_config=/etc/nftables.conf
stamp="$(date -u +%Y%m%d-%H%M%S)"
backup_directory=/root/linklake-nginx-backups
environment_backup="$environment.pre-acceptance-$stamp"
stream_backup="$backup_directory/linklake-443.conf.pre-acceptance-$stamp"
http_backup="$backup_directory/linklake-canary-http.conf.pre-acceptance-$stamp"
firewall_backup="$firewall_config.pre-acceptance-$stamp"
firewall_transaction="$(mktemp)"
rollback_required=0

if [[ "$EUID" -ne 0 ]]; then
  echo "请使用 root 运行此脚本。" >&2
  exit 1
fi

for path in "$environment" "$stream_config" "$secure_http_config" "$firewall_config"; do
  test -f "$path"
done
install -d -m 0700 "$backup_directory"

set_environment() {
  key="$1"
  value="$2"
  if grep -q "^${key}=" "$environment"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$environment"
  else
    printf '%s=%s\n' "$key" "$value" >>"$environment"
  fi
}

rollback() {
  status=$?
  if [[ "$rollback_required" -eq 1 ]]; then
    cp -a "$environment_backup" "$environment"
    cp -a "$stream_backup" "$stream_config"
    cp -a "$http_backup" "$secure_http_config"
    cp -a "$firewall_backup" "$firewall_config"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
    systemctl restart linklake-server.service >/dev/null 2>&1 || true
  fi
  rm -f "$firewall_transaction"
  exit "$status"
}
trap rollback ERR

cp -a "$environment" "$environment_backup"
cp -a "$stream_config" "$stream_backup"
cp -a "$secure_http_config" "$http_backup"
cp -a "$firewall_config" "$firewall_backup"
rollback_required=1

set_environment LINKLAKE_HTTPS_BIND 127.0.0.1:32103
set_environment LINKLAKE_TLS_PASSTHROUGH_BIND 0.0.0.0:32105
chmod 0600 "$environment"

# 公网 443 的外层 stream 会发送 PROXY protocol，先经中间监听剥离后再进入 LinkLake。
sed -i 's|proxy_pass 127.0.0.1:32443;|proxy_pass 127.0.0.1:32103;|' "$stream_config"
grep -q 'proxy_pass 127.0.0.1:32103;' "$stream_config"
sed -i 's|proxy_pass http://127.0.0.1:33102;|proxy_pass http://127.0.0.1:32102;|' "$secure_http_config"
grep -q 'proxy_pass http://127.0.0.1:32102;' "$secure_http_config"
nginx -t

if ! grep -q 'LinkLake RC acceptance TCP' "$firewall_config"; then
  sed -i '/tcp dport 32010 accept/a\
\t\tip saddr 124.221.25.210 tcp dport { 32012, 32020-32022, 32030-32031, 32105 } accept comment "LinkLake RC acceptance TCP"\
\t\tip saddr 124.221.25.210 udp dport { 32013, 32020-32022, 32030 } accept comment "LinkLake RC acceptance UDP"' "$firewall_config"
fi
grep -q 'LinkLake RC acceptance TCP' "$firewall_config"
grep -q 'LinkLake RC acceptance UDP' "$firewall_config"
printf 'delete table inet host_firewall\n' >"$firewall_transaction"
cat "$firewall_config" >>"$firewall_transaction"
nft -c -f "$firewall_transaction"

systemctl restart linklake-server.service
healthy=0
for _ in $(seq 1 45); do
  if curl -ksSf --max-time 3 https://127.0.0.1:32100/api/v1/health >/tmp/linklake-health.json \
    && ss -lnt | grep -Eq '127\.0\.0\.1:32103[[:space:]]' \
    && ss -lnt | grep -Eq '0\.0\.0\.0:32105[[:space:]]'; then
    healthy=1
    break
  fi
  sleep 1
done
test "$healthy" -eq 1

systemctl reload nginx
nft -f "$firewall_transaction"
rollback_required=0
trap - ERR
rm -f "$firewall_transaction"

cat /tmp/linklake-health.json
printf 'https_listener=127.0.0.1:32103\nsni_listener=0.0.0.0:32105\n'
nft list chain inet host_firewall input | grep 'LinkLake RC acceptance'
