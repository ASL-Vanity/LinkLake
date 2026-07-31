#!/usr/bin/env bash
set -euo pipefail

environment="${1:-/etc/linklake/server.env}"
test -f "$environment"
token="$(head -c 48 /dev/urandom | base64 | tr -d '\n=/+')"
temporary="${environment}.rotate.$$"
awk '!/^LINKLAKE_MANAGEMENT_TOKEN=/' "$environment" >"$temporary"
printf 'LINKLAKE_MANAGEMENT_TOKEN=%s\n' "$token" >>"$temporary"
chown --reference="$environment" "$temporary"
chmod --reference="$environment" "$temporary"
mv "$temporary" "$environment"
systemctl restart linklake-server.service
for _ in $(seq 1 30); do
  if curl -ksSf --max-time 3 https://127.0.0.1:32100/api/v1/health >/dev/null; then
    echo 'management_token_rotated=true'
    exit 0
  fi
  sleep 1
done
echo 'LinkLake server did not recover after management-token rotation.' >&2
exit 1
