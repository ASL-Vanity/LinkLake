#!/usr/bin/env bash
set -euo pipefail

environment_file="${1:-/etc/linklake/server.env}"
set -a
# shellcheck source=/dev/null
. "$environment_file"
set +a

base="https://127.0.0.1:32100/api/v1"
authorization="Authorization: Bearer ${LINKLAKE_MANAGEMENT_TOKEN:?missing management token}"
for path in status metrics clients tcp-tunnels udp-tunnels port-groups http-routes sni-routes secret-tunnels socks5-proxies http-proxies p2p/nodes; do
  printf '===%s===\n' "$path"
  curl -ksSf --header "$authorization" "$base/$path"
  printf '\n'
done
