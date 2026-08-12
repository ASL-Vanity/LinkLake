#!/usr/bin/env bash
set -euo pipefail

acceptance_source="${LINKLAKE_ACCEPTANCE_SOURCE_CIDR:-${1:-}}"
environment="${LINKLAKE_SERVER_ENV_PATH:-/etc/linklake/server.env}"
stream_config="${LINKLAKE_NGINX_STREAM_CONFIG:-/etc/nginx/stream-conf.d/linklake-443.conf}"
secure_http_config="${LINKLAKE_NGINX_HTTP_CONFIG:-/etc/nginx/sites-enabled/linklake-canary-http.conf}"
firewall_config="${LINKLAKE_NFTABLES_CONFIG:-/etc/nftables.conf}"
backup_directory="${LINKLAKE_ACCEPTANCE_BACKUP_DIRECTORY:-/root/linklake-nginx-backups}"
https_bind="${LINKLAKE_ACCEPTANCE_HTTPS_BIND:-127.0.0.1:32103}"
sni_bind="${LINKLAKE_ACCEPTANCE_SNI_BIND:-0.0.0.0:32105}"
stream_previous_upstream="${LINKLAKE_ACCEPTANCE_PREVIOUS_HTTPS_UPSTREAM:-127.0.0.1:32443}"
stream_upstream="${LINKLAKE_ACCEPTANCE_HTTPS_UPSTREAM:-127.0.0.1:32103}"
http_previous_upstream="${LINKLAKE_ACCEPTANCE_PREVIOUS_HTTP_UPSTREAM:-127.0.0.1:33102}"
http_upstream="${LINKLAKE_ACCEPTANCE_HTTP_UPSTREAM:-127.0.0.1:32102}"
management_health_url="${LINKLAKE_ACCEPTANCE_HEALTH_URL:-https://127.0.0.1:32100/api/v1/health}"
firewall_anchor="${LINKLAKE_ACCEPTANCE_FIREWALL_ANCHOR:-tcp dport 32010 accept}"
tcp_ports="${LINKLAKE_ACCEPTANCE_TCP_PORTS:-32012,32020-32022,32030-32031,32105}"
udp_ports="${LINKLAKE_ACCEPTANCE_UDP_PORTS:-32013,32020-32022,32030}"
stamp="$(date -u +%Y%m%d-%H%M%S)"
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
if [[ -z "$acceptance_source" ]]; then
  echo "必须通过 LINKLAKE_ACCEPTANCE_SOURCE_CIDR 或第一个参数指定验收来源 IP/CIDR。" >&2
  exit 2
fi

# 只接受规范 IP/CIDR，并由地址族决定 nftables 使用 ip 还是 ip6，避免将任意文本写入防火墙配置。
read -r address_family acceptance_source < <(
  python3 - "$acceptance_source" <<'PY'
import ipaddress
import sys

value = sys.argv[1].strip()
try:
    network = ipaddress.ip_network(value, strict=False)
except ValueError as error:
    raise SystemExit(f"invalid acceptance source IP/CIDR: {error}")
family = "ip" if network.version == 4 else "ip6"
print(family, network.with_prefixlen)
PY
)

python3 - "$https_bind" "$sni_bind" "$stream_previous_upstream" "$stream_upstream" \
  "$http_previous_upstream" "$http_upstream" "$management_health_url" \
  "$firewall_anchor" "$tcp_ports" "$udp_ports" <<'PY'
import ipaddress
import re
import sys
from urllib.parse import urlsplit


def validate_endpoint(value: str) -> None:
    if value.startswith("["):
        closing = value.find("]")
        if closing <= 1 or closing + 1 >= len(value) or value[closing + 1] != ":":
            raise ValueError("invalid bracketed endpoint")
        ipaddress.IPv6Address(value[1:closing])
        port_text = value[closing + 2 :]
    else:
        host, separator, port_text = value.rpartition(":")
        if not separator or not host or ":" in host:
            raise ValueError("invalid endpoint")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
                raise ValueError("invalid endpoint host")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("endpoint port is outside 1-65535")


for endpoint in sys.argv[1:7]:
    validate_endpoint(endpoint)

health = urlsplit(sys.argv[7])
if health.scheme != "https" or not health.hostname or health.username or health.password:
    raise ValueError("health URL must be HTTPS without embedded credentials")
if health.port is not None and not 1 <= health.port <= 65535:
    raise ValueError("health URL port is outside 1-65535")

anchor = sys.argv[8]
if not anchor or any(character in anchor for character in "\r\n"):
    raise ValueError("firewall anchor must be a single non-empty line")
for ports in sys.argv[9:11]:
    if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*", ports):
        raise ValueError("firewall port set is invalid")
    for item in ports.split(","):
        bounds = [int(value) for value in item.split("-")]
        if any(value < 1 or value > 65535 for value in bounds) or bounds != sorted(bounds):
            raise ValueError("firewall port range is outside 1-65535 or descending")
PY

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

set_environment LINKLAKE_HTTPS_BIND "$https_bind"
set_environment LINKLAKE_TLS_PASSTHROUGH_BIND "$sni_bind"
chmod 0600 "$environment"

# 公网 443 的外层 stream 会发送 PROXY protocol，先经中间监听剥离后再进入 LinkLake。
python3 - "$stream_config" "$stream_previous_upstream" "$stream_upstream" \
  "$secure_http_config" "$http_previous_upstream" "$http_upstream" <<'PY'
import sys
from pathlib import Path


def replace_upstream(path_text: str, previous: str, current: str, scheme: str) -> None:
    path = Path(path_text)
    content = path.read_text(encoding="utf-8")
    old = f"proxy_pass {scheme}{previous};"
    new = f"proxy_pass {scheme}{current};"
    if new not in content:
        if old not in content:
            raise SystemExit(f"expected nginx upstream not found in {path}")
        content = content.replace(old, new, 1)
        path.write_text(content, encoding="utf-8")


replace_upstream(sys.argv[1], sys.argv[2], sys.argv[3], "")
replace_upstream(sys.argv[4], sys.argv[5], sys.argv[6], "http://")
PY
grep -Fq "proxy_pass $stream_upstream;" "$stream_config"
grep -Fq "proxy_pass http://$http_upstream;" "$secure_http_config"
nginx -t

python3 - "$firewall_config" "$firewall_anchor" "$address_family" "$acceptance_source" \
  "$tcp_ports" "$udp_ports" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
anchor = sys.argv[2]
family = sys.argv[3]
source = sys.argv[4]
tcp_ports = sys.argv[5].replace(",", ", ")
udp_ports = sys.argv[6].replace(",", ", ")
start = "# BEGIN LinkLake RC acceptance"
end = "# END LinkLake RC acceptance"
lines = path.read_text(encoding="utf-8").splitlines()

cleaned: list[str] = []
inside = False
for line in lines:
    stripped = line.strip()
    if stripped == start:
        inside = True
        continue
    if stripped == end:
        inside = False
        continue
    if inside or "LinkLake RC acceptance TCP" in line or "LinkLake RC acceptance UDP" in line:
        continue
    cleaned.append(line)
if inside:
    raise SystemExit("unterminated LinkLake acceptance firewall block")

matches = [index for index, line in enumerate(cleaned) if anchor in line]
if len(matches) != 1:
    raise SystemExit(f"firewall anchor must match exactly once, found {len(matches)}")
indent = cleaned[matches[0]][: len(cleaned[matches[0]]) - len(cleaned[matches[0]].lstrip())]
block = [
    f"{indent}{start}",
    f'{indent}{family} saddr {source} tcp dport {{ {tcp_ports} }} accept comment "LinkLake RC acceptance TCP"',
    f'{indent}{family} saddr {source} udp dport {{ {udp_ports} }} accept comment "LinkLake RC acceptance UDP"',
    f"{indent}{end}",
]
cleaned[matches[0] + 1 : matches[0] + 1] = block
path.write_text("\n".join(cleaned) + "\n", encoding="utf-8")
PY
grep -q 'LinkLake RC acceptance TCP' "$firewall_config"
grep -q 'LinkLake RC acceptance UDP' "$firewall_config"
printf 'delete table inet host_firewall\n' >"$firewall_transaction"
cat "$firewall_config" >>"$firewall_transaction"
nft -c -f "$firewall_transaction"

systemctl restart linklake-server.service
healthy=0
for _ in $(seq 1 45); do
  if curl -ksSf --max-time 3 "$management_health_url" >/tmp/linklake-health.json \
    && ss -lnt | grep -Fq "$https_bind" \
    && ss -lnt | grep -Fq "$sni_bind"; then
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
printf 'https_listener=%s\nsni_listener=%s\nacceptance_source=%s\n' \
  "$https_bind" "$sni_bind" "$acceptance_source"
nft list chain inet host_firewall input | grep 'LinkLake RC acceptance'
