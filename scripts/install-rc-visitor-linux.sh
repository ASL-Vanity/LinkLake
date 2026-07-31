#!/usr/bin/env bash
set -euo pipefail

staging_directory="${1:-/tmp/linklake-visitor-staging}"
binary="$staging_directory/linklake-client"
certificate="$staging_directory/control-ca.pem"
secrets="$staging_directory/secrets.json"
unit="$staging_directory/linklake-client.service"
state_root=/root/linklake-acceptance
backup_root="$state_root/backups"
stamp="$(date -u +%Y%m%d-%H%M%S)"

if [[ "$EUID" -ne 0 ]]; then
  echo "请使用 root 运行此脚本。" >&2
  exit 1
fi

for path in "$binary" "$certificate" "$secrets" "$unit"; do
  test -f "$path"
done

if ! getent group linklake >/dev/null 2>&1; then
  groupadd --system linklake
fi
if ! id linklake >/dev/null 2>&1; then
  useradd --system --gid linklake --home-dir /var/lib/linklake-client --shell /usr/sbin/nologin linklake
fi

install -d -m 0700 "$state_root" "$backup_root"
install -d -m 0755 -o root -g root /etc/linklake
install -d -m 0750 -o linklake -g linklake /var/lib/linklake-client /var/log/linklake-client
systemctl stop linklake-client.service >/dev/null 2>&1 || true

for path in /usr/local/bin/linklake-client /etc/linklake/client.toml /etc/linklake/control-ca.pem; do
  if [[ -e "$path" ]]; then
    cp -a "$path" "$backup_root/$(basename "$path").pre-rc-$stamp"
  fi
done

install -m 0755 "$binary" /usr/local/bin/linklake-client
install -m 0640 -o root -g linklake "$certificate" /etc/linklake/control-ca.pem
install -m 0600 "$secrets" "$state_root/secrets.json"
python3 - "$state_root/secrets.json" /etc/linklake/client.toml <<'PY'
import json
import os
import sys
from pathlib import Path

secrets = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
visitor = secrets["visitor"]
content = f'''config_version = 1

[client]
control = "control.linklake.odelake.com:32101"
control_ca_cert = "/etc/linklake/control-ca.pem"
control_server_name = "control.linklake.odelake.com"
client_id = "{visitor['client_id']}"
client_token = "{visitor['client_token']}"
config_mode = "local"

[[secret_visitors]]
name = "rc-acceptance-secret"
local_bind = "127.0.0.1:32150"
access_key = "{secrets['secret_access_key']}"
prefer_direct = true
'''
path = Path(sys.argv[2])
path.write_text(content, encoding="utf-8")
os.chmod(path, 0o600)
PY
chown linklake:linklake /etc/linklake/client.toml
install -m 0644 "$unit" /etc/systemd/system/linklake-client.service
systemctl daemon-reload
systemctl enable --now linklake-client.service

healthy=0
for _ in $(seq 1 45); do
  if systemctl is-active --quiet linklake-client.service \
    && ss -lnt | grep -Eq '127\.0\.0\.1:32150[[:space:]]'; then
    healthy=1
    break
  fi
  sleep 1
done
test "$healthy" -eq 1

sha256sum /usr/local/bin/linklake-client
systemctl --no-pager --full status linklake-client.service | sed -n '1,14p'
ss -lnt | grep '127.0.0.1:32150'
