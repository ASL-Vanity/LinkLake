#!/usr/bin/env sh
set -eu

mode="${1:-}"
package_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer as root." >&2
  exit 1
fi

install -d -m 0755 /etc/linklake
if ! getent group linklake >/dev/null 2>&1; then
  groupadd --system linklake
fi
if ! id linklake >/dev/null 2>&1; then
  useradd --system --gid linklake --home-dir /var/lib/linklake --shell /usr/sbin/nologin linklake
fi

case "$mode" in
  server)
    install -m 0755 "$package_root/bin/linklake-server" /usr/local/bin/linklake-server
    install -m 0644 "$package_root/systemd/linklake-server.service" /etc/systemd/system/linklake-server.service
    install -d -o linklake -g linklake -m 0750 /var/lib/linklake /var/log/linklake
    if [ ! -e /etc/linklake/server.env ]; then
      install -m 0600 "$package_root/systemd/server.env.example" /etc/linklake/server.env
      echo "Edit /etc/linklake/server.env before starting the service."
    fi
    systemctl daemon-reload
    systemctl enable linklake-server.service
    ;;
  client)
    install -m 0755 "$package_root/bin/linklake-client" /usr/local/bin/linklake-client
    install -m 0644 "$package_root/systemd/linklake-client.service" /etc/systemd/system/linklake-client.service
    install -d -o linklake -g linklake -m 0750 /var/lib/linklake-client /var/log/linklake-client
    if [ ! -e /etc/linklake/client.toml ]; then
      install -m 0600 "$package_root/examples/linklake-client.toml" /etc/linklake/client.toml
      chown linklake:linklake /etc/linklake/client.toml
      echo "Edit /etc/linklake/client.toml before starting the service."
    fi
    systemctl daemon-reload
    systemctl enable linklake-client.service
    ;;
  *)
    echo "Usage: $0 server|client" >&2
    exit 2
    ;;
esac
