#!/usr/bin/env sh
set -eu

mode="${1:-}"
package_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer as root." >&2
  exit 1
fi

install -d -m 0755 /usr/local/bin /usr/local/etc/linklake /usr/local/var/lib /usr/local/var/log
case "$mode" in
  server)
    install -m 0755 "$package_root/bin/linklake-server" /usr/local/bin/linklake-server
    install -d -m 0750 /usr/local/var/lib/linklake /usr/local/var/log/linklake
    if [ ! -e /usr/local/etc/linklake/server.env ]; then
      sed 's#/var/lib/linklake#/usr/local/var/lib/linklake#g; s#/var/log/linklake#/usr/local/var/log/linklake#g' \
        "$package_root/launchd/server.env.example" >/usr/local/etc/linklake/server.env
      chmod 0600 /usr/local/etc/linklake/server.env
    fi
    install -m 0644 "$package_root/launchd/com.linklake.server.plist" /Library/LaunchDaemons/com.linklake.server.plist
    echo "Edit /usr/local/etc/linklake/server.env, then run: launchctl bootstrap system /Library/LaunchDaemons/com.linklake.server.plist"
    ;;
  client)
    install -m 0755 "$package_root/bin/linklake-client" /usr/local/bin/linklake-client
    install -d -m 0750 /usr/local/var/lib/linklake-client /usr/local/var/log/linklake-client
    if [ ! -e /usr/local/etc/linklake/client.toml ]; then
      install -m 0600 "$package_root/examples/linklake-client.toml" /usr/local/etc/linklake/client.toml
    fi
    install -m 0644 "$package_root/launchd/com.linklake.client.plist" /Library/LaunchDaemons/com.linklake.client.plist
    echo "Edit /usr/local/etc/linklake/client.toml, then run: launchctl bootstrap system /Library/LaunchDaemons/com.linklake.client.plist"
    ;;
  *)
    echo "Usage: $0 server|client" >&2
    exit 2
    ;;
esac
