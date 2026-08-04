#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行此脚本。" >&2
  exit 1
fi

if command -v cargo >/dev/null 2>&1; then
  cargo_bin="$(command -v cargo)"
elif [[ -x /root/.cargo/bin/cargo ]]; then
  cargo_bin=/root/.cargo/bin/cargo
else
  echo "未找到 Cargo。请先安装 Rust 1.91 或更新版本。" >&2
  exit 1
fi

cargo_target_directory="${CARGO_TARGET_DIR:-/var/cache/linklake/cargo-target/iroh-relay-1.0.3}"
if [[ -x /usr/local/bin/iroh-relay ]] \
  && [[ "$(/usr/local/bin/iroh-relay --version)" == "iroh-relay 1.0.3" ]]; then
  echo "iroh-relay 1.0.3 已安装，跳过重复编译。"
else
  install -d -m 0755 "$cargo_target_directory"
  CARGO_TARGET_DIR="$cargo_target_directory" \
    "$cargo_bin" install iroh-relay --version 1.0.3 --features server --locked --root /usr/local
fi

install -d -m 0750 -o root -g linklake /etc/linklake
install -d -m 0750 -o root -g linklake /etc/linklake/iroh-relay
if [[ ! -e /etc/linklake/iroh-relay/config.toml ]]; then
  install -m 0640 -o root -g linklake packaging/iroh-relay/config.toml.example /etc/linklake/iroh-relay/config.toml
fi
install -m 0644 packaging/iroh-relay/linklake-iroh-relay.service /etc/systemd/system/linklake-iroh-relay.service

systemctl daemon-reload
echo "请放置 TLS fullchain.pem/privkey.pem、合并 nginx-location.conf.example，并确认公网 443/tcp 与 7842/udp 已放行。"
echo "完成后运行：systemctl enable --now linklake-iroh-relay"
