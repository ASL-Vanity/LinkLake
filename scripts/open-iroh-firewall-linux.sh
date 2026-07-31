#!/usr/bin/env bash
set -euo pipefail

configuration="${1:-/etc/nftables.conf}"
stamp="$(date -u +%Y%m%d-%H%M%S)"
backup="$configuration.pre-iroh-$stamp"
transaction="$(mktemp)"
trap 'rm -f "$transaction"' EXIT

if [[ "$EUID" -ne 0 ]]; then
  echo "请使用 root 运行此脚本。" >&2
  exit 1
fi

test -f "$configuration"
if grep -Eq 'udp dport \{[^}]*7842' "$configuration"; then
  echo "iroh_udp_firewall=already_present"
else
  cp -a "$configuration" "$backup"
  sed -i \
    's/udp dport { 32104, 32011 }/udp dport { 7842, 32104, 32011 }/' \
    "$configuration"
  grep -Eq 'udp dport \{[^}]*7842' "$configuration"
  echo "iroh_udp_firewall=added"
  echo "firewall_backup=$backup"
fi

# 使用单个原子事务重建本表，避免反复加载配置产生重复规则。
if nft list table inet host_firewall >/dev/null 2>&1; then
  printf 'delete table inet host_firewall\n' >"$transaction"
fi
cat "$configuration" >>"$transaction"
nft -c -f "$transaction"
nft -f "$transaction"
nft list chain inet host_firewall input | grep -E '7842|32104'
