#!/bin/sh
set -eu

# 原生 Linux 包的升级状态只保存在固定的 root 专用目录中，避免把服务状态或备份暴露给低权限用户。
state_root=/var/lib/linklake/package-backup
pending_root="$state_root/pending"
state_file="$pending_root/service-state"
binary_root=/usr/local/bin
unit_root=/lib/systemd/system
managed_units='linklake-server.service linklake-client.service'
managed_binaries='linklake-server linklake-client'
managed_unit_files='linklake-server.service linklake-update-resume.service linklake-client.service'

fail() {
  echo "LinkLake package lifecycle: $*" >&2
  exit 1
}

ensure_directory() {
  directory="$1"
  if [ -L "$directory" ]; then
    fail "refusing symbolic-link lifecycle directory $directory"
  fi
  install -d -o root -g root -m 0700 "$directory"
}

systemctl_available() {
  command -v systemctl >/dev/null 2>&1
}

unit_enabled() {
  systemctl_available && systemctl is-enabled --quiet "$1" >/dev/null 2>&1
}

unit_active() {
  systemctl_available && systemctl is-active --quiet "$1" >/dev/null 2>&1
}

daemon_reload() {
  if systemctl_available; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
}

clear_pending() {
  for name in $managed_binaries; do
    rm -f -- "$pending_root/bin/$name"
  done
  for name in $managed_unit_files; do
    rm -f -- "$pending_root/units/$name"
  done
  rm -f -- "$state_file" "$pending_root/prepared"
  rm -f -- "$pending_root/rolled-back"
  rm -f -- "$pending_root/candidate-started"
  rmdir "$pending_root/bin" "$pending_root/units" "$pending_root" 2>/dev/null || true
}

restore_recorded_services() {
  [ -f "$state_file" ] || return 0
  while IFS='|' read -r unit enabled active; do
    case "$unit" in
      linklake-server.service|linklake-client.service) ;;
      *) fail "invalid recorded unit $unit" ;;
    esac
    if [ "$enabled" = 1 ] && systemctl_available; then
      systemctl enable "$unit" >/dev/null 2>&1 || return 1
    fi
    if [ "$active" = 1 ] && systemctl_available; then
      systemctl restart "$unit" >/dev/null 2>&1 || return 1
    fi
  done <"$state_file"
}

rollback_upgrade() {
  [ -f "$pending_root/prepared" ] || return 0
  # 候选进程可能已提交 SQLite 或共享 PG 迁移及新业务写入，不能自动降级旧二进制。
  if [ -e "$pending_root/candidate-started" ]; then
    fail "candidate service activation has started; preserving runtime and backup files for explicit schema-aware recovery; see docs/postgres-upgrades.md"
  fi
  for name in $managed_binaries; do
    if [ -f "$pending_root/bin/$name" ]; then
      install -o root -g root -m 0755 "$pending_root/bin/$name" "$binary_root/$name"
    fi
  done
  for name in $managed_unit_files; do
    if [ -f "$pending_root/units/$name" ]; then
      install -o root -g root -m 0644 "$pending_root/units/$name" "$unit_root/$name"
    fi
  done
  daemon_reload
  restore_recorded_services || true
  : >"$pending_root/rolled-back"
  chmod 0600 "$pending_root/rolled-back"
}

prepare_upgrade() {
  ensure_directory "$state_root"
  if [ -e "$pending_root" ]; then
    [ ! -L "$pending_root" ] || fail "refusing symbolic-link pending upgrade directory"
    rollback_upgrade
    clear_pending
  fi
  ensure_directory "$pending_root"
  ensure_directory "$pending_root/bin"
  ensure_directory "$pending_root/units"
  : >"$state_file"
  chmod 0600 "$state_file"
  : >"$pending_root/prepared"
  chmod 0600 "$pending_root/prepared"
  prepare_complete=0
  trap 'status=$?; if [ "$prepare_complete" -ne 1 ]; then rollback_upgrade; fi; exit "$status"' EXIT HUP INT TERM

  for unit in $managed_units; do
    enabled=0
    active=0
    unit_enabled "$unit" && enabled=1
    unit_active "$unit" && active=1
    printf '%s|%s|%s\n' "$unit" "$enabled" "$active" >>"$state_file"
    if [ "$active" = 1 ]; then
      systemctl stop "$unit"
    fi
  done
  for name in $managed_binaries; do
    if [ -f "$binary_root/$name" ] && [ ! -L "$binary_root/$name" ]; then
      cp -p -- "$binary_root/$name" "$pending_root/bin/$name"
    fi
  done
  for name in $managed_unit_files; do
    if [ -f "$unit_root/$name" ] && [ ! -L "$unit_root/$name" ]; then
      cp -p -- "$unit_root/$name" "$pending_root/units/$name"
    fi
  done
  prepare_complete=1
  trap - EXIT HUP INT TERM
}

validate_installation() {
  for name in $managed_binaries; do
    [ -x "$binary_root/$name" ] || return 1
    "$binary_root/$name" --version >/dev/null 2>&1 || return 1
  done
  if command -v systemd-analyze >/dev/null 2>&1; then
    systemd-analyze verify \
      "$unit_root/linklake-server.service" \
      "$unit_root/linklake-update-resume.service" \
      "$unit_root/linklake-client.service" >/dev/null 2>&1 || return 1
  fi
}

activate() {
  mode="${1:-install}"
  if [ "$mode" = upgrade ] && [ -f "$pending_root/rolled-back" ]; then
    fail "a previous activation was rolled back; install a repaired package before marking the upgrade complete"
  fi
  daemon_reload
  if ! validate_installation; then
    if [ "$mode" = upgrade ]; then
      rollback_upgrade
    fi
    fail "new package validation failed; the previous runtime files were restored when available"
  fi
  if [ "$mode" = upgrade ]; then
    : >"$pending_root/candidate-started"
    chmod 0600 "$pending_root/candidate-started"
    if ! restore_recorded_services; then
      fail "candidate service activation failed; runtime and backup files are preserved; automatic binary rollback is unsafe after a database migration"
    fi
  fi
  clear_pending
}

remove_package() {
  if systemctl_available; then
    for unit in $managed_units; do
      systemctl stop "$unit" >/dev/null 2>&1 || true
      systemctl disable "$unit" >/dev/null 2>&1 || true
    done
  fi
  daemon_reload
}

purge_configuration() {
  # 卸载和清除均保留 /var/lib/linklake 中的用户数据；purge 只删除由安装器生成的运行配置。
  rm -f -- /etc/linklake/server.env /etc/linklake/client.toml
  clear_pending
}

case "${1:-}" in
  prepare-upgrade) prepare_upgrade ;;
  activate) activate "${2:-install}" ;;
  rollback) rollback_upgrade ;;
  remove) remove_package ;;
  purge) purge_configuration ;;
  *) fail 'usage: package-lifecycle.sh prepare-upgrade|activate [install|upgrade]|rollback|remove|purge' ;;
esac
