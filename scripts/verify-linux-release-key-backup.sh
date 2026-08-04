#!/bin/sh
set -eu

# 验证仓库外的 OpenPGP 私钥备份、口令、公钥与固定指纹是否一致。
backup_dir="${1:-}"
passphrase="${GPG_PASSPHRASE:-}"
expected_fingerprint="${EXPECTED_FINGERPRINT:-}"

test -n "$backup_dir" || { echo 'usage: verify-linux-release-key-backup.sh <backup-directory>' >&2; exit 2; }
test -n "$passphrase" || { echo 'GPG_PASSPHRASE is required' >&2; exit 2; }
case "$expected_fingerprint" in
  *[!0-9A-F]*|'') echo 'EXPECTED_FINGERPRINT must be uppercase hexadecimal' >&2; exit 2 ;;
esac
test "${#expected_fingerprint}" -eq 40 || { echo 'EXPECTED_FINGERPRINT must contain 40 characters' >&2; exit 2; }

private_key="$backup_dir/linux-openpgp-private.asc"
public_key="$backup_dir/linux-openpgp-public.asc"
test -f "$private_key"
test -f "$public_key"

umask 077
signing_home="$(mktemp -d)"
verify_home="$(mktemp -d)"
work_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "$signing_home" "$verify_home" "$work_dir"
}
trap cleanup EXIT HUP INT TERM

GNUPGHOME="$signing_home" gpg --batch --import "$private_key" >/dev/null 2>&1
actual_fingerprint="$(GNUPGHOME="$signing_home" gpg --batch --with-colons --fingerprint |
  awk -F: '$1 == "fpr" { print $10; exit }')"
test "$actual_fingerprint" = "$expected_fingerprint"

message="$work_dir/message.txt"
printf 'LinkLake release-key backup verification\n' >"$message"
printf '%s' "$passphrase" |
  GNUPGHOME="$signing_home" gpg --batch --yes --pinentry-mode loopback \
    --passphrase-fd 0 --armor --detach-sign "$message"

GNUPGHOME="$verify_home" gpg --batch --import "$public_key" >/dev/null 2>&1
GNUPGHOME="$verify_home" gpg --batch --verify "$message.asc" "$message" >/dev/null 2>&1
printf '%s\n' "$actual_fingerprint"
