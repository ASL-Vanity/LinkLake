#!/bin/sh
set -eu

# 离线生成 Linux 发布签名密钥。口令只从环境读取，并通过标准输入交给 GnuPG。
output_dir="${1:-}"
uid="${LINKLAKE_LINUX_GPG_UID:-LinkLake Release <ASL-Vanity@users.noreply.github.com>}"
expiry="${LINKLAKE_LINUX_GPG_EXPIRY:-2y}"
passphrase="${GPG_PASSPHRASE:-}"

test -n "$output_dir" || { echo 'usage: generate-linux-release-key.sh <output-directory>' >&2; exit 2; }
test -d "$output_dir" || { echo 'output directory does not exist' >&2; exit 2; }
test -n "$passphrase" || { echo 'GPG_PASSPHRASE is required' >&2; exit 2; }

private_key="$output_dir/linux-openpgp-private.asc"
public_key="$output_dir/linux-openpgp-public.asc"
fingerprint_file="$output_dir/linux-openpgp-fingerprint.txt"
for path in "$private_key" "$public_key" "$fingerprint_file"; do
  test ! -e "$path" || { echo "refusing to overwrite $path" >&2; exit 2; }
done

umask 077
gnupg_home="$(mktemp -d)"
verify_home="$(mktemp -d)"
cleanup() {
  rm -rf -- "$gnupg_home" "$verify_home"
}
trap cleanup EXIT HUP INT TERM
export GNUPGHOME="$gnupg_home"

printf '%s' "$passphrase" |
  gpg --batch --pinentry-mode loopback --passphrase-fd 0 \
    --quick-generate-key "$uid" ed25519 sign "$expiry" >/dev/null 2>&1

fingerprint="$(gpg --batch --with-colons --fingerprint "$uid" |
  awk -F: '$1 == "fpr" { print $10; exit }')"
case "$fingerprint" in
  *[!0-9A-F]*|'') echo 'generated OpenPGP fingerprint is invalid' >&2; exit 1 ;;
esac
test "${#fingerprint}" -eq 40 || { echo 'generated OpenPGP fingerprint length is invalid' >&2; exit 1; }

gpg --batch --armor --export "$fingerprint" >"$public_key"
printf '%s' "$passphrase" |
  gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 \
    --armor --export-secret-keys "$fingerprint" >"$private_key"
printf '%s' "$fingerprint" >"$fingerprint_file"

message="$gnupg_home/verification-message.txt"
printf 'LinkLake release signing verification\n' >"$message"
printf '%s' "$passphrase" |
  gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 \
    --armor --detach-sign "$message"
GNUPGHOME="$verify_home" gpg --batch --import "$public_key" >/dev/null 2>&1
GNUPGHOME="$verify_home" gpg --batch --verify "$message.asc" "$message" >/dev/null 2>&1

printf '%s\n' "$fingerprint"
