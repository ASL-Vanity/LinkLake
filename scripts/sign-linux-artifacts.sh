#!/usr/bin/env sh
set -eu

# 正式 Linux 发布包使用独立 OpenPGP 密钥生成可离线验证的分离签名。
root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
out="${1:-$root/dist}"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -n 1)"
required="${LINKLAKE_LINUX_SIGNING_REQUIRED:-false}"

is_enabled() {
  case "$1" in 1|true|TRUE|yes|YES) return 0;; *) return 1;; esac
}

configured=0
for value in \
  "${LINKLAKE_LINUX_GPG_PRIVATE_KEY_B64:-}" \
  "${LINKLAKE_LINUX_GPG_PASSPHRASE:-}" \
  "${LINKLAKE_LINUX_GPG_FINGERPRINT:-}"; do
  if [ -n "$value" ]; then configured=$((configured + 1)); fi
done
if ! is_enabled "$required" && [ "$configured" -eq 0 ]; then
  echo 'Linux OpenPGP signing is not enabled for this development package.'
  exit 0
fi

for name in LINKLAKE_LINUX_GPG_PRIVATE_KEY_B64 LINKLAKE_LINUX_GPG_PASSPHRASE LINKLAKE_LINUX_GPG_FINGERPRINT; do
  eval "value=\${$name:-}"
  if [ -z "$value" ]; then
    echo "Linux OpenPGP signing requires environment variable $name." >&2
    exit 1
  fi
done
expected_fingerprint="$(printf '%s' "$LINKLAKE_LINUX_GPG_FINGERPRINT" | tr -d '[:space:]:' | tr '[:upper:]' '[:lower:]')"
case "$expected_fingerprint" in
  *[!0-9a-f]*|'') echo 'LINKLAKE_LINUX_GPG_FINGERPRINT must be a 40-character hexadecimal fingerprint.' >&2; exit 1;;
esac
if [ "${#expected_fingerprint}" -ne 40 ]; then
  echo 'LINKLAKE_LINUX_GPG_FINGERPRINT must be a 40-character hexadecimal fingerprint.' >&2
  exit 1
fi

for command in gpg python3 sha256sum; do
  command -v "$command" >/dev/null 2>&1 || { echo "Required signing command is missing: $command" >&2; exit 1; }
done
test -d "$out"

rpm_version="${version%%-*}"
if [ "$rpm_version" = "$version" ]; then
  rpm_release=1
else
  rpm_release="0.$(printf '%s' "${version#*-}" | tr '-' '.')"
fi

gnupg_home="$(mktemp -d)"
assets_file="$gnupg_home/assets.txt"
cleanup() {
  unset LINKLAKE_LINUX_GPG_PRIVATE_KEY_B64 LINKLAKE_LINUX_GPG_PASSPHRASE
  rm -rf -- "$gnupg_home"
}
trap cleanup EXIT HUP INT TERM
chmod 0700 "$gnupg_home"
export GNUPGHOME="$gnupg_home"

find "$out" -maxdepth 1 -type f \( \
  -name "linklake-$version-linux-*.tar.gz" -o \
  -name "linklake-manager-$version-linux-*.tar.gz" -o \
  -name "linklake_${version}_*.deb" -o \
  -name "linklake-${rpm_version}-${rpm_release}*.rpm" \
\) -print | LC_ALL=C sort >"$assets_file"

core_count="$(grep -c "/linklake-$version-linux-.*\.tar\.gz$" "$assets_file" || true)"
manager_count="$(grep -c "/linklake-manager-$version-linux-.*\.tar\.gz$" "$assets_file" || true)"
deb_count="$(grep -c "/linklake_${version}_.*\.deb$" "$assets_file" || true)"
rpm_count="$(grep -c "/linklake-${rpm_version}-${rpm_release}.*\.rpm$" "$assets_file" || true)"
if [ "$core_count" -ne 1 ] || [ "$manager_count" -ne 1 ] || [ "$deb_count" -ne 1 ] || [ "$rpm_count" -ne 1 ]; then
  echo 'Linux signing requires exactly one core archive, Manager archive, DEB, and RPM package.' >&2
  exit 1
fi

python3 - <<'PY' | gpg --batch --quiet --import
import base64
import os
import sys

try:
    encoded = os.environ['LINKLAKE_LINUX_GPG_PRIVATE_KEY_B64'].encode('ascii')
    raw = base64.b64decode(encoded, validate=True)
except Exception:
    raise SystemExit('LINKLAKE_LINUX_GPG_PRIVATE_KEY_B64 is not valid base64')
if not raw or len(raw) > 1024 * 1024:
    raise SystemExit('Linux OpenPGP private key has an invalid size')
sys.stdout.buffer.write(raw)
PY

actual_fingerprint="$(gpg --batch --with-colons --list-secret-keys "$expected_fingerprint" 2>/dev/null | awk -F: '$1 == "fpr" { print tolower($10); exit }')"
if [ "$actual_fingerprint" != "$expected_fingerprint" ]; then
  echo 'The imported Linux signing key does not match the pinned fingerprint.' >&2
  exit 1
fi

public_key="$out/linklake-linux-release-public-key.asc"
gpg --batch --armor --export "$expected_fingerprint" >"$public_key"
test -s "$public_key"
(cd "$out" && sha256sum "$(basename "$public_key")" >"$(basename "$public_key").sha256")

signed=0
while IFS= read -r artifact; do
  test -f "$artifact"
  test ! -L "$artifact"
  signature="$artifact.asc"
  rm -f -- "$signature" "$signature.sha256"
  printf '%s' "$LINKLAKE_LINUX_GPG_PASSPHRASE" | \
    gpg --batch --yes --quiet --pinentry-mode loopback --passphrase-fd 0 \
      --local-user "$expected_fingerprint" --digest-algo SHA256 \
      --armor --detach-sign --output "$signature" "$artifact"
  gpg --batch --quiet --verify "$signature" "$artifact"
  (cd "$out" && sha256sum "$(basename "$signature")" >"$(basename "$signature").sha256")
  signed=$((signed + 1))
done <"$assets_file"

echo "OpenPGP-signed and verified $signed Linux release packages."
