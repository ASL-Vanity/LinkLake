#!/usr/bin/env sh
set -eu

# 创建只在当前 CI 任务中存在的 Keychain 和 App Store Connect API 私钥文件。
required="${LINKLAKE_MACOS_SIGNING_REQUIRED:-false}"
is_enabled() {
  case "$1" in 1|true|TRUE|yes|YES) return 0;; *) return 1;; esac
}

configured=0
for value in \
  "${LINKLAKE_MACOS_SIGNING_CERT_P12_B64:-}" \
  "${LINKLAKE_MACOS_SIGNING_CERT_PASSWORD:-}" \
  "${LINKLAKE_MACOS_SIGNING_IDENTITY:-}" \
  "${LINKLAKE_MACOS_SIGNING_CERT_SHA256:-}" \
  "${LINKLAKE_APPLE_API_KEY_P8_B64:-}" \
  "${LINKLAKE_APPLE_API_KEY_ID:-}" \
  "${LINKLAKE_APPLE_API_ISSUER_ID:-}"; do
  if [ -n "$value" ]; then configured=$((configured + 1)); fi
done
if ! is_enabled "$required" && [ "$configured" -eq 0 ]; then
  if [ -n "${GITHUB_ENV:-}" ]; then printf '%s\n' 'LINKLAKE_MACOS_SIGNING_ACTIVE=false' >>"$GITHUB_ENV"; fi
  echo 'macOS Developer ID signing is not enabled for this development package.'
  exit 0
fi

for name in \
  LINKLAKE_MACOS_SIGNING_CERT_P12_B64 \
  LINKLAKE_MACOS_SIGNING_CERT_PASSWORD \
  LINKLAKE_MACOS_SIGNING_IDENTITY \
  LINKLAKE_MACOS_SIGNING_CERT_SHA256 \
  LINKLAKE_APPLE_API_KEY_P8_B64 \
  LINKLAKE_APPLE_API_KEY_ID \
  LINKLAKE_APPLE_API_ISSUER_ID; do
  eval "value=\${$name:-}"
  if [ -z "$value" ]; then
    echo "macOS production signing requires environment variable $name." >&2
    exit 1
  fi
done
test -n "${GITHUB_ENV:-}" || { echo 'GITHUB_ENV is required to persist the temporary signing context.' >&2; exit 1; }

for command in security swift python3 openssl shasum; do
  command -v "$command" >/dev/null 2>&1 || { echo "Required macOS signing command is missing: $command" >&2; exit 1; }
done

case "$LINKLAKE_APPLE_API_KEY_ID" in
  *[!A-Za-z0-9]*|'') echo 'LINKLAKE_APPLE_API_KEY_ID must contain exactly 10 alphanumeric characters.' >&2; exit 1;;
esac
if [ "${#LINKLAKE_APPLE_API_KEY_ID}" -ne 10 ]; then
  echo 'LINKLAKE_APPLE_API_KEY_ID must contain exactly 10 alphanumeric characters.' >&2
  exit 1
fi
case "$LINKLAKE_APPLE_API_ISSUER_ID" in
  *[!0-9A-Fa-f-]*|'') echo 'LINKLAKE_APPLE_API_ISSUER_ID must be a UUID.' >&2; exit 1;;
esac
if [ "${#LINKLAKE_APPLE_API_ISSUER_ID}" -ne 36 ]; then
  echo 'LINKLAKE_APPLE_API_ISSUER_ID must be a UUID.' >&2
  exit 1
fi
case "$LINKLAKE_MACOS_SIGNING_IDENTITY" in
  'Developer ID Application: '*) ;;
  *) echo 'LINKLAKE_MACOS_SIGNING_IDENTITY must name a Developer ID Application identity.' >&2; exit 1;;
esac
python3 - <<'PY'
import os

for name in (
    'LINKLAKE_MACOS_SIGNING_IDENTITY',
    'LINKLAKE_APPLE_API_KEY_ID',
    'LINKLAKE_APPLE_API_ISSUER_ID',
):
    if any(ord(character) < 32 or ord(character) == 127 for character in os.environ[name]):
        raise SystemExit(f'{name} contains a forbidden control character')
PY

expected_fingerprint="$(printf '%s' "$LINKLAKE_MACOS_SIGNING_CERT_SHA256" | tr -d '[:space:]:' | tr '[:upper:]' '[:lower:]')"
case "$expected_fingerprint" in
  *[!0-9a-f]*|'') echo 'LINKLAKE_MACOS_SIGNING_CERT_SHA256 must contain exactly 64 hexadecimal characters.' >&2; exit 1;;
esac
if [ "${#expected_fingerprint}" -ne 64 ]; then
  echo 'LINKLAKE_MACOS_SIGNING_CERT_SHA256 must contain exactly 64 hexadecimal characters.' >&2
  exit 1
fi

temp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
work_dir="$(mktemp -d "$temp_root/linklake-release-signing.XXXXXX")"
keychain="$work_dir/signing.keychain-db"
api_key="$work_dir/AuthKey_${LINKLAKE_APPLE_API_KEY_ID}.p8"
original_default=''
success=false
cleanup_on_failure() {
  if [ -n "$original_default" ]; then security default-keychain -d user -s "$original_default" >/dev/null 2>&1 || true; fi
  if [ "$success" != true ]; then
    security delete-keychain "$keychain" >/dev/null 2>&1 || true
    rm -rf -- "$work_dir"
  fi
}
trap cleanup_on_failure EXIT HUP INT TERM

security create-keychain -p '' "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p '' "$keychain"
original_default="$(security default-keychain -d user | sed 's/^[[:space:]]*"//;s/"[[:space:]]*$//')"
security default-keychain -d user -s "$keychain"
swift "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/import-macos-p12.swift"
security default-keychain -d user -s "$original_default"
original_default=''
security set-key-partition-list -S apple-tool:,apple: -s -k '' "$keychain" >/dev/null

identities="$(security find-identity -v -p codesigning "$keychain")"
printf '%s\n' "$identities" | grep -F "\"$LINKLAKE_MACOS_SIGNING_IDENTITY\"" >/dev/null || {
  echo 'The expected Developer ID Application identity was not imported.' >&2
  exit 1
}
actual_fingerprint="$(security find-certificate -c "$LINKLAKE_MACOS_SIGNING_IDENTITY" -p "$keychain" | \
  openssl x509 -outform DER | shasum -a 256 | awk '{ print tolower($1) }')"
if [ "$actual_fingerprint" != "$expected_fingerprint" ]; then
  echo 'The imported macOS signing certificate does not match the pinned SHA-256 fingerprint.' >&2
  exit 1
fi

python3 - "$api_key" <<'PY'
import base64
import os
import pathlib
import sys

target = pathlib.Path(sys.argv[1])
try:
    raw = base64.b64decode(os.environ['LINKLAKE_APPLE_API_KEY_P8_B64'].encode('ascii'), validate=True)
except Exception:
    raise SystemExit('LINKLAKE_APPLE_API_KEY_P8_B64 is not valid base64')
if not raw.startswith(b'-----BEGIN PRIVATE KEY-----') or len(raw) > 64 * 1024:
    raise SystemExit('The App Store Connect API key has an invalid format or size')
target.write_bytes(raw)
target.chmod(0o600)
PY

{
  printf 'LINKLAKE_MACOS_SIGNING_ACTIVE=true\n'
  printf 'LINKLAKE_MACOS_SIGNING_WORK_DIR=%s\n' "$work_dir"
  printf 'LINKLAKE_MACOS_KEYCHAIN_PATH=%s\n' "$keychain"
  printf 'LINKLAKE_MACOS_SIGNING_IDENTITY=%s\n' "$LINKLAKE_MACOS_SIGNING_IDENTITY"
  printf 'LINKLAKE_APPLE_API_KEY_PATH=%s\n' "$api_key"
  printf 'LINKLAKE_APPLE_API_KEY_ID=%s\n' "$LINKLAKE_APPLE_API_KEY_ID"
  printf 'LINKLAKE_APPLE_API_ISSUER_ID=%s\n' "$LINKLAKE_APPLE_API_ISSUER_ID"
} >>"$GITHUB_ENV"

success=true
echo 'Prepared and fingerprint-verified the temporary macOS signing context.'
