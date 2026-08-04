#!/usr/bin/env sh
set -eu

# 使用 App Store Connect API 密钥提交公证；私钥内容只存在于权限受限的临时文件中。
artifact="${1:-}"
staple_target="${2:-}"
required="${LINKLAKE_MACOS_SIGNING_REQUIRED:-false}"
active="${LINKLAKE_MACOS_SIGNING_ACTIVE:-false}"
case "$active" in 1|true|TRUE|yes|YES) active=true;; *) active=false;; esac
case "$required" in 1|true|TRUE|yes|YES) required=true;; *) required=false;; esac
if [ "$active" != true ]; then
  if [ "$required" = true ]; then echo 'macOS notarization is required but the signing context is inactive.' >&2; exit 1; fi
  echo 'macOS notarization is not enabled for this development package.'
  exit 0
fi

test -f "$artifact"
test ! -L "$artifact"
for name in LINKLAKE_MACOS_SIGNING_WORK_DIR LINKLAKE_APPLE_API_KEY_PATH LINKLAKE_APPLE_API_KEY_ID LINKLAKE_APPLE_API_ISSUER_ID; do
  eval "value=\${$name:-}"
  if [ -z "$value" ]; then echo "macOS notarization requires environment variable $name." >&2; exit 1; fi
done
case "$LINKLAKE_APPLE_API_KEY_PATH" in
  "$LINKLAKE_MACOS_SIGNING_WORK_DIR"/*) ;;
  *) echo 'The App Store Connect API key path is outside the temporary signing directory.' >&2; exit 1;;
esac
test -f "$LINKLAKE_APPLE_API_KEY_PATH"
test ! -L "$LINKLAKE_APPLE_API_KEY_PATH"

result="$(mktemp "$LINKLAKE_MACOS_SIGNING_WORK_DIR/notary.XXXXXX.json")"
if ! xcrun notarytool submit "$artifact" \
  --key "$LINKLAKE_APPLE_API_KEY_PATH" \
  --key-id "$LINKLAKE_APPLE_API_KEY_ID" \
  --issuer "$LINKLAKE_APPLE_API_ISSUER_ID" \
  --wait --output-format json >"$result"; then
  echo 'Apple notarization submission failed.' >&2
  exit 1
fi
python3 - "$result" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
if payload.get('status') != 'Accepted':
    raise SystemExit(f"Apple notarization did not return Accepted: {payload.get('status', 'unknown')}")
print(f"Apple notarization accepted submission {payload.get('id', 'unknown')}.")
PY
rm -f -- "$result"

if [ -n "$staple_target" ]; then
  test -e "$staple_target"
  test ! -L "$staple_target"
  xcrun stapler staple "$staple_target"
  xcrun stapler validate "$staple_target"
fi
