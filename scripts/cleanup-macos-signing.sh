#!/usr/bin/env sh
set -eu

# 只允许清理 setup-macos-signing.sh 在 RUNNER_TEMP 下创建的精确目录。
work_dir="${LINKLAKE_MACOS_SIGNING_WORK_DIR:-}"
keychain="${LINKLAKE_MACOS_KEYCHAIN_PATH:-}"
if [ -z "$work_dir" ]; then exit 0; fi
temp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
case "$work_dir" in
  "$temp_root"/linklake-release-signing.*) ;;
  *) echo 'Refusing to remove an unexpected macOS signing directory.' >&2; exit 1;;
esac
expected_keychain="$work_dir/signing.keychain-db"
if [ -n "$keychain" ] && [ "$keychain" != "$expected_keychain" ]; then
  echo 'Refusing to remove an unexpected macOS signing keychain.' >&2
  exit 1
fi
security delete-keychain "$expected_keychain" >/dev/null 2>&1 || true
rm -rf -- "$work_dir"
echo 'Removed the temporary macOS signing context.'
