#!/usr/bin/env sh
set -eu

# 发布汇总任务只依赖公开密钥和固定指纹，重新验证跨任务传递后的 Linux 资产。
root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
out="${1:-$root/dist}"
version="${2:-$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -n 1)}"
expected_fingerprint="$(printf '%s' "${LINKLAKE_LINUX_GPG_FINGERPRINT:-}" | tr -d '[:space:]:' | tr '[:upper:]' '[:lower:]')"
case "$expected_fingerprint" in
  *[!0-9a-f]*|'') echo 'A pinned 40-character Linux signing fingerprint is required.' >&2; exit 1;;
esac
if [ "${#expected_fingerprint}" -ne 40 ]; then
  echo 'A pinned 40-character Linux signing fingerprint is required.' >&2
  exit 1
fi

for command in gpg sha256sum; do
  command -v "$command" >/dev/null 2>&1 || { echo "Required verification command is missing: $command" >&2; exit 1; }
done
test -d "$out"

rpm_version="${version%%-*}"
if [ "$rpm_version" = "$version" ]; then rpm_release=1; else rpm_release="0.$(printf '%s' "${version#*-}" | tr '-' '.')"; fi
gnupg_home="$(mktemp -d)"
assets_file="$gnupg_home/assets.txt"
trap 'rm -rf -- "$gnupg_home"' EXIT HUP INT TERM
chmod 0700 "$gnupg_home"
export GNUPGHOME="$gnupg_home"

find "$out" -maxdepth 1 -type f \( \
  -name "linklake-$version-linux-*.tar.gz" -o \
  -name "linklake-manager-$version-linux-*.tar.gz" -o \
  -name "linklake_${version}_*.deb" -o \
  -name "linklake-${rpm_version}-${rpm_release}*.rpm" \
\) -print | LC_ALL=C sort >"$assets_file"
if [ "$(wc -l <"$assets_file" | tr -d '[:space:]')" -ne 4 ]; then
  echo 'The signed Linux release set is incomplete.' >&2
  exit 1
fi

public_key="$out/linklake-linux-release-public-key.asc"
test -f "$public_key"
test ! -L "$public_key"
(cd "$out" && sha256sum -c "$(basename "$public_key").sha256")
gpg --batch --quiet --import "$public_key"
actual_fingerprint="$(gpg --batch --with-colons --list-keys "$expected_fingerprint" 2>/dev/null | awk -F: '$1 == "fpr" { print tolower($10); exit }')"
if [ "$actual_fingerprint" != "$expected_fingerprint" ]; then
  echo 'The published Linux verification key does not match the pinned fingerprint.' >&2
  exit 1
fi

verified=0
while IFS= read -r artifact; do
  signature="$artifact.asc"
  test -f "$signature"
  test ! -L "$signature"
  (cd "$out" && sha256sum -c "$(basename "$signature").sha256")
  gpg --batch --quiet --verify "$signature" "$artifact"
  verified=$((verified + 1))
done <"$assets_file"

echo "Verified OpenPGP signatures for $verified Linux release packages."
