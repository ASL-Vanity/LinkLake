#!/usr/bin/env sh
set -eu

# 测试密钥仅在临时目录中生成，用于证明正式脚本不会依赖仓库内私钥。
root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -n 1)"
rpm_version="${version%%-*}"
if [ "$rpm_version" = "$version" ]; then rpm_release=1; else rpm_release="0.$(printf '%s' "${version#*-}" | tr '-' '.')"; fi
test_root="$(mktemp -d)"
key_home="$test_root/key-home"
mkdir -m 0700 "$key_home"
cleanup() {
  unset LINKLAKE_LINUX_GPG_PRIVATE_KEY_B64 LINKLAKE_LINUX_GPG_PASSPHRASE LINKLAKE_LINUX_GPG_FINGERPRINT LINKLAKE_LINUX_SIGNING_REQUIRED
  rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

export GNUPGHOME="$key_home"
passphrase='linklake-runtime-fixture'
printf '%s' "$passphrase" | gpg --batch --quiet --pinentry-mode loopback --passphrase-fd 0 \
  --quick-generate-key 'LinkLake Runtime Fixture <fixture@linklake.invalid>' ed25519 sign 1d
fingerprint="$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" { print tolower($10); exit }')"
private_key_b64="$(printf '%s' "$passphrase" | gpg --batch --quiet --pinentry-mode loopback --passphrase-fd 0 \
  --export-secret-keys "$fingerprint" | base64 -w 0)"

out="$test_root/dist"
mkdir "$out"
printf core >"$out/linklake-$version-linux-x86_64.tar.gz"
printf manager >"$out/linklake-manager-$version-linux-x86_64.tar.gz"
printf deb >"$out/linklake_${version}_amd64.deb"
printf rpm >"$out/linklake-${rpm_version}-${rpm_release}.x86_64.rpm"

unset GNUPGHOME
export LINKLAKE_LINUX_SIGNING_REQUIRED=true
export LINKLAKE_LINUX_GPG_PRIVATE_KEY_B64="$private_key_b64"
export LINKLAKE_LINUX_GPG_PASSPHRASE="$passphrase"
export LINKLAKE_LINUX_GPG_FINGERPRINT="$fingerprint"
sh "$root/scripts/sign-linux-artifacts.sh" "$out"
sh "$root/scripts/verify-linux-release-signatures.sh" "$out" "$version"

printf tamper >>"$out/linklake-$version-linux-x86_64.tar.gz"
if sh "$root/scripts/verify-linux-release-signatures.sh" "$out" "$version" >/dev/null 2>&1; then
  echo 'Tampered Linux package unexpectedly passed OpenPGP verification.' >&2
  exit 1
fi

echo 'Linux OpenPGP signing contract passed.'
