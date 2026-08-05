#!/usr/bin/env sh
set -eu

# 使用仅含 Dockerfile 的临时构建上下文，避免把工作区或 CI 环境传给依赖镜像构建。
mode="${1:-}"
case "$mode" in
  deb|rpm) ;;
  *) echo "Usage: $0 deb|rpm" >&2; exit 2 ;;
esac

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

require_command docker
require_command timeout
require_command sha256sum
require_command awk
require_command mktemp

root="${GITHUB_WORKSPACE:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)}"
root="$(CDPATH='' cd -- "$root" && pwd -P)"
case "$root" in
  /) echo 'Refusing to use the filesystem root as the native package contract workspace.' >&2; exit 1 ;;
esac

dockerfile="$root/tests/native-linux-package-contract-$mode.Dockerfile"
test -f "$dockerfile"
context="$(mktemp -d)"
cleanup() {
  rm -rf -- "$context"
}
trap cleanup EXIT HUP INT TERM

# 构建上下文只包含已审阅的 Dockerfile；运行时才以只读方式挂载工作区。
cp "$dockerfile" "$context/Dockerfile"
image_digest="$(sha256sum "$dockerfile" | awk '{print substr($1, 1, 16)}')"
image="linklake-native-package-contract-$mode:$image_digest"

echo "Building pinned native Linux $mode contract image."
timeout --foreground 600 docker build --pull=false --file "$context/Dockerfile" --tag "$image" "$context"

echo "Running native Linux $mode contract with no network and a read-only workspace mount."
timeout --foreground 300 docker run --rm \
  --network none \
  --user 0:0 \
  --security-opt no-new-privileges:true \
  --memory 1g \
  --pids-limit 256 \
  --mount "type=bind,source=$root,target=/workspace,readonly" \
  --workdir /workspace \
  --tmpfs /tmp:exec,mode=1777,size=1g \
  "$image" sh tests/native-linux-package-contract.sh "$mode"
