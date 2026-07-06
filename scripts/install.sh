#!/bin/sh
set -eu

VERSION="${OUTCALL_VERSION:-0.1.21}"
BIN_DIR="${OUTCALL_BIN_DIR:-$HOME/.local/bin}"
BASE_URL="${OUTCALL_RELEASE_BASE_URL:-https://github.com/outcall-dev/outcall/releases/download/v${VERSION}}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

need_cmd uname
need_cmd curl
need_cmd tar
need_cmd mktemp
need_cmd install

os="$(uname -s)"
arch="$(uname -m)"
docker_image_archive=""

case "$os:$arch" in
  Linux:x86_64)
    target="x86_64-unknown-linux-gnu"
    docker_image_archive="outcalld-image-linux-amd64.tar.gz"
    ;;
  Linux:aarch64|Linux:arm64)
    target="aarch64-unknown-linux-gnu"
    docker_image_archive="outcalld-image-linux-arm64.tar.gz"
    ;;
  Darwin:x86_64) target="x86_64-apple-darwin" ;;
  Darwin:arm64) target="aarch64-apple-darwin" ;;
  *)
    echo "error: unsupported platform $os $arch" >&2
    echo "supported targets: Linux x86_64/aarch64, macOS x86_64/arm64" >&2
    exit 1
    ;;
esac

archive="${target}.tar.gz"
tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

echo "==> Downloading Outcall v${VERSION} for ${target}"
curl -fsSL -o "$tmpdir/$archive" "$BASE_URL/$archive"

echo "==> Installing binaries to $BIN_DIR"
mkdir -p "$BIN_DIR"
tar -xzf "$tmpdir/$archive" -C "$tmpdir"
install -m 0755 "$tmpdir/outcall" "$BIN_DIR/outcall"
install -m 0755 "$tmpdir/outcalld" "$BIN_DIR/outcalld"
install -m 0755 "$tmpdir/outcall-agent" "$BIN_DIR/outcall-agent"

if [ -n "$docker_image_archive" ] && command -v docker >/dev/null 2>&1; then
  if command -v gzip >/dev/null 2>&1; then
    echo "==> Preloading daemon image for Docker"
    if curl -fsSL -o "$tmpdir/$docker_image_archive" "$BASE_URL/$docker_image_archive"; then
      if gzip -dc "$tmpdir/$docker_image_archive" | docker load >/dev/null; then
        echo "Loaded daemon image archive: $docker_image_archive"
      else
        echo "warning: failed to docker load $docker_image_archive; first run may fall back to a registry pull" >&2
      fi
    else
      echo "warning: daemon image archive not available at $BASE_URL/$docker_image_archive; first run may fall back to a registry pull" >&2
    fi
  else
    echo "warning: gzip not found; skipping daemon image preload" >&2
  fi
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    echo
    echo "Add $BIN_DIR to PATH before using Outcall:"
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
    ;;
esac

echo
echo "Installed:"
echo "  $BIN_DIR/outcall"
echo "  $BIN_DIR/outcalld"
echo "  $BIN_DIR/outcall-agent"

echo
if [ "$os" = "Linux" ]; then
  echo "Next:"
  echo "  cd /path/to/your/project"
  echo "  outcall doctor claude"
  echo "  outcall run claude"
  echo "  # or:"
  echo "  outcall doctor codex"
  echo "  outcall run codex"
else
  echo "Note: the CLI is installed, but the daemon is Linux-only."
  echo "Use a Linux host or VM to run isolated agent containers."
fi
