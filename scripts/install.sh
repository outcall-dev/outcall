#!/bin/sh
set -eu

VERSION="${OUTCALL_VERSION:-0.1.32}"
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
if ! command -v sha256sum >/dev/null 2>&1; then
  need_cmd shasum
fi

checksum() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

verify_checksum() {
  archive_path="$1"
  checksum_path="$2"
  expected=""
  read -r expected _ < "$checksum_path" || true
  if [ -z "$expected" ]; then
    echo "error: checksum file $checksum_path does not contain a SHA-256 digest" >&2
    exit 1
  fi
  set -- $(checksum "$archive_path")
  actual="$1"
  if [ "$actual" != "$expected" ]; then
    echo "error: SHA-256 verification failed for $(basename "$archive_path")" >&2
    exit 1
  fi
}

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
  Darwin:x86_64)
    target="x86_64-apple-darwin"
    docker_image_archive="outcalld-image-linux-amd64.tar.gz"
    ;;
  Darwin:arm64)
    target="aarch64-apple-darwin"
    docker_image_archive="outcalld-image-linux-arm64.tar.gz"
    ;;
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
curl -fsSL -o "$tmpdir/$archive.sha256" "$BASE_URL/$archive.sha256"
verify_checksum "$tmpdir/$archive" "$tmpdir/$archive.sha256"

echo "==> Installing binaries to $BIN_DIR"
mkdir -p "$BIN_DIR"
tar -xzf "$tmpdir/$archive" -C "$tmpdir"
install -m 0755 "$tmpdir/outcall" "$BIN_DIR/outcall"
install -m 0755 "$tmpdir/outcalld" "$BIN_DIR/outcalld"
install -m 0755 "$tmpdir/outcall-agent" "$BIN_DIR/outcall-agent"

if [ -n "$docker_image_archive" ] && command -v docker >/dev/null 2>&1 && [ "${OUTCALL_SKIP_IMAGE_PRELOAD:-0}" != "1" ]; then
  echo "==> Preloading verified daemon image for Docker"
  curl -fsSL -o "$tmpdir/$docker_image_archive" "$BASE_URL/$docker_image_archive"
  curl -fsSL -o "$tmpdir/$docker_image_archive.sha256" "$BASE_URL/$docker_image_archive.sha256"
  verify_checksum "$tmpdir/$docker_image_archive" "$tmpdir/$docker_image_archive.sha256"
  if docker load -i "$tmpdir/$docker_image_archive" >/dev/null; then
    echo "Loaded daemon image archive: $docker_image_archive"
  else
    echo "error: failed to load verified daemon image archive $docker_image_archive" >&2
    exit 1
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
next_outcall="$BIN_DIR/outcall"
echo "First run (works even before you update PATH):"
echo "  cd /path/to/your/project"
echo "  $next_outcall run codex"
echo "  $next_outcall run claude"
echo
if [ "$os" = "Linux" ]; then
  echo "Next:"
  echo "  outcall run codex"
  echo "  outcall run claude"
  echo "  outcall run codex"
  echo
  echo "If the first run stops on a prerequisite, inspect it with:"
  echo "  outcall doctor"
  echo "  outcall doctor claude"
  echo "  outcall doctor codex"
else
  echo "Next:"
  echo "  outcall run codex"
  echo "  outcall run claude"
  echo
  echo "On macOS, Outcall uses Docker Desktop's Linux runtime for the daemon and"
  echo "agent containers."
  echo
  echo "For unattended Claude runs, prefer:"
  echo "  export ANTHROPIC_API_KEY=..."
fi
