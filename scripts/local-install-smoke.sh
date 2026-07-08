#!/bin/sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
release_root="${OUTCALL_LOCAL_RELEASE_DIR:-$repo_root/release-smoke-local}"
smoke_home="${OUTCALL_SMOKE_HOME:-$(mktemp -d "${TMPDIR:-/tmp}/outcall-local-home.XXXXXX")}"
bin_dir="${OUTCALL_BIN_DIR:-$smoke_home/.local/bin}"
project_dir="${OUTCALL_SMOKE_PROJECT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/outcall-local-project.XXXXXX")}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

need_cmd cargo
need_cmd tar
need_cmd mktemp
need_cmd sed

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
    exit 1
    ;;
esac

version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_root/outcall/Cargo.toml" | head -n1)"

echo "==> Building release binaries for $target"
cargo build --release --workspace --locked

echo "==> Packaging local release into $release_root"
rm -rf "$release_root"
mkdir -p "$release_root/$target"
cp "$repo_root/target/release/outcall" "$release_root/$target/"
cp "$repo_root/target/release/outcalld" "$release_root/$target/"
cp "$repo_root/target/release/outcall-agent" "$release_root/$target/"
tar -czf "$release_root/$target.tar.gz" -C "$release_root/$target" .

if [ -n "$docker_image_archive" ] && command -v docker >/dev/null 2>&1 && command -v gzip >/dev/null 2>&1; then
  echo "==> Building local daemon image archive"
  docker build \
    -t "ghcr.io/outcall-dev/outcalld:v$version" \
    -t "ghcr.io/outcall-dev/outcalld:latest" \
    "$repo_root"
  docker save \
    "ghcr.io/outcall-dev/outcalld:v$version" \
    "ghcr.io/outcall-dev/outcalld:latest" | gzip > "$release_root/$docker_image_archive"
fi

echo "==> Installing from local file:// release"
OUTCALL_VERSION="$version" \
OUTCALL_RELEASE_BASE_URL="file://$release_root" \
OUTCALL_BIN_DIR="$bin_dir" \
sh "$repo_root/scripts/install.sh"

echo
echo "==> Verifying installed binaries"
"$bin_dir/outcall" --version
"$bin_dir/outcalld" --version
"$bin_dir/outcall-agent" --version

if [ "$#" -gt 0 ]; then
  echo
  echo "==> Running post-install command in $project_dir"
  mkdir -p "$project_dir"
  (
    cd "$project_dir"
    HOME="$smoke_home" \
    PATH="$bin_dir:$PATH" \
    "$@"
  )
fi

echo
echo "Local install smoke complete"
echo "  version:      $version"
echo "  release dir:  $release_root"
echo "  smoke home:   $smoke_home"
echo "  bin dir:      $bin_dir"
echo "  project dir:  $project_dir"
