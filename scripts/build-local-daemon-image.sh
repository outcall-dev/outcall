#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <release-directory>" >&2
  exit 2
fi

if [ "$(uname -s)" != "Linux" ]; then
  echo "error: prebuilt daemon image packaging requires Linux host binaries" >&2
  echo "On macOS, use scripts/local-install-smoke.sh; it builds the Linux image inside Docker." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64) image_arch=amd64 ;;
  aarch64|arm64) image_arch=arm64 ;;
  *)
    echo "error: unsupported Linux architecture $(uname -m)" >&2
    exit 1
    ;;
esac

release_dir=$1
root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root_dir/outcall/Cargo.toml" | head -n 1)
runtime_image="outcall-daemon-runtime:ci-$version"
daemon_image="ghcr.io/outcall-dev/outcalld:v$version"
context_dir=$(mktemp -d "${TMPDIR:-/tmp}/outcall-daemon-context.XXXXXX")

cleanup() {
  rm -rf "$context_dir"
}
trap cleanup EXIT INT TERM

for binary in outcalld outcall outcall-agent; do
  test -x "$root_dir/target/release/$binary"
  cp "$root_dir/target/release/$binary" "$context_dir/$binary"
done

mkdir -p "$release_dir"

# Build only the shared Debian runtime stage; Rust was already built on the runner.
docker build --target runtime -t "$runtime_image" -f "$root_dir/Dockerfile" "$root_dir"
docker build \
  --build-arg "BASE_IMAGE=$runtime_image" \
  -t "$daemon_image" \
  -t ghcr.io/outcall-dev/outcalld:latest \
  -f "$root_dir/Dockerfile.prebuilt" \
  "$context_dir"
archive="$release_dir/outcalld-image-linux-$image_arch.tar.gz"
docker save "$daemon_image" ghcr.io/outcall-dev/outcalld:latest | gzip > "$archive"
sha256sum "$archive" > "$archive.sha256"
