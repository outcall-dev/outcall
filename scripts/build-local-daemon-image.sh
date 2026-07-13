#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <release-directory>" >&2
  exit 2
fi

release_dir=$1
root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
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
docker save "$daemon_image" ghcr.io/outcall-dev/outcalld:latest | gzip > "$release_dir/outcalld-image-linux-amd64.tar.gz"
sha256sum "$release_dir/outcalld-image-linux-amd64.tar.gz" > "$release_dir/outcalld-image-linux-amd64.tar.gz.sha256"
