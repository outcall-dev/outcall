#!/usr/bin/env bash
set -euo pipefail

root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=scripts/lib/recipe-image.sh
source "$root_dir/scripts/lib/recipe-image.sh"
if [[ -n "${OUTCALL_BIN:-}" ]]; then
  outcall_bin=$OUTCALL_BIN
elif [[ -x "$root_dir/target/release/outcall" ]]; then
  outcall_bin="$root_dir/target/release/outcall"
else
  outcall_bin=outcall
fi
network=${OUTCALL_NETWORK:-outcall-default}
base_image=${OUTCALL_EGRESS_BASE_IMAGE:-$(outcall_recipe_image "$root_dir" codex)}
probe_image=${OUTCALL_EGRESS_IMAGE:-outcall-egress-policy:local}
allowed_host=${OUTCALL_EGRESS_ALLOWED_HOST:-github.com}
denied_host=${OUTCALL_EGRESS_DENIED_HOST:-example.com}
suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
container="outcall-egress-policy-$suffix"

fail() {
  printf 'egress policy test failed: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || fail "docker is not installed"
command -v "$outcall_bin" >/dev/null 2>&1 || fail "Outcall CLI not found: $outcall_bin"
docker network inspect "$network" >/dev/null 2>&1 || fail "network $network does not exist"
docker image inspect "$base_image" >/dev/null 2>&1 || fail "image $base_image does not exist"

docker build --quiet \
  --build-arg "BASE_IMAGE=$base_image" \
  --tag "$probe_image" \
  --file "$root_dir/tests/fixtures/egress-probe/Dockerfile" \
  "$root_dir/tests/fixtures/egress-probe" >/dev/null

"$outcall_bin" container create \
  --image "$probe_image" \
  --network "$network" \
  --name "$container" >/dev/null

running=$(docker inspect --format '{{.State.Running}}' "$container")
[[ "$running" == "true" ]] || fail "managed probe did not remain running"

docker exec "$container" getent ahostsv4 "$allowed_host" >/dev/null ||
  fail "allowed DNS query for $allowed_host failed"
if docker exec "$container" getent ahostsv4 "$denied_host" >/dev/null 2>&1; then
  fail "denied DNS query for $denied_host returned an address"
fi

https_status=$(docker exec "$container" curl \
  --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --connect-timeout 10 --max-time 20 "https://$allowed_host/") ||
  fail "allowed HTTPS request to $allowed_host failed"
[[ "$https_status" =~ ^(2|3)[0-9][0-9]$ ]] ||
  fail "allowed HTTPS request returned HTTP $https_status"

set +e
denied_status=$(docker exec "$container" curl \
  --silent --output /dev/null --write-out '%{http_connect}' \
  --connect-timeout 10 --max-time 20 "https://$denied_host/")
denied_curl_status=$?
set -e
[[ "$denied_status" == "403" ]] ||
  fail "denied HTTPS CONNECT returned HTTP $denied_status (curl exit $denied_curl_status), expected 403"

plaintext_status=$(docker exec "$container" curl \
  --silent --output /dev/null --write-out '%{http_code}' \
  --connect-timeout 10 --max-time 20 "http://$allowed_host/") ||
  fail "plaintext HTTP request did not receive the policy response"
[[ "$plaintext_status" == "403" ]] ||
  fail "plaintext HTTP request returned HTTP $plaintext_status, expected 403"

allowed_ip=$(docker exec "$container" getent ahostsv4 "$allowed_host" |
  awk 'NR == 1 { print $1 }')
[[ -n "$allowed_ip" ]] || fail "allowed host did not resolve to an IPv4 address"
if docker exec "$container" curl \
  --silent --show-error --insecure --output /dev/null \
  --noproxy '*' --connect-timeout 3 --max-time 5 \
  --resolve "$allowed_host:443:$allowed_ip" "https://$allowed_host/" \
  >/dev/null 2>&1; then
  fail "direct-IP HTTPS bypass reached $allowed_host without the proxy"
fi

raw_dns_script='const dgram=require("dgram"); const socket=dgram.createSocket("udp4"); const query=Buffer.from([0x12,0x34,0x01,0x00,0,0x01,0,0,0,0,0,0,0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x03,0x63,0x6f,0x6d,0,0,0x01,0,0x01]); socket.on("message",()=>process.exit(42)); socket.on("error",()=>process.exit(0)); socket.send(query,53,"1.1.1.1"); setTimeout(()=>process.exit(0),1500);'
set +e
docker exec "$container" node -e "$raw_dns_script" >/dev/null 2>&1
raw_dns_status=$?
set -e
[[ "$raw_dns_status" == "0" ]] ||
  fail "raw external DNS received a response (exit $raw_dns_status)"

cleanup
trap - EXIT
docker inspect "$container" >/dev/null 2>&1 && fail "probe container leaked after cleanup"

printf 'egress policy test passed: HTTPS allow, policy denies, forced DNS, and bypass blocking\n'
