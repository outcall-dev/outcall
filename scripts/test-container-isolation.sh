#!/usr/bin/env bash
set -euo pipefail

network=${OUTCALL_NETWORK:-outcall-default}
bridge=${OUTCALL_BRIDGE:-outcall0}
daemon=${OUTCALL_DAEMON_CONTAINER:-outcall-daemon}
image=${OUTCALL_ISOLATION_IMAGE:-outcall-recipe-codex:local}
suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
source_container="outcall-isolation-source-$suffix"
target_container="outcall-isolation-target-$suffix"
host_container="outcall-isolation-host-$suffix"
host_port=$((20000 + ($$ % 20000)))

fail() {
  printf 'container isolation test failed: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  docker rm -f "$source_container" "$target_container" "$host_container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || fail "docker is not installed"
docker network inspect "$network" >/dev/null 2>&1 || fail "network $network does not exist"
docker image inspect "$image" >/dev/null 2>&1 || fail "image $image does not exist"

actual_bridge=$(docker network inspect \
  --format '{{index .Options "com.docker.network.bridge.name"}}' \
  "$network")
[[ "$actual_bridge" == "$bridge" ]] ||
  fail "network $network uses bridge $actual_bridge, expected $bridge"

daemon_running=$(docker inspect --format '{{.State.Running}}' "$daemon" 2>/dev/null) ||
  fail "daemon container $daemon does not exist"
[[ "$daemon_running" == "true" ]] || fail "daemon container $daemon is not running"

for setting in bridge-nf-call-iptables bridge-nf-call-ip6tables; do
  value=$(docker exec "$daemon" cat "/proc/sys/net/bridge/$setting" | tr -d '[:space:]')
  [[ "$value" == "1" ]] || fail "$setting is $value, expected 1"
done

ruleset=$(docker exec "$daemon" nft list table inet outcall) ||
  fail "daemon has no inet outcall nftables table"
[[ "$ruleset" == *"hook forward"* ]] || fail "nftables forward hook is missing"
[[ "$ruleset" == *"policy drop"* ]] || fail "nftables forward policy is not drop"
[[ "$ruleset" == *"$bridge"* ]] || fail "nftables rules do not reference $bridge"
[[ "$ruleset" == *"chain input_from_agents"* ]] ||
  fail "nftables agent-to-host chain is missing"
[[ "$ruleset" == *"udp dport 53 accept"* ]] || fail "DNS host exception is missing"
[[ "$ruleset" == *"tcp dport 8080 accept"* ]] || fail "proxy host exception is missing"
[[ "$ruleset" == *"meta nfproto ipv4 drop"* ]] ||
  fail "agent-to-host IPv4 deny rule is missing"

server_script='const http = require("http"); http.createServer((_request, response) => { response.end("outcall-isolation-ok"); }).listen(8080, "0.0.0.0");'
host_server_script='const http = require("http"); const port = Number(process.argv[1]); http.createServer((_request, response) => { response.end("unauthorized-host-service"); }).listen(port, "0.0.0.0");'
client_script='const http = require("http"); const timer = setTimeout(() => process.exit(23), 3000); const request = http.get(process.argv[1], (response) => { response.resume(); response.on("end", () => { clearTimeout(timer); process.exit(response.statusCode === 200 ? 0 : 22); }); }); request.on("error", () => { clearTimeout(timer); process.exit(23); });'

expect_source_blocked() {
  local label=$1
  local url=$2
  local output
  local status

  set +e
  output=$(docker run --rm \
    --name "$source_container" \
    --network "$network" \
    --entrypoint node \
    "$image" \
    -e "$client_script" "$url" 2>&1)
  status=$?
  set -e

  case "$status" in
    23)
      ;;
    0)
      fail "source container reached $label despite the deny policy"
      ;;
    *)
      printf '%s\n' "$output" >&2
      fail "$label probe failed for an unexpected reason (exit $status)"
      ;;
  esac
}

docker run -d \
  --name "$target_container" \
  --network "$network" \
  --entrypoint node \
  "$image" \
  -e "$server_script" >/dev/null

target_ready=false
for _attempt in {1..20}; do
  if docker exec "$target_container" node -e "$client_script" http://127.0.0.1:8080; then
    target_ready=true
    break
  fi
  sleep 0.25
done
[[ "$target_ready" == "true" ]] || {
  docker logs "$target_container" >&2
  fail "target HTTP service did not become ready"
}

docker run -d \
  --name "$host_container" \
  --network host \
  --entrypoint node \
  "$image" \
  -e "$host_server_script" "$host_port" >/dev/null

host_ready=false
for _attempt in {1..20}; do
  if docker exec "$host_container" node -e "$client_script" "http://127.0.0.1:$host_port"; then
    host_ready=true
    break
  fi
  sleep 0.25
done
[[ "$host_ready" == "true" ]] || {
  docker logs "$host_container" >&2
  fail "unauthorized host HTTP service did not become ready"
}

gateway=$(docker network inspect --format '{{(index .IPAM.Config 0).Gateway}}' "$network")
[[ -n "$gateway" ]] || fail "network $network has no IPv4 gateway"

docker run --rm \
  --name "$source_container" \
  --network "$network" \
  --entrypoint node \
  "$image" \
  -e "$client_script" "http://$gateway:8080/outcall-health" ||
  fail "source container cannot reach the Outcall proxy on the bridge gateway"

expect_source_blocked "host service $gateway:$host_port" "http://$gateway:$host_port"

target_ip=$(docker inspect \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
  "$target_container")
[[ -n "$target_ip" ]] || fail "target container has no IPv4 address"

expect_source_blocked "peer $target_ip:8080" "http://$target_ip:8080"

cleanup
trap - EXIT

for container in "$source_container" "$target_container" "$host_container"; do
  if docker inspect "$container" >/dev/null 2>&1; then
    fail "test container $container leaked after cleanup"
  fi
done

printf 'container isolation test passed: %s blocks peer traffic on %s\n' "$network" "$bridge"
