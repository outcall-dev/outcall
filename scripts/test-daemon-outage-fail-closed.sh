#!/usr/bin/env bash
set -euo pipefail

root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=scripts/lib/recipe-image.sh
source "$root_dir/scripts/lib/recipe-image.sh"
network=${OUTCALL_NETWORK:-outcall-default}
bridge=${OUTCALL_BRIDGE:-outcall0}
daemon=${OUTCALL_DAEMON_CONTAINER:-outcall-daemon}
probe_image=${OUTCALL_ISOLATION_IMAGE:-$(outcall_recipe_image "$root_dir" codex)}
suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
source_container="outcall-outage-source-$suffix"
target_container="outcall-outage-target-$suffix"
inspector_container="outcall-outage-inspector-$suffix"
daemon_needs_restart=false

fail() {
  printf 'daemon outage test failed: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  docker rm -f \
    "$source_container" \
    "$target_container" \
    "$inspector_container" >/dev/null 2>&1 || true
  if [[ "$daemon_needs_restart" == "true" ]]; then
    docker start "$daemon" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || fail "docker is not installed"
docker network inspect "$network" >/dev/null 2>&1 || fail "network $network does not exist"
docker image inspect "$probe_image" >/dev/null 2>&1 || fail "image $probe_image does not exist"

daemon_running=$(docker inspect --format '{{.State.Running}}' "$daemon" 2>/dev/null) ||
  fail "daemon container $daemon does not exist"
[[ "$daemon_running" == "true" ]] || fail "daemon container $daemon is not running"

daemon_network=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$daemon")
[[ "$daemon_network" == "host" ]] ||
  fail "daemon container $daemon uses network mode $daemon_network, expected host"
daemon_image=$(docker inspect --format '{{.Config.Image}}' "$daemon")
docker image inspect "$daemon_image" >/dev/null 2>&1 ||
  fail "daemon image $daemon_image does not exist"

actual_bridge=$(docker network inspect \
  --format '{{index .Options "com.docker.network.bridge.name"}}' \
  "$network")
[[ "$actual_bridge" == "$bridge" ]] ||
  fail "network $network uses bridge $actual_bridge, expected $bridge"

idle_script='setInterval(() => {}, 60_000);'
server_script='const http = require("http"); http.createServer((_request, response) => { response.end("outcall-outage-ok"); }).listen(8080, "0.0.0.0");'
client_script='const http = require("http"); const timer = setTimeout(() => process.exit(23), 3000); const request = http.get(process.argv[1], (response) => { response.resume(); response.on("end", () => { clearTimeout(timer); process.exit(response.statusCode === 200 ? 0 : 22); }); }); request.on("error", () => { clearTimeout(timer); process.exit(23); });'

docker run -d \
  --name "$source_container" \
  --network "$network" \
  --entrypoint node \
  "$probe_image" \
  -e "$idle_script" >/dev/null

docker run -d \
  --name "$target_container" \
  --network "$network" \
  --entrypoint node \
  "$probe_image" \
  -e "$server_script" >/dev/null

target_ready=false
for _attempt in {1..20}; do
  if docker exec "$target_container" node -e "$client_script" http://127.0.0.1:8080; then
    target_ready=true
    break
  fi
  sleep 0.25
done
[[ "$target_ready" == "true" ]] || fail "target HTTP service did not become ready"

source_ip=$(docker inspect \
  --format "{{(index .NetworkSettings.Networks \"$network\").IPAddress}}" \
  "$source_container")
target_ip=$(docker inspect \
  --format "{{(index .NetworkSettings.Networks \"$network\").IPAddress}}" \
  "$target_container")
[[ -n "$source_ip" && -n "$target_ip" ]] || fail "probe containers have no IPv4 address"

# Model an active dynamic direct-egress grant. Graceful shutdown must replace
# the table atomically so this grant cannot survive without the control plane.
docker exec "$daemon" nft insert rule inet outcall forward \
  iifname "$bridge" \
  ip saddr "$source_ip" \
  ip daddr "$target_ip" \
  tcp dport 8080 accept

docker exec "$source_container" node -e "$client_script" "http://$target_ip:8080" ||
  fail "temporary direct-egress grant did not allow the probe"

daemon_needs_restart=true
docker stop --time 30 "$daemon" >/dev/null || fail "could not stop daemon $daemon"

ruleset=$(docker run --rm \
  --name "$inspector_container" \
  --network host \
  --cap-add NET_ADMIN \
  --entrypoint nft \
  "$daemon_image" \
  list table inet outcall) || fail "nftables policy disappeared with the daemon"

[[ "$ruleset" == *"hook forward"* ]] || fail "forward hook is missing after daemon shutdown"
[[ "$ruleset" == *"policy drop"* ]] || fail "forward policy is not drop after daemon shutdown"
[[ "$ruleset" == *"$bridge"* ]] || fail "rules no longer reference bridge $bridge"
[[ "$ruleset" != *"$source_ip"* ]] || fail "temporary direct-egress grant survived shutdown"

set +e
blocked_output=$(docker exec "$source_container" \
  node -e "$client_script" "http://$target_ip:8080" 2>&1)
blocked_status=$?
set -e
case "$blocked_status" in
  23)
    ;;
  0)
    fail "source reached its peer after the daemon stopped"
    ;;
  *)
    printf '%s\n' "$blocked_output" >&2
    fail "post-shutdown probe failed for an unexpected reason (exit $blocked_status)"
    ;;
esac

docker start "$daemon" >/dev/null || fail "could not restart daemon $daemon"
daemon_ready=false
for _attempt in {1..40}; do
  if docker exec "$daemon" nft list table inet outcall >/dev/null 2>&1; then
    daemon_ready=true
    break
  fi
  sleep 0.25
done
[[ "$daemon_ready" == "true" ]] || {
  docker logs "$daemon" >&2 || true
  fail "daemon did not restore its nftables policy after restart"
}
daemon_needs_restart=false

printf 'daemon outage test passed: %s retained a strict policy and restarted cleanly\n' "$daemon"
