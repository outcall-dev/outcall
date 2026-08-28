#!/usr/bin/env bash
set -euo pipefail

root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=scripts/lib/recipe-image.sh
source "$root_dir/scripts/lib/recipe-image.sh"
project_dir=${1:-$PWD}
recipe=${2:-codex}
outcall_bin=${OUTCALL_BIN:-outcall}
daemon=${OUTCALL_DAEMON_CONTAINER:-outcall-daemon}
network=${OUTCALL_NETWORK:-outcall-default}
image=${OUTCALL_PREFLIGHT_IMAGE:-$(outcall_recipe_image "$root_dir" codex)}
control=${OUTCALL_NETFILTER_CONTROL:-auto}
test_container="outcall-disabled-netfilter-must-not-start-$$"
helper_container="outcall-netfilter-toggle-$$"

ipv4_key=net.bridge.bridge-nf-call-iptables
ipv6_key=net.bridge.bridge-nf-call-ip6tables
ipv4_path=/proc/sys/net/bridge/bridge-nf-call-iptables
ipv6_path=/proc/sys/net/bridge/bridge-nf-call-ip6tables

fail() {
  printf 'netfilter preflight test failed: %s\n' "$*" >&2
  exit 1
}

if [[ "$control" == "auto" ]]; then
  if [[ "$(uname -s)" == "Linux" ]]; then
    control=host
  else
    control=helper
  fi
fi
[[ "$control" == "host" || "$control" == "daemon" || "$control" == "helper" ]] ||
  fail "OUTCALL_NETFILTER_CONTROL must be auto, host, daemon, or helper"

command -v docker >/dev/null 2>&1 || fail "docker is not installed"
[[ -x "$outcall_bin" ]] || command -v "$outcall_bin" >/dev/null 2>&1 ||
  fail "outcall binary is not executable: $outcall_bin"
[[ -d "$project_dir" ]] || fail "project directory does not exist: $project_dir"
docker inspect "$daemon" >/dev/null 2>&1 || fail "daemon container $daemon does not exist"
docker network inspect "$network" >/dev/null 2>&1 || fail "network $network does not exist"

read_setting() {
  local path=$1
  if [[ "$control" == "host" ]]; then
    tr -d '[:space:]' <"$path"
  else
    docker exec "$daemon" cat "$path" | tr -d '[:space:]'
  fi
}

helper_started=false
restore_helper() {
  local _attempt

  if [[ "$helper_started" != "true" ]]; then
    return
  fi
  if docker inspect "$helper_container" >/dev/null 2>&1; then
    docker exec "$helper_container" touch /tmp/outcall-netfilter-restore >/dev/null 2>&1 || true
    for _attempt in {1..50}; do
      if ! docker inspect "$helper_container" >/dev/null 2>&1; then
        helper_started=false
        return
      fi
      sleep 0.1
    done
    docker stop --time 10 "$helper_container" >/dev/null 2>&1 || true
  fi
  helper_started=false
}

start_helper() {
  local daemon_image helper_ready _attempt

  daemon_image=$(docker inspect --format '{{.Config.Image}}' "$daemon")
  docker image inspect "$daemon_image" >/dev/null 2>&1 ||
    fail "daemon image does not exist: $daemon_image"
  docker run --rm -d \
    --name "$helper_container" \
    --privileged \
    --pid=host \
    --network=host \
    --entrypoint sh \
    "$daemon_image" \
    -c '
      set -eu
      ipv4_path=/proc/sys/net/bridge/bridge-nf-call-iptables
      ipv6_path=/proc/sys/net/bridge/bridge-nf-call-ip6tables
      original_ipv4=$(cat "$ipv4_path")
      original_ipv6=$(cat "$ipv6_path")
      restore() {
        printf "%s\n" "$original_ipv4" >"$ipv4_path"
        printf "%s\n" "$original_ipv6" >"$ipv6_path"
      }
      trap restore EXIT HUP INT TERM
      printf "0\n" >"$ipv4_path"
      printf "0\n" >"$ipv6_path"
      printf "ready\n"
      while [ ! -e /tmp/outcall-netfilter-restore ]; do sleep 1; done
    ' >/dev/null
  helper_started=true

  helper_ready=false
  for _attempt in {1..50}; do
    if docker logs "$helper_container" 2>&1 | grep -Fqx ready; then
      helper_ready=true
      break
    fi
    sleep 0.1
  done
  [[ "$helper_ready" == "true" ]] || fail "privileged netfilter helper did not become ready"
}

set_setting() {
  local key=$1
  local path=$2
  local value=$3
  if [[ "$control" == "host" ]]; then
    sudo sysctl -w "$key=$value" >/dev/null
  else
    docker exec "$daemon" sh -c 'printf "%s\n" "$2" > "$1"' sh "$path" "$value"
  fi
}

original_ipv4=$(read_setting "$ipv4_path")
original_ipv6=$(read_setting "$ipv6_path")
[[ "$original_ipv4" == "1" && "$original_ipv6" == "1" ]] ||
  fail "test requires both hooks enabled first (ipv4=$original_ipv4 ipv6=$original_ipv6)"

ipv4_changed=false
ipv6_changed=false
cleanup() {
  docker rm -f "$test_container" >/dev/null 2>&1 || true
  set +e
  if [[ "$control" == "helper" ]]; then
    restore_helper
  elif [[ "$ipv4_changed" == "true" ]]; then
    set_setting "$ipv4_key" "$ipv4_path" "$original_ipv4"
  fi
  if [[ "$control" != "helper" && "$ipv6_changed" == "true" ]]; then
    set_setting "$ipv6_key" "$ipv6_path" "$original_ipv6"
  fi
  set -e
}
trap cleanup EXIT

if [[ "$control" == "helper" ]]; then
  start_helper
  ipv4_changed=true
  ipv6_changed=true
else
  if ! set_setting "$ipv4_key" "$ipv4_path" 0; then
    fail "cannot disable the IPv4 bridge hook through $control control; run this test on a privileged Linux host"
  fi
  ipv4_changed=true
  if ! set_setting "$ipv6_key" "$ipv6_path" 0; then
    fail "cannot disable the IPv6 bridge hook through $control control; run this test on a privileged Linux host"
  fi
  ipv6_changed=true
fi
[[ "$(read_setting "$ipv4_path")" == "0" && "$(read_setting "$ipv6_path")" == "0" ]] ||
  fail "could not disable both hooks through $control control"

set +e
recipe_output=$(cd "$project_dir" && "$outcall_bin" recipe test "$recipe" --no-build 2>&1)
recipe_status=$?
set -e
[[ "$recipe_status" -ne 0 ]] || fail "CLI preflight passed with bridge netfilter disabled"
printf '%s\n' "$recipe_output" |
  grep -Fq "Secure unattended mode requires bridge netfilter enforcement" ||
  fail "CLI preflight returned the wrong failure: $recipe_output"

set +e
daemon_output=$(cd "$project_dir" && "$outcall_bin" container create \
  --image "$image" \
  --network "$network" \
  --name "$test_container" 2>&1)
daemon_status=$?
set -e
[[ "$daemon_status" -ne 0 ]] || fail "daemon API created a container with netfilter disabled"
printf '%s\n' "$daemon_output" |
  grep -Fq "Secure unattended mode requires bridge netfilter enforcement" ||
  fail "daemon API returned the wrong failure: $daemon_output"
if docker inspect "$test_container" >/dev/null 2>&1; then
  fail "daemon API leaked a container after rejecting disabled netfilter"
fi

if [[ "$control" == "helper" ]]; then
  restore_helper
else
  set_setting "$ipv4_key" "$ipv4_path" "$original_ipv4"
  set_setting "$ipv6_key" "$ipv6_path" "$original_ipv6"
fi
ipv4_changed=false
ipv6_changed=false
[[ "$(read_setting "$ipv4_path")" == "$original_ipv4" ]] || fail "IPv4 hook was not restored"
[[ "$(read_setting "$ipv6_path")" == "$original_ipv6" ]] || fail "IPv6 hook was not restored"
if docker inspect "$helper_container" >/dev/null 2>&1; then
  fail "netfilter helper container leaked after cleanup"
fi

printf 'netfilter preflight test passed: CLI and daemon API fail closed (%s control)\n' "$control"
