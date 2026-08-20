#!/usr/bin/env bash
set -euo pipefail

network=${OUTCALL_NETWORK:-outcall-default}
dns=${OUTCALL_DNS:-10.200.0.1}
proxy=${OUTCALL_PROXY:-http://10.200.0.1:8080}

fail() {
  printf 'managed container security test failed: %s\n' "$*" >&2
  exit 1
}

has_line() {
  local content=$1
  local expected=$2
  grep -Fqx "$expected" <<<"$content"
}

[[ "$#" -gt 0 ]] || fail "pass at least one container name"
command -v docker >/dev/null 2>&1 || fail "docker is not installed"

for container in "$@"; do
  docker inspect "$container" >/dev/null 2>&1 || fail "container $container does not exist"

  managed_by=$(docker inspect --format '{{index .Config.Labels "managed-by"}}' "$container")
  [[ "$managed_by" == "outcalld" ]] || fail "$container is not daemon-managed"

  privileged=$(docker inspect --format '{{.HostConfig.Privileged}}' "$container")
  readonly_rootfs=$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container")
  pids_limit=$(docker inspect --format '{{.HostConfig.PidsLimit}}' "$container")
  memory_limit=$(docker inspect --format '{{.HostConfig.Memory}}' "$container")
  [[ "$privileged" == "false" ]] || fail "$container is privileged"
  [[ "$readonly_rootfs" == "true" ]] || fail "$container root filesystem is writable"
  [[ "$pids_limit" == "256" ]] || fail "$container PID limit is $pids_limit, expected 256"
  [[ "$memory_limit" == "536870912" ]] ||
    fail "$container memory limit is $memory_limit, expected 536870912"

  cap_drop=$(docker inspect --format '{{range .HostConfig.CapDrop}}{{println .}}{{end}}' "$container")
  security_opt=$(docker inspect --format '{{range .HostConfig.SecurityOpt}}{{println .}}{{end}}' "$container")
  has_line "$cap_drop" "ALL" || fail "$container does not drop all Linux capabilities"
  has_line "$security_opt" "no-new-privileges:true" ||
    fail "$container does not enforce no-new-privileges"

  attached=$(docker inspect \
    --format "{{if index .NetworkSettings.Networks \"$network\"}}true{{else}}false{{end}}" \
    "$container")
  network_count=$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$container")
  [[ "$attached" == "true" ]] || fail "$container is not attached to $network"
  [[ "$network_count" == "1" ]] ||
    fail "$container is attached to $network_count networks, expected exactly one"

  configured_dns=$(docker inspect --format '{{range .HostConfig.Dns}}{{println .}}{{end}}' "$container")
  has_line "$configured_dns" "$dns" || fail "$container DNS is not forced to $dns"

  environment=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container")
  has_line "$environment" "HTTP_PROXY=$proxy" || fail "$container HTTP proxy is not configured"
  has_line "$environment" "HTTPS_PROXY=$proxy" || fail "$container HTTPS proxy is not configured"
  has_line "$environment" "NO_PROXY=localhost,127.0.0.1" ||
    fail "$container NO_PROXY setting is broader than loopback"
  has_line "$environment" "http_proxy=$proxy" ||
    fail "$container lowercase HTTP proxy is not configured"
  has_line "$environment" "https_proxy=$proxy" ||
    fail "$container lowercase HTTPS proxy is not configured"
  has_line "$environment" "no_proxy=localhost,127.0.0.1" ||
    fail "$container lowercase no_proxy setting is broader than loopback"

  mounts=$(docker inspect \
    --format '{{range .Mounts}}{{printf "%s %t\n" .Destination .RW}}{{end}}' \
    "$container")
  has_line "$mounts" "/workspace true" || fail "$container workspace is not mounted read-write"
  has_line "$mounts" "/workspace/.outcall false" ||
    fail "$container policy directory is not mounted read-only"
  [[ "$mounts" != *"/var/run/docker.sock"* ]] || fail "$container can access the Docker socket"

  printf 'managed container security test passed: %s\n' "$container"
done
