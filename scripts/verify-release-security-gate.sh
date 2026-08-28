#!/usr/bin/env bash
set -euo pipefail

repository=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}
release_sha=${OUTCALL_RELEASE_SHA:?OUTCALL_RELEASE_SHA is required}
required_check='secure install + runtime + security validation'
timeout_seconds=${OUTCALL_SECURITY_GATE_TIMEOUT_SECONDS:-1800}
poll_seconds=${OUTCALL_SECURITY_GATE_POLL_SECONDS:-15}

[[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
  printf 'security gate timeout must be a positive integer\n' >&2
  exit 1
}
[[ "$poll_seconds" =~ ^[1-9][0-9]*$ ]] || {
  printf 'security gate poll interval must be a positive integer\n' >&2
  exit 1
}

deadline=$((SECONDS + timeout_seconds))
printf 'Waiting for %q on %s...\n' "$required_check" "$release_sha"

while ((SECONDS < deadline)); do
  if ! checks=$(gh api \
    -H 'Accept: application/vnd.github+json' \
    "/repos/$repository/commits/$release_sha/check-runs?per_page=100" \
    --jq ".check_runs[] | select(.name == \"$required_check\") | [.status, (.conclusion // \"\"), .html_url] | @tsv"); then
    printf 'GitHub check query failed; retrying in %s seconds.\n' "$poll_seconds" >&2
    sleep "$poll_seconds"
    continue
  fi

  if awk -F '\t' '$1 == "completed" && $2 == "success" { found = 1 } END { exit !found }' <<<"$checks"; then
    printf 'Release security gate passed for %s.\n' "$release_sha"
    exit 0
  fi

  if [[ -n "$checks" ]] &&
    ! awk -F '\t' '$1 != "completed" { pending = 1 } END { exit !pending }' <<<"$checks"; then
    printf 'Required security check completed without success:\n%s\n' "$checks" >&2
    exit 1
  fi

  sleep "$poll_seconds"
done

printf 'Timed out after %s seconds waiting for %q on %s.\n' \
  "$timeout_seconds" "$required_check" "$release_sha" >&2
exit 1
