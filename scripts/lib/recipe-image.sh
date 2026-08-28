#!/usr/bin/env bash

outcall_recipe_image() {
  local root_dir=$1
  local recipe=$2
  local version

  version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root_dir/outcall/Cargo.toml" | head -n 1)
  if [[ -z "$version" ]]; then
    printf 'failed to read Outcall version from %s\n' "$root_dir/outcall/Cargo.toml" >&2
    return 1
  fi
  printf 'ghcr.io/outcall-dev/outcall-recipe-%s:v%s\n' "$recipe" "$version"
}
