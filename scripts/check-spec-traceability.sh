#!/bin/sh
set -eu

manifest="${1:-spec-traceability.tsv}"
expected_header='spec_id	implementation_path	primary_test_path	status'
actual_header="$(sed -n '1p' "$manifest")"

if [ "$actual_header" != "$(printf '%b' "$expected_header")" ]; then
  echo "invalid traceability header in $manifest" >&2
  exit 1
fi

tab="$(printf '\t')"
seen=""
line_number=1
skip_header=true
while IFS="$tab" read -r spec_id implementation_path primary_test_path status extra; do
  if [ "$skip_header" = true ]; then
    skip_header=false
    continue
  fi
  line_number=$((line_number + 1))
  [ -n "$spec_id" ] || continue

  case "$spec_id" in
    S[0-9][0-9][0-9]) ;;
    *)
      echo "$manifest:$line_number: invalid spec ID: $spec_id" >&2
      exit 1
      ;;
  esac
  case " $seen " in
    *" $spec_id "*)
      echo "$manifest:$line_number: duplicate spec ID: $spec_id" >&2
      exit 1
      ;;
  esac
  seen="$seen $spec_id"

  if [ -n "${extra:-}" ]; then
    echo "$manifest:$line_number: expected exactly four tab-separated columns" >&2
    exit 1
  fi
  case "$status" in
    implemented|partial) ;;
    *)
      echo "$manifest:$line_number: invalid status for $spec_id: $status" >&2
      exit 1
      ;;
  esac
  if [ ! -f "$implementation_path" ]; then
    echo "$manifest:$line_number: implementation path does not exist: $implementation_path" >&2
    exit 1
  fi
  if [ ! -f "$primary_test_path" ]; then
    echo "$manifest:$line_number: test path does not exist: $primary_test_path" >&2
    exit 1
  fi
done < "$manifest"

number=0
while [ "$number" -le 15 ]; do
  spec_id="S$(printf '%03d' "$number")"
  case " $seen " in
    *" $spec_id "*) ;;
    *)
      echo "$manifest: missing required subsystem mapping for $spec_id" >&2
      exit 1
      ;;
  esac
  number=$((number + 1))
done

echo "Traceability manifest is valid: $manifest"
