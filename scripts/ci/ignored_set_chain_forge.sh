#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The chain forge's `#[ignore]`d set (CHAIN_FORGE.md §9), run by
# chain-forge.yml one subject per step. Each is minutes of proofs over a
# forged chain, so release, and not in the per-PR workspace tests.
#
#   --check            judge the set and stop (the per-PR Rust job; the
#                      debug build that job compiled).
#   --run <subject>    judge the set in release, then run that one subject
#                      (chain-forge.yml's steps).
#
# A subject is `<test target>::<test name>`. The set lives here, in the tree
# under test, for the reason ignored_set_chain_store.sh gives: a scheduled
# workflow runs the default branch's copy of its file.
#
# Rule 47, both ways: the set is exact. Every subject below must be in the
# crate's `--list --ignored`, so a renamed, deleted or un-ignored member
# fails here by name; every ignored test in the listing must be below, so a
# new `#[ignore]` stops the lane by name until it is added here. And a step
# runs a subject only through this script, by its exact name, so a step
# whose subject is renamed is refused rather than filtering to no test and
# passing. Either refusal comes before anything runs.
# Rule 46: the listing is captured once and judged; no verdict travels
# through a pipe.
set -euo pipefail
cd "$(dirname "$0")/../../rust"

# Run by chain-forge.yml, each by its own step.
subjects=(
  'determinism::the_small_plan_forges_the_same_bytes_in_two_processes'
  'determinism::each_source_drawn_from_the_os_moves_the_chain'
  'determinism::the_producer_plan_forges_the_same_bytes_in_two_processes'
  'determinism::the_shard_fill_plan_forges_its_pinned_chain_in_two_processes'
  'determinism::the_chain_l_plan_forges_its_pinned_chain_in_two_processes'
  'forged_chain::the_small_plan_is_regtests_alone_and_refuses_a_tampered_receipt'
  'forged_chain::chain_l_is_regtests_alone'
  'producer_audit::a_live_producer_run_settles_as_the_planned_one'
)
# Ignored so the set's parents can spawn them; never run on their own.
spawned=(
  'determinism::child_forge'
)

usage() {
  echo "usage: $0 --check | --run <target::test>" >&2
  exit 2
}

run=''
profile=()
case "$#:${1:-}" in
  1:--check) ;;
  2:--run)
    run=$2
    profile=(--release)
    ;;
  *) usage ;;
esac

# `--list --ignored` over every target of the crate, each name prefixed by
# the target cargo reports running it from (`tests/<t>.rs`, or `lib`).
if ! listing=$(cargo test --locked "${profile[@]}" -p shekyl-chain-forge --lib --tests -- --list --ignored 2>&1); then
  printf '%s\n' "$listing" >&2
  echo "::error::shekyl-chain-forge's ignored tests could not be listed" >&2
  exit 1
fi
listed=$(awk '
  /^ *Running unittests / { target = "lib"; next }
  /^ *Running tests\// { target = $2; sub(/^tests\//, "", target); sub(/\.rs$/, "", target); next }
  /^ *Running / { target = $2; next }
  /: test$/ { sub(/: test$/, ""); print target "::" $0 }
' <<< "$listing")

in_list() {
  local needle=$1
  shift
  local item
  for item in "$@"; do
    if [ "$item" = "$needle" ]; then return 0; fi
  done
  return 1
}

wrong=0
for subject in "${subjects[@]}" "${spawned[@]}"; do
  if ! grep -qxF -- "$subject" <<< "$listed"; then
    echo "::error::${subject} is not in shekyl-chain-forge's ignored set"
    wrong=1
  fi
done
while IFS= read -r name; do
  [ -n "$name" ] || continue
  if ! in_list "$name" "${subjects[@]}" "${spawned[@]}"; then
    echo "::error::${name} is an ignored test this lane does not list: add it to scripts/ci/ignored_set_chain_forge.sh and a chain-forge.yml step, or stop ignoring it"
    wrong=1
  fi
done <<< "$listed"
if [ "$wrong" -ne 0 ]; then
  exit 1
fi
echo "shekyl-chain-forge ignored set: ${#subjects[@]} subject(s) and ${#spawned[@]} spawned, exactly the listed set"

if [ -z "$run" ]; then
  exit 0
fi
if in_list "$run" "${spawned[@]}"; then
  echo "::error::${run} is spawned by its parent test; run the parent" >&2
  exit 1
fi
if ! in_list "$run" "${subjects[@]}"; then
  echo "::error::${run} is not a subject of this lane" >&2
  exit 1
fi
target=${run%%::*}
name=${run#*::}
cargo test --locked --release -p shekyl-chain-forge --test "$target" -- \
  --ignored --exact --nocapture --test-threads=1 "$name"
