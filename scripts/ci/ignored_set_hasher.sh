#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The hasher crate's `#[ignore]`d set, run by nightly.yml's hasher-ignored
# job. The set lives here, in the tree under test, for the reason
# ignored_set_chain_store.sh gives: a scheduled workflow runs the default
# branch's copy of nightly.yml over every branch in its matrix, so a list
# written there would judge `dev` by `main`'s.
#
# The set: the core's property test driven through the real shell, with
# threads, real 256 MiB derives, lists changing under the jobs and waiters
# stopping (docs/design/RANDOMX_CACHE_ACTOR.md §8). It finds what the
# core's per-PR property test cannot see: a lost wake-up, a lease kept past
# its return, a deadlock between the hasher's lock and the budget. Hundreds
# of derives, so release, and not per pull request.
#
# Budget: 172 s in release on a 16-core workstation under load (2026-11-12);
# the job allows 60 minutes for a 4-vCPU runner.
#
# Rule 47, both ways: the set is exact. Every subject below must be in the
# crate's `--list --ignored`, so a renamed, deleted or un-ignored member
# fails here by name; and every ignored test in the listing must be below,
# so a new `#[ignore]` stops the lane by name until it is added here (or
# made a non-ignored test). Either refusal comes before anything runs.
# `--check` (ignored_set_mode.sh) stops after this judgement. The per-PR
# Rust job uses it; the run below is the nightly lane.
# Rule 46: the listing is captured once and judged; no verdict travels
# through a pipe.
set -euo pipefail
. "$(dirname "$0")/ignored_set_mode.sh"
ignored_set_mode "$@"
cd "$(dirname "$0")/../../rust"
branch="${BRANCH:-the checked-out ref}"

subjects=(
  'shell_tests::a_long_random_sequence_through_the_shell_keeps_the_cap_and_quiesces_to_the_list'
)

list=$(cargo test --locked "${ignored_set_profile[@]}" -p shekyl-hasher --lib -- --list --ignored)
listed=$(sed -n 's/: test$//p' <<< "$list")

missing=0
for subject in "${subjects[@]}"; do
  if ! grep -qxF -- "$subject" <<< "$listed"; then
    echo "::error::${subject} is not in shekyl-hasher's ignored set"
    missing=1
  fi
done

extra=0
while IFS= read -r name; do
  [ -n "$name" ] || continue
  known=0
  for subject in "${subjects[@]}"; do
    if [ "$name" = "$subject" ]; then known=1; break; fi
  done
  if [ "$known" -eq 0 ]; then
    echo "::error::${name} is an ignored test this lane does not list: add it to scripts/ci/ignored_set_hasher.sh, or stop ignoring it"
    extra=1
  fi
done <<< "$listed"

if [ "$missing" -ne 0 ] || [ "$extra" -ne 0 ]; then
  exit 1
fi
echo "shekyl-hasher ignored set: ${#subjects[@]} test(s), exactly the listed set"
ignored_set_stop_after_judgement

START=$(date +%s)
cargo test --locked --release -p shekyl-hasher --lib -- --ignored --nocapture
END=$(date +%s)
echo "::notice::Hasher ignored set completed on ${branch} in $((END - START))s (budget 60m)"
