#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The chain store's `#[ignore]`d set, run by nightly.yml's store-ignored
# job. The set lives here, in the tree under test, and not in the workflow
# file: a scheduled workflow runs the default branch's copy of nightly.yml
# over every branch in its matrix, so a set written there judged `dev` by
# `main`'s list (#1094 and #1095: a test deleted on dev on 2026-10-09 stayed
# named on both branches' copies until this script). Each branch now judges
# itself, and the `workflow_dispatch` `ref` input proves a branch's own set.
#
# The set: the shard-boundary deletion test over real multi-input spends
# (`prune_tests::the_boundary_batch_discards_closed_shards_on_real_spends`,
# minutes of proving — the unit lane runs its padded-record twin) and the
# two benches (`weights_read_bench`, `slash_scan_bench`). An `#[ignore]`d
# test no scheduled lane runs is a deleted test with a comment on it.
#
# Rule 47: the lane asserts every subject it owns is in the set before
# running it — a renamed, deleted or un-ignored member fails here by name,
# not by passing a run that no longer contains it. The names are the lane's
# charter; a further ignored test runs too and is counted, and joins the
# list when it is this lane's to own. The benches run at their defaults: a
# default that builds a chain the constants refuse is exactly what this lane
# exists to see. Rule 46: the listing is captured once and judged, and the
# count that judges it reads to the end of its input (a `grep -q` can end
# the pipe early and fail `pipefail` on a match); the run's own exit is the
# verdict and travels through no pipe.
set -euo pipefail
cd "$(dirname "$0")/../../rust"
branch="${BRANCH:-the checked-out ref}"

list=$(cargo test --locked --release -p shekyl-chain-store --lib -- --list --ignored)
for subject in \
  'store::prune_tests::the_boundary_batch_discards_closed_shards_on_real_spends' \
  'store::slash_scan_bench_tests::slash_scan_bench' \
  'store::weights_read_bench_tests::weights_read_bench'
do
  matches=$(printf '%s\n' "$list" | grep -cx "${subject}: test" || true)
  if [ "${matches}" -eq 0 ]; then
    echo "::error::${subject} is not in shekyl-chain-store's ignored set"
    exit 1
  fi
done
count=$(printf '%s\n' "$list" | grep -c ': test$')
echo "shekyl-chain-store ignored set: ${count} test(s)"

START=$(date +%s)
cargo test --locked --release -p shekyl-chain-store --lib -- --ignored --nocapture
END=$(date +%s)
echo "::notice::Chain store ignored set completed on ${branch} in $((END - START))s (budget 120m)"
