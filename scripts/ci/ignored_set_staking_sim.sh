#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The staking sim's `#[ignore]`d tests, run by nightly.yml's
# staking-sim-ignored job. The set lives here, in the tree under test, for
# the reason ignored_set_economics_sim.sh gives: a scheduled workflow runs
# the default branch's copy of nightly.yml over every branch in its matrix,
# so each branch judges itself by this file.
#
# The tests run here are the five-seed L11/L13 pins
# (`docs/design/STAKER_ARCHIVAL_SIM.md`, EUP-3 check half): the registered
# plateau arm, which is the falsifier's control, and the production arm,
# the default. Each runs eleven scenarios on five seeds and compares bits.
# The crate has no regeneration helper.
#
# Rule 47: the lane asserts its subject before running it. The crate's
# ignored set must be EXACTLY the tests run here. A renamed, deleted or
# un-ignored member fails by name; a new ignored test fails too, until
# someone decides here whether it is run. The tests are passed by exact
# name. Rule 46: the run's log is written and its exit kept, then the log
# shown; no verdict travels through a pipe, and every pipe below carries
# data to a consumer that reads to the end of its input.
#
# `--check` (ignored_set_mode.sh) stops after this judgement. The per-PR
# Rust job uses it; the run below is the nightly lane.
#
# The crate is a binary with no library target: the tests are in
# `--bin shekyl-staking-sim`.
set -euo pipefail
. "$(dirname "$0")/ignored_set_mode.sh"
ignored_set_mode "$@"
cd "$(dirname "$0")/../../rust"
branch="${BRANCH:-the checked-out ref}"

run_tests='l11_l13_pin::l11_l13_five_seed_pins
l11_l13_pin::l11_l13_five_seed_production_pins'

# Rule 47 for this script's own list: it must name at least one test to
# run. Counted by awk, which exits 0 on an empty list where `grep -c`
# would not.
want=$(printf '%s\n' "$run_tests" | awk 'NF { n++ } END { print n + 0 }')
if [ "$want" -eq 0 ]; then
  echo "::error::scripts/ci/ignored_set_staking_sim.sh names no test to run"
  exit 1
fi

listing=$(cargo test --locked "${ignored_set_profile[@]}" -p shekyl-staking-sim --bin shekyl-staking-sim -- --list --ignored)
found=$(printf '%s\n' "$listing" | sed -n 's/: test$//p' | LC_ALL=C sort)
expected=$(printf '%s\n' "$run_tests" | LC_ALL=C sort)
if [ "$found" != "$expected" ]; then
  echo "::error::shekyl-staking-sim's ignored set is not the one this lane was written for."
  echo "expected:"
  printf '%s\n' "$expected"
  echo "found:"
  printf '%s\n' "$found"
  echo "Decide in scripts/ci/ignored_set_staking_sim.sh whether each new ignored test is run here."
  exit 1
fi
echo "shekyl-staking-sim ignored set: ${want} test(s), exactly the listed set"
ignored_set_stop_after_judgement

START=$(date +%s)
status=0
# shellcheck disable=SC2086 # one test name per word, by design
cargo test --locked --release -p shekyl-staking-sim --bin shekyl-staking-sim -- \
  --ignored --exact --nocapture $run_tests > staking-sim-ignored.log 2>&1 || status=$?
cat staking-sim-ignored.log
if [ "$status" -ne 0 ]; then
  echo "::error::staking-sim-ignored: a named test failed. A pin that moved is a sim change: predict it, then re-pin, or the sim drifted from its record."
  exit "$status"
fi
ran=$(sed -n 's/^test result: ok\. \([0-9]*\) passed.*/\1/p' staking-sim-ignored.log | tail -1)
if [ "$ran" != "$want" ]; then
  echo "::error::${ran:-0} of ${want} named tests ran: a name above no longer matches a test exactly."
  exit 1
fi
END=$(date +%s)
echo "::notice::Staking sim ignored tests completed on ${branch} in $((END - START))s (budget 90m)"
