#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The economics sim's `#[ignore]`d tests, run by nightly.yml's
# economics-sim-ignored job. The set lives here, in the tree under test,
# and not in the workflow file: a scheduled workflow runs the default
# branch's copy of nightly.yml over every branch in its matrix, so a set
# written there judged `dev` by `main`'s list (#1110: a test deleted on dev
# on 2026-10-15 stayed named on main's copy). Each branch now judges
# itself, and the `workflow_dispatch` `ref` input proves a branch's own set.
#
# The tests run here are the narration pins and the ESR-11 timing set. The
# two regeneration helpers, `regen_baseline_fixture` and
# `regen_stage2_narration_fixtures`, WRITE the committed fixtures: they are
# named as helpers and never run here, because a lane that regenerated the
# fixtures and then compared against them would pass every night.
#
# Rule 47: the lane asserts its subject before running it. The crate's
# ignored set must be EXACTLY the tests run here plus the helpers. A
# renamed, deleted or un-ignored member fails by name; a new ignored test
# fails too, until someone decides here whether it is run or is a helper.
# The tests are passed by exact name, so the helpers cannot be reached by a
# filter. Rule 46: the run's log is written and its exit kept, then the log
# shown; no verdict travels through a pipe, and every pipe below carries
# data to a consumer that reads to the end of its input.
#
# The crate is a binary with no library target: the tests are in
# `--bin shekyl-economics-sim`.
set -euo pipefail
cd "$(dirname "$0")/../../rust"
branch="${BRANCH:-the checked-out ref}"

run_tests='stage2::tests::stage2_narration_matches_the_committed_fixture
stage2::tests::stage2_narration_flat_control_matches_the_committed_fixture
secret_draw_production::tests::the_esr11_timing_set_runs_and_the_table_renders'
helpers='record::tests::regen_baseline_fixture
stage2::tests::regen_stage2_narration_fixtures'

listing=$(cargo test --locked --release -p shekyl-economics-sim --bin shekyl-economics-sim -- --list --ignored)
found=$(printf '%s\n' "$listing" | sed -n 's/: test$//p' | sort)
expected=$(printf '%s\n%s\n' "$run_tests" "$helpers" | sort)
if [ "$found" != "$expected" ]; then
  echo "::error::shekyl-economics-sim's ignored set is not the one this lane was written for."
  echo "expected (the tests run, then the helpers that are not):"
  printf '%s\n' "$expected"
  echo "found:"
  printf '%s\n' "$found"
  echo "Decide in scripts/ci/ignored_set_economics_sim.sh whether each new ignored test is run here or is a regeneration helper."
  exit 1
fi

START=$(date +%s)
status=0
# shellcheck disable=SC2086 # one test name per word, by design
cargo test --locked --release -p shekyl-economics-sim --bin shekyl-economics-sim -- \
  --ignored --exact --nocapture $run_tests > sim-ignored.log 2>&1 || status=$?
cat sim-ignored.log
if [ "$status" -ne 0 ]; then
  echo "::error::economics-sim-ignored: a named test failed. If a narration drifted, regenerate with regen_stage2_narration_fixtures only if the sim change is intended; otherwise the sim drifted from its record."
  exit "$status"
fi
ran=$(sed -n 's/^test result: ok\. \([0-9]*\) passed.*/\1/p' sim-ignored.log | tail -1)
want=$(printf '%s\n' "$run_tests" | grep -c .)
if [ "$ran" != "$want" ]; then
  echo "::error::${ran:-0} of ${want} named tests ran: a name above no longer matches a test exactly."
  exit 1
fi
END=$(date +%s)
echo "::notice::Economics sim ignored tests completed on ${branch} in $((END - START))s (budget 180m)"
