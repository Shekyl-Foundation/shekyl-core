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
# The tests run here are the narration pins, the ESR-11 timing set and the
# per-mode reader test (each field a mode declares moves its report). The
# regeneration helpers, `regen_baseline_fixture`,
# `regen_stage2_narration_fixtures` and `regen_esr10_narration_fixtures`,
# WRITE the committed fixtures: they are named as helpers and never run
# here, because a lane that regenerated the fixtures and then compared
# against them would pass every night.
#
# ESR-10's full narration (144 folds of 60 years, about 85 CPU-minutes) does
# not fit this lane's budget beside its other tests, so it is named on
# demand and never run here. The lane runs ESR-10's nightly scope instead:
# every cell on both arms, on the baseline and the stuffing attack, against
# its own fixture (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.29).
#
# Rule 47: the lane asserts its subject before running it. The crate's
# ignored set must be EXACTLY the tests run here, the helpers and the
# on-demand tests. A renamed, deleted or un-ignored member fails by name; a
# new ignored test fails too, until someone decides here whether it is run,
# is a helper, or runs on demand.
# The tests are passed by exact name, so the helpers cannot be reached by a
# filter. Rule 46: the run's log is written and its exit kept, then the log
# shown; no verdict travels through a pipe, and every pipe below carries
# data to a consumer that reads to the end of its input.
#
# `--check` (ignored_set_mode.sh) stops after this judgement. The per-PR
# Rust job uses it; the run below is the nightly lane.
#
# The crate is a binary with no library target: the tests are in
# `--bin shekyl-economics-sim`.
set -euo pipefail
. "$(dirname "$0")/ignored_set_mode.sh"
ignored_set_mode "$@"
cd "$(dirname "$0")/../../rust"
branch="${BRANCH:-the checked-out ref}"

run_tests='stage2::tests::stage2_narration_matches_the_committed_fixture
stage2::tests::stage2_narration_flat_control_matches_the_committed_fixture
esr10::tests::esr10_nightly_narration_matches_the_committed_fixture
secret_draw_production::tests::the_esr11_timing_set_runs_and_the_table_renders
baseline::tests::every_declared_reader_moves_its_report'
helpers='record::tests::regen_baseline_fixture
stage2::tests::regen_stage2_narration_fixtures
esr10::tests::regen_esr10_narration_fixtures'
on_demand='esr10::tests::esr10_narration_matches_the_committed_fixture'

# Rule 47 for this script's own list: it must name at least one test to
# run. Counted by awk, which exits 0 on an empty list where `grep -c`
# would not; the refusal below is then this script's words, not `set -e`'s
# silence.
want=$(printf '%s\n' "$run_tests" | awk 'NF { n++ } END { print n + 0 }')
if [ "$want" -eq 0 ]; then
  echo "::error::scripts/ci/ignored_set_economics_sim.sh names no test to run"
  exit 1
fi

listing=$(cargo test --locked "${ignored_set_profile[@]}" -p shekyl-economics-sim --bin shekyl-economics-sim -- --list --ignored)
# Both sides are sorted in this one environment, so the compare is
# locale-independent either way; LC_ALL=C makes the printed listing the
# same on every runner.
found=$(printf '%s\n' "$listing" | sed -n 's/: test$//p' | LC_ALL=C sort)
expected=$(printf '%s\n%s\n%s\n' "$run_tests" "$helpers" "$on_demand" | LC_ALL=C sort)
if [ "$found" != "$expected" ]; then
  echo "::error::shekyl-economics-sim's ignored set is not the one this lane was written for."
  echo "expected (the tests run, the helpers, and the tests run on demand):"
  printf '%s\n' "$expected"
  echo "found:"
  printf '%s\n' "$found"
  echo "Decide in scripts/ci/ignored_set_economics_sim.sh whether each new ignored test is run here, is a regeneration helper, or runs on demand."
  exit 1
fi
echo "shekyl-economics-sim ignored set: ${want} test(s) run, the regeneration helpers and the on-demand tests, exactly the listed set"
ignored_set_stop_after_judgement

START=$(date +%s)
status=0
# shellcheck disable=SC2086 # one test name per word, by design
cargo test --locked --release -p shekyl-economics-sim --bin shekyl-economics-sim -- \
  --ignored --exact --nocapture $run_tests > sim-ignored.log 2>&1 || status=$?
cat sim-ignored.log
if [ "$status" -ne 0 ]; then
  echo "::error::economics-sim-ignored: a named test failed. If a narration drifted, regenerate with regen_stage2_narration_fixtures or regen_esr10_narration_fixtures only if the sim change is intended; otherwise the sim drifted from its record."
  exit "$status"
fi
ran=$(sed -n 's/^test result: ok\. \([0-9]*\) passed.*/\1/p' sim-ignored.log | tail -1)
if [ "$ran" != "$want" ]; then
  echo "::error::${ran:-0} of ${want} named tests ran: a name above no longer matches a test exactly."
  exit 1
fi
END=$(date +%s)
echo "::notice::Economics sim ignored tests completed on ${branch} in $((END - START))s (budget 180m)"
