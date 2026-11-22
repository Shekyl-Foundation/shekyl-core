#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The economics sim's `#[ignore]`d tests, run by nightly.yml's
# economics-sim-ignored job, one leg per lane. The set lives here, in the
# tree under test, and not in the workflow file: a scheduled workflow runs the default
# branch's copy of nightly.yml over every branch in its matrix, so a set
# written there judged `dev` by `main`'s list (#1110: a test deleted on dev
# on 2026-10-15 stayed named on main's copy). Each branch now judges
# itself, and the `workflow_dispatch` `ref` input proves a branch's own set.
#
# The tests run here are the narration pins, the steady control's pins, the
# ESR-11 timing set and the per-mode reader test (each field a mode declares moves its report). The
# regeneration helpers, `regen_baseline_fixture`,
# `regen_stage2_narration_fixtures` and `regen_esr10_narration_fixtures`,
# WRITE the committed fixtures: they are named as helpers and never run
# here, because a lane that regenerated the fixtures and then compared
# against them would pass every night. They are armed (rule 50): each
# refuses unless SHEKYL_PINNED_REGEN_DECISION cites the dated
# ECONOMICS_SIM_PRODUCTION_REBASE.md entry that records what moved.
#
# ESR-10's full narration (144 folds of 60 years, about 85 CPU-minutes) does
# not fit this lane's budget beside its other tests, so it is named on
# demand and never run here. The lane runs ESR-10's nightly scope instead:
# every cell on both arms, on the baseline and the stuffing attack, against
# its own fixture (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.29). EUP-4 prep
# 2's instruments (`--eup4`, §5.32) are pinned the same way: the full
# narration on demand, its nightly scope here. So is the J x G grid
# (`--jg-grid`, §5.33 and §5.34): the full grid, about 160 000 fold-years,
# on demand on a fleet host; its nightly slice here.
#
# Rule 47: the lane asserts its subject before running it. The crate's
# ignored set must be EXACTLY the tests run here, the helpers and the
# on-demand tests. A renamed, deleted or un-ignored member fails by name; a
# new ignored test fails too, until someone decides here whether it is run,
# is a helper, or runs on demand.
# The tests are passed by exact name, so the helpers cannot be reached by a
# filter. Rule 46: the run's output streams through `tee` and a line stamper,
# both of which read to the end of their input, and the verdict is cargo's
# own exit from PIPESTATUS, never the pipe's. Each line carries the UTC date
# and time it arrived, so a run its job's timeout cuts still names the tests
# that finished and when (libtest prints `test <name> ... ok` as each one
# ends).
#
# `--check` (ignored_set_mode.sh) stops after this judgement. The per-PR
# Rust job uses it; the run below is the nightly lane.
#
# `--narrations` runs the narration pins alone, after the same judgement:
# rust-audit-test.yml's economics-sim-narrations job, on every change whose
# Rust test scope reaches the sim (scripts/ci/change_scope.py,
# `sim_narrations`). A change to a value the sim reads moves a narration
# without failing any per-PR test: #1323 (the surge factor, 4 to 3) merged
# green and turned this lane red for three nights
# (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.31).
#
# The nightly lanes, each a leg of economics-sim-ignored with its own runner
# and budget, so one slow test cannot cut the others and a test that grows
# shows in its own leg:
#   --pins    the narration pins, the steady control's pins and the ESR-11
#             timing set;
#   --reader  the per-mode reader test alone: about half the set's wall
#             time, measured one test at a time on a 16-vCPU build host at
#             dev 46f266ac08, 2026-11-22.
# With no lane it runs the whole nightly set, as the jobs did before the
# split; the schedule runs main's copy of nightly.yml, which calls it that
# way until the split reaches main.
#
# The crate is a binary with no library target: the tests are in
# `--bin shekyl-economics-sim`.
set -euo pipefail
. "$(dirname "$0")/ignored_set_mode.sh"
lane=nightly
budget='180m, the nightly job'
case "${1:-}" in
  --narrations)
    lane=narrations
    budget='55m, the per-PR narrations job'
    shift
    ;;
  --pins)
    lane=pins
    budget="180m, the economics-sim-ignored job's pins leg"
    shift
    ;;
  --reader)
    lane=reader
    budget="180m, the economics-sim-ignored job's reader leg"
    shift
    ;;
esac
ignored_set_mode "$@"
if [ "$lane" != nightly ] && [ "$ignored_set_check" -eq 1 ]; then
  echo "usage: $0 [--check | --narrations | --pins | --reader]" >&2
  exit 2
fi
cd "$(dirname "$0")/../../rust"
branch="${BRANCH:-the checked-out ref}"

# The narration pins: each folds the sim and compares its report with the
# committed fixture. They are the per-PR lane's whole set and the head of
# the nightly's.
narration_pins='stage2::tests::stage2_narration_matches_the_committed_fixture
stage2::tests::stage2_narration_flat_control_matches_the_committed_fixture
esr10::tests::esr10_nightly_narration_matches_the_committed_fixture
eup4::tests::eup4_nightly_narration_matches_the_committed_fixture
jg_grid::tests::jg_grid_nightly_narration_matches_the_committed_fixture'
# The steady control's pins: each narration at the per-PR scope on the
# `steady` traffic every block offered its demand, the regression anchor
# beside standard traffic (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.35). They
# run nightly, not per PR: a change that moves them moves the standard pins
# first.
steady_pins='stage2::tests::stage2_steady_narrations_match_the_committed_fixtures
esr10::tests::esr10_steady_nightly_narration_matches_the_committed_fixture
eup4::tests::eup4_steady_nightly_narration_matches_the_committed_fixture'
pins="$narration_pins
$steady_pins
secret_draw_production::tests::the_esr11_timing_set_runs_and_the_table_renders"
reader='baseline::tests::every_declared_reader_moves_its_report'
run_tests="$pins
$reader"
helpers='record::tests::regen_baseline_fixture
stage2::tests::regen_stage2_narration_fixtures
esr10::tests::regen_esr10_narration_fixtures
eup4::tests::regen_eup4_narration_fixtures
jg_grid::tests::regen_jg_grid_narration_fixtures
growth_trace::tests::regen_growth_trace_narration_fixture'
on_demand='esr10::tests::esr10_narration_matches_the_committed_fixture
eup4::tests::eup4_narration_matches_the_committed_fixture
jg_grid::tests::jg_grid_narration_matches_the_committed_fixture
growth_trace::tests::growth_trace_narration_matches_the_committed_fixture'

# Rule 47 for this script's own list: it must name at least one test to
# run. Counted by awk, which exits 0 on an empty list where `grep -c`
# would not; the refusal below is then this script's words, not `set -e`'s
# silence.
case "$lane" in
  narrations) lane_tests=$narration_pins ;;
  pins) lane_tests=$pins ;;
  reader) lane_tests=$reader ;;
  *) lane_tests=$run_tests ;;
esac
want=$(printf '%s\n' "$lane_tests" | awk 'NF { n++ } END { print n + 0 }')
if [ "$want" -eq 0 ]; then
  echo "::error::scripts/ci/ignored_set_economics_sim.sh names no test to run in the ${lane} lane"
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
echo "shekyl-economics-sim ignored set: exactly the listed set; the ${lane} lane runs ${want} of it"
ignored_set_stop_after_judgement

START=$(date +%s)
# Each line of output as it arrives, with the UTC date and time, to the
# job's log; the raw lines to sim-ignored.log for the count below. printf's
# own `%(...)T` reads the clock without a process per line; TZ is set in
# the function's own subshell (it runs as a pipeline stage), so the stamp
# is UTC wherever the runner's zone points.
stamp() {
  local line
  export TZ=UTC
  while IFS= read -r line; do
    printf '%(%Y-%m-%dT%H:%M:%SZ)T %s\n' -1 "$line"
  done
}
set +e
# shellcheck disable=SC2086 # one test name per word, by design
cargo test --locked --release -p shekyl-economics-sim --bin shekyl-economics-sim -- \
  --ignored --exact --nocapture $lane_tests 2>&1 | tee sim-ignored.log | stamp
pipe=("${PIPESTATUS[@]}")
set -e
status=${pipe[0]}
if [ "${pipe[1]}" -ne 0 ] || [ "${pipe[2]}" -ne 0 ]; then
  echo "::error::economics-sim ${lane} lane: the log's tee or stamper failed (${pipe[*]}); the run's verdict cannot be read"
  exit 1
fi
if [ "$status" -ne 0 ]; then
  echo "::error::economics-sim ${lane} lane: a named test failed. If a narration drifted and the sim change is intended, record it in ECONOMICS_SIM_PRODUCTION_REBASE.md and regenerate with regen_stage2_narration_fixtures, regen_esr10_narration_fixtures, regen_eup4_narration_fixtures or regen_jg_grid_narration_fixtures under SHEKYL_PINNED_REGEN_DECISION citing that entry; otherwise the sim drifted from its record."
  exit "$status"
fi
ran=$(sed -n 's/^test result: ok\. \([0-9]*\) passed.*/\1/p' sim-ignored.log | tail -1)
if [ "$ran" != "$want" ]; then
  echo "::error::${ran:-0} of ${want} named tests ran: a name above no longer matches a test exactly."
  exit 1
fi
END=$(date +%s)
echo "::notice::Economics sim ${lane} lane completed on ${branch} in $((END - START))s (budget ${budget})"
