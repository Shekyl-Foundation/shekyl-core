#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The trybuild harnesses whose fixture build is too long for a pull
# request, run by nightly.yml's trybuild-ignored job. The set lives here,
# in the tree under test, for the reason ignored_set_economics_sim.sh
# gives: a scheduled workflow runs the default branch's copy of nightly.yml
# over every branch in its matrix, so each branch judges itself by this
# file.
#
# What the tests are. Each `tests/trybuild.rs` compiles programs as a
# separate crate that depends on the crate under test and compares rustc's
# whole stderr against a snapshot. The programs that must not compile are
# the crate's by-construction guarantees seen from downstream: an output
# field cannot be built unencrypted (shekyl-crypto-pq), a verdict connects
# only under the view it was judged against (shekyl-chain-rules), a verdict
# over the pool's view never reaches `connect` and the pool's internals are
# not public (shekyl-mempool). trybuild builds those programs in a cargo
# project of its own under target/tests/trybuild, so their first build
# compiles the crate's whole dependency tree again there, and the
# workspace's profile overrides do not reach it. On the 4-vCPU runner that
# is about 19 minutes for shekyl-chain-rules (a `cargo build`, since it has
# a passing program) and 19 again for shekyl-crypto-pq (a `cargo check`;
# cargo shares nothing between the two kinds). shekyl-mempool's programs
# link chain-rules and reuse its build when it ran first, which is why they
# measured two minutes on pull requests and would measure twenty alone.
# shekyl-logging's harness checks shekyl-core and little else (14 s cold)
# and stays in the pull-request run.
#
# What moves. Three harnesses, four tests, left the per-PR Rust job on
# 2026-11-09 and run here every night on main and dev. A pull request that
# opens one of these surfaces merges to dev and is caught the next night,
# not before merge. That trade is deliberate and named in the CHANGELOG
# entry; the per-PR `--check` below still fails a pull request that
# renames, deletes or un-ignores one of these tests without deciding here.
#
# Rule 47: every crate with a tests/trybuild.rs is judged. A listed crate's
# ignored set in its trybuild target must be EXACTLY the tests run here; an
# unlisted crate's (logging's today) must be empty. The listing is per
# target, so a crate's other ignored tests (crypto-pq's fixture
# regenerators) are not this lane's census. A renamed, deleted or
# un-ignored member fails by name; a new ignored test in any trybuild
# target, or a crate dropped from the list, fails too, until someone
# decides here whether it is run. Rule 46: each run's log is written and
# its exit kept, then the log shown; no verdict travels through a pipe.
#
# Debug profile in both modes, where the other lanes list and run with
# --release: the work is the fixture build inside trybuild's own cargo
# project, which the outer profile does not reach (the opt-level change of
# #1332 left these tests' times unchanged), so a release build of the
# harness crates would be minutes of waste. ignored_set_mode.sh's profile
# variable is therefore not used here; its --check parsing and stop are.
#
# Order: chain-rules before mempool, so mempool's programs find
# chain-rules' dependencies already built in target/tests/trybuild.
#
# Features: a harness is built with the features its programs need, named
# per crate below, because a `-p` run resolves the crate's features alone
# where the workspace run unifies every member's. chain-rules' programs
# judge with `Trust::UNPINNED`, a `harness`-feature item, which the
# workspace run had turned on through the store's dev-edge; its trybuild
# target now requires the feature (Cargo.toml), so a run without it is
# refused by cargo instead of failing inside the programs. trybuild passes
# the enabled features on to the programs' dependency on the crate (it
# reads them from the crate's fingerprint).
set -euo pipefail
. "$(dirname "$0")/ignored_set_mode.sh"
ignored_set_mode "$@"
cd "$(dirname "$0")/../../rust"
branch="${BRANCH:-the checked-out ref}"

# The cargo feature flags a crate's trybuild target is built with (see
# "Features" above). Printed one flag per line; empty for a crate whose
# programs need none.
features_for() {
  case "$1" in
    shekyl-chain-rules) printf '%s\n' --features harness ;;
    *) ;;
  esac
}

# crate:test, one per line, in run order; a crate may appear more than once.
run_tests='shekyl-chain-rules:a_verdict_connects_under_the_view_it_was_judged_against_and_no_other
shekyl-mempool:a_verdict_judged_over_the_pool_view_does_not_connect
shekyl-mempool:a_block_arrival_and_an_unfiltered_read_are_not_public
shekyl-crypto-pq:an_unencrypted_output_field_cannot_be_constructed_downstream'

# Rule 47 for this script's own list: it must name at least one test to
# run. Counted by awk, which exits 0 on an empty list where `grep -c`
# would not.
want=$(printf '%s\n' "$run_tests" | awk 'NF { n++ } END { print n + 0 }')
if [ "$want" -eq 0 ]; then
  echo "::error::scripts/ci/ignored_set_trybuild.sh names no test to run"
  exit 1
fi
crates=$(printf '%s\n' "$run_tests" | cut -d: -f1 | awk '!seen[$0]++')

# The harnesses in the tree: every crate with a tests/trybuild.rs, by the
# package name in its manifest. A crate the list names must be one of them,
# and every one of them is judged, listed or not: an unlisted crate's
# trybuild target must have no ignored test, so a crate dropped from the
# list, or a new harness that ignores a test, fails by name here rather
# than running nowhere. Rule 47 for the glob: it must match at least one.
tree_crates=''
for harness in */tests/trybuild.rs; do
  [ -f "$harness" ] || continue
  name=$(sed -n 's/^name = "\(.*\)"$/\1/p' "${harness%%/*}/Cargo.toml" | head -1)
  if [ -z "$name" ]; then
    echo "::error::${harness%%/*}/Cargo.toml names no package"
    exit 1
  fi
  tree_crates="${tree_crates}${name}
"
done
if [ -z "$tree_crates" ]; then
  echo "::error::no */tests/trybuild.rs under rust/: the harnesses moved, or this script's glob did"
  exit 1
fi
for crate in $crates; do
  if ! printf '%s' "$tree_crates" | grep -qx "$crate"; then
    echo "::error::${crate} is listed in scripts/ci/ignored_set_trybuild.sh but has no tests/trybuild.rs"
    exit 1
  fi
done

for crate in $tree_crates; do
  expected=$(printf '%s\n' "$run_tests" | awk -F: -v c="$crate" '$1 == c { print $2 }' | LC_ALL=C sort)
  mapfile -t flags < <(features_for "$crate")
  listing=$(cargo test --locked -p "$crate" "${flags[@]}" --test trybuild -- --list --ignored)
  found=$(printf '%s\n' "$listing" | sed -n 's/: test$//p' | LC_ALL=C sort)
  if [ "$found" != "$expected" ]; then
    if [ -z "$expected" ]; then
      echo "::error::${crate}'s trybuild target has ignored tests this lane does not name:"
    else
      echo "::error::${crate}'s trybuild target's ignored set is not the one this lane was written for."
      echo "expected:"
      printf '%s\n' "$expected"
      echo "found:"
    fi
    printf '%s\n' "$found"
    echo "Decide in scripts/ci/ignored_set_trybuild.sh whether each new ignored test is run here."
    exit 1
  fi
  n=$(printf '%s\n' "$expected" | awk 'NF { n++ } END { print n + 0 }')
  echo "${crate} trybuild ignored set: ${n} test(s), exactly the listed set"
done
ignored_set_stop_after_judgement

START=$(date +%s)
ran=0
for crate in $crates; do
  names=$(printf '%s\n' "$run_tests" | awk -F: -v c="$crate" '$1 == c { print $2 }')
  log="trybuild-ignored-${crate}.log"
  mapfile -t flags < <(features_for "$crate")
  status=0
  # shellcheck disable=SC2086 # one test name per word, by design
  cargo test --locked -p "$crate" "${flags[@]}" --test trybuild -- \
    --ignored --exact --nocapture $names > "$log" 2>&1 || status=$?
  cat "$log"
  if [ "$status" -ne 0 ]; then
    echo "::error::trybuild-ignored: a ${crate} program's stderr is not its snapshot. Read the harness's doc comment: an E0046 means a stub fell behind a trait (fix the stub); a reworded diagnostic after a toolchain bump is regenerated with TRYBUILD=overwrite after reading it; a different error at the guarded call, or none, is a finding against the crate, not a snapshot to refresh."
    exit "$status"
  fi
  passed=$(sed -n 's/^test result: ok\. \([0-9]*\) passed.*/\1/p' "$log" | tail -1)
  ran=$((ran + ${passed:-0}))
done
if [ "$ran" != "$want" ]; then
  echo "::error::${ran} of ${want} named tests ran: a name above no longer matches a test exactly."
  exit 1
fi
END=$(date +%s)
echo "::notice::trybuild ignored tests completed on ${branch} in $((END - START))s (budget 120m)"
