#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# shekyl-wire's `#[ignore]`d tests, run by nightly.yml's wire-ignored job.
# The set lives here, in the tree under test, for the reason the other
# lanes' sets do (ignored_set_economics_sim.sh): the schedule runs main's
# copy of nightly.yml over every branch, so each branch judges itself.
#
# Run here: the RT-W10 listed-tx parse harness (`rt_w10_tx_parse`), which
# with RT_W10_OUT unset writes a few samples into a temporary directory and
# removes it, so the run proves the harness still works and measures nothing
# (its figures come from the floor device, rt_w10_request_cost_20261102.md);
# and the input-cap measurement (`input_cap_cost`, BA-I30), seconds in
# release. An ignored test no scheduled lane runs is a deleted test with a
# comment on it.
#
# Helpers, never run here: the five fixture and vector writers and the
# regtest-address printer. They WRITE committed files or print a value for
# a regeneration; a lane that regenerated a fixture and then compared
# against it would pass every night.
#
# Rule 47: the crate's ignored set must be EXACTLY the tests run here plus
# the helpers. A renamed, deleted or un-ignored member fails by name; a new
# ignored test fails too, until someone decides here whether it is run or
# is a helper. The tests run by exact name in their own test targets, so a
# helper cannot be reached by a filter, and the run must report as many
# passes as names. Rule 46: the run's log is written and its exit kept,
# then the log shown; no verdict travels through a pipe.
#
# The ignored tests are all integration tests, one target each; the lib has
# none. `rt_w10_tx_parse` is Linux-only (`#![cfg(target_os = "linux")]`),
# as the runner is.
set -euo pipefail
cd "$(dirname "$0")/../../rust"
branch="${BRANCH:-the checked-out ref}"

# target:test, one per line.
run_tests='rt_w10_tx_parse:rt_w10_listed_tx_parse
input_cap_cost:the_input_caps_cost_is_measured_not_inherited'
helpers='emit_rpc_types_miner_tx_vectors
emit_regtest_mining_address
emit_pqc_signing_preimage_kat_inputs
regenerate_prunable_digest_parity_fixture
regenerate_pruned_tx_hash_parity_fixture
regenerate_serve_credit_tx_parity_fixture'

want=$(printf '%s\n' "$run_tests" | awk 'NF { n++ } END { print n + 0 }')
if [ "$want" -eq 0 ]; then
  echo "::error::scripts/ci/ignored_set_wire.sh names no test to run"
  exit 1
fi

listing=$(cargo test --locked --release -p shekyl-wire --tests -- --list --ignored)
found=$(printf '%s\n' "$listing" | sed -n 's/: test$//p' | LC_ALL=C sort)
expected=$(printf '%s\n%s\n' "$(printf '%s\n' "$run_tests" | cut -d: -f2)" "$helpers" | LC_ALL=C sort)
if [ "$found" != "$expected" ]; then
  echo "::error::shekyl-wire's ignored set is not the one this lane was written for."
  echo "expected (the tests run, then the helpers that are not):"
  printf '%s\n' "$expected"
  echo "found:"
  printf '%s\n' "$found"
  echo "Decide in scripts/ci/ignored_set_wire.sh whether each new ignored test is run here or is a helper."
  exit 1
fi

targets=()
names=()
while IFS=: read -r target name; do
  [ -n "$target" ] || continue
  targets+=(--test "$target")
  names+=("$name")
done <<< "$run_tests"

START=$(date +%s)
status=0
env -u RT_W10_OUT cargo test --locked --release -p shekyl-wire "${targets[@]}" -- \
  --ignored --exact --nocapture "${names[@]}" > wire-ignored.log 2>&1 || status=$?
cat wire-ignored.log
if [ "$status" -ne 0 ]; then
  echo "::error::wire-ignored: a named test failed."
  exit "$status"
fi
# One `test result` line per target; the passes are summed across them.
ran=$(sed -n 's/^test result: ok\. \([0-9]*\) passed.*/\1/p' wire-ignored.log | awk '{ n += $1 } END { print n + 0 }')
if [ "$ran" != "$want" ]; then
  echo "::error::${ran} of ${want} named tests ran: a name above no longer matches a test exactly."
  exit 1
fi
END=$(date +%s)
echo "::notice::shekyl-wire ignored tests completed on ${branch} in $((END - START))s (budget 60m)"
