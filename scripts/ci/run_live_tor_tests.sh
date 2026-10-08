#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Run one crate's `#[ignore]`d live-tor tests for the tor-pin-verify lane, and
# retry once when — and only when — every failure is a Tor bootstrap timeout.
#
# These tests bootstrap a real tor against the real network from a CI runner.
# That step times out now and then for reasons that have nothing to do with
# the tree (two of the lane's first five runs: once on x86_64, once on
# aarch64, a different test each time, each green on a manual re-run). A gate
# that fails on the weather teaches whoever dispatches it to click re-run, and
# a re-run clears a real failure as readily as a flake.
#
# So the retry is done here, by rule, and the rule is narrow:
#
#   * every panic in the failed attempt must be a bootstrap timeout, and
#   * the pin-match test must not be among the failures.
#
# Anything else — a digest mismatch, a refused directory, a spawn failure, a
# reap that did not happen — fails on the first attempt and is never retried.
# A second bootstrap timeout fails too: one retry, not a loop. A retried run
# says so in an annotation, so a flake rate that climbs is seen.
#
# Usage: run_live_tor_tests.sh <crate> <output-file>
# Run from the `rust/` directory. The caller reads <output-file> for its own
# assertions (which tests ran, how many); this script's exit status is the
# test run's. No verdict travels through a pipe (rule 46).

# No pipeline in this script carries a verdict (there are none); pipefail is
# set so that one added later cannot lose its status quietly.
set -u -o pipefail

crate="${1:?usage: run_live_tor_tests.sh <crate> <output-file>}"
out="${2:?usage: run_live_tor_tests.sh <crate> <output-file>}"

# How the live suites report a tor that started and did not reach the
# network: the client and wallet tests panic with "did not bootstrap", and the
# daemon's start error is the typed `BootstrapTimeout`. The tests decide which
# failure they saw, from the state they hold (the wallet suite's `await_ready`
# reads the supervisor's posture at the deadline); this script does not infer
# it from the name of a wait. A timeout in any other state says so in other
# words and is not retried.
BOOTSTRAP_RE='did not bootstrap|BootstrapTimeout'
PIN_TEST='bundled_tor_matches_recorded_pin'

attempt() {
  cargo test --locked -p "$crate" --lib -- --ignored --test-threads=1 > "$out" 2>&1
  local rc=$?
  cat "$out"
  return "$rc"
}

# Every panic message in the output is a bootstrap timeout, there is at least
# one, and the pin-match test did not fail. A panic line is followed by its
# message on the next line.
only_bootstrap_timeouts() {
  if grep -qE "${PIN_TEST} \.\.\. FAILED" "$out"; then
    return 1
  fi
  local messages
  messages="$(awk '/panicked at /{getline; print}' "$out")"
  [ -n "$messages" ] || return 1
  # A here-string, not a pipe: nothing to carry a verdict out of.
  if grep -qvE "$BOOTSTRAP_RE" <<< "$messages"; then
    return 1
  fi
  return 0
}

attempt
rc=$?
if [ "$rc" -eq 0 ]; then
  exit 0
fi
if ! only_bootstrap_timeouts; then
  echo "live tor tests ($crate): failed, and not only on a bootstrap timeout — not retried" >&2
  exit "$rc"
fi

cp "$out" "$out.attempt1"
echo "::warning title=tor bootstrap timeout, retried once::$crate: the first attempt failed only on a Tor bootstrap timeout (network). Retrying once. First attempt kept in $out.attempt1."
attempt
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "live tor tests ($crate): failed again after the one permitted retry" >&2
fi
exit "$rc"
