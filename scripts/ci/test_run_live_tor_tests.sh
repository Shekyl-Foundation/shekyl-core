#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Self-test for run_live_tor_tests.sh's retry rule. A stand-in `cargo` replays
# canned attempts, so each case states what the first attempt printed and how
# it exited, and this asserts how many attempts were made and the final
# status. The cases that matter are the ones that must NOT retry: a retry rule
# that is wider than "bootstrap timeout" turns the lane into one that clears
# real failures on its own.

set -u -o pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/bin"
cat > "$work/bin/cargo" <<'FAKE'
#!/usr/bin/env bash
n=$(cat "$SCEN/count" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$SCEN/count"
cat "$SCEN/attempt$n.txt"; exit "$(cat "$SCEN/attempt$n.rc")"
FAKE
chmod +x "$work/bin/cargo"

BOOT="test a::boots ... FAILED\nthread 'a' (1) panicked at x.rs:1:1:\nsecond boot start: BootstrapTimeout\n"
BOOT2="test b::pub ... FAILED\nthread 'b' (1) panicked at x.rs:2:2:\ntor did not bootstrap in 180s\n"
PIN="test binary::tests::bundled_tor_matches_recorded_pin ... FAILED\nthread 'p' (1) panicked at x.rs:3:3:\nthe staged bundle must match the recorded pin\n"
MIX="${BOOT}test c::reap ... FAILED\nthread 'c' (1) panicked at x.rs:4:4:\nchild was not reaped\n"
PIN_AND_BOOT="${PIN}${BOOT}"
FIRST_READY="test s::crash ... FAILED\nthread 's' (1) panicked at x.rs:5:5:\ntimed out awaiting first Ready\n"
SECOND_READY="test s::crash ... FAILED\nthread 's' (1) panicked at x.rs:6:6:\ntimed out awaiting second Ready\n"
OK="test result: ok. 4 passed\n"

failures=0
# case <name> <attempt1 text> <attempt1 rc> <attempt2 text> <attempt2 rc> <want exit> <want attempts>
case_() {
  local name="$1" dir="$work/$1"
  mkdir -p "$dir"
  printf '%b' "$2" > "$dir/attempt1.txt"; echo "$3" > "$dir/attempt1.rc"
  printf '%b' "$4" > "$dir/attempt2.txt"; echo "$5" > "$dir/attempt2.rc"
  SCEN="$dir" PATH="$work/bin:$PATH" bash "$here/run_live_tor_tests.sh" crate "$dir/out" \
    > "$dir/stdout" 2> "$dir/stderr"
  local rc=$? attempts
  attempts="$(cat "$dir/count")"
  if [ "$rc" != "$6" ] || [ "$attempts" != "$7" ]; then
    echo "FAIL $name: exit $rc after $attempts attempt(s), wanted exit $6 after $7"
    failures=$((failures+1))
  fi
}

case_ "a pass is one attempt"                        "$OK"           0   ""     0   0   1
case_ "a bootstrap timeout is retried once"          "$BOOT"         101 "$OK"  0   0   2
case_ "the other bootstrap wording is retried too"   "$BOOT2"        101 "$OK"  0   0   2
case_ "the wallet's first-Ready wait is a bootstrap"  "$FIRST_READY"  101 "$OK"  0   0   2
# The same helper, a later wait: that is a respawn that did not recover.
case_ "a wait for a later Ready is not"              "$SECOND_READY" 101 "$OK"  0   101 1
case_ "a second timeout fails: one retry, no loop"   "$BOOT2"        101 "$BOOT" 101 101 2
case_ "a pin mismatch is never retried"              "$PIN"          101 "$OK"  0   101 1
case_ "a pin mismatch beside a timeout is not either" "$PIN_AND_BOOT" 101 "$OK" 0   101 1
# The pin test reported FAILED and the only panic text is a timeout's: the
# pin guard, not the message rule, is what refuses this one.
case_ "a failed pin test is not, whatever it printed" "test binary::tests::bundled_tor_matches_recorded_pin ... FAILED\n${BOOT}" 101 "$OK" 0 101 1
case_ "a timeout beside another failure is not"      "$MIX"          101 "$OK"  0   101 1
case_ "a failure with no panic is not"               "error: could not compile\n" 101 "$OK" 0 101 1

# A retried run must say so.
if ! grep -q '^::warning' "$work/a bootstrap timeout is retried once/stdout"; then
  echo "FAIL a retried run did not annotate itself"
  failures=$((failures+1))
fi

if [ "$failures" -ne 0 ]; then
  echo "run_live_tor_tests self-test: $failures case(s) FAILED"
  exit 1
fi
echo "run_live_tor_tests self-test: all 11 cases pass"
