#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The provenance marker for transit-derived levels must not outlive the
# constant it names.
#
# `DAEMON_RELAY_PRIVACY.md` §94.4 rules that when the measured transit constant
# lands, `ANON_ZONE_TRANSIT_ASSUMPTION_MS` is DELETED in the same commit. Every
# recorded level derived from that assumption carries a marker naming it, so the
# re-derivation round can find them by search:
#
#     instrument output at ANON_ZONE_TRANSIT_ASSUMPTION_MS (1625); moves with §94
#
# Deleting the constant breaks code references — `transit_for` and the
# reconciliation test — but NOT the markers, which live in doc comments and a
# `println!` string. So the sweep would depend on somebody remembering to run
# it, which is an armed marker with no trigger. This is the trigger.
#
# What edit reds this gate: delete `ANON_ZONE_TRANSIT_ASSUMPTION_MS` without
# sweeping the marked sites. It then names every one of them.
#
# Rule 46: no verdict travels through a pipe. Rule 47: the gate asserts its own
# subject — if neither the constant nor a marker exists, the gate has lost its
# subject and says so rather than passing on absence.

set -uo pipefail

MARKER='moves with §94'
CONST='ANON_ZONE_TRANSIT_ASSUMPTION_MS'
DEF_GLOB='rust/shekyl-relay-privacy/src/verify_cost.rs'

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root" || exit 2

# Rule 47, and the reason this block is not a one-liner: grep returns 1 for
# "no match" and 2 for "could not read" (missing file, unreadable path). The
# earlier form captured $? and tested only `-eq 0`, so a RENAMED verify_cost.rs
# fell through to the constant-is-gone arm -- and, with no marker found, the
# gate printed "the §94 sweep is complete / this gate has no remaining subject
# and should be deleted". It did not merely go green on a broken run: it
# recommended its own retirement on a false premise, which is the one failure a
# provenance tripwire must never have.
#
# So the SUBJECT FILE is asserted readable before its contents are read as
# evidence of anything. Absence of the constant is only a deletion event if we
# could actually read the file it should be in.
if [ ! -r "$DEF_GLOB" ]; then
  echo "FAIL: ${DEF_GLOB} is missing or unreadable."
  echo "      The gate could not read its subject, so the absence of"
  echo "      ${CONST} is NOT evidence that §94 landed -- it is evidence the"
  echo "      file moved. Re-point this gate; do not delete it, and do not"
  echo "      read this as the sweep being complete."
  exit 2
fi

grep -q "pub const ${CONST}" "$DEF_GLOB"
const_present=$?
if [ "$const_present" -gt 1 ]; then
  echo "FAIL: grep could not scan ${DEF_GLOB} (rc ${const_present})."
  echo "      A scan error is not a no-match; the gate has no verdict."
  exit 2
fi

# Marked sites, one path per line. `-l` so the verdict is a file list.
# stderr is NOT discarded and rc>1 is NOT folded into "no markers": an
# unreadable search root would otherwise read as a completed sweep.
marked_rc=0
marked=$(grep -rl "$MARKER" rust/ docs/ src/ --include='*.rs' --include='*.md' --include='*.h' --include='*.cpp') || marked_rc=$?
if [ "$marked_rc" -gt 1 ]; then
  echo "FAIL: the marker search errored (rc ${marked_rc}) -- a search that could"
  echo "      not read its roots has not shown that no marker survives."
  exit 2
fi

if [ "$const_present" -eq 0 ]; then
  if [ "$marked_rc" -ne 0 ] || [ -z "$marked" ]; then
    echo "FAIL: ${CONST} is defined but no site carries the provenance marker."
    echo "      Either the marked levels were removed without removing this gate,"
    echo "      or the marker text drifted. The gate has no subject; fix one or"
    echo "      the other rather than deleting the check."
    exit 1
  fi
  echo "PASS: ${CONST} is defined; $(printf '%s\n' "$marked" | wc -l) file(s) carry the marker."
  exit 0
fi

# The constant is gone: §94 landed. Every marker is now a dangling provenance
# claim pointing at a constant that does not exist.
if [ "$marked_rc" -ne 0 ] || [ -z "$marked" ]; then
  echo "PASS: ${CONST} is gone and no marker survives it — the §94 sweep is complete."
  echo "      This gate has no remaining subject and should be deleted with the"
  echo "      commit that lands the measured constant."
  exit 0
fi

echo "FAIL: ${CONST} has been deleted, but these files still record levels as"
echo "      derived from it. Re-read each against the measured constant, then"
echo "      remove the marker:"
# Indent every line, not just the first: `printf fmt "$multiline"` applies the
# format once. The verdict is the explicit `exit 1` below, never this pipe.
printf '%s\n' "$marked" | sed 's/^/        /'
exit 1
