#!/usr/bin/env bash
#
# Copyright (c) 2025-2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# Consensus-invariant checks — Phase 4 of `docs/completed/DAA_LWMA1_PLAN.md`
# work-items 8, 9, 10 (`docs/completed/DAA_LWMA1.md` §7).
#
# Invariants verified at source level:
#
#   1. No-C-ABI in `rust/shekyl-difficulty`: the algorithm crate defines
#      no C-ABI surface (`#[no_mangle]`, `extern "C" fn`,
#      `#[export_name]`). Nothing in the tree calls Rust through a C ABI,
#      and a pure algorithm crate never grows one.
#   2. The archival reward gates (`check_archival_reward_gates.sh`).
#   3. The sync loop's orphan arm re-syncs and never punishes.
#
# The C++ tree's own invariants (no consumer of the deleted CryptoNote
# difficulty functions or `#define`s) went with the C++: the outcome gate
# (`check_no_first_party_c.py`) admits no first-party C or C++ at all.
#
# The script exits 0 on all invariants passing; non-zero with a
# pinpoint message on any failure.

set -euo pipefail

# Dependency precondition. `rg` (ripgrep) is the load-bearing tool for all
# three invariants below; a missing `rg` would turn the gate into a silent
# pass via `2>/dev/null` masking the "command not found" failure. Fail
# loudly at the top with a clear remediation hint, so local developers
# without ripgrep installed see the actual problem.
if ! command -v rg >/dev/null 2>&1; then
  echo "ERROR: ripgrep (rg) is required for consensus-invariants checks." >&2
  echo "       Install via your package manager (e.g., apt install ripgrep)." >&2
  exit 2
fi

# Run from the repo root.
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

FAIL=0

# ----------------------------------------------------------------------
# Rule 46/47: rg exits 0 = matches, 1 = no matches, >1 = SCAN ERROR.
# `if rg ...; then FAIL; else OK; fi` cannot tell 2 from 1, so a missing
# search root or a malformed -g glob landed in the OK branch -- WITH the
# offending line printed to stdout. Measured 2026-09-11: rg prints
# `present/live.cpp:1:next_difficulty(1);` and exits 2 when one of several
# roots is absent. A gate that could not read its subject has not returned
# a verdict, and must not be read as one.
#
# This idiom is LIFTED, not invented -- check_carrier_flag_hidden.sh has
# split grep's 2 from its 1 (with a comment naming the failure mode) since
# it was written, and check_ignore_reasons.sh does count-then-FATAL-at-zero.
# The knowledge was in the tree; it just had not been swept across.
# ----------------------------------------------------------------------

# Child gates exit 0 = clean, 1 = violations (already printed), >1 = could
# not judge. Folding >1 into FAIL=1 would let later invariants print OK
# after a scan error on an inflation surface. Propagate.
run_child() {
  local rc=0
  "$@" || rc=$?
  case "$rc" in
    0) echo "      OK" ;;
    1) FAIL=1 ;;
    *) echo "      FATAL: $* exited ${rc} (scan error, not a verdict)" >&2
       exit "$rc" ;;
  esac
}

# Returns 0 = clean (no matches), 1 = violations found (printed).
# Exits 2 on a scan error -- never silently clean.
rg_verdict() {
  local out rc=0
  out=$(rg "$@") || rc=$?
  case "$rc" in
    0) printf '%s\n' "$out"; return 1 ;;
    1) return 0 ;;
    *) echo "FATAL: rg exited ${rc} (scan error, not no-match) during:" >&2
       echo "       rg $*" >&2
       echo "       The gate could not read its subject, so it has NO verdict." >&2
       echo "       Usual cause: a search root was deleted or renamed." >&2
       exit 2 ;;
  esac
}

# Rule 47 positive control: the searched population must be non-empty.
# A zero-file scan reports the same clean as a scan that examined
# everything, and the glob excludes are exactly what could empty it.
assert_population() {
  local label="$1"; shift
  local files rc=0
  files=$(rg --files "$@") || rc=$?
  if [ "$rc" -ne 0 ] || [ -z "$files" ]; then
    echo "FATAL: ${label}: the search enumerated no files (rg rc ${rc})." >&2
    echo "       The invariant below would pass over an empty set." >&2
    exit 2
  fi
}

# ----------------------------------------------------------------------
# Invariant 1: no C-ABI declarations in shekyl-difficulty.
# ----------------------------------------------------------------------
echo "[1/3] No-C-ABI in rust/shekyl-difficulty/src/"

assert_population "invariant 2 (no C-ABI in shekyl-difficulty)" \
  --type rust rust/shekyl-difficulty/src/

if ! rg_verdict --type rust \
      -n \
      '(#\[no_mangle\]|extern\s+"C"\s+fn|#\[export_name)' \
      rust/shekyl-difficulty/src/
then
  echo "FAIL: C-ABI declaration(s) in shekyl-difficulty above."
  echo
  echo "The shekyl-difficulty crate is a pure-Rust algorithm crate and"
  echo "nothing in the tree calls Rust through a C ABI. Call the algorithm"
  echo "from Rust; delete the C-ABI declaration."
  FAIL=1
else
  echo "      OK"
fi
echo

# ----------------------------------------------------------------------
# Invariant 2: archival reward gates (mint + integer arithmetic).
# ----------------------------------------------------------------------
echo "[2/3] Archival reward gates"
run_child scripts/ci/check_archival_reward_gates.sh
echo

# ----------------------------------------------------------------------
# 3. C2-R1c-Q3b: the sync-loop orphan arm re-syncs; it never punishes.
#    An in-loop orphan during span processing means OUR store lost the
#    parent between the span pre-check and the add (checkpoint-rollback
#    discard, operator pop, Q1a flip-flop discard) -- degradation, not
#    peer misconduct. Misrepresentation is caught at the queue
#    bookkeeping-mismatch arm instead. Rule 47: the arm's own marker is
#    asserted present before its content is judged.
# ----------------------------------------------------------------------
echo "[3/3] sync orphan arm re-syncs without penalizing (C2-R1c-Q3b)"
# The decision is chain sync's model since CS-5: the entry's `Unlinked`
# reply (a body whose parent reaches nothing this node holds) re-locates
# the supplier with a header request and closes nothing; a refused block
# is the arm that closes. The test
# an_unlinked_body_relocates_its_supplier_and_closes_nothing pins the
# same split. (The C++ handler whose `m_marked_as_orphaned` this gate
# also refused was deleted on 2026-11-05; chain sync is the only arm.)
ENTRY=rust/shekyl-chain-sync/src/runs/entry.rs
ORPHAN_TEST=rust/shekyl-chain-sync/src/relay_tests.rs
UNLINKED_ARM=$(awk '/Outcome::Unlinked \{ at \} => \{/,/^            \}$/' "$ENTRY")
REFUSED_ARM=$(awk '/Outcome::Refused \{ verdict \} => \{/,/^            \}$/' "$ENTRY")
if [[ ! -f "$ENTRY" || -z "$UNLINKED_ARM" || -z "$REFUSED_ARM" ]]; then
  echo "      FAIL: could not extract the Unlinked and Refused arms from $ENTRY"
  echo "            -- the sync action moved; re-point this gate, do not delete it."
  FAIL=1
elif ! rg -q 'fn an_unlinked_body_relocates_its_supplier_and_closes_nothing' "$ORPHAN_TEST"; then
  echo "      FAIL: $ORPHAN_TEST lost the test that pins the orphan split."
  FAIL=1
elif printf '%s\n' "$UNLINKED_ARM" | grep -q 'self.close('; then
  echo "      FAIL: the Unlinked arm closes the session -- an orphan re-sync would sever."
  FAIL=1
elif ! printf '%s\n' "$UNLINKED_ARM" | grep -q 'self.locate('; then
  echo "      FAIL: the Unlinked arm no longer re-locates the supplier."
  FAIL=1
elif ! printf '%s\n' "$REFUSED_ARM" | grep -q 'self.close('; then
  echo "      FAIL: the Refused arm no longer closes -- the severing arm is gone."
  FAIL=1
else
  echo "      OK"
fi
echo

# ----------------------------------------------------------------------
# Result summary.
# ----------------------------------------------------------------------
if [[ "$FAIL" -ne 0 ]]; then
  echo "consensus-invariants: FAIL"
  exit 1
fi
echo "consensus-invariants: PASS (3/3)"
