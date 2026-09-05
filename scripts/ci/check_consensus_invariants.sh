#!/usr/bin/env bash
#
# Copyright (c) 2025-2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# Consensus-invariant checks — Phase 4 of `docs/completed/DAA_LWMA1_PLAN.md`
# work-items 8, 9, 10 (`docs/completed/DAA_LWMA1.md` §7).
#
# Three invariants verified at source level (binary-level `nm` checks
# require building the C++ daemon and are deferred to a separate
# hardening pass; absence of the symbol in source is a necessary
# precondition for absence in the binary, so this gate catches the
# regression class the binary-level check would catch, just earlier):
#
#   1. Symbol-isolation: no live consumers of the deleted CryptoNote
#      DAA functions `next_difficulty` and `next_difficulty_64` remain
#      in the C++ source tree. Comment-only mentions inside files that
#      document the deletion are allowlisted.
#
#   2. No-C-ABI in `rust/shekyl-difficulty`: the algorithm crate must
#      not define C-ABI surface (`#[no_mangle]`, `extern "C" fn`,
#      `#[export_name]`); the C ABI lives in `rust/shekyl-ffi` per
#      `25-rust-architecture.mdc`.
#
#   3. No-orphaned-magic-numbers: no source references to the
#      `DIFFICULTY_*`, `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT`,
#      `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW`, or
#      `CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1` macros that
#      Phase 4 deleted from `cryptonote_config.h`. Comment-only
#      mentions inside files that document the deletion are
#      allowlisted.
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
# Allowlists (comment-only mentions of deleted symbols).
#
# Each entry is a file path that may legitimately reference a deleted
# symbol in a documentation comment. New allowlist entries require a
# review-time justification in the PR description.
# ----------------------------------------------------------------------

# Files that document the C++ DAA deletion in prose (item 1 / item 3
# allowlist).
DOC_ALLOWLIST=(
  'src/cryptonote_config.h'
  'src/cryptonote_basic/difficulty.h'
  'src/cryptonote_core/difficulty_engine_error.h'
  'tests/core_tests/block_validation.cpp'
  'tests/difficulty/CMakeLists.txt'
  'tests/difficulty/zawy12_lwma1_reference.h'
  'tests/unit_tests/rpc_target_wire_contract.cpp'
  'tests/unit_tests/stall_detection_calibration.cpp'
)

build_glob_excludes() {
  local args=()
  for f in "${DOC_ALLOWLIST[@]}"; do
    args+=(-g "!${f}")
  done
  printf '%s\n' "${args[@]}"
}

# ----------------------------------------------------------------------
# Invariant 1: no live consumers of deleted DAA functions.
# ----------------------------------------------------------------------
echo "[1/5] Symbol-isolation: next_difficulty / next_difficulty_64"

mapfile -t glob_excludes < <(build_glob_excludes)

if rg --type-add 'cpp:*.{c,h,cpp,hpp,cc,inl}' --type cpp \
      "${glob_excludes[@]}" \
      -g '!build/**' \
      -n \
      '\b(next_difficulty|next_difficulty_64)\b' \
      src/ tests/ contrib/
then
  echo "FAIL: live reference(s) to deleted DAA function(s) above."
  echo
  echo "If the match is a comment-only mention documenting the deletion,"
  echo "add the file path to DOC_ALLOWLIST in this script and re-run."
  echo "If the match is a live consumer, the Phase 4 cutover is"
  echo "incomplete; rewire the consumer to shekyl_difficulty_lwma1_next"
  echo "via the lwma1_next_difficulty helper."
  FAIL=1
else
  echo "      OK"
fi
echo

# ----------------------------------------------------------------------
# Invariant 2: no C-ABI declarations in shekyl-difficulty.
# ----------------------------------------------------------------------
echo "[2/5] No-C-ABI in rust/shekyl-difficulty/src/"

if rg --type rust \
      -n \
      '(#\[no_mangle\]|extern\s+"C"\s+fn|#\[export_name)' \
      rust/shekyl-difficulty/src/
then
  echo "FAIL: C-ABI declaration(s) in shekyl-difficulty above."
  echo
  echo "The shekyl-difficulty crate is a pure-Rust algorithm crate;"
  echo "the C ABI lives in rust/shekyl-ffi per 25-rust-architecture.mdc."
  echo "Move the C-ABI declaration to rust/shekyl-ffi and re-export"
  echo "shekyl-difficulty's algorithm types through a wrapping fn."
  FAIL=1
else
  echo "      OK"
fi
echo

# ----------------------------------------------------------------------
# Invariant 3: no orphaned references to deleted #defines.
# ----------------------------------------------------------------------
echo "[3/5] No-orphaned-magic-numbers: DIFFICULTY_* / FTL / MTP legacy"

DELETED_DEFINES='DIFFICULTY_TARGET_V[12]|DIFFICULTY_WINDOW|DIFFICULTY_LAG|DIFFICULTY_CUT|DIFFICULTY_BLOCKS_COUNT|DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN|CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT|BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW|CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1'

if rg --type-add 'cpp:*.{c,h,cpp,hpp,cc,inl}' --type cpp \
      "${glob_excludes[@]}" \
      -g '!build/**' \
      -n \
      "\\b(${DELETED_DEFINES})\\b" \
      src/ tests/ contrib/
then
  echo "FAIL: reference(s) to deleted #define(s) above."
  echo
  echo "If the match is a comment-only mention documenting the deletion,"
  echo "add the file path to DOC_ALLOWLIST in this script and re-run."
  echo "If the match is a live consumer, the Phase 4 sweep is"
  echo "incomplete; rewire the consumer to its SHEKYL_DAA_* / generated"
  echo "JSON-authority equivalent."
  FAIL=1
else
  echo "      OK"
fi
echo

# ----------------------------------------------------------------------
# Invariant 4: archival reward gates (mint + integer arithmetic).
# ----------------------------------------------------------------------
echo "[4/5] Archival reward gates"
if ! scripts/ci/check_archival_reward_gates.sh; then
  FAIL=1
else
  echo "      OK"
fi
echo

# ----------------------------------------------------------------------
# Invariant 5: segment-freeze one-site tripwires (cursor accounting,
# boundary operator, writer/division/counter-mutation one-site —
# ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §4.4/§8; the substrate half of the
# retired M1 gate's former tripwire, ARCHIVAL_REWARD_GATE_M1.md §13).
# ----------------------------------------------------------------------
echo "[5/5] Segment-freeze one-site tripwires"
if ! scripts/ci/check_segment_freeze_sites.sh; then
  FAIL=1
else
  echo "      OK"
fi
echo

# ----------------------------------------------------------------------
# 6. C2-R1b-Q1c / F-2: the prune watermark has ONE writer and no revert.
#    The pop floor is the prune's durable receipt: written only inside
#    prune_archival_epochs_before (same txn as the deletions), monotonic,
#    and deliberately EXEMPT from pop reversal -- pops cannot restore
#    pruned rows, so the floor never retreats. A second key site is a
#    drift twin; a mention inside any revert_* function body is the
#    walk-down hole reopening through the back door. (Rule 47: writer
#    presence is asserted before its uniqueness.)
# ----------------------------------------------------------------------
echo "[6/6] prune-watermark single-writer + no-revert (C2-R1b F-2)"
# Exactly two identifier occurrences: the definition and the prune call.
# A floor (>= 2) would let a THIRD call site ride in under a gate that
# claims single-writer -- the count is an equality, so an unauthorized
# second caller of the writer turns this red instead of passing.
WM_CALLS=$(grep -c "note_archival_prune_watermark_epoch" src/blockchain_db/lmdb/db_lmdb.cpp || true)
if [[ "${WM_CALLS:-0}" -ne 2 ]]; then
  echo "      FAIL: expected exactly 2 note_archival_prune_watermark_epoch"
  echo "            occurrences (definition + the prune call site), found"
  echo "            ${WM_CALLS:-0} -- fewer means the writer or its call is gone,"
  echo "            more means an unauthorized second caller."
  FAIL=1
else
  WM_KEY_SITES=$(grep -c '"archival_prune_watermark_epoch"' src/blockchain_db/lmdb/db_lmdb.cpp || true)
  # Anchored on the prune watermark's own identifiers: the slash revert
  # legitimately speaks of the slash-fold watermark, a different concept.
  # Region bound: from each revert_* definition to the NEXT top-level
  # BlockchainLMDB member -- not the first column-0 '}'. Review asked
  # about inner-brace truncation (all seven bodies verified to end at
  # their true '}' today), and checking that surfaced the real adjacent
  # hole the wider bound closes: anonymous-namespace helpers that sit
  # BETWEEN reverts (and are called by them) escaped a body-only scan,
  # so a revert could launder the forbidden reference through a helper.
  # Close only on a COLUMN-0 definition of a non-revert member: bodies
  # log their own qualified name (LOG_PRINT_L3("BlockchainLMDB::"...)),
  # so an unanchored close fires two lines into every function.
  WM_IN_REVERTS=$(awk '/^void BlockchainLMDB::revert_/{inr=1} inr && /^[A-Za-z_].*BlockchainLMDB::/ && !/BlockchainLMDB::revert_/{inr=0} inr' src/blockchain_db/lmdb/db_lmdb.cpp | grep -c "archival_prune_watermark" || true)
  if [[ "${WM_KEY_SITES:-0}" -ne 2 ]]; then
    echo "      FAIL: property key must appear exactly twice (reader + writer);"
    echo "            found ${WM_KEY_SITES:-0} -- a third site is a drift twin or"
    echo "            an unauthorized writer."
    FAIL=1
  elif [[ "${WM_IN_REVERTS:-0}" -ne 0 ]]; then
    echo "      FAIL: a revert_* body references the prune watermark -- the floor"
    echo "            is exempt from pop reversal BY DESIGN (F-2)."
    FAIL=1
  else
    echo "      OK"
  fi
fi
echo

# ----------------------------------------------------------------------
# 7. C2-R1c-Q3b: the sync-loop orphan arm re-syncs; it never punishes.
#    An in-loop orphan during span processing means OUR store lost the
#    parent between the span pre-check and the add (checkpoint-rollback
#    discard, operator pop, Q1a flip-flop discard) -- degradation, not
#    peer misconduct. Misrepresentation is caught at the queue
#    bookkeeping-mismatch arm instead. Rule 47: the arm's own marker is
#    asserted present before its content is judged.
# ----------------------------------------------------------------------
echo "[7/7] sync orphan arm re-syncs without penalizing (C2-R1c-Q3b)"
INL=src/cryptonote_protocol/cryptonote_protocol_handler.inl
# Capture each WHOLE m_marked_as_orphaned arm (its if-line through the
# closing brace at the same indent) and keep the one carrying the Q3b
# marker -- a fixed post-marker line count missed both a punitive call
# placed before the marker and the arm growing past the window (review
# round 1 on the R1c PR). Punitive tokens: every drop_* spelling plus
# host scoring and host blocking.
# set -e would abort at this assignment on extractor failure, making the
# pinpoint diagnostic below unreachable (rule 46's class: the verdict
# must not die in transit) -- capture the rc through an || arm.
Q3B_RC=0
Q3B_ARM=$(awk '
  /if\(bvc\.m_marked_as_orphaned\)/ { cap=1; buf="" }
  cap { buf = buf $0 "\n";
        if ($0 ~ /^            \}$/) { cap=0;
          if (buf ~ /re-syncing without penalizing the origin/) { print buf; found++ } } }
  END { if (found != 1) exit 3 }' "$INL") || Q3B_RC=$?
if [[ "$Q3B_RC" -ne 0 || -z "$Q3B_ARM" ]]; then
  echo "      FAIL: could not extract exactly one marker-carrying orphan arm"
  echo "            (extractor rc $Q3B_RC) -- the arm was removed, reworded,"
  echo "            or re-indented; re-point this gate, do not delete it."
  FAIL=1
else
  Q3B_PUNISH=$(printf '%s' "$Q3B_ARM" | grep -cE "drop_connection|add_host_fail|block_host|hit_score|m_score" || true)
  if [[ "${Q3B_PUNISH:-0}" -ne 0 ]]; then
    echo "      FAIL: the sync orphan arm contains a punitive call"
    echo "            (drop_connection*/add_host_fail/block_host/hit_score/m_score) --"
    echo "            punishment re-entered the arm (C2-R1c-Q3b ruled this a"
    echo "            defect; the fix falsifier in the round doc names the"
    echo "            only evidence that reopens HOW, and nothing reopens"
    echo "            WHETHER)."
    FAIL=1
  else
    echo "      OK"
  fi
fi
echo

# ----------------------------------------------------------------------
# Result summary.
# ----------------------------------------------------------------------
if [[ "$FAIL" -ne 0 ]]; then
  echo "consensus-invariants: FAIL"
  exit 1
fi
echo "consensus-invariants: PASS (7/7)"
