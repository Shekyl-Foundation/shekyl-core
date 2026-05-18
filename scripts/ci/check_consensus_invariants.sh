#!/usr/bin/env bash
#
# Copyright (c) 2025-2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# Consensus-invariant checks — Phase 4 of `docs/design/DAA_LWMA1_PLAN.md`
# work-items 8, 9, 10 (`docs/design/DAA_LWMA1.md` §7).
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
echo "[1/3] Symbol-isolation: next_difficulty / next_difficulty_64"

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
echo "[2/3] No-C-ABI in rust/shekyl-difficulty/src/"

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
echo "[3/3] No-orphaned-magic-numbers: DIFFICULTY_* / FTL / MTP legacy"

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
# Result summary.
# ----------------------------------------------------------------------
if [[ "$FAIL" -ne 0 ]]; then
  echo "consensus-invariants: FAIL"
  exit 1
fi
echo "consensus-invariants: PASS (3/3)"
