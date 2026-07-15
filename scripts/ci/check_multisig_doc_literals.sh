#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# check_multisig_doc_literals.sh — P0-n (V3.1 multisig Phase 0).
#
# Doc prose KAT for the defect class that produced D-1 / D-3 / D-4:
# a value whose semantics live in its consumers, surviving a sweep
# because nothing tests the prose.
#
# Fails on:
#   1. Cap fossils: `n_total > 7`, `MAX_MULTISIG_PARTICIPANTS = 7`,
#      operator configs `5-of-7` / `7-of-7` (MSW-G = 5).
#   2. Fee-oracle fossils: solo `pqc_auth` sized as 5385 (omit varints);
#      oracle is `pqc_auth_weight()` = 5389 in
#      `rust/shekyl-engine-core/src/engine/tx_fee_model.rs`.
#
# Scoped to operator / protocol / design prose under `docs/`. Excludes
# CHANGELOG (historical arrows), `docs/completed/`, test vectors /
# benchmarks / JSON KATs (MSW-1 owns those), and the design carrier's
# decision-log rows that intentionally record withdrawn MAX=7/8 picks.
#
# Exit 0 = clean; non-zero = hits printed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

# Prefer system ripgrep. Cursor's bundled rg (first on PATH in some
# agent shells) has hung on repo-root glob scans in bring-up.
RG_BIN=""
for candidate in /usr/bin/rg /bin/rg; do
  if [[ -x "${candidate}" ]]; then
    RG_BIN="${candidate}"
    break
  fi
done
if [[ -z "${RG_BIN}" ]]; then
  if command -v rg >/dev/null 2>&1; then
    RG_BIN="$(command -v rg)"
  else
    echo "FATAL: ripgrep (rg) required" >&2
    exit 2
  fi
fi

# Explicit path + file-type filter — do not scan from repo root with
# only -g globs (slow / flaky with some rg builds). No pattern below uses
# a PCRE2-only feature (look-around / backreferences); `(?:...)` groups are
# native to ripgrep's default engine, so we do NOT pass `--pcre2` — a build
# of rg without PCRE2 support would otherwise error and, combined with the
# no-match handling in `hit()`, could bypass the gate.
RG_COMMON=(
  -n
  --type md
  --glob '!**/CHANGELOG.md'
  --glob '!**/completed/**'
  --glob '!**/test_vectors/**'
  --glob '!**/benchmarks/**'
  --glob '!**/V3_1_MULTISIG_RUST_ENGINE.md'
  --glob '!**/IMPLEMENTATION_INDEX.md'
  --glob '!**/FOLLOWUPS.md'
)

fail=0

hit() {
  local label="$1"
  local pattern="$2"
  local matches
  local status=0
  # rg exit codes: 0 = match found, 1 = no match, >=2 = real error (bad
  # flag, unusable regex, unreadable path, missing engine feature). Only 1
  # is "clean" — anything >=2 must abort loudly, otherwise a broken rg
  # invocation prints to stderr and the gate silently passes on empty
  # stdout. `|| status=$?` also keeps `set -e` from firing on exit 1.
  matches="$("${RG_BIN}" "${RG_COMMON[@]}" "${pattern}" docs)" || status=$?
  if [[ "${status}" -ge 2 ]]; then
    echo "FATAL: ripgrep failed (exit ${status}) on pattern: ${pattern}" >&2
    exit 2
  fi
  if [[ -n "${matches}" ]]; then
    echo "FAIL [${label}]:" >&2
    echo "${matches}" >&2
    echo >&2
    fail=1
  fi
}

# --- Cap fossils (MSW-G = 5) ----------------------------------------------
hit "n_total > 7 (use MAX_MULTISIG_PARTICIPANTS)" \
  'n_total\s*>\s*7\b'

hit "MAX_MULTISIG_PARTICIPANTS = 7" \
  'MAX_MULTISIG_PARTICIPANTS\s*=\s*7\b'

hit "operator config 5-of-7 / 7-of-7 (unreachable under MAX=5)" \
  '\b(?:5-of-7|7-of-7)\b'

# --- Fee-oracle fossils (pqc_auth_weight = 5389) ---------------------------
# Keep patterns simple (no .{0,N} spans) — PCRE2 backtracking on large
# docs hung an earlier gate draft.
hit "solo pqc_auth sized 5385 (omit-varint fossil; oracle is 5389)" \
  '4\s*\+\s*1996\s*\+\s*3385\s*=\s*5385'
hit "tilde-5385 / comma-5385 fee figure (oracle is 5389)" \
  '~5,385|~5385\b'
hit "bare 5385 bytes near pqc_auth prose" \
  '5385\s+bytes'

if [[ "${fail}" -ne 0 ]]; then
  echo "P0-n: multisig doc-literal gate FAILED." >&2
  echo "Fix the hits, or if a hit is intentional historical prose," >&2
  echo "move it under an excluded path / rephrase with MAX_MULTISIG_PARTICIPANTS." >&2
  echo "See docs/design/V3_1_MULTISIG_RUST_ENGINE.md P0-n." >&2
  exit 1
fi

echo "P0-n: multisig doc-literal gate clean."
exit 0
