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
#   1. Cap fossils: `n_total > 7`, `MAX_MULTISIG_PARTICIPANTS = 7`, and
#      any operator config `k-of-n` whose participant count exceeds
#      MSW-G = 5 (`6-of-6`, `5-of-6`, `7-of-5`, `5-of-7`, …) — not just
#      the two literals containing a 7.
#   2. Fee-oracle fossils: solo `pqc_auth` sized as 5385 (omit varints);
#      oracle is `pqc_auth_weight()` = 5389 in
#      `rust/shekyl-engine-core/src/engine/tx_fee_model.rs`. The 5385
#      figure is caught whether written bare (`5385`), comma-grouped
#      (`5,385`), or approximation-prefixed (`~5,385`, `≈5385`) — the
#      earlier draft required a leading `~` and so missed comma forms.
#
# Scoped to operator / protocol / design prose under `docs/`. Excludes
# CHANGELOG (historical arrows), `docs/completed/`, test vectors /
# benchmarks / JSON KATs (MSW-1 owns those). The design carrier
# (`V3_1_MULTISIG_RUST_ENGINE.md`), the tracking index, and FOLLOWUPS
# are NO LONGER excluded wholesale — that hole let a new fossil land
# undetected in the very file most likely to carry one. Instead, the
# handful of genuinely-historical rows those files carry (decision-log
# entries recording withdrawn MAX=7/8 picks, reward-zone `7-of-7`
# analysis) are exempted line-by-line with an inline
# `doc-literal-gate-allow` marker — a reviewable, fail-closed carve-out:
# a NEW fossil on an un-annotated line still fails the gate.
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
# The design carrier / tracking index / FOLLOWUPS are intentionally NOT
# excluded here (see the header note): they are scanned, and their few
# legitimately-historical lines are exempted individually via the
# `doc-literal-gate-allow` marker filtered in `hit()`.
RG_COMMON=(
  -n
  --type md
  --glob '!**/CHANGELOG.md'
  --glob '!**/completed/**'
  --glob '!**/test_vectors/**'
  --glob '!**/benchmarks/**'
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
  # Drop lines that carry an inline `doc-literal-gate-allow` marker —
  # the reviewable, per-line carve-out for genuinely-historical prose
  # (decision-log rows, reward-zone analysis) in the design carrier /
  # index / FOLLOWUPS. grep exit codes: 0 = lines survived, 1 = every
  # match was annotated away (clean), >=2 = real error (abort loudly).
  if [[ -n "${matches}" ]]; then
    local gstatus=0
    matches="$(printf '%s\n' "${matches}" | grep -v 'doc-literal-gate-allow')" || gstatus=$?
    if [[ "${gstatus}" -ge 2 ]]; then
      echo "FATAL: grep failed (exit ${gstatus}) filtering allow-markers" >&2
      exit 2
    fi
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

# Any `k-of-n` where either count exceeds MSW-G = 5 is an unreachable
# cap fossil — `6-of-6`, `5-of-6`, `7-of-5`, `5-of-7`, `12-of-3`, … —
# not only the two literals that happen to contain a 7. Single digit
# 6-9 or any 2+-digit count (>=10) on either side trips it; valid
# configs (`3-of-5`, `5-of-5`, `2-of-3`) do not.
hit "operator config >5 participants (unreachable under MAX_MULTISIG_PARTICIPANTS=5)" \
  '\b(?:[6-9]-of-[0-9]+|[0-9]+-of-[6-9]|[0-9]{2,}-of-[0-9]+|[0-9]+-of-[0-9]{2,})\b'

# --- Fee-oracle fossils (pqc_auth_weight = 5389) ---------------------------
# Keep patterns simple (no .{0,N} spans) — PCRE2 backtracking on large
# docs hung an earlier gate draft. `5,?385` matches the figure whether
# comma-grouped or bare; the leading `\b` keeps it from matching inside a
# larger number (`15,385`, `45385`).
hit "omit-varint sum '4 + 1996 + 3385 = 5385' (oracle is 5389)" \
  '\b4\s*\+\s*1996\s*\+\s*3385\s*=\s*5,?385\b'
hit "5385-byte figure, bare or comma-grouped (oracle is 5389)" \
  '\b5,?385[- ]?bytes?\b'
hit "approximation-prefixed 5385 figure ~/≈ (oracle is 5389)" \
  '(?:~|≈)\s*5,?385\b'

if [[ "${fail}" -ne 0 ]]; then
  echo "P0-n: multisig doc-literal gate FAILED." >&2
  echo "Fix the hits, or if a hit is intentional historical prose," >&2
  echo "move it under an excluded path / rephrase with MAX_MULTISIG_PARTICIPANTS." >&2
  echo "See docs/design/V3_1_MULTISIG_RUST_ENGINE.md P0-n." >&2
  exit 1
fi

echo "P0-n: multisig doc-literal gate clean."
exit 0
