#!/usr/bin/env bash
#
# Copyright (c) 2025-2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# Archival reward gates — mint + integer arithmetic discipline.
# Invoked from check_consensus_invariants.sh and CI.

set -euo pipefail

# Resolve from the script, not the caller's cwd. The comment stripper is a
# sibling file; `$0` is relative when the parent gate invokes us, so reading
# it after a cd-to-root would look for the helper under the repo root.
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit 2
cd "${here}/../.." || exit 2

if ! command -v rg >/dev/null 2>&1; then
  echo "FAIL: ripgrep (rg) not found — the gate cannot enforce its contract" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "FAIL: python3 not found — the comment stripper cannot run" >&2
  exit 2
fi

FAIL=0

# rg exit-code discipline: 0 = matches, 1 = no matches, >1 = scan error.
# `if VAR="$(rg …)"` folds >1 into "no matches" because set -e is suppressed
# in if-conditions — a false-green on the gate's own scanner. `scan` maps
# no-match to success (empty output) and propagates scan errors, so a plain
# `VAR="$(scan …)"` assignment aborts loudly under set -e / pipefail.
# Presence checks branch on [[ -n "$VAR" ]], never on rg's exit status
# (`scan -q` would map no-match to 0 and make a missing subject look present).
scan() {
  local rc=0
  rg "$@" || rc=$?
  if (( rc > 1 )); then
    echo "FAIL: rg exited ${rc} (scan error, not no-match) during: rg $*" >&2
    return "${rc}"
  fi
  return 0
}

# Comment-stripped body. A stripper failure is not a match-less file (rule 47).
code_only() { python3 "$here/strip_c_comments.py" "$1"; }

# path:line:content hits in FILE after comments are stripped. Empty output is
# no hit. Uses the shared stripper (trailing `// TODO`, block-disabled code,
# and `*out = reward_P` are all live code — a line-regex on rg -n output is
# not). Stripper failure exits 2; it is not a clean scan.
stripped_hits() {
  local file="$1" pattern="$2" body hits
  body=$(code_only "$file") || {
    echo "FATAL: comment stripper failed on ${file} — an unreadable file is not a clean scan" >&2
    exit 2
  }
  hits=$(printf '%s' "$body" | scan -n "$pattern")
  if [[ -n "$hits" ]]; then
    while IFS= read -r line; do
      printf '%s:%s\n' "$file" "$line"
    done <<< "$hits"
  fi
}

# The mint / accrual arms read the stripper's output, so a stripper regression
# would widen both in the passing direction at once.
if ! python3 "$here/strip_c_comments.py" --self-test >/dev/null; then
  echo "FAIL: the comment stripper failed its own regression cases; mint and" >&2
  echo "      accrual checks read its output, so their verdicts cannot be trusted." >&2
  exit 2
fi

MINT_PATTERN='reward_P|archival.*emission.*mint|mint.*archival.*reward'
MINT_ROOTS=(src/fcmp src/cryptonote_core)

# Negative controls for comment handling (rule 50). A regression here is a
# silent green on the tree: refuse to judge until these hold.
mint_predicate_self_test() {
  local d f hits
  d=$(mktemp -d) || return 2
  f="$d/probe.cpp"

  _expect() {
    local want="$1" label="$2" src="$3"
    printf '%s\n' "$src" > "$f"
    hits=$(stripped_hits "$f" "$MINT_PATTERN")
    if [[ "$want" == hit && -z "$hits" ]]; then
      echo "SELF-TEST FAIL: ${label}: expected a hit" >&2
      return 1
    fi
    if [[ "$want" == miss && -n "$hits" ]]; then
      echo "SELF-TEST FAIL: ${label}: expected no hit, got:" >&2
      printf '%s' "$hits" >&2
      return 1
    fi
    return 0
  }

  local rc=0
  _expect miss "line comment"            '// reward_P = 1;'                          || rc=1
  _expect miss "block comment"           '/* reward_P = 1; */'                       || rc=1
  _expect miss "block-disabled code"     '/* uint64_t x = reward_P; */'              || rc=1
  _expect hit  "bare assignment"         'uint64_t reward_P = 2;'                    || rc=1
  _expect hit  "trailing TODO"           'reward_P = 1; // TODO: move to rust'       || rc=1
  _expect hit  "trailing word comment"   'void h() { reward_P = 2; } // no comment here' || rc=1
  _expect hit  "pointer write"           '*out = reward_P;'                          || rc=1
  _expect hit  "indented pointer write"  '  *out = reward_P;'                        || rc=1
  unset -f _expect
  rm -rf "$d"
  return "$rc"
}

if ! mint_predicate_self_test; then
  echo "FAIL: mint-predicate self-test failed; refusing to judge the tree." >&2
  exit 2
fi

REWARD_ARITH="rust/shekyl-archival-retention/src/reward_arithmetic.rs"

# This is a consensus-discipline guardrail: if the guarded module is missing or
# renamed, the gate must fail loudly rather than silently stop enforcing. (A
# swallowed `rg` "no such file" error inside the `if` below would otherwise leave
# the pure-integer contract unenforced with a green check.)
if [[ ! -f "$REWARD_ARITH" ]]; then
  echo "FAIL: $REWARD_ARITH not found — pure-integer gate cannot enforce its contract" >&2
  echo "  (if the module moved, update REWARD_ARITH in this gate; do not let it pass silently)" >&2
  exit 2
fi

# Pure fixed-width integer discipline for the canonical reward arithmetic.
#
# The cross-architecture bit-identity guarantee (REWARD_EMISSION_VIN_PLAN.md §9,
# M-1 half (b)) rests on the module being *pure fixed-width integer*: u64/u128
# only, no float and no width-varying or non-deterministic types. The aarch64
# determinism KAT runs under qemu-user, whose only known divergence surface from
# real aarch64 is FP rounding / denormals / NaN / some atomic orderings — none of
# which exist in a pure-integer path. That soundness is *contingent* on the path
# staying pure integer, so the property is enforced here, not left to convention:
#
#   - float (f32/f64) — width-correct but qemu's FP divergence surface, and the
#     §F-E8 u128 width audit assumes integer operands. clippy::float_arithmetic
#     denies float *arithmetic* in-crate; this also denies float *types/casts*.
#   - usize/isize — 64-bit on both supported arches today, so benign in practice,
#     but a usize that leaks into a credited value would silently drop the aarch64
#     guarantee from "real" to "emulated-and-hoping" on a future 32-bit target,
#     and qemu-user would not flag it. Block the token so the day it appears is a
#     conscious, reviewed decision.
#   - atomics — ordering-dependent results are exactly qemu's other divergence
#     surface and have no place in pure recomputation arithmetic.
#
# Escape hatch: a line carrying the marker `reward-arith-allow` is exempt (for a
# genuinely-benign, reviewed use — e.g. a slice index that provably never reaches
# a credited value). The marker forces the exemption to be explicit and grep-able.
NONFIXED_PATTERN='\bf32\b|\bf64\b|\busize\b|\bisize\b|\bAtomic[A-Za-z0-9]+\b|::atomic\b'
NONFIXED_HITS="$(scan -n "$NONFIXED_PATTERN" "$REWARD_ARITH" | scan -v 'reward-arith-allow')"
if [[ -n "$NONFIXED_HITS" ]]; then
  echo "FAIL: non-fixed-width / non-deterministic type in reward_arithmetic.rs" >&2
  echo "  (pure-integer contract underwrites cross-arch bit-identity; see gate comment)" >&2
  printf '%s\n' "$NONFIXED_HITS" >&2
  FAIL=1
fi

# Mint gate: no live emission vin crediting outputs (provisional bands).
# Verdict is comment-stripped content, never rg's exit status. Comments are
# excluded by being comments, not by containing a word; a code line with a
# trailing TODO is still a mint path.
for d in "${MINT_ROOTS[@]}"; do
  if [[ ! -d "$d" ]]; then
    echo "FATAL: ${d} not found — mint gate cannot read its subject" >&2
    echo "  (if the tree moved, update MINT_ROOTS; do not let it pass silently)" >&2
    exit 2
  fi
done

MINT_HITS=""
for d in "${MINT_ROOTS[@]}"; do
  files=$(scan --files "$d" --glob '*.cpp' --glob '*.h')
  if [[ -z "$files" ]]; then
    echo "FATAL: ${d} enumerates no C++ files (*.cpp/*.h) — the mint gate" >&2
    echo "       would pass over an empty set (rule 47)." >&2
    exit 2
  fi
  while IFS= read -r f; do
    hits=$(stripped_hits "$f" "$MINT_PATTERN")
    if [[ -n "$hits" ]]; then
      MINT_HITS+="${hits}"$'\n'
    fi
  done <<< "$files"
done

if [[ -n "$MINT_HITS" ]]; then
  echo "FAIL: possible live archival reward mint path in C++ (grep hit)" >&2
  printf '%s' "$MINT_HITS" >&2
  FAIL=1
fi

exit "$FAIL"
