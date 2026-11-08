#!/usr/bin/env bash
#
# Copyright (c) 2025-2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# Archival reward gates — integer arithmetic discipline.
# Invoked from check_consensus_invariants.sh and CI.
#
# The reward arithmetic is pure fixed-width integer (below). Connect, and
# with it any mint path, is Rust's (rust/shekyl-chain-rules).

set -euo pipefail

# Resolve from the script, not the caller's cwd.
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit 2
cd "${here}/../.." || exit 2

if ! command -v rg >/dev/null 2>&1; then
  echo "FAIL: ripgrep (rg) not found — the gate cannot enforce its contract" >&2
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

exit "$FAIL"
