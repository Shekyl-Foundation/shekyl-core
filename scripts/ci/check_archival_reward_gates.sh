#!/usr/bin/env bash
#
# Archival reward gates — mint + integer arithmetic discipline.
# Invoked from check_consensus_invariants.sh and CI.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

FAIL=0

REWARD_ARITH="rust/shekyl-archival-retention/src/reward_arithmetic.rs"

# This is a consensus-discipline guardrail: if the guarded module is missing or
# renamed, the gate must fail loudly rather than silently stop enforcing. (A
# swallowed `rg` "no such file" error inside the `if` below would otherwise leave
# the pure-integer contract unenforced with a green check.)
if [[ ! -f "$REWARD_ARITH" ]]; then
  echo "FAIL: $REWARD_ARITH not found — pure-integer gate cannot enforce its contract" >&2
  echo "  (if the module moved, update REWARD_ARITH in this gate; do not let it pass silently)" >&2
  exit 1
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
if NONFIXED_HITS="$(rg -n "$NONFIXED_PATTERN" "$REWARD_ARITH" | rg -v 'reward-arith-allow')"; then
  echo "FAIL: non-fixed-width / non-deterministic type in reward_arithmetic.rs" >&2
  echo "  (pure-integer contract underwrites cross-arch bit-identity; see gate comment)" >&2
  echo "$NONFIXED_HITS" >&2
  FAIL=1
fi

# Mint gate: no live emission vin crediting outputs (provisional bands).
MINT_PATTERN='reward_P|archival.*emission.*mint|mint.*archival.*reward'
MINT_EXCLUDE='TODO|FOLLOWUP|comment'
if rg -n "$MINT_PATTERN" src/fcmp src/cryptonote_core \
  --glob '*.cpp' --glob '*.h' 2>/dev/null | rg -v "$MINT_EXCLUDE" >/dev/null; then
  echo "FAIL: possible live archival reward mint path in C++ (grep hit)" >&2
  # Diagnostic: same pattern and exclusion as the gate, so the printed hits
  # are exactly the ones that tripped it.
  rg -n "$MINT_PATTERN" src/fcmp src/cryptonote_core --glob '*.cpp' --glob '*.h' 2>/dev/null \
    | rg -v "$MINT_EXCLUDE" || true
  FAIL=1
fi

exit "$FAIL"
