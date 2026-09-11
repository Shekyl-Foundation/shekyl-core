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

# Staker-inflow accrual operand tripwire (F-B1b / F-B1c-c2, gating round
# §9.9). The accrual block in handle_block_to_main_chain must:
#
#   - split verify's base_reward, with NO second get_block_reward call — a
#     second call reintroduces the c2 operand drift (an unmodulated staker
#     leg, re-mintable through emission claims once accrued into
#     budget(E): an inflation surface);
#   - read NO tip-relative get_current_version() and NO table-only
#     get_ideal_version(h), which respectively resurrect F-B1b's boundary
#     off-by-one under API-convention drift and ignore the vote threshold.
#
# F-B1b's operand discipline is RETIRED, and this comment previously said the
# opposite. It read: "the version still feeds compute_emission_split /
# compute_fee_burn, so the operand discipline is unchanged." That is no longer
# true — those helpers take no version at all. Their hf_version gate compared
# against a constant of 1 on a chain whose only fork entry is version 1, so it
# could never be taken, and the gate went with the parameters that fed it.
#
# So there is no version operand here to take from the right place, and this
# gate no longer demands bl.major_version be present — demanding it would force
# a dead local back into consensus code to satisfy a tripwire, which is rule 15
# backwards. What survives is narrower and still real:
#
#   * the F-B1c-c2 rule below (no second get_block_reward) is UNTOUCHED — it
#     guards an inflation surface, not a version;
#   * the two banned version reads stay banned, as a REINTRODUCTION guard. If
#     version-dependence ever returns to this block, bl.major_version is still
#     the only correct source, and whoever adds it should revisit this gate
#     rather than discover F-B1b again.
#
# The block is extracted by its comment anchor and its m_db->add_block
# terminator; comment lines are stripped before the negative checks (the
# block's own comments name the banned symbols as warnings). The positive
# presence checks fail loudly if the anchors drift, so a refactor that
# moves the block cannot silently retire the gate.
BLOCKCHAIN_CPP="src/cryptonote_core/blockchain.cpp"
ACCRUAL_BLOCK="$(awk '/Staker-inflow accrual \(ARCHIVAL_BUDGET_SCHEDULE/,/m_db->add_block\(/' "$BLOCKCHAIN_CPP")"
ACCRUAL_CODE="$(rg -v '^\s*//' <<<"$ACCRUAL_BLOCK" || true)"
if [[ -z "$ACCRUAL_BLOCK" ]]; then
  echo "FAIL: staker-inflow accrual block not found in $BLOCKCHAIN_CPP" >&2
  echo "  (if the anchors moved, update this tripwire; do not let it pass silently)" >&2
  FAIL=1
else
  if rg -n 'get_block_reward' <<<"$ACCRUAL_CODE"; then
    echo "FAIL: get_block_reward call inside the staker-inflow accrual block" >&2
    echo "  (the split operand is verify's base_reward; a second reward computation" >&2
    echo "   reintroduces the F-B1c-c2 operand drift — see gating round §9.9)" >&2
    FAIL=1
  fi
  if rg -n 'get_current_version|get_ideal_version\(' <<<"$ACCRUAL_CODE"; then
    echo "FAIL: tip-relative or table-only version read inside the accrual block" >&2
    echo "  (the version operand is bl.major_version — the block's own consensus-checked" >&2
    echo "   version; see F-B1b in gating round §9.9)" >&2
    FAIL=1
  fi
  # Anchors are the three symbols that MAKE this the accrual block: both legs
  # of the staker inflow and the variable they sum into. Anchoring on an
  # operand instead was the flaw the hf_version deletion exposed — an anchor
  # must be something the block cannot lose without ceasing to be itself, or
  # the tripwire fires on correct refactors and gets weakened to shut it up.
  for anchor in 'compute_emission_split' 'compute_fee_burn' 'archival_budget_accrual'; do
    if ! rg -q "$anchor" <<<"$ACCRUAL_CODE"; then
      echo "FAIL: accrual-block anchor '${anchor}' not found in the extracted block" >&2
      echo "  Either the block moved (re-anchor this tripwire to it), or a leg of the" >&2
      echo "  staker inflow was removed (that is a consensus change — justify it)." >&2
      FAIL=1
    fi
  done
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
