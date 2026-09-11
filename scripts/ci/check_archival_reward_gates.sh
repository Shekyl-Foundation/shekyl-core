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
# terminator; comments are then stripped before the checks (the block's own
# comments name the banned symbols as warnings, and a `/* */`-disabled
# compute_emission_split would otherwise still satisfy the positive anchors).
# The positive presence checks fail loudly if the anchors drift, so a refactor
# that moves the block cannot silently retire the gate.
BLOCKCHAIN_CPP="src/cryptonote_core/blockchain.cpp"
if [[ ! -f "$BLOCKCHAIN_CPP" ]]; then
  echo "FAIL: $BLOCKCHAIN_CPP not found — accrual tripwire cannot enforce its contract" >&2
  echo "  (if the file moved, update BLOCKCHAIN_CPP in this gate; do not let it pass silently)" >&2
  exit 2
fi
ACCRUAL_BLOCK="$(awk '/Staker-inflow accrual \(ARCHIVAL_BUDGET_SCHEDULE/,/m_db->add_block\(/' "$BLOCKCHAIN_CPP")"
if [[ -z "$ACCRUAL_BLOCK" ]]; then
  echo "FAIL: staker-inflow accrual block not found in $BLOCKCHAIN_CPP" >&2
  echo "  (if the anchors moved, update this tripwire; do not let it pass silently)" >&2
  FAIL=1
else
  accrual_tmp=$(mktemp)
  printf '%s\n' "$ACCRUAL_BLOCK" > "$accrual_tmp"
  ACCRUAL_CODE=$(code_only "$accrual_tmp") || {
    rm -f "$accrual_tmp"
    echo "FATAL: comment stripper failed on the extracted accrual block" >&2
    exit 2
  }
  rm -f "$accrual_tmp"

  hits=$(printf '%s' "$ACCRUAL_CODE" | scan -n 'get_block_reward')
  if [[ -n "$hits" ]]; then
    echo "FAIL: get_block_reward call inside the staker-inflow accrual block" >&2
    echo "  (the split operand is verify's base_reward; a second reward computation" >&2
    echo "   reintroduces the F-B1c-c2 operand drift — see gating round §9.9)" >&2
    printf '%s\n' "$hits" >&2
    FAIL=1
  fi
  hits=$(printf '%s' "$ACCRUAL_CODE" | scan -n 'get_current_version|get_ideal_version\(')
  if [[ -n "$hits" ]]; then
    echo "FAIL: tip-relative or table-only version read inside the accrual block" >&2
    echo "  (the version operand is bl.major_version — the block's own consensus-checked" >&2
    echo "   version; see F-B1b in gating round §9.9)" >&2
    printf '%s\n' "$hits" >&2
    FAIL=1
  fi
  # Anchors are the three symbols that MAKE this the accrual block: both legs
  # of the staker inflow and the variable they sum into. Anchoring on an
  # operand instead was the flaw the hf_version deletion exposed — an anchor
  # must be something the block cannot lose without ceasing to be itself, or
  # the tripwire fires on correct refactors and gets weakened to shut it up.
  for anchor in 'compute_emission_split' 'compute_fee_burn' 'archival_budget_accrual'; do
    if [[ -z "$(printf '%s' "$ACCRUAL_CODE" | scan "$anchor")" ]]; then
      echo "FAIL: accrual-block anchor '${anchor}' not found in the extracted block" >&2
      echo "  Either the block moved (re-anchor this tripwire to it), or a leg of the" >&2
      echo "  staker inflow was removed (that is a consensus change — justify it)." >&2
      FAIL=1
    fi
  done
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
