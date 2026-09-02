#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Rule 71: on the consensus/validation surface, nettype selects DATA, never
# CONTROL FLOW. Once `nettype == X` decides whether a check runs, "testnet
# passed" stops meaning "this logic is correct" and starts meaning "the logic
# testnet happens to run is correct" -- the networks become analogs that rot
# instead of tests. Both inherited checkpoint mechanisms had exactly this
# shape (`if (nettype == MAINNET) { do the real thing }` with nothing in the
# else); one died in C2-R1a, the other is being re-homed by C2-R1b.
#
# This gate flags every equality OR inequality test against a PUBLIC
# network type (MAINNET / TESTNET / STAGENET) in the fenced consensus
# directories, against an annotated allowlist. Both operators: an
# `if (m_nettype != MAINNET) return;` guard is the SAME rot shape as the
# `== MAINNET` wrapper -- it keys control flow on the network -- and the
# first revision of this gate, matching `==` only, was blind to the live
# `update_checkpoints` guard (caught by review, 2026-09-02). FAKECHAIN branches are deliberately out of scope:
# the test-seam family is census batch R9's subject and carries rule 71's
# named-ratified-and-loud exception discipline, not this grep.
#
# The allowlist SHRINKS, never grows silently (rule 71 §4): adding an entry
# requires either a rule-21 ratification trail or a named migration owner,
# recorded beside the entry. Enforcement is a BIJECTION, not two one-sided
# checks: every live hit must exactly equal an allowlist entry, every entry
# must be hit (rule 47: a gate must assert its own subject exists -- a
# deleted branch means its entry is removed in the same PR), and the TOTAL
# hit count must equal the entry count. The total is what catches the
# copy-paste case the per-entry checks cannot: a DUPLICATED branch matches
# an existing entry, so "entry present" and "hit allowlisted" both stay
# green while the surface gained a second instance -- only the N+1-hits-
# against-N-entries total goes red. Observed counts are printed on failure.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
cd "$here/../.."

fail=0

# The stripper is shared with the other grep gates; assert it before
# trusting its output (a stripper regression widens every check silently).
if ! python3 "$here/strip_c_comments.py" --self-test; then
  echo "FAIL: the comment stripper failed its own regression cases."
  exit 1
fi

# Fenced directories: the consensus/validation surface (rule 71's globs,
# minus rust/ -- the Rust spine is born parameterized and a nettype enum
# equality there is caught in review; extend the fence when the first Rust
# consensus crate grows a network-type parameter).
FENCE=(src/cryptonote_core src/checkpoints src/blockchain_db)

# Allowlist: one entry per line, TAB-separated: file, then the EXACT
# normalized (comment-stripped, statement-joined, whitespace-collapsed)
# branch text as the extraction below produces it, then the disposition
# note that justifies the entry's existence. Dispositions are claims their
# owners defend. Exact equality, not prefix match: a prefix would let one
# entry absorb a second, longer branch that happens to share its opening.
ALLOWLIST=$(cat <<'EOF'
src/cryptonote_core/cryptonote_core.cpp	if (m_nettype == MAINNET) {	checkpoint wiring wrapped mainnet-only (inherited); C2-R1b re-homes the operator-override path across all nettypes
src/cryptonote_core/cryptonote_core.cpp	if (m_nettype != MAINNET) return true;	update_checkpoints periodic-reload guard -- the E5 mechanism's THIRD wiring site (independent of the init block); C2-R1b re-homes it with the init wiring
src/cryptonote_core/blockchain.cpp	if (m_nettype == FAKECHAIN || m_nettype == STAGENET) m_hardfork = new HardFork(*db, 1, 0);	hard-fork TABLE selection: data-selection written as branches; migration debt toward the parameter table (rule 71 owner: consensus lane)
src/cryptonote_core/blockchain.cpp	else if (m_nettype == TESTNET) m_hardfork = new HardFork(*db, 1, testnet_hard_fork_version_1_till);	hard-fork TABLE selection: data, not control flow; migration debt (consensus lane)
src/cryptonote_core/blockchain.cpp	else if (m_nettype == TESTNET) {	hard-fork schedule selection loop: data, not control flow; migration debt (consensus lane)
src/cryptonote_core/blockchain.cpp	else if (m_nettype == STAGENET) {	hard-fork schedule selection loop: data, not control flow; migration debt (consensus lane)
src/checkpoints/checkpoints.cpp	if (nettype == TESTNET) {	init_default_checkpoints no-op arm (zero compiled checkpoints); C2-R1b re-homes or deletes
src/checkpoints/checkpoints.cpp	if (nettype == STAGENET) {	init_default_checkpoints no-op arm (zero compiled checkpoints); C2-R1b re-homes or deletes
EOF
)

# Collect live hits: comment-stripped, statements joined, whitespace
# normalized BEFORE matching, one "file<TAB>text" per matched construct.
# The join means a branch wrapped across lines is still one hit; fragments
# are [;{}]-split so the non-greedy any-span cannot leak across statements
# (a compound condition like `if (feature_enabled() && m_nettype == MAINNET)`
# closes a paren before the comparison -- the first-`)`-stops form was blind
# to it). The match is OPERAND-INDEPENDENT: any comparison against a public
# network constant, on either side of `==`/`!=`, under any variable name --
# `if (network == MAINNET)` through a local alias is the same rot as
# `if (m_nettype == MAINNET)`, and the reversed spelling needs no separate
# unjoined pass (its old separate scan missed wrapped forms). `if ?\(`
# covers the no-space `if(` style. (Round-4 review hardening.)
#
# Collection failures are LOUD, not empty (rule 46/47): a stripper failure
# on any file fails the gate (an unreadable file is not a match-less file),
# and every fence directory must enumerate at least one source file -- an
# empty fence means the surface being asserted about is gone, which is a
# gate error, never a PASS.
hits_file=$(mktemp)
for d in "${FENCE[@]}"; do
  files=$(rg --files "$d" -g '*.cpp' -g '*.h' -g '*.inl')
  if [ -z "$files" ]; then
    echo "FAIL: fence directory '$d' enumerates no source files -- the"
    echo "      surface this gate asserts about is missing (rule 47)."
    fail=1
    continue
  fi
  while IFS= read -r f; do
    if ! body=$(python3 "$here/strip_c_comments.py" "$f"); then
      echo "FAIL: comment stripper failed on '$f' -- an unreadable file is"
      echo "      not a match-less file; refusing to treat it as clean."
      fail=1
      continue
    fi
    printf '%s' "$body" \
      | tr '\n\t' '  ' \
      | sed -e 's/  */ /g' -e 's:[;{}]:&\n:g' \
      | rg -o '(else )?if ?\([^\n]*?((MAINNET|TESTNET|STAGENET) *[!=]=|[!=]= *(MAINNET|TESTNET|STAGENET))[^\n]*' \
      | sed "s:^:${f}\t:" >> "$hits_file" || true
  done <<< "$files"
done

# switch-on-nettype is the remaining spelling of network-keyed control flow;
# none exists in the fence today, so it is a plain forbidden-pattern arm
# (an instance would need the same rule-71 SS2 ratification as a branch).
# Operand-independent like the if-arm: a `case MAINNET:` label convicts the
# switch regardless of what variable name the head scrutinizes.
for d in "${FENCE[@]}"; do
  while IFS= read -r f; do
    if ! body=$(python3 "$here/strip_c_comments.py" "$f"); then
      continue  # already failed above
    fi
    sw=$(printf '%s' "$body" | rg -c 'switch *\( *(m_)?nettype|case *(MAINNET|TESTNET|STAGENET) *:' || true)
    if [ "${sw:-0}" -ge 1 ]; then
      echo "FAIL: switch on nettype in '$f' -- network-keyed control flow"
      echo "      by another spelling (rule 71); ratify or parameterize."
      fail=1
    fi
  done < <(rg --files "$d" -g '*.cpp' -g '*.h' -g '*.inl')
done

# 1) Rule 47 + duplicate detection: every allowlisted branch must exist,
#    and its observed count is reported. Exact-text equality.
while IFS=$'\t' read -r af atext anote; do
  [ -z "$af" ] && continue
  n=$(awk -F'\t' -v f="$af" -v t="$atext" '$1==f && $2==t' "$hits_file" | wc -l)
  if [ "$n" -eq 0 ]; then
    echo "FAIL: allowlisted branch no longer exists (observed count 0) --"
    echo "      remove its entry in this PR:"
    echo "      $af : $atext"
    fail=1
  fi
done <<< "$ALLOWLIST"

# 2) Every live hit must exactly equal an allowlist entry. New public-nettype
#    control flow on the consensus surface needs a rule-71 §2 ratification,
#    not a green CI.
while IFS=$'\t' read -r hf htext; do
  [ -z "$hf" ] && continue
  ok=$(awk -F'\t' -v f="$hf" -v t="$htext" '$1==f && $2==t' <<< "$ALLOWLIST" | wc -l)
  if [ "$ok" -eq 0 ]; then
    echo "FAIL: unlisted public-nettype branch on the consensus surface (rule 71):"
    echo "      $hf : $htext"
    echo "      nettype selects data, never control flow. Either express this as"
    echo "      a parameter-table lookup, or ratify the divergence (named, loud,"
    echo "      rule 71 SS2) and add an annotated allowlist entry."
    fail=1
  fi
done < "$hits_file"

# 3) Bijection total: a duplicated branch exactly matches an existing entry,
#    so checks 1 and 2 both stay green -- only the totals disagree.
n_hits=$(grep -c . "$hits_file" || true)
n_entries=$(grep -c . <<< "$ALLOWLIST" || true)
if [ "${n_hits:-0}" -ne "${n_entries:-0}" ]; then
  echo "FAIL: hit count ($n_hits) != allowlist entry count ($n_entries)."
  echo "      A branch was duplicated or removed without its entry moving in"
  echo "      the same PR. Live hits:"
  sed 's/^/      /' "$hits_file"
  fail=1
fi

rm -f "$hits_file"

if [ "$fail" -eq 0 ]; then
  echo "PASS: no unratified public-nettype control flow on the consensus surface."
fi
exit "$fail"
