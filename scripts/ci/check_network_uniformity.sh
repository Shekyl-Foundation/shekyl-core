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
# This gate flags every equality test against a PUBLIC network type
# (MAINNET / TESTNET / STAGENET) in the fenced consensus directories, against
# an annotated allowlist. FAKECHAIN branches are deliberately out of scope:
# the test-seam family is census batch R9's subject and carries rule 71's
# named-ratified-and-loud exception discipline, not this grep.
#
# The allowlist SHRINKS, never grows silently (rule 71 §4): adding an entry
# requires either a rule-21 ratification trail or a named migration owner,
# recorded beside the entry. Every entry is also asserted PRESENT (rule 47:
# a gate must assert its own subject exists) -- when a listed branch is
# deleted, its entry must be removed in the same PR, so the list cannot
# accumulate fossils that would mask a reintroduction at the same spot.
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

# Allowlist: one entry per line, TAB-separated: file, then the normalized
# (whitespace-collapsed) branch text, then the disposition note that
# justifies its existence. Dispositions are claims their owners defend.
ALLOWLIST=$(cat <<'EOF'
src/cryptonote_core/cryptonote_core.cpp	if (m_nettype == MAINNET)	checkpoint wiring wrapped mainnet-only (inherited); C2-R1b re-homes the operator-override path across all nettypes
src/cryptonote_core/blockchain.cpp	if (m_nettype == FAKECHAIN || m_nettype == STAGENET)	hard-fork TABLE selection: data-selection written as branches; migration debt toward the parameter table (rule 71 owner: consensus lane)
src/cryptonote_core/blockchain.cpp	else if (m_nettype == TESTNET) m_hardfork = new HardFork(*db, 1, testnet_hard_fork_version_1_till);	hard-fork TABLE selection: data, not control flow; migration debt (consensus lane)
src/cryptonote_core/blockchain.cpp	else if (m_nettype == TESTNET)	hard-fork schedule selection loop: data, not control flow; migration debt (consensus lane)
src/cryptonote_core/blockchain.cpp	else if (m_nettype == STAGENET)	hard-fork schedule selection loop: data, not control flow; migration debt (consensus lane)
src/checkpoints/checkpoints.cpp	if (nettype == TESTNET)	init_default_checkpoints no-op arm (zero compiled checkpoints); C2-R1b re-homes or deletes
src/checkpoints/checkpoints.cpp	if (nettype == STAGENET)	init_default_checkpoints no-op arm (zero compiled checkpoints); C2-R1b re-homes or deletes
EOF
)

# Collect live hits: comment-stripped, statements joined, whitespace
# normalized, one "file<TAB>text" per matched physical construct. The join
# means a branch wrapped across lines is still one hit (the same reason the
# debit gate joins statements: clang-format wraps at 100 columns and a
# wrapped copy is the LIKELY evasion, accidental or not).
hits_file=$(mktemp)
for d in "${FENCE[@]}"; do
  while IFS= read -r f; do
    python3 "$here/strip_c_comments.py" "$f" \
      | tr '\n' ' ' \
      | sed 's:[;{}]:&\n:g' \
      | rg -o '(else )?if \([^)]*(m_nettype|nettype) *== *(MAINNET|TESTNET|STAGENET)[^)]*\)[^\n]*' \
      | sed -e 's/  */ /g' -e "s:^:${f}\t:" >> "$hits_file" || true
  done < <(rg --files "$d" -g '*.cpp' -g '*.h' -g '*.inl')
done

# Also catch the reversed spelling (MAINNET == nettype) separately -- the
# main pattern anchors on the member name first and would miss it.
for d in "${FENCE[@]}"; do
  while IFS= read -r f; do
    python3 "$here/strip_c_comments.py" "$f" \
      | rg -n '(MAINNET|TESTNET|STAGENET) *== *(m_)?nettype' \
      | sed "s:^:${f}\t(reversed) :" >> "$hits_file" || true
  done < <(rg --files "$d" -g '*.cpp' -g '*.h' -g '*.inl')
done

# 1) Rule 47: every allowlisted branch must still exist, exactly once.
while IFS=$'\t' read -r af atext anote; do
  [ -z "$af" ] && continue
  n=$(awk -F'\t' -v f="$af" -v t="$atext" '$1==f && index($2, t)==1' "$hits_file" | wc -l)
  if [ "$n" -eq 0 ]; then
    echo "FAIL: allowlisted branch no longer exists -- remove its entry in this PR:"
    echo "      $af : $atext"
    fail=1
  fi
done <<< "$ALLOWLIST"

# 2) Every live hit must be allowlisted. New public-nettype control flow on
#    the consensus surface needs a rule-71 §2 ratification, not a green CI.
while IFS=$'\t' read -r hf htext; do
  [ -z "$hf" ] && continue
  ok=0
  while IFS=$'\t' read -r af atext anote; do
    [ -z "$af" ] && continue
    if [ "$hf" = "$af" ] && case "$htext" in "$atext"*) true;; *) false;; esac; then
      ok=1; break
    fi
  done <<< "$ALLOWLIST"
  if [ "$ok" -eq 0 ]; then
    echo "FAIL: unlisted public-nettype branch on the consensus surface (rule 71):"
    echo "      $hf : $htext"
    echo "      nettype selects data, never control flow. Either express this as"
    echo "      a parameter-table lookup, or ratify the divergence (named, loud,"
    echo "      rule 71 SS2) and add an annotated allowlist entry."
    fail=1
  fi
done < "$hits_file"

rm -f "$hits_file"

if [ "$fail" -eq 0 ]; then
  echo "PASS: no unratified public-nettype control flow on the consensus surface."
fi
exit "$fail"
