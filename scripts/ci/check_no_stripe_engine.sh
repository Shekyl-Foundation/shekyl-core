#!/usr/bin/env bash
#
# Copyright (c) 2025-2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# PDM-Q7 residue gate — the Monero stripe-pruning engine is deleted
# (`docs/design/ARCHIVAL_PRUNED_DAEMON_MODE.md` Q7, RULED 2026-09-18;
# deleted 2026-09-21). Under archival pruning every node prunes the same
# way and nobody holds a stripe, so a `pruning_seed` anywhere is either
# the engine coming back or its wire field coming back.
#
# The wire field is the reason this gate exists rather than "the cutover
# will delete it": `peerlist_entry.pruning_seed` was a durable,
# address-keyed, self-asserted attribute gossiped in every peerlist — the
# exact shape PWD-I1 deleted `peer_id` for — and a faithful codec port
# (LV-2) carried it into `shekyl-levin` once already. A port carries the
# wire by default; only a gate stops it.
#
# Two invariants, both at source level:
#
#   1. No stripe-engine identifier in code (C++ or Rust). Comment-only
#      mentions are allowed — the structs that lost the field document
#      why, and a deletion that may not name what it deleted is the
#      "comment that outlived its architecture" failure inverted.
#
#   2. No `pruning_seed` key on any wire map or current RPC vector.
#      Checked separately because a KV_SERIALIZE / `section.insert` of the
#      key is the wire coming back even if the struct field is spelled
#      differently.
#
# Rule 47: the searched population is asserted non-empty, and the structs
# the field was deleted from are asserted present, before any "clean" is
# reported. Rule 46: rg exit 2 is a scan error, not a verdict, and is
# never folded into "no match".

set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
  echo "ERROR: ripgrep (rg) is required for the stripe-engine residue gate." >&2
  exit 2
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

FAIL=0

# Populations. `rust/target` is a build product; `docs/` is where the
# deletion is recorded and may say the word.
ROOTS=(src tests contrib/epee rust)
EXCLUDES=(
  -g '!rust/target/**' -g '!**/target/**'
  # The two negative tests that pin the deletion by spelling the key and
  # asserting it is ignored / subtracted. They are this gate's own
  # negative control, not residue.
  -g '!rust/shekyl-levin/tests/payload_kats.rs'
  -g '!rust/shekyl-rpc-types/tests/rpc_parity.rs'
  # Retained oracle captures the parity suite derives from (records-was).
  -g '!rust/shekyl-rpc-types/tests/vectors/rpc/*_v1.json'
  -g '!rust/shekyl-rpc-types/tests/vectors/rpc/*_v2.json'
)
# A comment line: leading whitespace then `//`, `///`, `//!`, `*` or `#`.
COMMENT_LINE='^[^:]+:[0-9]+:\s*(//|\*|#)'

# rg with the exit codes kept apart. Prints matches to stdout.
#   returns 0 = matches printed, 1 = none, exits 2 on scan error.
rg_scan() {
  local rc=0
  rg "$@" || rc=$?
  case "$rc" in
    0|1) return "$rc" ;;
    *) echo "FATAL: rg exited ${rc} (scan error, not a verdict) during: rg $*" >&2
       echo "       The gate could not read its subject, so it has NO verdict." >&2
       exit 2 ;;
  esac
}

# Given rg -n output on stdin, print the non-comment lines.
#   returns 0 = some printed, 1 = all were comments (or empty input).
drop_comment_lines() {
  local rc=0
  rg -v --pcre2 -e "${COMMENT_LINE}" || rc=$?
  case "$rc" in
    0|1) return "$rc" ;;
    *) echo "FATAL: rg exited ${rc} filtering comment lines" >&2; exit 2 ;;
  esac
}

# ---- Rule 47 positive controls ----------------------------------------
# The population must contain the structs the field was deleted from, in
# both languages. If any is missing the tree is not the one this gate was
# written against, and "no residue" would mean nothing.
for control in \
  'struct peerlist_entry_base|src/p2p/p2p_protocol_defs.h' \
  'struct CORE_SYNC_DATA|src/cryptonote_protocol/cryptonote_protocol_defs.h' \
  'pub struct PeerlistEntry|rust/shekyl-levin/src/payload/types.rs' \
  'pub struct CoreSyncData|rust/shekyl-levin/src/payload/types.rs' ; do
  pat="${control%%|*}"; file="${control##*|}"
  if ! rg_scan -q -e "${pat}" "${file}"; then
    echo "FATAL: positive control failed: '${pat}' not found in ${file}" >&2
    exit 2
  fi
done

# ---- Invariant 1: no stripe-engine identifier in code -----------------
# Identifiers, not words: `prunable`, `pruned` and the `prune` request flag
# are Q6's good and F28's skeleton wire, and stay. (`prune_tx_data`, the C++
# tx-data discard, was deleted 2026-09-22 — a different mechanism from the
# stripe engine, so it is not on this list either way.)
ENGINE_IDENTS='\b(pruning_seed|m_pruning_seed|next_needed_pruning_seed|next_needed_pruning_stripe|get_pruning_stripe|get_pruning_seed|make_pruning_seed|get_random_stripe|has_unpruned_block|get_next_unpruned_block_height|get_next_pruned_block_height|get_pruning_log_stripes|prune_worker|prune_blockchain|update_blockchain_pruning|check_blockchain_pruning|get_blockchain_pruning_seed|sync_pruned_blocks|CRYPTONOTE_PRUNING_(LOG_STRIPES|STRIPE_SIZE|TIP_BLOCKS)|PRUNING_SEED_(LOG_STRIPES|STRIPE)_(SHIFT|MASK)|used_stripe_peer)\b'

echo "[1/2] stripe-engine identifiers in code"
hits=""
rc=0
hits=$(rg_scan -n --pcre2 -e "${ENGINE_IDENTS}" \
        -g '*.cpp' -g '*.h' -g '*.inl' -g '*.hpp' -g '*.rs' \
        "${EXCLUDES[@]}" "${ROOTS[@]}") || rc=$?
# `exit 2` inside `$(...)` ends the subshell, not this script (rule 46):
# re-check the status here so a scan error is never read as clean.
if [ "$rc" -gt 1 ]; then exit "$rc"; fi
if [ "$rc" -eq 0 ]; then
  rc2=0
  residue=$(printf '%s\n' "$hits" | drop_comment_lines) || rc2=$?
  if [ "$rc2" -gt 1 ]; then exit "$rc2"; fi
  if [ "$rc2" -eq 0 ]; then
    printf '%s\n' "$residue"
    echo "FAIL: a stripe-engine identifier is back in code (PDM-Q7 deleted the engine)."
    FAIL=1
  else
    echo "      OK (comment-only mentions)"
  fi
else
  echo "      OK"
fi

# ---- Invariant 2: no pruning_seed key on any wire map or vector -------
echo "[2/2] pruning_seed as a wire key"
rc=0
hits=$(rg_scan -n \
        -e 'KV_SERIALIZE(_OPT)?\(pruning_seed' -e 'VARINT_FIELD\(pruning_seed\)' -e 'FIELD\(pruning_seed\)' \
        -e '"pruning_seed"' -e '"next_needed_pruning_seed"' \
        -g '*.cpp' -g '*.h' -g '*.inl' -g '*.rs' -g '*.json' -g '*.yaml' -g '*.yml' \
        "${EXCLUDES[@]}" "${ROOTS[@]}") || rc=$?
if [ "$rc" -gt 1 ]; then exit "$rc"; fi
if [ "$rc" -eq 0 ]; then
  rc2=0
  residue=$(printf '%s\n' "$hits" | drop_comment_lines) || rc2=$?
  if [ "$rc2" -gt 1 ]; then exit "$rc2"; fi
  if [ "$rc2" -eq 0 ]; then
    printf '%s\n' "$residue"
    echo "FAIL: pruning_seed is back on a wire map or a current RPC vector."
    FAIL=1
  else
    echo "      OK (comment-only mentions)"
  fi
else
  echo "      OK"
fi

if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
echo "stripe-engine residue: none (PDM-Q7)"
