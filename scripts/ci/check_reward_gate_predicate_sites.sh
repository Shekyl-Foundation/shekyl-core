#!/usr/bin/env bash
#
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# M1 reward-gate predicate + operand tripwire — ARCHIVAL_REWARD_GATE_M1.md
# §6 (tripwire row), §10 M1-1, §11.8 M3-1. Invoked from
# check_consensus_invariants.sh and CI.
#
# Two one-site guarantees, both consensus-load-bearing at exactly the
# activation boundary the runtime exercises once (§7 dead-rule acceptance):
#
#   1. PREDICATE: `K_COVER` / `k_cover` is *compared* at exactly one code
#      site — the gate factor in `epoch_close_compute`
#      (rust/shekyl-archival-retention/src/consensus_state.rs). The
#      constants surface (k_cover.rs sentinel assert, build.rs value
#      validation) is the only other legitimate comparison home. A second
#      comparison site is the off-by-one-at-K_COVER±1 consensus-fork
#      adversary M1-1 names.
#
#   2. OPERAND: the gate input `frozen_shard_count` is produced by exactly
#      one counting read over `m_archival_shard_segment` —
#      `count_frozen_shards_at_close` (db_lmdb.cpp), one production call
#      site (the epoch-close gather). §11.1's pattern: the operand's
#      production site gets the same one-site guarantee as the predicate
#      site. Named drift adversaries (§11.8 M3-1): an RPC "corpus size"
#      surface, a verification-path recount, or a cached counter lacking
#      O-3 pop-symmetry. `mdb_stat` over the segment table is refused
#      outright — it is precisely the cached-counter shortcut.
#
# The boundary operator is also pinned: `freeze_height <= h_close`
# (equality counts, §1.1) must exist exactly once, and no strict-`<`
# freeze-height comparison may exist anywhere in src/ — an off-by-one
# edit here is a consensus fork at exactly the boundary class the Rust
# KAT cannot reach (G-10 injects the count).
#
# Escape hatch: a line carrying the marker `reward-gate-site-allow` is
# exempt (genuinely-benign, reviewed use). The marker forces the exemption
# to be explicit and grep-able, per the reward-arith precedent.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Dependency precondition: rg is the load-bearing tool; a missing rg must
# be a loud failure, not a silently-green gate.
if ! command -v rg >/dev/null 2>&1; then
  echo "FAIL: ripgrep (rg) not found — the gate cannot enforce its contract" >&2
  exit 1
fi

FAIL=0

GATE_RS="rust/shekyl-archival-retention/src/consensus_state.rs"
KCOVER_RS="rust/shekyl-archival-retention/src/k_cover.rs"
BUILD_RS="rust/shekyl-archival-retention/build.rs"
FFI_RS="rust/shekyl-ffi/src/archival_ffi.rs"
LMDB_CPP="src/blockchain_db/lmdb/db_lmdb.cpp"
LMDB_H="src/blockchain_db/lmdb/db_lmdb.h"

# Path-exact exemption regexes (escape `.` so only the pinned files match;
# check_pending_post_write_path.sh precedent).
GATE_RE="${GATE_RS//./\\.}"
KCOVER_RE="${KCOVER_RS//./\\.}"
BUILD_RE="${BUILD_RS//./\\.}"
LMDB_CPP_RE="${LMDB_CPP//./\\.}"

# Guardrail: if a pinned choke file moved or was renamed, fail loudly rather
# than let the invariants below pass vacuously on zero hits.
for f in "$GATE_RS" "$KCOVER_RS" "$BUILD_RS" "$FFI_RS" "$LMDB_CPP" "$LMDB_H"; do
  if [[ ! -f "$f" ]]; then
    echo "FAIL: $f not found — a pinned choke moved; update this gate, do not let it pass silently" >&2
    exit 1
  fi
done

# -- Invariant 1: single K_COVER comparison site ------------------------------
#
# A comparison is the token adjacent to a relational/equality operator, in
# either order. Scope is production code (rust/*/src, rust/*/build.rs,
# src/) — tests inject k_cover as a parameter per §5's parameterization pin
# and may compare their local copies freely; a test comparison cannot fork
# consensus. Doc-comment prose mentions without an operator do not match.
CMP_PATTERN='(\b(K_COVER|k_cover)\b\s*(==|!=|<=|>=|<|>))|((==|!=|<=|>=|<|>)\s*[A-Za-z_.:]*\b(K_COVER|k_cover)\b)'
if CMP_STRAYS="$(rg -n "$CMP_PATTERN" rust/ src/ \
  --glob '*.rs' --glob '*.cpp' --glob '*.h' --glob '*.hpp' \
  --glob '!rust/*/tests/**' --glob '!rust/target/**' \
  | rg -v 'reward-gate-site-allow' \
  | rg -v "^(${GATE_RE}|${KCOVER_RE}|${BUILD_RE}):")"; then
  echo "FAIL: K_COVER / k_cover comparison outside the canonical gate site" >&2
  echo "  (sole predicate site: epoch_close_compute in $GATE_RS;" >&2
  echo "   constants surface: $KCOVER_RS + $BUILD_RS)" >&2
  echo "$CMP_STRAYS" >&2
  FAIL=1
fi

# Positive control (guards the guard): the canonical gate compare must still
# exist under this exact spelling — a rename must fail here, not silently
# de-arm invariant 1.
if ! rg -q 'frozen_shard_count\s*<\s*inputs\.k_cover' "$GATE_RS"; then
  echo "FAIL: positive control — no 'frozen_shard_count < inputs.k_cover' gate compare in $GATE_RS" >&2
  echo "  (if epoch_close_compute's gate factor moved or was respelled, update this gate)" >&2
  FAIL=1
fi

# Positive control: the production FFI threads the constant through the
# PF-6a capability constructor (`k_cover: KCover::consensus()`) — the only
# production path to a threshold value. The sentinel's compile-refusal story
# (§4) assumes the constant reaches the gate unmodified through this one
# assignment.
if ! rg -q 'k_cover:\s*KCover::consensus\(\)' "$FFI_RS"; then
  echo "FAIL: positive control — no 'k_cover: KCover::consensus()' threading in $FFI_RS" >&2
  echo "  (if the FFI shim stopped threading the constant through the capability constructor, update this gate)" >&2
  FAIL=1
fi

# PF-6a companion: `KCover::for_kat` is the KAT-injection constructor, gated
# behind the dev-only `consensus-kat` feature. Its legitimate homes are the
# definition (k_cover.rs), integration tests (rust/*/tests/ — excluded from
# scope below), and the single in-crate #[cfg(test)] helper in
# consensus_state.rs. Any other production-source hit is the arbitrary-
# threshold adversary the newtype exists to refuse.
# A *call* (`for_kat(`) is the adversary; doc-comment prose mentions cannot
# construct a value and are ignored (invariant 1's operator-adjacency logic).
FOR_KAT_STRAYS="$(rg -n 'for_kat\(' rust/ --glob '*.rs' \
  --glob '!rust/*/tests/**' --glob '!rust/target/**' \
  | rg -v 'reward-gate-site-allow' \
  | rg -v "^(${KCOVER_RE}|${GATE_RE}):" || true)"
if [[ -n "$FOR_KAT_STRAYS" ]]; then
  echo "FAIL: KCover::for_kat referenced outside its definition, the consensus_state.rs test module, and rust/*/tests/" >&2
  echo "  (production code constructs the threshold only via KCover::consensus() — PF-6a)" >&2
  echo "$FOR_KAT_STRAYS" >&2
  FAIL=1
fi
# Guard the guard: the gate-file exemption above admits consensus_state.rs
# wholesale, so pin that its only for_kat use stays in the test module —
# exactly one hit, and the file still has a #[cfg(test)] module.
GATE_FOR_KAT_COUNT="$(rg -c 'for_kat\(' "$GATE_RS" || true)"
if [[ "${GATE_FOR_KAT_COUNT:-0}" -ne 1 ]] || ! rg -q '#\[cfg\(test\)\]' "$GATE_RS"; then
  echo "FAIL: expected exactly one for_kat use in $GATE_RS (the #[cfg(test)] helper), found ${GATE_FOR_KAT_COUNT:-0}" >&2
  FAIL=1
fi

# -- Invariant 2: single counting read over m_archival_shard_segment ---------
#
# Iteration capability = counting capability: a cursor open over the segment
# table outside the pinned sites is the second-count-site adversary. Pinned
# sites (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §8 cursor accounting, 4 total):
#   1. count_frozen_shards_at_close — the count helper itself;
#   2. process_archival_slash_for_epoch — pre-existing slash-scan shard
#      enumeration (enumeration read predating the gate, not a count
#      feeding a consensus predicate);
#   3. process_archival_segment_freezes_at_height — the freeze processor's
#      one-row resume peek (the writer deriving its own frontier from its
#      own rows, not a second count pass);
#   4. revert_archival_segment_freezes — the pop revert's reverse walk
#      deleting rows above the post-trim frontier.
CURSOR_HITS="$(rg -n 'mdb_cursor_open\([^)]*m_archival_shard_segment' src/ \
  | rg -v 'reward-gate-site-allow' || true)"
CURSOR_COUNT="$(printf '%s' "$CURSOR_HITS" | rg -c '.' || true)"
if [[ "${CURSOR_COUNT:-0}" -ne 4 ]]; then
  echo "FAIL: expected exactly 4 cursor opens over m_archival_shard_segment (count helper, slash scan, freeze resume peek, revert walk), found ${CURSOR_COUNT:-0}" >&2
  echo "  (a new iteration over the segment table must route through" >&2
  echo "   count_frozen_shards_at_close or carry a reviewed reward-gate-site-allow marker)" >&2
  printf '%s\n' "$CURSOR_HITS" >&2
  FAIL=1
fi
# Positive controls for the two freeze-pipeline cursor sites: a rename or
# removal must fail here, not silently re-shape the count above.
for fn in process_archival_segment_freezes_at_height revert_archival_segment_freezes; do
  if ! rg -q "BlockchainLMDB::${fn}\(" "$LMDB_CPP"; then
    echo "FAIL: positive control — ${fn} not found in $LMDB_CPP (freeze-pipeline site renamed or removed; update this gate)" >&2
    FAIL=1
  fi
done

# mdb_stat over the segment table is the cached-counter shortcut (§11.8
# M3-1's third drift adversary) — refused outright, no allowlist.
if STAT_HITS="$(rg -n 'mdb_stat\([^)]*m_archival_shard_segment' src/)"; then
  echo "FAIL: mdb_stat over m_archival_shard_segment — a counting read outside count_frozen_shards_at_close" >&2
  echo "$STAT_HITS" >&2
  FAIL=1
fi

# Positive control: the helper exists and has exactly one production call
# site (the epoch-close gather). Declaration (.h) + definition + call = the
# expected shape; more calls mean a second consumer of the count, which is a
# review item even when it routes through the helper (the gate input must
# come from the close's own write-txn snapshot, §1.1).
CALL_HITS="$(rg -n 'count_frozen_shards_at_close\(' "$LMDB_CPP" | rg -v 'reward-gate-site-allow' || true)"
CALL_COUNT="$(printf '%s' "$CALL_HITS" | rg -c '.' || true)"
if [[ "${CALL_COUNT:-0}" -ne 2 ]]; then
  echo "FAIL: expected exactly 2 count_frozen_shards_at_close occurrences in $LMDB_CPP (definition + close-gather call), found ${CALL_COUNT:-0}" >&2
  printf '%s\n' "$CALL_HITS" >&2
  FAIL=1
fi

# -- Invariant 3: boundary operator pinned (freeze_height <= h_close) --------
#
# Exactly one `freeze_height <= h_close` in the helper; zero strict-`<`
# freeze-height comparisons anywhere in src/. Equality counts (§1.1); the
# off-by-one edit is a consensus fork at exactly the boundary class the
# Rust KAT cannot reach.
LE_COUNT="$(rg -c 'segment\.freeze_height\s*<=\s*h_close' "$LMDB_CPP" || true)"
if [[ "${LE_COUNT:-0}" -ne 1 ]]; then
  echo "FAIL: expected exactly one 'segment.freeze_height <= h_close' comparison in $LMDB_CPP, found ${LE_COUNT:-0}" >&2
  FAIL=1
fi
if LT_HITS="$(rg -n 'freeze_height\s*<[^=]' src/ | rg -v 'reward-gate-site-allow')"; then
  echo "FAIL: strict-< freeze_height comparison in src/ — boundary inclusivity is consensus (§1.1: equality counts)" >&2
  echo "$LT_HITS" >&2
  FAIL=1
fi

# -- Invariant 4: segment-table writer one-site --------------------------------
#
# ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §8 writer one-site. The segment table
# has exactly one production writer (put_archival_shard_segment) and one
# named test exemption (put_archival_shard_segment_raw_for_corruption_test,
# the §9 corruption-injection surface). A third mdb_put is the
# overwrite-the-frozen-row adversary O-2 refuses.
PUT_HITS="$(rg -n 'mdb_put\([^)]*m_archival_shard_segment' src/ \
  | rg -v 'reward-gate-site-allow' || true)"
PUT_COUNT="$(printf '%s' "$PUT_HITS" | rg -c '.' || true)"
if [[ "${PUT_COUNT:-0}" -ne 2 ]]; then
  echo "FAIL: expected exactly 2 mdb_put sites over m_archival_shard_segment (production writer + corruption-test raw writer), found ${PUT_COUNT:-0}" >&2
  printf '%s\n' "$PUT_HITS" >&2
  FAIL=1
fi
for fn in put_archival_shard_segment put_archival_shard_segment_raw_for_corruption_test; do
  if ! rg -q "BlockchainLMDB::${fn}\(" "$LMDB_CPP"; then
    echo "FAIL: positive control — ${fn} not found in $LMDB_CPP (writer site renamed or removed; update this gate)" >&2
    FAIL=1
  fi
done

# Direct mdb_del over the segment table is refused: deletion happens only
# through the revert walk's cursor (invariant 2 site 4), preserving O-3
# pop-symmetry. A stray point-delete is the partial-revert adversary.
if DEL_HITS="$(rg -n 'mdb_del\([^)]*m_archival_shard_segment' src/ | rg -v 'reward-gate-site-allow')"; then
  echo "FAIL: direct mdb_del over m_archival_shard_segment — segment rows are deleted only by revert_archival_segment_freezes' cursor walk" >&2
  echo "$DEL_HITS" >&2
  FAIL=1
fi

# put_archival_shard_segment has exactly one production caller — the freeze
# processor. (Declarations/definitions carry 'void'/'::' context and are
# excluded; tests/ live outside src/ and are out of scope.) A second caller
# bypasses the first-crossing discipline that makes freeze_height
# per-branch-monotone (O-2).
PUT_CALLS="$(rg -n 'put_archival_shard_segment\(' src/ \
  | rg -v '::put_archival_shard_segment|void\s+put_archival_shard_segment|reward-gate-site-allow' || true)"
PUT_CALL_COUNT="$(printf '%s' "$PUT_CALLS" | rg -c '.' || true)"
if [[ "${PUT_CALL_COUNT:-0}" -ne 1 ]]; then
  echo "FAIL: expected exactly 1 production call to put_archival_shard_segment (the freeze processor), found ${PUT_CALL_COUNT:-0}" >&2
  printf '%s\n' "$PUT_CALLS" >&2
  FAIL=1
fi

# -- Invariant 5: SEGMENT_LEAF_COUNT division one-site --------------------------
#
# §8 division one-site: floor(leaf_count / E) is computed ONLY by the Rust
# entry point shekyl_archival_frozen_segment_count. Any C++ '/' or '%'
# against the constant re-implements the boundary arithmetic — the
# duplicated-division drift adversary (§3 obligation O-1).
# Comment lines are excluded: prose describing the formula (the FFI header's
# contract doc) is not arithmetic. Code operators survive the filter.
if DIV_HITS="$(rg -n '(/|%)\s*(SHEKYL_ARCHIVAL_)?SEGMENT_LEAF_COUNT|(SHEKYL_ARCHIVAL_)?SEGMENT_LEAF_COUNT\s*(/|%)' src/ \
  | rg -v '^[^:]+:[0-9]+:\s*(//|/\*|\*)' \
  | rg -v 'reward-gate-site-allow')"; then
  echo "FAIL: SEGMENT_LEAF_COUNT-adjacent division/modulo in src/ — boundary arithmetic lives only in shekyl_archival_frozen_segment_count (Rust)" >&2
  echo "$DIV_HITS" >&2
  FAIL=1
fi

# Positive control: the FFI entry point is declared, called exactly once
# (inside frozen_segment_count_on_write_txn), and both hooks route through
# that helper — the division site exists and is reachable from connect and
# revert alike.
if ! rg -q 'shekyl_archival_frozen_segment_count\(' src/shekyl/shekyl_ffi.h; then
  echo "FAIL: positive control — shekyl_archival_frozen_segment_count not declared in src/shekyl/shekyl_ffi.h" >&2
  FAIL=1
fi
FSC_CALLS="$(rg -n 'return shekyl_archival_frozen_segment_count\(' "$LMDB_CPP" || true)"
FSC_COUNT="$(printf '%s' "$FSC_CALLS" | rg -c '.' || true)"
if [[ "${FSC_COUNT:-0}" -ne 1 ]]; then
  echo "FAIL: positive control — expected exactly 1 shekyl_archival_frozen_segment_count call in $LMDB_CPP, found ${FSC_COUNT:-0}" >&2
  FAIL=1
fi
FSC_HELPER_CALLS="$(rg -n 'frozen_segment_count_on_write_txn\(\)' "$LMDB_CPP" | rg -v '::frozen_segment_count_on_write_txn' || true)"
FSC_HELPER_COUNT="$(printf '%s' "$FSC_HELPER_CALLS" | rg -c '.' || true)"
if [[ "${FSC_HELPER_COUNT:-0}" -ne 2 ]]; then
  echo "FAIL: positive control — expected exactly 2 frozen_segment_count_on_write_txn() calls in $LMDB_CPP (freeze processor + revert), found ${FSC_HELPER_COUNT:-0}" >&2
  printf '%s\n' "$FSC_HELPER_CALLS" >&2
  FAIL=1
fi

exit "$FAIL"
