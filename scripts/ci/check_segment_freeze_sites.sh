#!/usr/bin/env bash
#
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# Segment-freeze one-site tripwires — ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md
# (§4.4 counter lockstep, §8 cursor accounting). Invoked from
# check_consensus_invariants.sh and CI.
#
# Provenance: this file is the substrate half of the former
# check_reward_gate_predicate_sites.sh. The M1 K_COVER gate is RETIRED
# (ARCHIVAL_REWARD_GATE_M1.md §13) and its predicate invariant (single
# K_COVER comparison site) is gone with the machinery; the five invariants
# below guard the segment-freeze substrate, which survives the retirement —
# the frozen-count is freeze bookkeeping (and the wallet thin-market
# disclosure's natural operand), not gate machinery.
#
# Escape hatch: a line carrying the marker `reward-gate-site-allow` is
# exempt (genuinely-benign, reviewed use; marker name retained from the
# predecessor so any historical allows keep working).

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

# rg exit-code discipline: 0 = matches, 1 = no matches, >1 = scan error
# (regex error, I/O failure). `if VAR="$(rg …)"` folds >1 into "no matches"
# because set -e is suppressed in if-conditions — a false-green on the gate's
# own scanner. `scan` maps no-match to success (empty output) and propagates
# scan errors, so a plain `VAR="$(scan …)"` assignment aborts loudly under
# set -e / pipefail. Presence checks branch on [[ -n "$VAR" ]], never on rg's
# exit status directly.
scan() {
  local rc=0
  rg "$@" || rc=$?
  if (( rc > 1 )); then
    echo "FAIL: rg exited ${rc} (scan error, not no-match) during: rg $*" >&2
    return "${rc}"
  fi
  return 0
}

# Drop `rg -n` hits (path:line:content) whose content is a comment or doc line
# (`// …`, `/* …`, ` * …`), so an explanatory comment, a log line, or an assert
# message that merely names a pinned symbol cannot trip a raw textual count.
# A genuinely-benign in-code mention still uses the reward-gate-site-allow
# marker; this only spares prose from the magic-number tripwires.
drop_comment_hits() { scan -v '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*)'; }

LMDB_CPP="src/blockchain_db/lmdb/db_lmdb.cpp"
LMDB_H="src/blockchain_db/lmdb/db_lmdb.h"

# Path-exact exemption regexes (escape `.` so only the pinned files match;
# check_pending_post_write_path.sh precedent).
LMDB_CPP_RE="${LMDB_CPP//./\\.}"

# Guardrail: if a pinned choke file moved or was renamed, fail loudly rather
# than let the invariants below pass vacuously on zero hits.
for f in "$LMDB_CPP" "$LMDB_H"; do
  if [[ ! -f "$f" ]]; then
    echo "FAIL: $f not found — a pinned choke moved; update this gate, do not let it pass silently" >&2
    exit 1
  fi
done

# -- Invariant 1: single counting read over m_archival_shard_segment ---------
#
# Iteration capability = counting capability: a cursor open over the segment
# table outside the pinned sites is the second-count-site adversary. Pinned
# sites (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §8 cursor accounting, 5 total):
#   1. count_frozen_shards_at_close — the O(1) frozen-count reader's one-row
#      frontier probe (MDB_LAST decode + boundary check; no production
#      caller since the M1 retirement — see the call-site invariant below);
#   2. process_archival_slash_for_epoch — slash-scan shard enumeration
#      (an enumeration read, not a count feeding a consensus predicate);
#   3. process_archival_segment_freezes_at_height — the freeze processor's
#      one-row resume peek (the writer deriving its own frontier from its
#      own rows, not a second count pass);
#   4. revert_archival_segment_freezes — the pop revert's reverse walk
#      deleting rows above the post-trim frontier;
#   5. count_frozen_shard_rows_by_walk_for_test — the differential oracle
#      the counter is tested against (test-support, no production caller;
#      the _for_test suffix is the named exemption shape).
CURSOR_HITS="$(scan -n 'mdb_cursor_open\([^)]*m_archival_shard_segment' src/ \
  | drop_comment_hits \
  | scan -v 'reward-gate-site-allow')"
CURSOR_COUNT="$(printf '%s' "$CURSOR_HITS" | scan -c '.')"
if [[ "${CURSOR_COUNT:-0}" -ne 5 ]]; then
  echo "FAIL: expected exactly 5 cursor opens over m_archival_shard_segment (operand frontier probe, slash scan, freeze resume peek, revert walk, differential-walk test oracle), found ${CURSOR_COUNT:-0}" >&2
  echo "  (a new iteration over the segment table must route through" >&2
  echo "   count_frozen_shards_at_close or carry a reviewed reward-gate-site-allow marker)" >&2
  printf '%s\n' "$CURSOR_HITS" >&2
  FAIL=1
fi
# Positive controls for the freeze-pipeline cursor sites: a rename or
# removal must fail here, not silently re-shape the count above.
for fn in process_archival_segment_freezes_at_height revert_archival_segment_freezes count_frozen_shard_rows_by_walk_for_test; do
  if ! rg -q "BlockchainLMDB::${fn}\(" "$LMDB_CPP"; then
    echo "FAIL: positive control — ${fn} not found in $LMDB_CPP (freeze-pipeline site renamed or removed; update this gate)" >&2
    FAIL=1
  fi
done

# mdb_stat over the segment table is the cached-counter shortcut (§11.8
# M3-1's third drift adversary) — refused outright, no allowlist.
STAT_HITS="$(scan -n 'mdb_stat\([^)]*m_archival_shard_segment' src/)"
if [[ -n "$STAT_HITS" ]]; then
  echo "FAIL: mdb_stat over m_archival_shard_segment — a counting read outside count_frozen_shards_at_close" >&2
  echo "$STAT_HITS" >&2
  FAIL=1
fi

# Positive control: the helper is defined exactly once (its definition carries
# the BlockchainLMDB:: qualifier). A rename or a lost definition fails here
# rather than silently de-arming the call-site count below.
DEF_COUNT="$(scan -c 'BlockchainLMDB::count_frozen_shards_at_close\(' "$LMDB_CPP")"
if [[ "${DEF_COUNT:-0}" -ne 1 ]]; then
  echo "FAIL: expected exactly one BlockchainLMDB::count_frozen_shards_at_close definition in $LMDB_CPP, found ${DEF_COUNT:-0}" >&2
  FAIL=1
fi

# The real invariant: the helper is the ONLY sanctioned counting read, and
# since the M1 gate's retirement removed its epoch-close consumer it has
# exactly ZERO production call sites (tests still drive it; the wallet
# thin-market disclosure is its named future consumer — adding that consumer
# updates this expectation to 1 deliberately). Count invocations that are
# neither the definition (BlockchainLMDB:: qualifier) nor a comment/doc line.
CALL_HITS="$(scan -n 'count_frozen_shards_at_close\(' "$LMDB_CPP" \
  | scan -v 'BlockchainLMDB::count_frozen_shards_at_close' \
  | drop_comment_hits \
  | scan -v 'reward-gate-site-allow')"
CALL_COUNT="$(printf '%s' "$CALL_HITS" | scan -c '.')"
if [[ "${CALL_COUNT:-0}" -ne 0 ]]; then
  echo "FAIL: expected zero count_frozen_shards_at_close production call sites in $LMDB_CPP (the M1 gate consumer is retired; a new consumer updates this gate deliberately), found ${CALL_COUNT:-0}" >&2
  printf '%s\n' "$CALL_HITS" >&2
  FAIL=1
fi

# -- Invariant 2: boundary operator pinned (freeze_height <= h_close) --------
#
# Exactly one `freeze_height <= h_close` in the helper; zero strict-`<`
# freeze-height comparisons anywhere in src/. Equality counts (§1.1); the
# off-by-one edit is a consensus fork at exactly the boundary class the
# Rust KAT cannot reach.
LE_COUNT="$(scan -c 'segment\.freeze_height\s*<=\s*h_close' "$LMDB_CPP")"
if [[ "${LE_COUNT:-0}" -ne 1 ]]; then
  echo "FAIL: expected exactly one 'segment.freeze_height <= h_close' comparison in $LMDB_CPP, found ${LE_COUNT:-0}" >&2
  FAIL=1
fi
LT_HITS="$(scan -n 'freeze_height\s*<[^=]' src/ | scan -v 'reward-gate-site-allow')"
if [[ -n "$LT_HITS" ]]; then
  echo "FAIL: strict-< freeze_height comparison in src/ — boundary inclusivity is consensus (§1.1: equality counts)" >&2
  echo "$LT_HITS" >&2
  FAIL=1
fi

# -- Invariant 3: segment-table writer one-site --------------------------------
#
# ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §8 writer one-site. The segment table
# has exactly one production writer (put_archival_shard_segment) and one
# named test exemption (put_archival_shard_segment_raw_for_corruption_test,
# the §9 corruption-injection surface). A third mdb_put is the
# overwrite-the-frozen-row adversary O-2 refuses.
PUT_HITS="$(scan -n 'mdb_put\([^)]*m_archival_shard_segment' src/ \
  | scan -v 'reward-gate-site-allow')"
PUT_COUNT="$(printf '%s' "$PUT_HITS" | scan -c '.')"
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
DEL_HITS="$(scan -n 'mdb_del\([^)]*m_archival_shard_segment' src/ | scan -v 'reward-gate-site-allow')"
if [[ -n "$DEL_HITS" ]]; then
  echo "FAIL: direct mdb_del over m_archival_shard_segment — segment rows are deleted only by revert_archival_segment_freezes' cursor walk" >&2
  echo "$DEL_HITS" >&2
  FAIL=1
fi

# put_archival_shard_segment has exactly one production caller — the freeze
# processor. (Declarations/definitions carry 'void'/'::' context and are
# excluded; tests/ live outside src/ and are out of scope.) A second caller
# bypasses the first-crossing discipline that makes freeze_height
# per-branch-monotone (O-2).
PUT_CALLS="$(scan -n 'put_archival_shard_segment\(' src/ \
  | scan -v '::put_archival_shard_segment|void\s+put_archival_shard_segment|reward-gate-site-allow')"
PUT_CALL_COUNT="$(printf '%s' "$PUT_CALLS" | scan -c '.')"
if [[ "${PUT_CALL_COUNT:-0}" -ne 1 ]]; then
  echo "FAIL: expected exactly 1 production call to put_archival_shard_segment (the freeze processor), found ${PUT_CALL_COUNT:-0}" >&2
  printf '%s\n' "$PUT_CALLS" >&2
  FAIL=1
fi

# -- Invariant 4: SEGMENT_LEAF_COUNT division one-site --------------------------
#
# §8 division one-site: floor(leaf_count / E) is computed ONLY by the Rust
# entry point shekyl_archival_frozen_segment_count. Any C++ '/' or '%'
# against the constant re-implements the boundary arithmetic — the
# duplicated-division drift adversary (§3 obligation O-1).
# Comment lines are excluded: prose describing the formula (the FFI header's
# contract doc) is not arithmetic. Code operators survive the filter.
DIV_HITS="$(scan -n '(/|%)\s*(SHEKYL_ARCHIVAL_)?SEGMENT_LEAF_COUNT|(SHEKYL_ARCHIVAL_)?SEGMENT_LEAF_COUNT\s*(/|%)' src/ \
  | drop_comment_hits \
  | scan -v 'reward-gate-site-allow')"
if [[ -n "$DIV_HITS" ]]; then
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

# -- Invariant 5: pop-symmetric counter mutation surface ------------------------
#
# The persisted frozen-shard counter (properties `archival_frozen_shard_count`,
# ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §4.4) is the M1 gate operand's O(1)
# backing store. Its soundness is structural: the counter moves ONLY where a
# registry row is created (+1, put_archival_shard_segment) or deleted (−1,
# revert_archival_segment_freezes). A third mutation site is the counter-drift
# adversary — the exact "cached counter" M3-1 refused, reintroduced without
# its lockstep property.

# The key literal appears exactly twice in code (the getter and setter key
# definitions); everything else routes through those helpers.
KEY_HITS="$(scan -n '"archival_frozen_shard_count"' src/ | drop_comment_hits)"
KEY_COUNT="$(printf '%s' "$KEY_HITS" | scan -c '.')"
if [[ "${KEY_COUNT:-0}" -ne 2 ]]; then
  echo "FAIL: expected exactly 2 code uses of the \"archival_frozen_shard_count\" key in src/ (getter + setter), found ${KEY_COUNT:-0}" >&2
  printf '%s\n' "$KEY_HITS" >&2
  FAIL=1
fi

# The setter has exactly 2 production call sites: the row writer's +1 and
# the revert walk's −1 (the pop-symmetric pair).
SET_CALLS="$(scan -n 'set_archival_frozen_shard_count_on_write_txn\(' src/ \
  | scan -v '::set_archival_frozen_shard_count_on_write_txn|void\s+set_archival_frozen_shard_count_on_write_txn' \
  | drop_comment_hits \
  | scan -v 'reward-gate-site-allow')"
SET_COUNT="$(printf '%s' "$SET_CALLS" | scan -c '.')"
if [[ "${SET_COUNT:-0}" -ne 2 ]]; then
  echo "FAIL: expected exactly 2 set_archival_frozen_shard_count_on_write_txn call sites (put_archival_shard_segment +1, revert_archival_segment_freezes −1), found ${SET_COUNT:-0}" >&2
  printf '%s\n' "$SET_CALLS" >&2
  FAIL=1
fi

# Positive controls: both counter helpers are defined, and the differential
# walk oracle has no production caller (its only invocations are its
# definition/declaration; tests/ live outside src/).
for fn in get_archival_frozen_shard_count_on_write_txn set_archival_frozen_shard_count_on_write_txn; do
  if ! rg -q "BlockchainLMDB::${fn}\(" "$LMDB_CPP"; then
    echo "FAIL: positive control — ${fn} not found in $LMDB_CPP (counter helper renamed or removed; update this gate)" >&2
    FAIL=1
  fi
done
WALK_CALLS="$(scan -n 'count_frozen_shard_rows_by_walk_for_test\(' src/ \
  | scan -v '::count_frozen_shard_rows_by_walk_for_test|uint64_t\s+count_frozen_shard_rows_by_walk_for_test' \
  | drop_comment_hits \
  | scan -v 'reward-gate-site-allow')"
if [[ -n "$WALK_CALLS" ]]; then
  echo "FAIL: count_frozen_shard_rows_by_walk_for_test has a production caller in src/ — the differential oracle is test-support only" >&2
  printf '%s\n' "$WALK_CALLS" >&2
  FAIL=1
fi

exit "$FAIL"
