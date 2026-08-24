// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared archival FFI verdict codes and error mappers.
//!
//! Domain modules may also define local codes next to their entry points.
//! C++ / `shekyl_ffi.h` mirror the literals (rule 25).

use shekyl_archival_retention::{
    BondPostError, HoldingsUpdateConnectError, HoldingsUpdatePopError, RebondConnectError,
    RebondPopError, UnbondConnectError, UnbondPopError, WireError,
};

/// `shekyl_archival_settlement_epoch_arm_regtest`: armed (or the variable
/// is unset and the genesis pin latched).
pub const SHEKYL_ARCHIVAL_SEB_ARM_OK: u8 = 0;
/// The lever is set but is not an integer in the accepted range — an
/// operator input error; fix the value or unset the variable.
pub const SHEKYL_ARCHIVAL_SEB_ARM_ERR_INVALID: u8 = 1;
/// The schedule had already latched before arming ran — an
/// initialization-order defect in the arming process, not a bad value.
pub const SHEKYL_ARCHIVAL_SEB_ARM_ERR_TOO_LATE: u8 = 2;

/// Success.
pub const SHEKYL_ARCHIVAL_VERIFY_OK: u8 = 0;
/// Required pointer was null.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR: u8 = 1;
/// Vin payload failed structural decode.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_WIRE: u8 = 2;
/// Segment path depth < 2.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_PATH_TOO_SHALLOW: u8 = 3;
/// Challenged leaf not present in opening.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_LEAF_NOT_IN_OPENING: u8 = 4;
/// Recomputed sub-root does not match `R_k`.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_SUBROOT_MISMATCH: u8 = 5;
// Code 6 (`ERR_LEAF_INDEX`) is RETIRED with code 7: the index it compared is
// derived, not transported (RF-D6). Unassigned, not reused.
// Code 7 (`ERR_REGISTRY_RK`) is RETIRED, not reusable: it reported a wire `R_k`
// disagreeing with the registry's, and RF-D6 took `R_k` off the wire. The
// number stays unassigned so an old log line cannot be misread as a new
// condition.
/// `current_height` is not past `H_fire`.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_FIRE_NOT_REACHED: u8 = 8;
/// `current_height` is past `H_credit_deadline` (`H_close`).
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_CREDIT_DEADLINE: u8 = 9;
/// Hybrid signature verification failed.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_PQC_VERIFY: u8 = 10;
/// Hybrid pubkey or signature blob failed deserialization.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_PQC_DESER: u8 = 11;
/// Registry reports zero segment leaf count.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_ZERO_GEOMETRY: u8 = 12;
/// `settlement_epoch` in vin disagrees with context epoch.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_EPOCH_MISMATCH: u8 = 13;
/// Leaf-layer scalar count is not a multiple of four.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_SCALAR_SHAPE: u8 = 14;

/// `PC-D3`: `ctx.prev_block_hash` was all-zeros — the unpopulated-field
/// sentinel, on `RF-D5`'s precedent.
///
/// Deriving the leaf index against a zero hash would succeed and produce a
/// well-formed index for the wrong block, so the failure has to be here rather
/// than downstream where it would surface as a path mismatch and be
/// misattributed to the prover.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_PREVHASH_UNPOPULATED: u8 = 15;

/// Bond-post CT balance sum matches (ARCHIVAL_BOND_GATE4.md §3.2).
pub const SHEKYL_ARCHIVAL_BOND_CT_BALANCE_OK: u8 = 0;
/// Required pointer was null while count > 0.
pub const SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NULL_PTR: u8 = 1;
/// Both `bond_credit` and `bond_debit` are non-zero.
pub const SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_BOTH_TERMS: u8 = 2;
/// Invalid commitment point, malformed flat buffer (length not a multiple of 32), or
/// `count * 32` overflow / oversize slice in the FFI flatten path.
pub const SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_INVALID_POINT: u8 = 3;
/// Left and right commitment sums differ.
pub const SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_SUM_MISMATCH: u8 = 4;
/// Neither `bond_credit` nor `bond_debit` is set (§3.2 term rigidity).
pub const SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NO_BOND_TERM: u8 = 5;

/// JoinMarket bond-post semantic verify succeeded (gate-4 §3.5).
pub const SHEKYL_ARCHIVAL_BOND_POST_OK: u8 = 0;
/// `shard_ids_ptr` was null while `shard_ids_len > 0`.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_NULL_PTR: u8 = 1;
/// `post_kind` is not JoinMarket.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND: u8 = 2;
/// ShardSetCompact with empty shard list.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_SHARD_SET_EMPTY: u8 = 3;
/// CompleteTree carries shard ids.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_COMPLETE_TREE_WITH_SHARDS: u8 = 4;
/// JoinMarket bond-post must not carry `bond_debit`.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_DEBIT_NONZERO: u8 = 5;
/// Both `bond_credit` and `bond_debit` are non-zero (§3.2 term rigidity).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_BOTH_TERMS: u8 = 6;
/// `bond_floor(holdings)` is zero.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_FLOOR_ZERO: u8 = 7;
/// `bonded_total_atomic` / `bond_credit` do not equal `bond_floor`.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_FLOOR_MISMATCH: u8 = 8;
/// Bond record already exists for `P_canonical_id`.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_EXISTS: u8 = 9;
/// `holdings_kind` is not a known enum value.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_KIND: u8 = 10;
/// `Unbond` verify: `post_kind` is not `Unbond`.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_UNBOND: u8 = 11;
/// `Unbond` verify: no bond record exists for `P_canonical_id`.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_MISSING: u8 = 12;
/// `Unbond` verify: record's `bonded_total` is zero (nothing to unbond).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_NOTHING_TO_UNBOND: u8 = 13;
/// `Unbond` verify: `bond_credit` is non-zero on a debit path.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_UNBOND_CREDIT: u8 = 14;
/// `Unbond` verify: post-connect `bonded_total_atomic != bond_floor(holdings)`.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_UNBOND_FLOOR_MISMATCH: u8 = 15;
/// `Unbond` verify: post-connect `bonded_total_atomic != 0` (partial, not full exit).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_NOT_FULL_UNBOND: u8 = 16;
/// `Unbond` verify: `bond_debit` != the record's current `bonded_total`.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_NOT_FULL: u8 = 17;
/// `Unbond` verify: the release cooldown has not elapsed.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_COOLDOWN_NOT_ELAPSED: u8 = 18;
/// A shard/served-epoch array length would overflow the `from_raw_parts`
/// `isize::MAX` byte bound — a corrupted or hostile marshaled length.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_LEN_OVERFLOW: u8 = 19;
/// `Unbond` verify: a full exit must end at empty holdings, but the post-connect
/// descriptor is floor-zero only because its shard set is oversize/invalid.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_UNBOND_HOLDINGS_NOT_EMPTY: u8 = 20;
/// `Unbond` verify: the record's interval log is at the codec cap, so the
/// connect's clean interval-close could not append — reject at admission.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_INTERVAL_LOG_FULL: u8 = 21;
/// `Unbond` verify: the slash scheduler has not yet settled every epoch through
/// the record's last-served anchor (the one-block connect-ordering race guard).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_SLASH_SETTLEMENT_PENDING: u8 = 22;
/// The marshaled `bond_spend_pk` violates the §9.11 JoinMarket coupling:
/// missing/non-canonical length on JoinMarket, or present on any other kind.
/// Returned by the shared vin marshaler, so both entry points can return it —
/// the marshaler refuses to construct a vin the wire codec could not emit.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_SPEND_PK_COUPLING: u8 = 23;
// ── HoldingsUpdate add + drop verify (gate-4 §4.4) ──────────────────────────
/// HoldingsUpdate verify: `post_kind` is not HoldingsUpdate.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_HOLDINGS_UPDATE: u8 = 24;
/// HoldingsUpdate verify: the record is CompleteTree (foundation) — not a shard set.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ON_COMPLETE_TREE: u8 = 25;
/// HoldingsUpdate verify: the post-holdings are not ShardSetCompact.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_POST_NOT_COMPACT: u8 = 26;
/// HoldingsUpdate-add verify: terms are not `bond_credit == FLOOR, bond_debit == 0`.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ADD_TERMS: u8 = 27;
/// HoldingsUpdate-add verify: the record is not in good standing (open bad interval).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_GOOD_STANDING: u8 = 28;
/// HoldingsUpdate-add verify: post is not current holdings plus exactly one shard.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_SINGLE_ADD: u8 = 29;
/// HoldingsUpdate-add verify: post bonded_total != bond_floor(post-holdings).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ADD_FLOOR_MISMATCH: u8 = 30;
/// HoldingsUpdate-drop verify: terms are not `bond_debit == FLOOR, bond_credit == 0`.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_TERMS: u8 = 31;
/// HoldingsUpdate-drop verify: post is not current holdings minus exactly one shard.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_SINGLE_DROP: u8 = 32;
/// HoldingsUpdate-drop verify: dropping the last shard (use Unbond for a full exit).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_LAST_SHARD: u8 = 33;
/// HoldingsUpdate-drop verify: post bonded_total != bond_floor(post-holdings).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_FLOOR_MISMATCH: u8 = 34;
/// HoldingsUpdate-drop verify: the shard is within its bond_duration retention horizon.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_WITHIN_HORIZON: u8 = 35;
/// `HoldingsUpdate` verify: the record is not Bonded — zero collateral / no held
/// shards (P2B-7 Pin 1: `Bonded → Bonded`; an Exited or slash-emptied record
/// re-enters via JoinMarket/Rebond, never a voluntary adjustment).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_RECORD_NOT_BONDED: u8 = 36;
/// `Rebond` verify (gate-4 §3.4; P2B-9): the vin's post_kind is not Rebond.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_REBOND: u8 = 37;
/// Rebond verify: the record is CompleteTree (unrepresentable — demotion flips
/// the kind atomically with the interval append; belt).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_ON_COMPLETE_TREE: u8 = 38;
/// Rebond verify: the vin's post-holdings are not ShardSetCompact.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_POST_NOT_COMPACT: u8 = 39;
/// Rebond verify: no open bad interval — the record is not slashed.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_NOT_SLASHED: u8 = 40;
/// Rebond verify: more than one open bad interval (P2B-9 Pin 5 coalescing
/// invariant broken — record corruption).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_MULTIPLE_OPEN: u8 = 41;
/// Rebond verify: interval log lacks headroom (> 254 entries; Pin 6 reserves one
/// slot for the next slash + one for the Unbond clean close).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_LOG_HEADROOM: u8 = 42;
/// Rebond verify: terms mismatch (debit nonzero, or credit != bond_floor(post) −
/// record bonded_total, or post bonded_total != bond_floor(post)).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_TERMS: u8 = 43;
/// Rebond verify: post-holdings are not a duplicate-free superset of the record's
/// current holdings (Pin 1 — reinstatement, not restructuring).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_NOT_SUPERSET: u8 = 44;
/// **RETIRED — never returned.** Code 45 was the Rebond verify-level oversize
/// belt (`REBOND_POST_OVERSIZE`), removed with the `ShardSet` newtype: an
/// oversize post is now unrepresentable in the vin's holdings, so no verify
/// produces it. The symbol stays **defined and reserved** (rather than
/// renumbering 46/47/48, or leaving a dangling name) so the Rust↔C++ code
/// contract is explicit and a stray/legacy 45 maps to a meaningful message.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_POST_OVERSIZE_RETIRED: u8 = 45;
/// Rebond verify: the record's `bonded_total != bond_floor(record holdings)`
/// (floor-drifted record) — rejected at verify so the tx can never ride to the
/// connect fold's FATAL floor belt (tx rejection, not a chain halt).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_RECORD_FLOOR: u8 = 46;
/// Shared vin marshal: the vin's holdings shard count exceeds the wire codec
/// bound (`MAX_HOLDINGS_SHARDS`). The FFI marshal is a second decoder for the
/// same wire object, so it routes through `ShardSet::new` — an oversize set is
/// unrepresentable past the boundary for every post kind.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_COUNT_EXCEEDED: u8 = 47;
/// Shared vin marshal: the vin's holdings carry a duplicate shard id. Rejected
/// at the same `ShardSet::new` boundary as the count cap ("a set on the wire").
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_DUPLICATE_SHARD: u8 = 48;

/// `Unbond` connect/pop fold succeeded (gate-4 §4.3 / §5).
pub const SHEKYL_ARCHIVAL_UNBOND_APPLY_OK: u8 = 0;
/// A required out-pointer was null.
pub const SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_NULL_PTR: u8 = 1;
/// Retired: the connect fold takes the record's held shard COUNT, not a
/// pointer/length pair, so no slice marshal exists to guard. The value stays
/// reserved so the family's codes never renumber.
pub const SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_LEN_OVERFLOW: u8 = 2;
/// `record_holdings_kind` is not a known enum value.
pub const SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_HOLDINGS_KIND: u8 = 3;
/// Connect: `bond_debit` is zero.
pub const SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_DEBIT_ZERO: u8 = 4;
/// Connect: `bond_debit` != the record's current `bonded_total`.
pub const SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_DEBIT_NOT_RECORD_TOTAL: u8 = 5;
/// Connect: the record's `bonded_total == bond_floor(holdings)` invariant is broken.
pub const SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_RECORD_FLOOR_INVARIANT: u8 = 6;
/// Connect: `total_bonded_atomic` would underflow.
pub const SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_TOTAL_BONDED_UNDERFLOW: u8 = 7;
/// Connect: the interval log is at the codec cap; the clean close cannot append.
pub const SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_INTERVAL_LOG_FULL: u8 = 8;
/// Pop: the record is not in the `Unbond` post-connect (`Exited`) state.
pub const SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_RECORD_NOT_EXITED: u8 = 9;
/// Pop: the trailing interval-log entry is not the expected clean interval-close.
pub const SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_MISSING_CLEAN_CLOSE: u8 = 10;
/// Pop: the journaled pre-image `bonded_total` is zero.
pub const SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_PRE_IMAGE_EMPTY: u8 = 11;
/// Pop: `total_bonded_atomic` re-credit would overflow.
pub const SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_TOTAL_BONDED_OVERFLOW: u8 = 12;

// ── HoldingsUpdate add/drop connect + pop fold codes (gate-4 §4.4) ───────────
/// HoldingsUpdate connect/pop fold succeeded.
pub const SHEKYL_ARCHIVAL_HU_APPLY_OK: u8 = 0;
/// A required out-pointer was null.
pub const SHEKYL_ARCHIVAL_HU_APPLY_ERR_NULL_PTR: u8 = 1;
/// The record shard-id length would overflow the `from_raw_parts` byte bound.
pub const SHEKYL_ARCHIVAL_HU_APPLY_ERR_LEN_OVERFLOW: u8 = 2;
/// Connect: post is not `current ∪ {one shard}` (add).
pub const SHEKYL_ARCHIVAL_HU_APPLY_ERR_NOT_SINGLE_ADD: u8 = 3;
/// Connect: post is not `current ∖ {one shard}` (drop).
pub const SHEKYL_ARCHIVAL_HU_APPLY_ERR_NOT_SINGLE_DROP: u8 = 4;
/// Connect: drop would leave no shards (use Unbond).
pub const SHEKYL_ARCHIVAL_HU_APPLY_ERR_DROP_LAST_SHARD: u8 = 5;
/// Connect: the record's `bonded_total == bond_floor(holdings)` invariant is broken.
pub const SHEKYL_ARCHIVAL_HU_APPLY_ERR_RECORD_FLOOR_INVARIANT: u8 = 6;
/// Connect/pop: a `bonded_total` / `total_bonded_atomic` over/underflow.
pub const SHEKYL_ARCHIVAL_HU_APPLY_ERR_COUNTER_RANGE: u8 = 7;
/// Pop: the per-`P` balance changed by something other than one FLOOR.
pub const SHEKYL_ARCHIVAL_HU_APPLY_ERR_NOT_SINGLE_DELTA: u8 = 8;
/// Connect-fold belt of the verify-side Bonded gate: the record holds no
/// bonded collateral / no shards (an Exited record cannot be resurrected).
pub const SHEKYL_ARCHIVAL_HU_APPLY_ERR_RECORD_NOT_BONDED: u8 = 9;

#[must_use]
pub(super) fn map_holdings_update_connect_error(e: HoldingsUpdateConnectError) -> u8 {
    match e {
        HoldingsUpdateConnectError::NotSingleAdd => SHEKYL_ARCHIVAL_HU_APPLY_ERR_NOT_SINGLE_ADD,
        HoldingsUpdateConnectError::NotSingleDrop => SHEKYL_ARCHIVAL_HU_APPLY_ERR_NOT_SINGLE_DROP,
        HoldingsUpdateConnectError::DropLastShard => SHEKYL_ARCHIVAL_HU_APPLY_ERR_DROP_LAST_SHARD,
        HoldingsUpdateConnectError::RecordFloorInvariantBroken => {
            SHEKYL_ARCHIVAL_HU_APPLY_ERR_RECORD_FLOOR_INVARIANT
        }
        HoldingsUpdateConnectError::CounterRange => SHEKYL_ARCHIVAL_HU_APPLY_ERR_COUNTER_RANGE,
        HoldingsUpdateConnectError::RecordNotBonded => {
            SHEKYL_ARCHIVAL_HU_APPLY_ERR_RECORD_NOT_BONDED
        }
    }
}

#[must_use]
pub(super) fn map_holdings_update_pop_error(e: HoldingsUpdatePopError) -> u8 {
    match e {
        HoldingsUpdatePopError::NotSingleShardDelta => {
            SHEKYL_ARCHIVAL_HU_APPLY_ERR_NOT_SINGLE_DELTA
        }
        HoldingsUpdatePopError::CounterRange => SHEKYL_ARCHIVAL_HU_APPLY_ERR_COUNTER_RANGE,
    }
}

/// `Rebond` connect/pop fold succeeded (gate-4 §3.4; P2B-9).
pub const SHEKYL_ARCHIVAL_REBOND_APPLY_OK: u8 = 0;
/// A required out-pointer is null.
pub const SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_NULL_PTR: u8 = 1;
/// A marshaled array length overflows.
pub const SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_LEN_OVERFLOW: u8 = 2;
/// Connect: post is not a duplicate-free superset of the record's holdings.
pub const SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_NOT_SUPERSET: u8 = 3;
/// Connect: empty post (reinstatement needs a position).
pub const SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_EMPTY_POST: u8 = 4;
/// Connect: the record's `bonded_total == bond_floor(holdings)` invariant is broken.
pub const SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_RECORD_FLOOR_INVARIANT: u8 = 5;
/// Connect: no open bad interval to close (record not slashed).
pub const SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_NO_OPEN_INTERVAL: u8 = 6;
/// Connect: multiple open bad intervals (Pin 5 coalescing invariant broken).
pub const SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_MULTIPLE_OPEN_INTERVALS: u8 = 7;
/// Connect: `E_rebond + 1` is not strictly after the open interval's start.
pub const SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_INTERVAL_ORDERING: u8 = 8;
/// Connect/pop: counter or epoch arithmetic out of range.
pub const SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_COUNTER_RANGE: u8 = 9;
/// Pop: the per-`P` balance delta is not a non-negative whole number of FLOORs.
pub const SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_NOT_REBOND_DELTA: u8 = 10;
/// Connect: the caller's added-shard out buffer is smaller than the added set.
pub const SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_ADDED_BUFFER_TOO_SMALL: u8 = 11;
/// Connect: the post set exceeds the codec shard cap (the record could never
/// encode) — verify's `REBOND_POST_OVERSIZE` forecloses this at admission.
pub const SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_POST_OVERSIZE: u8 = 12;

#[must_use]
pub(super) fn map_rebond_connect_error(e: RebondConnectError) -> u8 {
    match e {
        RebondConnectError::NotSuperset => SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_NOT_SUPERSET,
        RebondConnectError::EmptyPost => SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_EMPTY_POST,
        RebondConnectError::PostOversize => SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_POST_OVERSIZE,
        RebondConnectError::RecordFloorInvariantBroken => {
            SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_RECORD_FLOOR_INVARIANT
        }
        RebondConnectError::NoOpenInterval => SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_NO_OPEN_INTERVAL,
        RebondConnectError::MultipleOpenIntervals => {
            SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_MULTIPLE_OPEN_INTERVALS
        }
        RebondConnectError::IntervalOrdering => SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_INTERVAL_ORDERING,
        RebondConnectError::CounterRange => SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_COUNTER_RANGE,
    }
}

#[must_use]
pub(super) fn map_rebond_pop_error(e: RebondPopError) -> u8 {
    match e {
        RebondPopError::NotRebondDelta => SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_NOT_REBOND_DELTA,
        RebondPopError::CounterRange => SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_COUNTER_RANGE,
    }
}

/// Context supplied by consensus after bond/registry LMDB reads (gate-2 §5.3 steps 2, 6–7).
#[repr(C)]
pub struct ShekylArchivalVerifyCtx {
    pub current_height: u64,
    pub settlement_epoch: u64,
    pub block_hash_at_seal: [u8; 32],
    /// `block_hash(h−1)` of the block this record rides in (`PC-D3`).
    ///
    /// **Verifier-supplied, never transported.** `PC-D2` makes the block
    /// implicit — the record arrives in its own producer's block — so consensus
    /// fills this from the block it is validating. A prover-supplied hash would
    /// be the `PC-D1`/`RF-D8` violation this round exists to refuse.
    ///
    /// All-zeros is refused with its own code, on `RF-D5`'s precedent and for
    /// its reason: a caller that forgets the field must fail loudly rather than
    /// derive a leaf index against a zero hash, and a readability flag would
    /// itself be caller-populated and forgotten alongside it.
    pub prev_block_hash: [u8; 32],
    pub registry_segment_subroot_rk: [u8; 32],
    pub segment_leaf_count: u64,
    pub pqc_pubkey_ptr: *const u8,
    pub pqc_pubkey_len: usize,
    pub leaf_layer_scalars_ptr: *const u8,
    /// Byte length of the flattened scalar blob (`N × 32`); not a scalar count.
    pub leaf_layer_scalars_len: usize,
}

#[must_use]
pub(super) fn map_verify_error(err: &shekyl_archival_retention::VerifyError) -> u8 {
    use shekyl_archival_retention::VerifyError;
    match *err {
        VerifyError::PathTooShallow => SHEKYL_ARCHIVAL_VERIFY_ERR_PATH_TOO_SHALLOW,
        VerifyError::LeafNotInOpening => SHEKYL_ARCHIVAL_VERIFY_ERR_LEAF_NOT_IN_OPENING,
        VerifyError::SubrootMismatch => SHEKYL_ARCHIVAL_VERIFY_ERR_SUBROOT_MISMATCH,
    }
}

pub(super) fn map_wire_error(_err: &WireError) -> u8 {
    SHEKYL_ARCHIVAL_VERIFY_ERR_WIRE
}

/// Map a `BondPostError` to the stable Rust↔C++ bond-post verdict code.
///
/// Part of the archival FFI contract: C++ classifies failures only by these
/// `u8` codes; the Rust verify body stays free of C-side string tables.
pub(super) fn map_bond_post_error(err: BondPostError) -> u8 {
    match err {
        BondPostError::PostKindNotJoinMarket => SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND,
        BondPostError::ShardSetCompactEmpty => SHEKYL_ARCHIVAL_BOND_POST_ERR_SHARD_SET_EMPTY,
        BondPostError::CompleteTreeWithShardIds => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_COMPLETE_TREE_WITH_SHARDS
        }
        BondPostError::BondDebitNonzero => SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_DEBIT_NONZERO,
        BondPostError::BothTermsNonzero => SHEKYL_ARCHIVAL_BOND_POST_ERR_BOTH_TERMS,
        BondPostError::BondFloorZero => SHEKYL_ARCHIVAL_BOND_POST_ERR_FLOOR_ZERO,
        BondPostError::FloorMismatch => SHEKYL_ARCHIVAL_BOND_POST_ERR_FLOOR_MISMATCH,
        BondPostError::RecordExists => SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_EXISTS,
        BondPostError::PostKindNotUnbond => SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_UNBOND,
        BondPostError::RecordMissing => SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_MISSING,
        BondPostError::NothingToUnbond => SHEKYL_ARCHIVAL_BOND_POST_ERR_NOTHING_TO_UNBOND,
        BondPostError::UnbondCreditNonzero => SHEKYL_ARCHIVAL_BOND_POST_ERR_UNBOND_CREDIT,
        BondPostError::UnbondHoldingsNotEmpty => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_UNBOND_HOLDINGS_NOT_EMPTY
        }
        BondPostError::UnbondFloorMismatch => SHEKYL_ARCHIVAL_BOND_POST_ERR_UNBOND_FLOOR_MISMATCH,
        BondPostError::NotFullUnbond => SHEKYL_ARCHIVAL_BOND_POST_ERR_NOT_FULL_UNBOND,
        BondPostError::DebitNotFullBalance => SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_NOT_FULL,
        BondPostError::CooldownNotElapsed => SHEKYL_ARCHIVAL_BOND_POST_ERR_COOLDOWN_NOT_ELAPSED,
        BondPostError::IntervalLogFull => SHEKYL_ARCHIVAL_BOND_POST_ERR_INTERVAL_LOG_FULL,
        BondPostError::SlashSettlementPending => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_SLASH_SETTLEMENT_PENDING
        }
        BondPostError::PostKindNotHoldingsUpdate => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_HOLDINGS_UPDATE
        }
        BondPostError::HoldingsUpdateOnCompleteTree => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ON_COMPLETE_TREE
        }
        BondPostError::HoldingsUpdatePostNotCompact => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_POST_NOT_COMPACT
        }
        BondPostError::HoldingsUpdateAddTerms => SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ADD_TERMS,
        BondPostError::HoldingsUpdateNotGoodStanding => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_GOOD_STANDING
        }
        BondPostError::HoldingsUpdateNotSingleAdd => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_SINGLE_ADD
        }
        BondPostError::HoldingsUpdateAddFloorMismatch => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ADD_FLOOR_MISMATCH
        }
        BondPostError::HoldingsUpdateDropTerms => SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_TERMS,
        BondPostError::HoldingsUpdateNotSingleDrop => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_SINGLE_DROP
        }
        BondPostError::HoldingsUpdateDropLastShard => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_LAST_SHARD
        }
        BondPostError::HoldingsUpdateDropFloorMismatch => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_FLOOR_MISMATCH
        }
        BondPostError::HoldingsUpdateDropWithinHorizon => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_WITHIN_HORIZON
        }
        BondPostError::HoldingsUpdateRecordNotBonded => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_RECORD_NOT_BONDED
        }
        BondPostError::PostKindNotRebond => SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_REBOND,
        BondPostError::RebondRecordFloorBroken => SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_RECORD_FLOOR,
        BondPostError::RebondOnCompleteTree => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_ON_COMPLETE_TREE
        }
        BondPostError::RebondPostNotCompact => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_POST_NOT_COMPACT
        }
        BondPostError::RebondNotSlashed => SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_NOT_SLASHED,
        BondPostError::RebondMultipleOpenIntervals => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_MULTIPLE_OPEN
        }
        BondPostError::RebondIntervalLogHeadroom => {
            SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_LOG_HEADROOM
        }
        BondPostError::RebondTerms => SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_TERMS,
        BondPostError::RebondNotSuperset => SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_NOT_SUPERSET,
    }
}

#[must_use]
pub(super) fn map_unbond_connect_error(e: UnbondConnectError) -> u8 {
    match e {
        UnbondConnectError::DebitZero => SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_DEBIT_ZERO,
        UnbondConnectError::DebitNotRecordTotal => {
            SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_DEBIT_NOT_RECORD_TOTAL
        }
        UnbondConnectError::RecordFloorInvariantBroken => {
            SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_RECORD_FLOOR_INVARIANT
        }
        UnbondConnectError::TotalBondedUnderflow => {
            SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_TOTAL_BONDED_UNDERFLOW
        }
        UnbondConnectError::IntervalLogFull => SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_INTERVAL_LOG_FULL,
    }
}

#[must_use]
pub(super) fn map_unbond_pop_error(e: UnbondPopError) -> u8 {
    match e {
        UnbondPopError::RecordNotExited => SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_RECORD_NOT_EXITED,
        UnbondPopError::MissingCleanClose => SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_MISSING_CLEAN_CLOSE,
        UnbondPopError::PreImageEmpty => SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_PRE_IMAGE_EMPTY,
        UnbondPopError::TotalBondedOverflow => {
            SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_TOTAL_BONDED_OVERFLOW
        }
    }
}
