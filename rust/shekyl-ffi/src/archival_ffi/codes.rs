// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared archival FFI verdict codes and error mappers.
//!
//! Domain modules may also define local codes next to their entry points.
//! C++ / `shekyl_ffi.h` mirror the literals (rule 25).

use std::ffi::CStr;

use shekyl_archival_retention::WireError;

/// Success.
pub const SHEKYL_ARCHIVAL_VERIFY_OK: u8 = 0;
/// Required pointer was null.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR: u8 = 1;
/// Vin payload failed structural decode.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_WIRE: u8 = 2;
// Code 6 (`ERR_LEAF_INDEX`) is RETIRED with code 7: the index it compared is
// derived, not transported (RF-D6). Unassigned, not reused.
// Code 7 (`ERR_REGISTRY_RK`) is RETIRED, not reusable: it reported a wire `R_k`
// disagreeing with the registry's, and RF-D6 took `R_k` off the wire. The
// number stays unassigned so an old log line cannot be misread as a new
// condition.

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
/// Retired-assigned: zero-money is `BondTerm::Unmoved` (Reinstate), not an
/// error. Number 5 stays so it cannot be reminted.
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
/// `Release` verify: `post_kind` is not `Release`.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_RELEASE: u8 = 11;
/// `Release` verify: no bond record exists for `P_canonical_id`.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_MISSING: u8 = 12;
/// `Release` verify: record's `bonded_total` is zero (nothing to release).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_NOTHING_TO_RELEASE: u8 = 13;
/// `Release` verify: `bond_credit` is non-zero on a debit path.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_RELEASE_CREDIT: u8 = 14;
/// `Release` verify: post-connect `bonded_total_atomic != bond_floor(holdings)`.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_RELEASE_FLOOR_MISMATCH: u8 = 15;
/// `Release` verify: post-connect `bonded_total_atomic != 0` (partial, not full exit).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_NOT_FULL_RELEASE: u8 = 16;
/// `Release` verify: `bond_debit` != the record's current `bonded_total`.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_NOT_FULL: u8 = 17;
/// `Release` verify: the release cooldown has not elapsed.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_COOLDOWN_NOT_ELAPSED: u8 = 18;
/// A shard/served-epoch array length would overflow the `from_raw_parts`
/// `isize::MAX` byte bound — a corrupted or hostile marshaled length.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_LEN_OVERFLOW: u8 = 19;
/// `Release` verify: a full exit must end at empty holdings, but the post-connect
/// descriptor is floor-zero only because its shard set is oversize/invalid.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_RELEASE_HOLDINGS_NOT_EMPTY: u8 = 20;
/// `Release` verify: the record's interval log is at the codec cap, so the
/// connect's clean interval-close could not append — reject at admission.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_INTERVAL_LOG_FULL: u8 = 21;
/// `Release` verify: the slash scheduler has not yet settled every epoch through
/// the record's last-served anchor (the one-block connect-ordering race guard).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_SLASH_SETTLEMENT_PENDING: u8 = 22;
/// The marshaled `bond_spend_pk` violates the §9.11 JoinMarket coupling:
/// missing/non-canonical length on JoinMarket, or present on any other kind.
/// Returned by the shared vin marshaler, so both entry points can return it —
/// the marshaler refuses to construct a vin the wire codec could not emit.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_SPEND_PK_COUPLING: u8 = 23;
// ── HoldingsUpdate verify codes 24–36 RETIRED 2026-09-20 (immutable-bond).
// Numbers stay assigned so an old log line cannot be misread as a new
// condition; no mapper arm produces them.
/// **RETIRED** — `HoldingsUpdate` kind deleted.
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
/// HoldingsUpdate-drop verify: dropping the last shard (use Release for a full exit).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_LAST_SHARD: u8 = 33;
/// HoldingsUpdate-drop verify: post bonded_total != bond_floor(post-holdings).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_FLOOR_MISMATCH: u8 = 34;
/// HoldingsUpdate-drop verify: the shard is within its bond_duration retention horizon.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_WITHIN_HORIZON: u8 = 35;
/// `HoldingsUpdate` verify: the record is not Bonded — zero collateral / no held
/// shards (P2B-7 Pin 1: `Bonded → Bonded`; an Exited or slash-emptied record
/// re-enters via JoinMarket/Reinstate, never a voluntary adjustment).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_RECORD_NOT_BONDED: u8 = 36;
/// `Reinstate` verify (gate-4 §3.4; P2B-9): the vin's post_kind is not Reinstate.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_REINSTATE: u8 = 37;
/// Reinstate verify: the record is CompleteTree (unrepresentable — demotion flips
/// the kind atomically with the interval append; belt).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_ON_COMPLETE_TREE: u8 = 38;
/// Reinstate verify: the vin's post-holdings are not ShardSetCompact.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_POST_NOT_COMPACT: u8 = 39;
/// Reinstate verify: no open bad interval — the record is not slashed.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_NOT_SLASHED: u8 = 40;
/// Reinstate verify: more than one open bad interval (P2B-9 Pin 5 coalescing
/// invariant broken — record corruption).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_MULTIPLE_OPEN: u8 = 41;
/// Reinstate verify: interval log lacks headroom (> 254 entries; Pin 6 reserves one
/// slot for the next slash + one for the Release clean close).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_LOG_HEADROOM: u8 = 42;
/// Reinstate verify: terms mismatch (debit or credit nonzero, or bonded_total
/// moved — a persona's bond is immutable; Reinstate is zero-money).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_TERMS: u8 = 43;
/// Reinstate verify: post-holdings do not equal the record's current holdings.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_HOLDINGS_CHANGED: u8 = 44;
/// **RETIRED — never returned.** Code 45 was the Reinstate verify-level oversize
/// belt (`REINSTATE_POST_OVERSIZE`), removed with the `ShardSet` newtype: an
/// oversize post is now unrepresentable in the vin's holdings, so no verify
/// produces it. The symbol stays **defined and reserved** (rather than
/// renumbering 46/47/48, or leaving a dangling name) so the Rust↔C++ code
/// contract is explicit and a stray/legacy 45 maps to a meaningful message.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_POST_OVERSIZE_RETIRED: u8 = 45;
/// Reinstate verify: the record's `bonded_total != bond_floor(record holdings)`
/// (floor-drifted record) — rejected at verify so the tx can never ride to the
/// connect fold's FATAL floor belt (tx rejection, not a chain halt).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_RECORD_FLOOR: u8 = 46;
/// Shared vin marshal: the vin's holdings shard count exceeds the wire codec
/// bound (`MAX_HOLDINGS_SHARDS`). The FFI marshal is a second decoder for the
/// same wire object, so it routes through `ShardSet::new` — an oversize set is
/// unrepresentable past the boundary for every post kind.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_COUNT_EXCEEDED: u8 = 47;
/// Shared vin marshal: the vin's holdings carry a duplicate shard id. Rejected
/// at the same `ShardSet::new` boundary as the count cap ("a set on the wire").
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_DUPLICATE_SHARD: u8 = 48;

/// Cold authority (`shekyl_archival_cold_authority_pin`): the bond record
/// commits no canonical-length `bond_spend_pk`, so it authorizes **no** debit.
/// Fail closed — never an identity-key fallback.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_AUTH_NO_RECORD_KEY: u8 = 49;
/// Cold authority: the presented `pqc_auths` key is not the record's
/// committed `bond_spend_pk` (identity-key or foreign-key authorization).
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_AUTH_KEY_MISMATCH: u8 = 50;
/// Cold authority: the gate was invoked for a `(post_kind, bond_debit)` that
/// `requires_cold_authority` excludes. The calling arm and the predicate
/// disagree about this kind — an implementation error, never the sender's
/// form, so it classifies as an internal failure. Unreachable through a
/// correct caller; exists so a new arm cannot silently authorize hot.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_NOT_COLD_AUTHORITY_POST: u8 = 51;

/// JoinMarket vin marshal / verify: the endpoint violates its coupling
/// (`EU-D3`) — absent, not 32 bytes, or the all-zero key (the bond record
/// encodes "no endpoint" as zero, so a zero key is refused as absent). The
/// other kinds have no endpoint slot, so a coupling on them is unrepresentable.
pub const SHEKYL_ARCHIVAL_BOND_POST_ERR_ENDPOINT_COUPLING: u8 = 52;

/// Stable operator strings for the bond-post C-ABI code space.
///
/// **This is THE table.** NUL-terminated so C++ can hand these to
/// `MERROR_VER` without allocating. ASCII-only: they cross into consoles
/// whose encoding we do not control.
#[must_use]
pub const fn bond_post_err_cstr(code: u8) -> &'static CStr {
    match code {
        SHEKYL_ARCHIVAL_BOND_POST_OK => c"ok",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_NULL_PTR => c"null shard id pointer",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND => c"post_kind not JoinMarket",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_SHARD_SET_EMPTY => c"ShardSetCompact requires shards",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_COMPLETE_TREE_WITH_SHARDS => {
            c"CompleteTree must not carry shard ids"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_DEBIT_NONZERO => c"JoinMarket bond_debit must be zero",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_BOTH_TERMS => c"bond_credit and bond_debit both non-zero",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_FLOOR_ZERO => c"bond_floor is zero",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_FLOOR_MISMATCH => {
            c"bonded_total/bond_credit must equal bond_floor"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_EXISTS => c"bond record already exists",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_KIND => c"invalid holdings_kind",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_RELEASE => c"post_kind not Release",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_MISSING => c"Release requires an existing bond record",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_NOTHING_TO_RELEASE => c"record bonded_total is zero",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_RELEASE_CREDIT => c"Release bond_credit must be zero",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_RELEASE_FLOOR_MISMATCH => {
            c"post-connect bonded_total must equal bond_floor(holdings)"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_NOT_FULL_RELEASE => {
            c"Release is a full exit: post-connect bonded_total must be zero"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_NOT_FULL => {
            c"bond_debit must equal the record's current bonded_total"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_COOLDOWN_NOT_ELAPSED => c"release cooldown has not elapsed",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_LEN_OVERFLOW => c"marshaled array length overflow",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_RELEASE_HOLDINGS_NOT_EMPTY => {
            c"full exit must end at empty holdings"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_INTERVAL_LOG_FULL => c"record interval log is full",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_SLASH_SETTLEMENT_PENDING => {
            c"slash scheduler has not settled every epoch through the last-served anchor"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_SPEND_PK_COUPLING => {
            c"bond_spend_pk violates the JoinMarket coupling (missing/non-canonical on JoinMarket, or present on another kind)"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_ENDPOINT_COUPLING => {
            c"JoinMarket endpoint violates its coupling (missing, not 32 bytes, or the all-zero key)"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_HOLDINGS_UPDATE => {
            c"post_kind is not HoldingsUpdate"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ON_COMPLETE_TREE => {
            c"HoldingsUpdate on a CompleteTree record (no shard set to change)"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_POST_NOT_COMPACT => {
            c"HoldingsUpdate post holdings are not ShardSetCompact"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ADD_TERMS => {
            c"HoldingsUpdate-add terms are not exactly +FLOOR credit / no debit"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_GOOD_STANDING => {
            c"HoldingsUpdate-add on a record not good_through the current epoch"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_SINGLE_ADD => {
            c"HoldingsUpdate-add is not exactly one added shard"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ADD_FLOOR_MISMATCH => {
            c"HoldingsUpdate-add post bonded_total != bond_floor(post) / current + FLOOR"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_TERMS => {
            c"HoldingsUpdate-drop terms are not exactly -FLOOR debit / no credit"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_SINGLE_DROP => {
            c"HoldingsUpdate-drop must remove exactly one shard, and it must be the shard whose per-shard facts were marshaled"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_LAST_SHARD => {
            c"HoldingsUpdate-drop would empty the shard set (a full exit is Release)"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_FLOOR_MISMATCH => {
            c"HoldingsUpdate-drop post bonded_total != bond_floor(post) / current - FLOOR"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_WITHIN_HORIZON => {
            c"HoldingsUpdate-drop before the shard's retention-commitment horizon elapsed"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_REINSTATE => c"post_kind is not Reinstate",
        SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_ON_COMPLETE_TREE => {
            c"Reinstate on a CompleteTree record (demotion flips the kind; unrepresentable)"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_POST_NOT_COMPACT => {
            c"Reinstate post-holdings are not ShardSetCompact"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_NOT_SLASHED => {
            c"Reinstate requires an open bad interval (the record is not slashed)"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_MULTIPLE_OPEN => {
            c"record carries multiple open bad intervals (coalescing invariant broken)"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_LOG_HEADROOM => {
            c"record interval log lacks Reinstate headroom (must leave a slot for the next slash and the Release clean close)"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_TERMS => {
            c"Reinstate terms mismatch (debit or credit nonzero, or bonded_total moved)"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_HOLDINGS_CHANGED => {
            c"Reinstate post-holdings do not equal the record's current holdings (a persona's bond is immutable)"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_POST_OVERSIZE_RETIRED => {
            c"retired Reinstate oversize code (45) — never returned; oversize is now unrepresentable in the vin's ShardSet holdings"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_REINSTATE_RECORD_FLOOR => {
            c"record bonded_total != bond_floor(record holdings) (floor-drifted record)"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_COUNT_EXCEEDED => {
            c"vin holdings shard count exceeds the wire codec bound"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_DUPLICATE_SHARD => {
            c"vin holdings carry a duplicate shard id (a set on the wire)"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_RECORD_NOT_BONDED => {
            c"HoldingsUpdate requires a Bonded record (an Exited or slash-emptied record re-enters via JoinMarket/Reinstate)"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_AUTH_NO_RECORD_KEY => {
            c"bond record commits no bond_spend_pk; it authorizes no debit"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_AUTH_KEY_MISMATCH => {
            c"pqc auth key is not the record's committed bond_spend_pk"
        }
        SHEKYL_ARCHIVAL_BOND_POST_ERR_NOT_COLD_AUTHORITY_POST => {
            c"cold-authority gate invoked for a post that requires none (the calling arm and requires_cold_authority disagree)"
        }
        _ => c"unknown bond-post verify code",
    }
}

// ── HoldingsUpdate add/drop connect + pop fold codes (gate-4 §4.4) ───────────

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

// ── ABI pins, mirrored by `static_assert`s in `src/shekyl/shekyl_ffi.h` ──────
//
// `PC-D3` added `prev_block_hash` MID-STRUCT, and a mid-struct addition is the
// one ABI change that fails silently in both directions: if the C++ header
// lags, C++ builds the shorter struct and Rust reads stack residue past its
// end. Residue is not all-zeros, so the `ERR_PREVHASH_UNPOPULATED` guard --
// written for exactly this hazard -- stays quiet, and the leaf index derives
// from garbage. The symptom is a path mismatch attributed to the prover: a
// consensus-visible verdict produced by a local wiring defect.
//
// Offsets rather than only size, because a field MOVING preserves size. These
// four are platform-independent: every field at or before `segment_leaf_count`
// is fixed-width, so no pointer or `usize` participates. Size is deliberately
// not pinned here -- it varies with pointer width, and the offsets already
// cover the failure.
const _: () = assert!(core::mem::offset_of!(ShekylArchivalVerifyCtx, current_height) == 0);
const _: () = assert!(core::mem::offset_of!(ShekylArchivalVerifyCtx, block_hash_at_seal) == 16);
const _: () = assert!(core::mem::offset_of!(ShekylArchivalVerifyCtx, prev_block_hash) == 48);
const _: () = assert!(core::mem::offset_of!(ShekylArchivalVerifyCtx, segment_leaf_count) == 112);

pub(super) fn map_wire_error(_err: &WireError) -> u8 {
    SHEKYL_ARCHIVAL_VERIFY_ERR_WIRE
}
