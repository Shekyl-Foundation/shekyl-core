// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Archival serve-credit verification FFI (`ARCHIVAL_RETENTION_GATE2.md` §5.3).
//!
//! Wraps `shekyl-archival-retention` for the C++ consensus hook. Bond posture,
//! shard-registry geometry, and LMDB bit writes stay in the daemon; this module
//! covers challenge replay, path verify, hybrid signature, and credit-window timing.

use std::io::Cursor;

use shekyl_archival_retention::{
    as_of_e_served_work, capped_work_milli, challenge_fire_height, challenge_leaf_chunk_bounds,
    challenge_seal_height, claim_window_floor, claimed_epochs_check_and_set,
    emission_block_claims_unique, emission_vin_verify, emission_vin_verify_auth,
    emission_vin_verify_backing, emission_vin_verify_claims, epoch_close_compute,
    epoch_close_due_at_height, epoch_close_height, frozen_segment_count, good_through,
    p_canonical_id_from_hybrid_pubkey, prune_below_epoch_at_height, serve_credit_epoch_ok,
    settlement_epoch_at_height, verify_bond_post_ct_balance, verify_join_market_bond_post,
    verify_leaf_index, verify_segment_path, ArchivalBondPostVin, ArchivalRewardEmissionVin,
    ArchivalServeCreditResponse, BadInterval, BandedCurveParams, BondCtBalanceError, BondPostError,
    BondPostKind, BondTerm, ClaimantBondRecord, ClaimedEpochsError, CreditPair,
    EmissionEpochSource, EmissionVerifyContext, EmissionVerifyError, EpochCloseBond,
    EpochCloseInputs, EpochCloseShard, HoldingsDescriptor, HoldingsKind, KCover, RewardCommit,
    WireError, ARCHIVAL_REWARD_AGE_WEIGHT_MILLI, ARCHIVAL_REWARD_PLATEAU_VALUE_MILLI,
    ARCHIVAL_REWARD_PLATEAU_WORK_MILLI, CHALLENGE_RESOLUTION_BLOCKS, MAX_CLAIMED_EPOCH_ENTRIES,
    MAX_CLAIM_AGE_W, SETTLEMENT_EPOCH_BLOCKS,
};
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, HybridPublicKey, SignatureScheme};
use shekyl_fcmp::SCALARS_PER_LEAF;
use shekyl_units::{AtomicUnits, NonZeroAtomicUnits};

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
/// `leaf_index_in_segment` does not match epoch challenge index.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_LEAF_INDEX: u8 = 6;
/// Vin `segment_subroot_rk` does not match registry value in context.
pub const SHEKYL_ARCHIVAL_VERIFY_ERR_REGISTRY_RK: u8 = 7;
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

/// Context supplied by consensus after bond/registry LMDB reads (gate-2 §5.3 steps 2, 6–7).
#[repr(C)]
pub struct ShekylArchivalVerifyCtx {
    pub current_height: u64,
    pub settlement_epoch: u64,
    pub block_hash_at_seal: [u8; 32],
    pub registry_segment_subroot_rk: [u8; 32],
    pub segment_leaf_count: u64,
    pub pqc_pubkey_ptr: *const u8,
    pub pqc_pubkey_len: usize,
    pub leaf_layer_scalars_ptr: *const u8,
    /// Byte length of the flattened scalar blob (`N × 32`); not a scalar count.
    pub leaf_layer_scalars_len: usize,
}

#[must_use]
pub fn settlement_epoch_open_height(e: u64) -> u64 {
    e.saturating_mul(SETTLEMENT_EPOCH_BLOCKS)
}

#[must_use]
pub fn settlement_epoch_close_height(e: u64) -> u64 {
    settlement_epoch_open_height(e.saturating_add(1)).saturating_sub(1)
}

#[must_use]
pub fn settlement_epoch_slash_deadline_height(e: u64) -> u64 {
    settlement_epoch_close_height(e).saturating_add(CHALLENGE_RESOLUTION_BLOCKS)
}

fn map_verify_error(err: &shekyl_archival_retention::VerifyError) -> u8 {
    use shekyl_archival_retention::VerifyError;
    match *err {
        VerifyError::PathTooShallow => SHEKYL_ARCHIVAL_VERIFY_ERR_PATH_TOO_SHALLOW,
        VerifyError::LeafNotInOpening => SHEKYL_ARCHIVAL_VERIFY_ERR_LEAF_NOT_IN_OPENING,
        VerifyError::SubrootMismatch => SHEKYL_ARCHIVAL_VERIFY_ERR_SUBROOT_MISMATCH,
        VerifyError::LeafIndexMismatch { .. } => SHEKYL_ARCHIVAL_VERIFY_ERR_LEAF_INDEX,
    }
}

fn map_wire_error(_err: &WireError) -> u8 {
    SHEKYL_ARCHIVAL_VERIFY_ERR_WIRE
}

/// Recompute `P_canonical_id` from hybrid pubkey bytes (gate-4 §3.4 / emission §6.1).
///
/// Returns `1` on success and writes 32 bytes to `out_p_id`; `0` on null/short buffer.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_p_canonical_id_from_pubkey(
    hybrid_pubkey_ptr: *const u8,
    hybrid_pubkey_len: usize,
    out_p_id: *mut u8,
) -> u8 {
    if hybrid_pubkey_ptr.is_null() || out_p_id.is_null() || hybrid_pubkey_len == 0 {
        return 0;
    }
    let pubkey = unsafe { std::slice::from_raw_parts(hybrid_pubkey_ptr, hybrid_pubkey_len) };
    let pid = p_canonical_id_from_hybrid_pubkey(pubkey);
    unsafe {
        // `PCanonicalId` is the domain newtype; take the raw bytes at the C edge.
        std::ptr::copy_nonoverlapping(pid.as_bytes().as_ptr(), out_p_id, 32);
    }
    1
}

/// Overflow-checked sum of plaintext output amounts (rule 20: integer
/// arithmetic on untrusted tx amounts lives behind the FFI, single-sourced so
/// the emission reward total cannot drift between the check_tx_inputs operand
/// and the CT-balance shape check). Writes the sum to `*out_sum` and returns
/// `0` on success, `1` on `u64` overflow or invalid arguments — the caller must
/// reject the tx on any non-zero return. `amounts_ptr` may be null iff `len == 0`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_checked_sum_amounts(
    amounts_ptr: *const u64,
    len: usize,
    out_sum: *mut u64,
) -> u8 {
    if out_sum.is_null() {
        return 1;
    }
    if len == 0 {
        unsafe { *out_sum = 0 };
        return 0;
    }
    if amounts_ptr.is_null() {
        return 1;
    }
    let amounts = unsafe { std::slice::from_raw_parts(amounts_ptr, len) };
    let mut sum: u64 = 0;
    for &a in amounts {
        match sum.checked_add(a) {
            Some(s) => sum = s,
            None => return 1,
        }
    }
    unsafe { *out_sum = sum };
    0
}

/// First block of settlement epoch `E` (`H_open`).
#[no_mangle]
pub extern "C" fn shekyl_archival_epoch_open_height(settlement_epoch: u64) -> u64 {
    settlement_epoch_open_height(settlement_epoch)
}

/// Last block of settlement epoch `E` (`H_close`, credit deadline).
#[no_mangle]
pub extern "C" fn shekyl_archival_epoch_close_height(settlement_epoch: u64) -> u64 {
    settlement_epoch_close_height(settlement_epoch)
}

/// The close-**processing** boundary for settlement epoch `E` — `(E+1)·SEB`,
/// the height `process_archival_epoch_close_at_height` runs the close at and
/// the `close_block_height` shard-age operand the close compute received.
/// Single-sources `consensus_state::epoch_close_height` so the emission
/// snapshot gather does not re-derive the boundary by hand (that function's
/// own pinned rationale). Returns 0 for the overflowing (impossible) epoch;
/// callers treat 0 as invalid.
#[no_mangle]
pub extern "C" fn shekyl_archival_epoch_close_processing_height(settlement_epoch: u64) -> u64 {
    epoch_close_height(settlement_epoch).unwrap_or(0)
}

/// Slash grace after `H_close` (`CHALLENGE_RESOLUTION_BLOCKS`).
#[no_mangle]
pub extern "C" fn shekyl_archival_challenge_resolution_blocks() -> u64 {
    CHALLENGE_RESOLUTION_BLOCKS
}

/// Last block before slash may fire for settlement epoch `E` (`H_slash_deadline`).
#[no_mangle]
pub extern "C" fn shekyl_archival_epoch_slash_deadline_height(settlement_epoch: u64) -> u64 {
    settlement_epoch_slash_deadline_height(settlement_epoch)
}

/// Seal height for epoch open (`H_seal` in gate-2 §3.4).
#[no_mangle]
pub extern "C" fn shekyl_archival_challenge_seal_height(h_open: u64) -> u64 {
    challenge_seal_height(h_open)
}

/// Beacon fire height `H_fire` for `(P, shard, E)` (gate-2 §3.4).
#[no_mangle]
pub extern "C" fn shekyl_archival_challenge_fire_height(
    h_open: u64,
    h_close: u64,
    block_hash_at_seal: *const u8,
    p_id: *const u8,
    shard_id: u64,
    settlement_epoch: u64,
) -> u64 {
    if block_hash_at_seal.is_null() || p_id.is_null() {
        return 0;
    }
    let seal_hash = unsafe { std::slice::from_raw_parts(block_hash_at_seal, 32) };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(seal_hash);
    let pid = unsafe { std::slice::from_raw_parts(p_id, 32) };
    let mut p = [0u8; 32];
    p.copy_from_slice(pid);
    challenge_fire_height(h_open, h_close, &hash, &p, shard_id, settlement_epoch)
}

/// Frozen-segment count at a curve-tree leaf count — the first-crossing
/// rule (`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` §1/§5.1).
///
/// Both daemon hooks (the `add_block` freeze processor and the
/// `pop_block` revert) call this; C++ never performs the boundary
/// division inline (division-one-site tripwire, pipeline doc §8).
#[no_mangle]
pub extern "C" fn shekyl_archival_frozen_segment_count(leaf_count: u64) -> u64 {
    frozen_segment_count(leaf_count)
}

/// Leaf-layer chunk backing challenged index `leaf_index_in_segment` of
/// frozen shard `shard_id`, as a global position range over the daemon's
/// leaf table (pipeline doc §6.2). Returns 1 and writes the bounds; 0
/// (no write) when the index is out of segment range, the position
/// overflows, or an out pointer is null — verifier-input rejection, not
/// abort.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_challenge_leaf_chunk_bounds(
    shard_id: u64,
    leaf_index_in_segment: u64,
    out_first_leaf_position: *mut u64,
    out_leaf_count: *mut u64,
) -> u8 {
    if out_first_leaf_position.is_null() || out_leaf_count.is_null() {
        return 0;
    }
    match challenge_leaf_chunk_bounds(shard_id, leaf_index_in_segment) {
        Some(bounds) => {
            unsafe {
                *out_first_leaf_position = bounds.first_leaf_position;
                *out_leaf_count = bounds.leaf_count;
            }
            1
        }
        None => 0,
    }
}

/// Verify vin payload bytes (after the type tag) for steps 4–9 of gate-2 §5.3.
///
/// `vin_payload` is the C++ `txin_archival_serve_credit_response` body only
/// (no leading `0x04` tag). Bond posture, market, and idempotency are C++-side.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_verify_serve_credit_vin(
    vin_payload_ptr: *const u8,
    vin_payload_len: usize,
    ctx_ptr: *const ShekylArchivalVerifyCtx,
) -> u8 {
    if vin_payload_ptr.is_null() || ctx_ptr.is_null() {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR;
    }
    let ctx = unsafe { &*ctx_ptr };
    if ctx.segment_leaf_count == 0 {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_ZERO_GEOMETRY;
    }
    if ctx.pqc_pubkey_ptr.is_null() || ctx.pqc_pubkey_len == 0 {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR;
    }
    if ctx.leaf_layer_scalars_ptr.is_null() || ctx.leaf_layer_scalars_len == 0 {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR;
    }
    if !ctx.leaf_layer_scalars_len.is_multiple_of(32) {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_SCALAR_SHAPE;
    }
    let scalar_count = ctx.leaf_layer_scalars_len / 32;
    if !scalar_count.is_multiple_of(SCALARS_PER_LEAF) {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_SCALAR_SHAPE;
    }

    let payload = unsafe { std::slice::from_raw_parts(vin_payload_ptr, vin_payload_len) };
    let response = match ArchivalServeCreditResponse::read_payload_exact(&mut Cursor::new(payload))
    {
        Ok(r) => r,
        Err(e) => return map_wire_error(&e),
    };

    if response.settlement_epoch != ctx.settlement_epoch {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_EPOCH_MISMATCH;
    }
    if response.segment_subroot_rk != ctx.registry_segment_subroot_rk {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_REGISTRY_RK;
    }

    if let Err(e) = verify_leaf_index(
        response.leaf_index_in_segment,
        &response.p_canonical_id,
        response.shard_id,
        response.settlement_epoch,
        ctx.segment_leaf_count,
    ) {
        return map_verify_error(&e);
    }

    let h_open = settlement_epoch_open_height(response.settlement_epoch);
    let h_close = settlement_epoch_close_height(response.settlement_epoch);
    let h_fire = challenge_fire_height(
        h_open,
        h_close,
        &ctx.block_hash_at_seal,
        &response.p_canonical_id,
        response.shard_id,
        response.settlement_epoch,
    );

    if ctx.current_height <= h_fire {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_FIRE_NOT_REACHED;
    }
    if ctx.current_height > h_close {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_CREDIT_DEADLINE;
    }

    let mut scalars = Vec::with_capacity(scalar_count);
    let flat = unsafe {
        std::slice::from_raw_parts(ctx.leaf_layer_scalars_ptr, ctx.leaf_layer_scalars_len)
    };
    for chunk in flat.chunks_exact(32) {
        let mut s = [0u8; 32];
        s.copy_from_slice(chunk);
        scalars.push(s);
    }

    if let Err(e) = verify_segment_path(
        &response.leaf_bytes,
        &scalars,
        &response.path,
        &response.segment_subroot_rk,
    ) {
        return map_verify_error(&e);
    }

    let preimage = response.signature_preimage();
    let pubkey = unsafe { std::slice::from_raw_parts(ctx.pqc_pubkey_ptr, ctx.pqc_pubkey_len) };
    let pk = match HybridPublicKey::from_canonical_bytes(pubkey) {
        Ok(pk) => pk,
        Err(_) => return SHEKYL_ARCHIVAL_VERIFY_ERR_PQC_DESER,
    };
    if HybridEd25519MlDsa
        .verify(&pk, &preimage, &response.hybrid_signature)
        .is_err()
    {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_PQC_VERIFY;
    }

    SHEKYL_ARCHIVAL_VERIFY_OK
}

fn map_bond_post_error(err: BondPostError) -> u8 {
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
    }
}

fn holdings_kind_from_u8(kind: u8) -> Result<HoldingsKind, u8> {
    HoldingsKind::from_u8(kind).map_err(|_| SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_KIND)
}

/// Verify JoinMarket bond-post semantics after C++ hybrid-pubkey and `P_id` checks.
///
/// Hybrid pubkey bounds and `p_canonical_id` hint recompute stay in C++ consensus glue.
/// `record_exists` is `1` when LMDB already has a bond record for this `P_id`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_verify_join_market_bond_post(
    post_kind: u8,
    holdings_kind: u8,
    shard_ids_ptr: *const u64,
    shard_ids_len: usize,
    bonded_total_atomic: u64,
    bond_credit: u64,
    bond_debit: u64,
    record_exists: u8,
) -> u8 {
    if shard_ids_len > 0 && shard_ids_ptr.is_null() {
        return SHEKYL_ARCHIVAL_BOND_POST_ERR_NULL_PTR;
    }
    let holdings_kind = match holdings_kind_from_u8(holdings_kind) {
        Ok(k) => k,
        Err(code) => return code,
    };
    let post_kind = match BondPostKind::from_u8(post_kind) {
        Ok(k) => k,
        Err(_) => return SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND,
    };
    let shard_ids: Vec<u64> = if shard_ids_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(shard_ids_ptr, shard_ids_len) }.to_vec()
    };
    let vin = ArchivalBondPostVin {
        hybrid_public_key: Vec::new(),
        p_canonical_id: [0u8; 32],
        post_kind,
        holdings: HoldingsDescriptor {
            kind: holdings_kind,
            shard_ids,
        },
        bonded_total_atomic,
        bond_credit,
        bond_debit,
    };
    match verify_join_market_bond_post(&vin, record_exists != 0) {
        Ok(()) => SHEKYL_ARCHIVAL_BOND_POST_OK,
        Err(e) => map_bond_post_error(e),
    }
}

/// Returns `1` when `settlement_epoch >= join_settlement_epoch + 1` (gate-4 §2.2 `E_first` lower bound).
#[no_mangle]
pub extern "C" fn shekyl_archival_serve_credit_epoch_ok(
    settlement_epoch: u64,
    join_settlement_epoch: u64,
) -> u8 {
    u8::from(serve_credit_epoch_ok(
        settlement_epoch,
        join_settlement_epoch,
    ))
}

/// `good_through(P, E)` from bond fields (ARCHIVAL_CONSENSUS_STATE.md §3.4 interval semantics).
///
/// `bad_intervals_ptr` is `2 × bad_intervals_len` `u64` values — flattened
/// `(start_epoch, end_exclusive)` pairs. The buffer is typed (`*const u64`),
/// so no byte-order applies; callers pass in-memory `u64`s, not serialized
/// bytes. Returns `0` (fail-closed) on a null pointer with nonzero length or
/// on pair-count overflow.
///
/// # Safety
///
/// When `bad_intervals_len > 0`, `bad_intervals_ptr` must address
/// `2 × bad_intervals_len` valid `u64`s for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_good_through(
    join_settlement_epoch: u64,
    settlement_epoch: u64,
    bad_intervals_ptr: *const u64,
    bad_intervals_len: usize,
) -> u8 {
    let Some(bad) = (unsafe { gather_bad_intervals(bad_intervals_ptr, bad_intervals_len) }) else {
        return 0;
    };
    u8::from(good_through(join_settlement_epoch, settlement_epoch, &bad))
}

/// Settlement epoch containing `block_height` (bond-connect join epoch derivation).
#[no_mangle]
pub extern "C" fn shekyl_archival_settlement_epoch_at_height(block_height: u64) -> u64 {
    settlement_epoch_at_height(block_height)
}

/// Returns `1` and writes the settlement epoch whose close is processed at
/// `block_height`; `0` (no write) at height 0, non-boundary heights, or null out.
///
/// # Safety
///
/// `out_settlement_epoch` must be a valid writable `u64` pointer or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_epoch_close_due(
    block_height: u64,
    out_settlement_epoch: *mut u64,
) -> u8 {
    if out_settlement_epoch.is_null() {
        return 0;
    }
    match epoch_close_due_at_height(block_height) {
        Some(epoch) => {
            unsafe { *out_settlement_epoch = epoch };
            1
        }
        None => 0,
    }
}

/// The oldest still-claimable settlement epoch for `current_settled_epoch` —
/// a thin delegate to [`claim_window_floor`], the **single source of the
/// claim-window boundary** (`claimed_epochs.rs`). Exposed for the emission
/// claim-source RPC handler so the daemon-side window derivation resolves
/// through the one landed definition rather than an inline `settled − W`
/// copy (`EMISSION_CLAIM_BUILDER.md` §2 step 1's consumption-not-re-derivation
/// pin, applied daemon-side).
#[no_mangle]
pub extern "C" fn shekyl_archival_claim_window_floor(current_settled_epoch: u64) -> u64 {
    claim_window_floor(current_settled_epoch)
}

/// Returns `1` and writes the prune horizon (`tip_epoch − MAX_CLAIM_AGE_W`) when the
/// chain is older than the claim window at `block_height`; `0` (no write) otherwise.
///
/// # Safety
///
/// `out_prune_below_epoch` must be a valid writable `u64` pointer or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_prune_below_epoch(
    block_height: u64,
    out_prune_below_epoch: *mut u64,
) -> u8 {
    if out_prune_below_epoch.is_null() {
        return 0;
    }
    match prune_below_epoch_at_height(block_height, MAX_CLAIM_AGE_W) {
        Some(below) => {
            unsafe { *out_prune_below_epoch = below };
            1
        }
        None => 0,
    }
}

/// Epoch-close computation succeeded.
pub const SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK: u8 = 0;
/// A required pointer was null (or null with nonzero length).
pub const SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR: u8 = 1;
/// A per-bond interval pair count overflowed `usize`.
pub const SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_LEN_OVERFLOW: u8 = 2;
/// A credit pair referenced a bond/shard index outside the gather arrays.
pub const SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE: u8 = 3;

/// One gathered bond for `shekyl_archival_epoch_close_compute`.
///
/// Layout must match `struct shekyl_archival_epoch_close_bond` in `shekyl_ffi.h`.
///
/// Carries no holdings descriptor (WS-1): the held-and-served set is sourced
/// solely from the serve-credit ledger rows the gather passes as credit
/// pairs, so tip holdings never cross into the work channel.
#[repr(C)]
pub struct ShekylArchivalEpochCloseBond {
    pub join_settlement_epoch: u64,
    /// Flattened `(start_epoch, end_exclusive)` pairs; `2 × bad_intervals_len` u64s.
    pub bad_intervals_ptr: *const u64,
    /// Pair count (not u64 count).
    pub bad_intervals_len: usize,
    pub is_foundation_complete_tree: u8,
}

/// One gathered shard-registry row for `shekyl_archival_epoch_close_compute`.
///
/// Layout must match `struct shekyl_archival_epoch_close_shard` in `shekyl_ffi.h`.
#[repr(C)]
pub struct ShekylArchivalEpochCloseShard {
    pub shard_id: u64,
    pub freeze_height: u64,
    /// `0` when no frozen segment row exists (shard age is then zero).
    pub has_segment: u8,
}

/// One serve-credit row as indices into the bond/shard gather arrays.
///
/// Layout must match `struct shekyl_archival_credit_pair` in `shekyl_ffi.h`.
#[repr(C)]
pub struct ShekylArchivalCreditPair {
    pub bond_idx: usize,
    pub shard_idx: usize,
}

/// Owned decode of the as-of-`E` gather arrays, shared by
/// `shekyl_archival_epoch_close_compute` and
/// `shekyl_archival_emission_epoch_work`. One decoder for both consumers of
/// the frozen gather (WS-1 single sourcing, `REWARD_EMISSION_E3_GATING_ROUND.md`
/// §5.5): close and verify cannot diverge on marshaling semantics because
/// there is only one marshaling path to diverge from.
struct DecodedEpochRows {
    joins: Vec<u64>,
    completes: Vec<bool>,
    bad: Vec<Vec<BadInterval>>,
    shards: Vec<EpochCloseShard>,
    pairs: Vec<CreditPair>,
}

impl DecodedEpochRows {
    fn bonds(&self) -> Vec<EpochCloseBond<'_>> {
        self.joins
            .iter()
            .zip(&self.completes)
            .zip(&self.bad)
            .map(|((&join, &complete), bad)| EpochCloseBond {
                join_settlement_epoch: join,
                is_foundation_complete_tree: complete,
                bad_intervals: bad,
            })
            .collect()
    }
}

/// # Safety
///
/// Pointers must satisfy their stated lengths for the duration of the call,
/// including each bond's interval buffer per its embedded lengths.
unsafe fn decode_epoch_rows(
    bonds_ptr: *const ShekylArchivalEpochCloseBond,
    bonds_len: usize,
    shards_ptr: *const ShekylArchivalEpochCloseShard,
    shards_len: usize,
    credit_pairs_ptr: *const ShekylArchivalCreditPair,
    credit_pairs_len: usize,
) -> Result<DecodedEpochRows, u8> {
    if (bonds_ptr.is_null() && bonds_len > 0)
        || (shards_ptr.is_null() && shards_len > 0)
        || (credit_pairs_ptr.is_null() && credit_pairs_len > 0)
    {
        return Err(SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR);
    }

    let raw_bonds: &[ShekylArchivalEpochCloseBond] = if bonds_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(bonds_ptr, bonds_len) }
    };
    let raw_shards: &[ShekylArchivalEpochCloseShard] = if shards_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(shards_ptr, shards_len) }
    };
    let raw_pairs: &[ShekylArchivalCreditPair] = if credit_pairs_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(credit_pairs_ptr, credit_pairs_len) }
    };

    let mut joins = Vec::with_capacity(raw_bonds.len());
    let mut completes = Vec::with_capacity(raw_bonds.len());
    let mut bad = Vec::with_capacity(raw_bonds.len());
    for bond in raw_bonds {
        let Some(intervals) =
            (unsafe { gather_bad_intervals(bond.bad_intervals_ptr, bond.bad_intervals_len) })
        else {
            return Err(if bond.bad_intervals_ptr.is_null() {
                SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR
            } else {
                SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_LEN_OVERFLOW
            });
        };
        joins.push(bond.join_settlement_epoch);
        completes.push(bond.is_foundation_complete_tree != 0);
        bad.push(intervals);
    }

    let shards: Vec<EpochCloseShard> = raw_shards
        .iter()
        .map(|s| EpochCloseShard {
            shard_id: s.shard_id,
            has_segment: s.has_segment != 0,
            freeze_height: s.freeze_height,
        })
        .collect();
    let pairs: Vec<CreditPair> = raw_pairs
        .iter()
        .map(|p| CreditPair {
            bond_idx: p.bond_idx,
            shard_idx: p.shard_idx,
        })
        .collect();

    Ok(DecodedEpochRows {
        joins,
        completes,
        bad,
        shards,
        pairs,
    })
}

/// Decode a flattened `(start, end_exclusive)` interval buffer; `None` on
/// null-with-length or pair-count overflow.
unsafe fn gather_bad_intervals(ptr: *const u64, pair_len: usize) -> Option<Vec<BadInterval>> {
    if pair_len == 0 {
        return Some(Vec::new());
    }
    if ptr.is_null() {
        return None;
    }
    let flat_len = pair_len.checked_mul(2)?;
    let flat = unsafe { std::slice::from_raw_parts(ptr, flat_len) };
    Some(
        flat.chunks_exact(2)
            .map(|pair| BadInterval {
                start_epoch: pair[0],
                end_exclusive: pair[1],
            })
            .collect(),
    )
}

/// Full epoch-close consensus computation (ARCHIVAL_CONSENSUS_STATE.md §3.3, §3.5).
///
/// The daemon gathers raw LMDB rows — distinct credit-bearing bonds, the shards
/// they credited, and the credit pairs — and receives `R_market` per shard plus
/// the finalized `Σwork(E)` milli value. All consensus arithmetic (membership,
/// counting, age weighting, scarcity, curve, saturation) runs in
/// `shekyl-archival-retention` against pinned `consensus_constants.json` values;
/// C++ performs storage orchestration only (`40-ffi-discipline.mdc` coarse-call rule).
///
/// `frozen_shard_count` is the M1 reward-gate input
/// (`ARCHIVAL_REWARD_GATE_M1.md` §1.1): the segment-table count at
/// `H_close(E)`, produced by the C++ gather's single
/// `count_frozen_shards_at_close` helper (`freeze_height ≤ H_close(E)`,
/// equality counts, decode failure aborts loudly) inside the close's write
/// transaction. The `K_COVER` threshold itself is threaded here through the
/// PF-6a `KCover::consensus()` capability constructor — the only production
/// path to a threshold value — and the comparison lives only in
/// `epoch_close_compute`.
///
/// `out_r_market_ptr` must address `shards_len` writable `u64`s; outputs are
/// zeroed before computation so a failure never leaves stale values.
///
/// # Safety
///
/// All pointers must satisfy their stated lengths for the duration of the call:
/// `bonds_ptr[0..bonds_len]`, `shards_ptr[0..shards_len]`,
/// `credit_pairs_ptr[0..credit_pairs_len]`, `out_r_market_ptr[0..shards_len]`,
/// and each bond's interval buffer per its embedded lengths.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_epoch_close_compute(
    settlement_epoch: u64,
    close_block_height: u64,
    frozen_shard_count: u64,
    bonds_ptr: *const ShekylArchivalEpochCloseBond,
    bonds_len: usize,
    shards_ptr: *const ShekylArchivalEpochCloseShard,
    shards_len: usize,
    credit_pairs_ptr: *const ShekylArchivalCreditPair,
    credit_pairs_len: usize,
    out_r_market_ptr: *mut u64,
    out_sigma_work_milli_ptr: *mut u64,
) -> u8 {
    if (bonds_ptr.is_null() && bonds_len > 0)
        || (shards_ptr.is_null() && shards_len > 0)
        || (credit_pairs_ptr.is_null() && credit_pairs_len > 0)
        || out_sigma_work_milli_ptr.is_null()
    {
        return SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR;
    }

    unsafe { *out_sigma_work_milli_ptr = 0 };
    if shards_len > 0 {
        if out_r_market_ptr.is_null() {
            return SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR;
        }
        unsafe { std::ptr::write_bytes(out_r_market_ptr, 0, shards_len) };
    }

    let rows = match unsafe {
        decode_epoch_rows(
            bonds_ptr,
            bonds_len,
            shards_ptr,
            shards_len,
            credit_pairs_ptr,
            credit_pairs_len,
        )
    } {
        Ok(rows) => rows,
        Err(code) => return code,
    };

    let bonds = rows.bonds();
    let inputs = EpochCloseInputs {
        settlement_epoch,
        close_block_height,
        settlement_epoch_blocks: SETTLEMENT_EPOCH_BLOCKS,
        age_weight_milli: ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
        curve: BandedCurveParams {
            plateau_work_milli: ARCHIVAL_REWARD_PLATEAU_WORK_MILLI,
            plateau_value_milli: ARCHIVAL_REWARD_PLATEAU_VALUE_MILLI,
        },
        bonds: &bonds,
        shards: &rows.shards,
        credit_pairs: &rows.pairs,
        frozen_shard_count,
        // PF-6a: the consensus() constructor is the only production path to
        // a threshold value; a divergent threshold is a type error here.
        k_cover: KCover::consensus(),
    };
    let result = match epoch_close_compute(&inputs) {
        Ok(r) => r,
        Err(_) => return SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE,
    };

    unsafe {
        if shards_len > 0 {
            std::ptr::copy_nonoverlapping(
                result.r_market_by_shard.as_ptr(),
                out_r_market_ptr,
                shards_len,
            );
        }
        *out_sigma_work_milli_ptr = result.sigma_work_milli;
    }
    SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK
}

/// The M-2/Q7 as-of-`E` consensus snapshot for one claimed settlement epoch
/// (`REWARD_EMISSION_E3_GATING_ROUND.md` §3 item 2;
/// `REWARD_EMISSION_VIN_PLAN.md` §8.0.2(B)).
///
/// Layout must match `struct shekyl_archival_emission_epoch_snapshot` in
/// `shekyl_ffi.h`. Marshaled by value from the frozen `E`-close
/// materialization: the serve-credit rows for `E` (the WS-1 §5 held source),
/// the credited bonds' standing fields, shard freeze heights, and the
/// **persisted** `Σwork(E)` — never the live bond holdings descriptor. Every
/// row is immutable for a claimable `E` (credit acceptance rejects past
/// `H_close(E)`; pruning deletes only below the claim window's floor; reorg
/// pops revert close and credits symmetrically), so a re-gather at any height
/// in the claim window reproduces the close's gather exactly.
///
/// `sigma_work_milli` must be the persisted close output, not a recompute:
/// the M1 `K_COVER` gate's operand (`frozen_shard_count` as-of-close) is a
/// close-only quantity, so the gate's outcome reaches verify only through the
/// stored denominator.
#[repr(C)]
pub struct ShekylArchivalEmissionEpochSnapshot {
    pub settlement_epoch: u64,
    /// The close-processing height `(E+1) × SEB` the gather froze at (shard-age
    /// operand; must equal the height the close ran at). NOT `H_close(E)` =
    /// `shekyl_archival_epoch_close_height(E)` = the epoch's last block =
    /// `(E+1) × SEB − 1`, one block lower.
    pub close_block_height: u64,
    /// Persisted finalized `Σwork(E)` milli — the stored denominator.
    pub sigma_work_milli: u64,
    /// Persisted frozen `budget(E)` atomic — the gate-1 numerator operand,
    /// stored at close beside `Σwork(E)` (the `archival_budget` close row,
    /// `ARCHIVAL_BUDGET_SCHEDULE.md` §5). Like the denominator, always the
    /// stored value, never a recompute: the accrual accumulator is live
    /// state; only the close row is frozen.
    pub budget_atomic: u64,
    pub bonds_ptr: *const ShekylArchivalEpochCloseBond,
    pub bonds_len: usize,
    pub shards_ptr: *const ShekylArchivalEpochCloseShard,
    pub shards_len: usize,
    pub credit_pairs_ptr: *const ShekylArchivalCreditPair,
    pub credit_pairs_len: usize,
    /// Claimant `P`'s index into `bonds`, or `SIZE_MAX` when `P` has no
    /// serve-credit row in `E` (its work is then zero by construction).
    pub claimant_bond_idx: usize,
}

/// Claimant work over the as-of-`E` snapshot: `work_P(E)` milli and its
/// `Curve(work_P)` term — the emission verify numerator
/// (`REWARD_EMISSION_VIN_PLAN.md` §8.0.2 step 4).
///
/// Sources via [`as_of_e_served_work`], the same single sourcing function
/// whose output built the persisted `Σwork(E)` denominator at close, over the
/// same frozen gather — so `out_capped_work_milli` is `P`'s exact per-P term
/// of that denominator by construction (WS-1 §5.5: sourcing divergence, the
/// M-2 silent over/under-mint, is unrepresentable rather than tested-against).
/// This is the numerator only — it does not read `snapshot.sigma_work_milli`
/// or re-apply the M1 `K_COVER` gate, so a gated/empty epoch persists
/// `Σwork(E) == 0` while this may return a positive capped term; the consumer
/// divides through the persisted denominator (reward is 0 at `Σwork(E) == 0`,
/// enforced by `reward_share_floor`).
///
/// Both outputs are zero when `claimant_bond_idx == SIZE_MAX` (no credit row
/// for `P` in `E`) or when `P` is not a market member at `E` (foundation
/// complete-tree, joined too late, or a bad interval covering `E`). Errors
/// reuse the `SHEKYL_ARCHIVAL_EPOCH_CLOSE_*` codes; outputs are zeroed before
/// computation so a failure never leaves stale values.
///
/// # Safety
///
/// `snapshot` must point to a valid struct whose array pointers satisfy their
/// stated lengths for the duration of the call, including each bond's
/// interval buffer per its embedded lengths. `out_work_milli` and
/// `out_capped_work_milli` must be writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_emission_epoch_work(
    snapshot: *const ShekylArchivalEmissionEpochSnapshot,
    out_work_milli: *mut u64,
    out_capped_work_milli: *mut u64,
) -> u8 {
    if snapshot.is_null() || out_work_milli.is_null() || out_capped_work_milli.is_null() {
        return SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR;
    }
    unsafe {
        *out_work_milli = 0;
        *out_capped_work_milli = 0;
    }
    let snap = unsafe { &*snapshot };

    let rows = match unsafe {
        decode_epoch_rows(
            snap.bonds_ptr,
            snap.bonds_len,
            snap.shards_ptr,
            snap.shards_len,
            snap.credit_pairs_ptr,
            snap.credit_pairs_len,
        )
    } {
        Ok(rows) => rows,
        Err(code) => return code,
    };

    if snap.claimant_bond_idx == usize::MAX {
        return SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK;
    }
    if snap.claimant_bond_idx >= rows.joins.len() {
        return SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE;
    }

    let bonds = rows.bonds();
    // Single-sourced verify-view construction (constants + stubbed close-only
    // M1 operands) — see `EpochCloseInputs::verify_view`.
    let inputs = EpochCloseInputs::verify_view(
        snap.settlement_epoch,
        snap.close_block_height,
        &bonds,
        &rows.shards,
        &rows.pairs,
    );
    let served = match as_of_e_served_work(&inputs) {
        Ok(served) => served,
        Err(_) => return SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE,
    };

    let work = served.work_by_bond[snap.claimant_bond_idx];
    // The single-sourced per-P capped term: non-members and zero-work members
    // contribute nothing to the stored denominator, so their capped term is
    // zero here too.
    let capped = capped_work_milli(work, served.member[snap.claimant_bond_idx], &inputs.curve);
    unsafe {
        *out_work_milli = work;
        *out_capped_work_milli = capped;
    }
    SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK
}

// ---------------------------------------------------------------------------
// C-1 emission-vin verify FFI (`REWARD_EMISSION_E3_GATING_ROUND.md` §9.5
// items 3–5; `REWARD_EMISSION_VIN_PLAN.md` §7.1). Two entries: a pre-parse
// extractor the C++ dispatch uses for operand gathering (bond record + epoch
// snapshots are keyed by fields inside the opaque blob), and the coarse
// verify call that runs the full §7.1 body — claims (1–5), backing (6), and
// the hybrid auth gate (8) — in one FFI crossing (`40-ffi-discipline.mdc`).
// ---------------------------------------------------------------------------

/// Verdict: the emission vin verified end-to-end.
pub const SHEKYL_EMISSION_VIN_OK: u8 = 0;
/// Required pointer was null (or an output buffer was too small).
pub const SHEKYL_EMISSION_VIN_ERR_NULL_PTR: u8 = 1;
/// The canonical bytes failed the wire parse (tag, bounds, ordering,
/// positivity, trailing bytes) or the in-memory structural re-validate.
pub const SHEKYL_EMISSION_VIN_ERR_WIRE: u8 = 2;
/// Caller marshaling is inconsistent — epoch snapshots misaligned with the
/// claimed set, malformed gather rows, or a claimant index out of range.
/// Never a claimant-attributable rejection: this is a daemon bug surfaced
/// loudly (`EmissionVerifyError::EpochSourceMisaligned` and kin).
pub const SHEKYL_EMISSION_VIN_ERR_MARSHAL: u8 = 3;
/// Step 1: a claimed epoch is not finalized at the carrying height.
pub const SHEKYL_EMISSION_VIN_ERR_EPOCH_NOT_FINALIZED: u8 = 4;
/// Step 1: a claimed epoch fell below the claim window (`MAX_CLAIM_AGE_W`).
pub const SHEKYL_EMISSION_VIN_ERR_EPOCH_EXPIRED: u8 = 5;
/// Step 2: no bond record for the claimant.
pub const SHEKYL_EMISSION_VIN_ERR_BOND_MISSING: u8 = 6;
/// Step 2: vin holdings descriptor does not match the bond record.
pub const SHEKYL_EMISSION_VIN_ERR_HOLDINGS_MISMATCH: u8 = 7;
/// Step 2: a claimed epoch precedes the claimable range for the join epoch.
pub const SHEKYL_EMISSION_VIN_ERR_EPOCH_BEFORE_JOIN: u8 = 8;
/// Step 3 (WS-2 read-only layer): a claimed epoch is already in the
/// pre-block claimed set.
pub const SHEKYL_EMISSION_VIN_ERR_ALREADY_CLAIMED: u8 = 9;
/// Step 4: the work claim contradicts the frozen as-of-`E` recompute
/// (duplicate shard, credit-bit mismatch, scarcity mismatch, or total).
pub const SHEKYL_EMISSION_VIN_ERR_WORK_MISMATCH: u8 = 10;
/// Step 5 (R1.B zero-tolerance): a per-epoch reward amount differs from the
/// three-channel recompute, or the total overflows.
pub const SHEKYL_EMISSION_VIN_ERR_REWARD_MISMATCH: u8 = 11;
/// Step 5 (loud inflation check): Σ rewards != reward vout sum.
pub const SHEKYL_EMISSION_VIN_ERR_VOUT_SUM_MISMATCH: u8 = 12;
/// Step 6: revealed backing pubkey does not hash to the committed leaf.
pub const SHEKYL_EMISSION_VIN_ERR_BACKING_LEAF: u8 = 13;
/// Step 6: membership-only proof rejected.
pub const SHEKYL_EMISSION_VIN_ERR_BACKING_REJECTED: u8 = 14;
/// Step 8: an auth pubkey/signature failed hybrid deserialization.
pub const SHEKYL_EMISSION_VIN_ERR_AUTH_MALFORMED: u8 = 15;
/// Step 8: a hybrid auth signature rejected over its Q1 binding message.
pub const SHEKYL_EMISSION_VIN_ERR_AUTH_REJECTED: u8 = 16;

/// Pure code mapping — no re-decision (the decision-placement pin: every
/// consensus decision lives in `shekyl-archival-retention`; this collapses
/// diagnostic detail the C ABI cannot carry).
fn map_emission_vin_error(err: &EmissionVerifyError) -> u8 {
    use EmissionVerifyError as E;
    match err {
        E::Structural(_) => SHEKYL_EMISSION_VIN_ERR_WIRE,
        E::EpochSourceMisaligned { .. }
        | E::GatherMalformed { .. }
        | E::ClaimantIndexOutOfRange { .. } => SHEKYL_EMISSION_VIN_ERR_MARSHAL,
        E::EpochNotFinalized { .. } => SHEKYL_EMISSION_VIN_ERR_EPOCH_NOT_FINALIZED,
        E::EpochClaimExpired { .. } => SHEKYL_EMISSION_VIN_ERR_EPOCH_EXPIRED,
        E::BondMissing => SHEKYL_EMISSION_VIN_ERR_BOND_MISSING,
        E::HoldingsMismatch => SHEKYL_EMISSION_VIN_ERR_HOLDINGS_MISMATCH,
        E::EpochBeforeJoin { .. } => SHEKYL_EMISSION_VIN_ERR_EPOCH_BEFORE_JOIN,
        E::EpochAlreadyClaimed { .. } => SHEKYL_EMISSION_VIN_ERR_ALREADY_CLAIMED,
        E::WorkClaimDuplicateShard { .. }
        | E::ServeCreditBitMismatch { .. }
        | E::ScarcityMismatch { .. }
        | E::WorkTotalMismatch { .. } => SHEKYL_EMISSION_VIN_ERR_WORK_MISMATCH,
        E::RewardMismatch { .. } | E::RewardTotalOverflow => {
            SHEKYL_EMISSION_VIN_ERR_REWARD_MISMATCH
        }
        E::VoutSumMismatch { .. } => SHEKYL_EMISSION_VIN_ERR_VOUT_SUM_MISMATCH,
        E::BackingLeafMismatch => SHEKYL_EMISSION_VIN_ERR_BACKING_LEAF,
        E::BackingRejected(_) => SHEKYL_EMISSION_VIN_ERR_BACKING_REJECTED,
        E::AuthMalformed { .. } => SHEKYL_EMISSION_VIN_ERR_AUTH_MALFORMED,
        E::AuthRejected { .. } => SHEKYL_EMISSION_VIN_ERR_AUTH_REJECTED,
    }
}

/// Length-exact parse of the canonical vin bytes (tag included): the wire
/// codec's own tag/bounds/ordering checks plus a trailing-bytes rejection.
fn parse_emission_vin(bytes: &[u8]) -> Result<ArchivalRewardEmissionVin, u8> {
    let mut cursor = bytes;
    let vin =
        ArchivalRewardEmissionVin::read(&mut cursor).map_err(|_| SHEKYL_EMISSION_VIN_ERR_WIRE)?;
    if !cursor.is_empty() {
        return Err(SHEKYL_EMISSION_VIN_ERR_WIRE);
    }
    Ok(vin)
}

/// Pre-parse extractor for the C++ dispatch's operand gathering: parses the
/// opaque `txin_archival_reward_emission` bytes and surfaces the two fields
/// the daemon needs **before** it can marshal the verify call — the
/// claimant's `P_canonical_id` (bond-record key, recomputed from `P_pubkey`
/// per emission §6.1) and the claimed `settlement_epochs` (one as-of-`E`
/// snapshot gather per entry).
///
/// Extraction implies nothing about validity beyond the wire parse; the
/// verify call re-parses and re-validates the same bytes (the blob, not this
/// call's outputs, is the consensus input).
///
/// `out_epochs_ptr` must address `epochs_cap ≥ MAX_SETTLEMENT_EPOCHS_PER_EMISSION`
/// writable `u64`s (the parse rejects longer sets, so that capacity is always
/// sufficient).
///
/// # Safety
///
/// `vin_ptr[0..vin_len]` must be readable; `out_p_canonical_id` must address
/// 32 writable bytes; `out_epochs_ptr[0..epochs_cap]` and `out_epochs_len`
/// must be writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_emission_vin_extract(
    vin_ptr: *const u8,
    vin_len: usize,
    out_p_canonical_id: *mut u8,
    out_epochs_ptr: *mut u64,
    epochs_cap: usize,
    out_epochs_len: *mut usize,
) -> u8 {
    if vin_ptr.is_null()
        || vin_len == 0
        || out_p_canonical_id.is_null()
        || out_epochs_ptr.is_null()
        || out_epochs_len.is_null()
    {
        return SHEKYL_EMISSION_VIN_ERR_NULL_PTR;
    }
    unsafe { *out_epochs_len = 0 };

    let bytes = unsafe { std::slice::from_raw_parts(vin_ptr, vin_len) };
    let vin = match parse_emission_vin(bytes) {
        Ok(vin) => vin,
        Err(code) => return code,
    };
    if vin.settlement_epochs.len() > epochs_cap {
        return SHEKYL_EMISSION_VIN_ERR_NULL_PTR;
    }

    let pid = p_canonical_id_from_hybrid_pubkey(&vin.p_pubkey);
    unsafe {
        std::ptr::copy_nonoverlapping(pid.as_bytes().as_ptr(), out_p_canonical_id, 32);
        std::ptr::copy_nonoverlapping(
            vin.settlement_epochs.as_ptr(),
            out_epochs_ptr,
            vin.settlement_epochs.len(),
        );
        *out_epochs_len = vin.settlement_epochs.len();
    }
    SHEKYL_EMISSION_VIN_OK
}

/// Block-level intra-block cross-tx `(P, E)` uniqueness verdict
/// (`REWARD_EMISSION_E3_GATING_ROUND.md` §6.2 layer 2; decision-placement
/// pin §9.5 item 6 — C++ marshals the block's claim pairs, Rust decides).
///
/// `pairs_ptr` is a flattened array of `num_pairs` 40-byte entries:
/// `p_canonical_id[32] ‖ epoch_le[8]`, one entry per `(P, E_i)` of every
/// emission vin in the block, in block order.
///
/// Returns 1 when every pair is distinct (block passes this layer), 0 on any
/// duplicate — or on a null pointer with `num_pairs > 0` (fail closed).
///
/// # Safety
///
/// When `num_pairs > 0`, `pairs_ptr` must address `num_pairs * 40` readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_emission_block_claims_unique(
    pairs_ptr: *const u8,
    num_pairs: usize,
) -> u8 {
    if num_pairs == 0 {
        return 1;
    }
    if pairs_ptr.is_null() {
        return 0;
    }
    let Some(byte_len) = num_pairs.checked_mul(40) else {
        return 0;
    };
    if byte_len > isize::MAX as usize {
        return 0;
    }
    let flat = unsafe { std::slice::from_raw_parts(pairs_ptr, byte_len) };
    let mut pairs = Vec::with_capacity(num_pairs);
    for entry in flat.chunks_exact(40) {
        let mut pid = [0u8; 32];
        pid.copy_from_slice(&entry[..32]);
        let epoch = u64::from_le_bytes(entry[32..40].try_into().expect("8-byte chunk"));
        pairs.push((pid, epoch));
    }
    u8::from(emission_block_claims_unique(&pairs))
}

/// The full §7.1 emission verify body in one coarse FFI crossing: wire parse,
/// claims steps 1–5 over the marshaled as-of-`E` snapshots, membership-only
/// backing (step 6), and the hybrid auth gate (step 8) — assembling the three
/// sealed witnesses into the verdict. Step 7 (FCMP balance over the fee
/// `txin_to_key`s) stays with the existing C++ tx layer.
///
/// Inputs mirror the operands' production sites:
/// - `vin_ptr[0..vin_len]`: the `txin_archival_reward_emission` canonical
///   bytes, tag included (the C++ shim's opaque blob, unparsed by C++).
/// - Bond record (`bond_present`, `bond_join_settlement_epoch`,
///   `bond_holdings_*`, `claimed_epochs_*`): the claimant's **pre-block**
///   `ArchivalBondValue` fields, keyed by the extract call's
///   `P_canonical_id`. `bond_present == 0` marshals "no record" (reject) —
///   the remaining bond arguments are then ignored.
/// - `snapshots_ptr[0..snapshots_len]`: one frozen as-of-`E` snapshot per
///   claimed epoch, in claim order
///   (`BlockchainLMDB::gather_archival_emission_epoch_snapshot`), each
///   carrying the **persisted** `Σwork(E)` and `budget(E)` close rows.
/// - `tree_root`/`tree_depth`: the reference block's curve-tree root context.
/// - `signable_tx_hash`: the emission tx's signable hash (32 bytes).
/// - `reward_commits_ptr[0..reward_commits_len]`: the ordered reward vout
///   commit set as flattened 72-byte entries
///   (`commitment[32] ‖ amount_plain LE u64[8] ‖ one_time_key[32]`) — the
///   R1.A destination binding the auths signed over.
/// - `vout_reward_sum`: Σ reward vout `amount_plain` (step 5's loud compare).
///
/// On `SHEKYL_EMISSION_VIN_OK`: `*out_total_reward` is the verified Σ reward
/// (the connect arm's mint amount) and `out_epochs_ptr[0..*out_epochs_len]`
/// holds the epochs to commit via
/// `shekyl_archival_claimed_epochs_check_and_set`, in wire order. Outputs are
/// zeroed on entry; a non-zero return never leaves stale values.
///
/// # Safety
///
/// All pointers must satisfy their stated lengths for the duration of the
/// call, including each snapshot's embedded row arrays and each bond row's
/// interval buffer per its embedded lengths. `tree_root` and
/// `signable_tx_hash` must address 32 readable bytes each;
/// `out_epochs_ptr[0..epochs_cap]`, `out_epochs_len`, and `out_total_reward`
/// must be writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)] // coarse-call FFI: one crossing carries every §7.1 operand
pub unsafe extern "C" fn shekyl_emission_vin_verify(
    vin_ptr: *const u8,
    vin_len: usize,
    current_block_height: u64,
    vout_reward_sum: u64,
    bond_present: u8,
    bond_join_settlement_epoch: u64,
    bond_holdings_kind: u8,
    bond_shard_ids_ptr: *const u64,
    bond_shard_ids_len: usize,
    claimed_epochs_ptr: *const u64,
    claimed_epochs_len: usize,
    snapshots_ptr: *const ShekylArchivalEmissionEpochSnapshot,
    snapshots_len: usize,
    tree_root: *const u8,
    tree_depth: u8,
    signable_tx_hash: *const u8,
    reward_commits_ptr: *const u8,
    reward_commits_len: usize,
    out_total_reward: *mut u64,
    out_epochs_ptr: *mut u64,
    epochs_cap: usize,
    out_epochs_len: *mut usize,
) -> u8 {
    if vin_ptr.is_null()
        || vin_len == 0
        || tree_root.is_null()
        || signable_tx_hash.is_null()
        || (snapshots_ptr.is_null() && snapshots_len > 0)
        || (reward_commits_ptr.is_null() && reward_commits_len > 0)
        || out_total_reward.is_null()
        || out_epochs_ptr.is_null()
        || out_epochs_len.is_null()
    {
        return SHEKYL_EMISSION_VIN_ERR_NULL_PTR;
    }
    unsafe {
        *out_total_reward = 0;
        *out_epochs_len = 0;
    }

    let bytes = unsafe { std::slice::from_raw_parts(vin_ptr, vin_len) };
    let vin = match parse_emission_vin(bytes) {
        Ok(vin) => vin,
        Err(code) => return code,
    };

    // Bond record marshaling (step 2/3 operands, pre-block state).
    let bond_holdings;
    let claimed_epochs: &[u64];
    let bond = if bond_present == 0 {
        None
    } else {
        if (bond_shard_ids_ptr.is_null() && bond_shard_ids_len > 0)
            || (claimed_epochs_ptr.is_null() && claimed_epochs_len > 0)
        {
            return SHEKYL_EMISSION_VIN_ERR_NULL_PTR;
        }
        let Ok(kind) = HoldingsKind::from_u8(bond_holdings_kind) else {
            return SHEKYL_EMISSION_VIN_ERR_MARSHAL;
        };
        let shard_ids: Vec<u64> = if bond_shard_ids_len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(bond_shard_ids_ptr, bond_shard_ids_len) }.to_vec()
        };
        bond_holdings = HoldingsDescriptor { kind, shard_ids };
        claimed_epochs = if claimed_epochs_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(claimed_epochs_ptr, claimed_epochs_len) }
        };
        Some(ClaimantBondRecord {
            join_settlement_epoch: bond_join_settlement_epoch,
            holdings: &bond_holdings,
            claimed_settlement_epochs: claimed_epochs,
        })
    };

    // Snapshot decode: owned rows first, then the borrowing source structs
    // (EpochCloseInputs borrows the bond/shard/pair rows; the two-pass shape
    // keeps every borrow anchored to this frame).
    let raw_snaps: &[ShekylArchivalEmissionEpochSnapshot] = if snapshots_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(snapshots_ptr, snapshots_len) }
    };
    let mut decoded = Vec::with_capacity(raw_snaps.len());
    for snap in raw_snaps {
        let rows = match unsafe {
            decode_epoch_rows(
                snap.bonds_ptr,
                snap.bonds_len,
                snap.shards_ptr,
                snap.shards_len,
                snap.credit_pairs_ptr,
                snap.credit_pairs_len,
            )
        } {
            Ok(rows) => rows,
            Err(_) => return SHEKYL_EMISSION_VIN_ERR_MARSHAL,
        };
        decoded.push(rows);
    }
    let bonds_per: Vec<Vec<EpochCloseBond<'_>>> =
        decoded.iter().map(DecodedEpochRows::bonds).collect();
    let sources: Vec<EmissionEpochSource<'_>> = raw_snaps
        .iter()
        .zip(&decoded)
        .zip(&bonds_per)
        .map(|((snap, rows), bonds)| EmissionEpochSource {
            // Single-sourced verify-view construction (constants + stubbed
            // close-only M1 operands) — see `EpochCloseInputs::verify_view`.
            inputs: EpochCloseInputs::verify_view(
                snap.settlement_epoch,
                snap.close_block_height,
                bonds,
                &rows.shards,
                &rows.pairs,
            ),
            persisted_sigma_work_milli: snap.sigma_work_milli,
            claimant_bond_idx: (snap.claimant_bond_idx != usize::MAX)
                .then_some(snap.claimant_bond_idx),
            budget: snap.budget_atomic,
        })
        .collect();

    let ctx = EmissionVerifyContext {
        current_block_height,
        bond,
        vout_reward_sum,
    };

    // Auth context: the ordered reward vout commit set, flattened 72-byte
    // entries (commitment ‖ amount LE ‖ one-time key).
    let commits_bytes: &[u8] = if reward_commits_len == 0 {
        &[]
    } else {
        let Some(flat_len) = reward_commits_len.checked_mul(72) else {
            return SHEKYL_EMISSION_VIN_ERR_MARSHAL;
        };
        unsafe { std::slice::from_raw_parts(reward_commits_ptr, flat_len) }
    };
    let reward_commits: Vec<RewardCommit> = commits_bytes
        .chunks_exact(72)
        .map(|chunk| RewardCommit {
            commitment: chunk[0..32].try_into().expect("32-byte slice"),
            amount_plain: u64::from_le_bytes(chunk[32..40].try_into().expect("8-byte slice")),
            one_time_key: chunk[40..72].try_into().expect("32-byte slice"),
        })
        .collect();

    let tree_root_arr: [u8; 32] = unsafe { *tree_root.cast::<[u8; 32]>() };
    let tx_hash_arr: [u8; 32] = unsafe { *signable_tx_hash.cast::<[u8; 32]>() };

    // Fail-fast minting of the three sealed witnesses. Claims (steps 1–5)
    // first, then the hybrid auth gate (step 8) *before* the membership-only
    // backing (step 6): the auths are orders of magnitude cheaper than the
    // FCMP proof, so a forged vin is rejected before the expensive
    // verification (DoS ordering — not consensus-visible, since every
    // ordering rejects the same vins, and the verdict still requires all
    // three witnesses).
    let claims = match emission_vin_verify_claims(&vin, &ctx, &sources) {
        Ok(claims) => claims,
        Err(e) => return map_emission_vin_error(&e),
    };
    let auth = match emission_vin_verify_auth(&vin, &reward_commits, &tx_hash_arr) {
        Ok(auth) => auth,
        Err(e) => return map_emission_vin_error(&e),
    };
    let backing = match emission_vin_verify_backing(&vin, &tree_root_arr, tree_depth, tx_hash_arr) {
        Ok(backing) => backing,
        Err(e) => return map_emission_vin_error(&e),
    };
    let verdict = emission_vin_verify(claims, backing, auth);

    if verdict.epochs_to_commit.len() > epochs_cap {
        return SHEKYL_EMISSION_VIN_ERR_NULL_PTR;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            verdict.epochs_to_commit.as_ptr(),
            out_epochs_ptr,
            verdict.epochs_to_commit.len(),
        );
        *out_epochs_len = verdict.epochs_to_commit.len();
        *out_total_reward = verdict.total_reward;
    }
    SHEKYL_EMISSION_VIN_OK
}

/// `epoch` was inserted into the claimed set (and stale entries pruned).
pub const SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_INSERTED: u8 = 0;
/// `epoch` was already claimed — the connect path treats this as a hard
/// error, never a soft skip (WS-2 §6.2: verify's contains-check plus the
/// block-level `(P,E)` pass foreclose it; reaching it means a dedup layer
/// was bypassed).
pub const SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ALREADY_CLAIMED: u8 = 1;
/// `epoch >= current_settled_epoch`: not yet settled, unclaimable.
pub const SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_NOT_SETTLED: u8 = 2;
/// `epoch` has fallen below the claim window (`MAX_CLAIM_AGE_W`).
pub const SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_EXPIRED: u8 = 3;
/// Null pointer, capacity overflow, or a set that is not strictly increasing.
pub const SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID: u8 = 4;

/// Record `epoch` as claimed in the caller-owned claimed-epoch buffer — the
/// **single writer** for `ArchivalBondValue::claimed_settlement_epochs`
/// (WS-2 §6.2; the read side is `claimed_epochs_contains` on the verify
/// path). Wraps [`claimed_epochs_check_and_set`]: window maintenance
/// (prune below `current_settled_epoch − W`) happens on insert, so the
/// buffer contents *and* length change on success.
///
/// `set_ptr[0..*set_len_ptr]` is the strictly increasing claimed set on
/// entry; on `INSERTED` the updated set is written back in place and
/// `*set_len_ptr` holds the new length (never exceeding the entry cap, so
/// a `MAX_CLAIMED_EPOCH_ENTRIES`-sized buffer is always sufficient). On any
/// other return the buffer and length are unchanged.
///
/// # Safety
///
/// `set_ptr` must address `set_cap` valid, writable `u64`s; `set_len_ptr`
/// must be a valid writable `usize` pointer with `*set_len_ptr <= set_cap`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_claimed_epochs_check_and_set(
    set_ptr: *mut u64,
    set_len_ptr: *mut usize,
    set_cap: usize,
    epoch: u64,
    current_settled_epoch: u64,
) -> u8 {
    if set_ptr.is_null() || set_len_ptr.is_null() {
        return SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID;
    }
    let len = unsafe { *set_len_ptr };
    if len > set_cap || set_cap > MAX_CLAIMED_EPOCH_ENTRIES as usize {
        return SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID;
    }
    let mut set: Vec<u64> = unsafe { std::slice::from_raw_parts(set_ptr, len) }.to_vec();
    // The at-rest codec enforces strict ordering; re-check here so a
    // corrupted buffer cannot silently satisfy the binary-search contract.
    if !set.windows(2).all(|w| w[0] < w[1]) {
        return SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID;
    }
    match claimed_epochs_check_and_set(&mut set, epoch, current_settled_epoch) {
        Ok(true) => {
            // Fail closed rather than overrun: the window prune bounds the set
            // below `set_cap` in practice, but a debug_assert vanishes in
            // release, so guard the write at runtime — an insert that grew the
            // set past the caller's buffer is a structured error, never a
            // copy_nonoverlapping past the end.
            if set.len() > set_cap {
                return SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(set.as_ptr(), set_ptr, set.len());
                *set_len_ptr = set.len();
            }
            SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_INSERTED
        }
        Ok(false) => SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ALREADY_CLAIMED,
        Err(ClaimedEpochsError::NotSettled) => SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_NOT_SETTLED,
        Err(ClaimedEpochsError::Expired) => SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_EXPIRED,
    }
}

fn map_bond_ct_balance_error(err: BondCtBalanceError) -> u8 {
    match err {
        BondCtBalanceError::InvalidPoint => SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_INVALID_POINT,
        BondCtBalanceError::SumMismatch => SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_SUM_MISMATCH,
    }
}

/// Flattened `count × 32` commitment keys from a C pointer; rejects overflow and oversize slices.
///
/// # Safety
///
/// When `count > 0`, `ptr` must address `count * 32` valid bytes for the lifetime `'a`.
unsafe fn flat_commitment_keys<'a>(ptr: *const u8, count: usize) -> Result<&'a [u8], u8> {
    if count == 0 {
        return Ok(&[]);
    }
    let Some(byte_len) = count.checked_mul(32) else {
        return Err(SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_INVALID_POINT);
    };
    if byte_len > isize::MAX as usize {
        return Err(SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_INVALID_POINT);
    }
    // SAFETY: caller contract per function docs.
    Ok(std::slice::from_raw_parts(ptr, byte_len))
}

/// Verify bond-post CT balance: `sum(pseudoOuts) + bond_debit = sum(out masks) + fee + bond_credit`.
///
/// `pseudo_outs_ptr` and `out_masks_ptr` are flattened `N × 32` byte arrays; either pointer may
/// be null when the corresponding count is zero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_verify_bond_post_ct_balance(
    pseudo_outs_ptr: *const u8,
    num_pseudo_outs: usize,
    out_masks_ptr: *const u8,
    num_out_masks: usize,
    txn_fee: u64,
    bond_credit: u64,
    bond_debit: u64,
) -> u8 {
    if num_pseudo_outs > 0 && pseudo_outs_ptr.is_null() {
        return SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NULL_PTR;
    }
    if num_out_masks > 0 && out_masks_ptr.is_null() {
        return SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NULL_PTR;
    }

    let pseudo_flat = match unsafe { flat_commitment_keys(pseudo_outs_ptr, num_pseudo_outs) } {
        Ok(slice) => slice,
        Err(code) => return code,
    };
    let mask_flat = match unsafe { flat_commitment_keys(out_masks_ptr, num_out_masks) } {
        Ok(slice) => slice,
        Err(code) => return code,
    };

    // The C ABI carries the two directions as separate u64s; convert to the
    // `BondTerm` the (total) core function takes, rejecting the both / neither /
    // zero states here — at the untrusted-input boundary — with the same status
    // codes. Matching on the `NonZeroAtomicUnits` options folds the zero-amount
    // case into "neither term" for free (a zero credit or debit is `None`).
    let term = match (
        NonZeroAtomicUnits::new(AtomicUnits::from_raw(bond_credit)),
        NonZeroAtomicUnits::new(AtomicUnits::from_raw(bond_debit)),
    ) {
        (None, None) => return SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NO_BOND_TERM,
        (Some(credit), None) => BondTerm::Credit(credit),
        (None, Some(debit)) => BondTerm::Debit(debit),
        (Some(_), Some(_)) => return SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_BOTH_TERMS,
    };

    match verify_bond_post_ct_balance(pseudo_flat, mask_flat, txn_fee, term) {
        Ok(()) => SHEKYL_ARCHIVAL_BOND_CT_BALANCE_OK,
        Err(e) => map_bond_ct_balance_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn ffi_constants_match_timing_cluster() {
        assert_eq!(SETTLEMENT_EPOCH_BLOCKS, 10_000);
        assert_eq!(shekyl_archival_epoch_open_height(100), 1_000_000);
        assert_eq!(shekyl_archival_epoch_close_height(100), 1_009_999);
    }

    #[test]
    fn ffi_rejects_null_context() {
        let code = unsafe { shekyl_archival_verify_serve_credit_vin(ptr::null(), 0, ptr::null()) };
        assert_eq!(code, SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR);
    }

    #[test]
    fn checked_sum_amounts_sums_overflows_and_guards() {
        // Empty set (null allowed iff len == 0) sums to 0.
        let mut out: u64 = 7;
        assert_eq!(
            unsafe { shekyl_checked_sum_amounts(ptr::null(), 0, &raw mut out) },
            0
        );
        assert_eq!(out, 0);

        // Normal sum.
        let amounts = [1u64, 2, 3, 4];
        let mut sum: u64 = 0;
        assert_eq!(
            unsafe { shekyl_checked_sum_amounts(amounts.as_ptr(), amounts.len(), &raw mut sum) },
            0
        );
        assert_eq!(sum, 10);

        // Overflow rejects (non-zero return, caller must reject the tx).
        let overflow = [u64::MAX, 1];
        let mut bad: u64 = 0;
        assert_eq!(
            unsafe { shekyl_checked_sum_amounts(overflow.as_ptr(), overflow.len(), &raw mut bad) },
            1
        );

        // Null out pointer and null data with non-zero len both reject.
        assert_eq!(
            unsafe { shekyl_checked_sum_amounts(amounts.as_ptr(), amounts.len(), ptr::null_mut()) },
            1
        );
        let mut o: u64 = 0;
        assert_eq!(
            unsafe { shekyl_checked_sum_amounts(ptr::null(), 3, &raw mut o) },
            1
        );
    }

    #[test]
    fn bond_post_ffi_maps_each_reject_reason() {
        use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;

        let floor = ARCHIVAL_BOND_FLOOR_ATOMIC;
        let shard = 42u64;
        let verify = |post_kind: u8,
                      holdings_kind: u8,
                      shards: Option<&u64>,
                      shard_len: usize,
                      total: u64,
                      credit: u64,
                      debit: u64,
                      record_exists: u8| unsafe {
            shekyl_archival_verify_join_market_bond_post(
                post_kind,
                holdings_kind,
                shards.map_or(std::ptr::null(), std::ptr::from_ref),
                shard_len,
                total,
                credit,
                debit,
                record_exists,
            )
        };

        assert_eq!(
            verify(0, 0, Some(&shard), 1, floor, floor, 0, 0),
            SHEKYL_ARCHIVAL_BOND_POST_OK
        );
        assert_eq!(
            verify(1, 0, Some(&shard), 1, floor, floor, 0, 0),
            SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND
        );
        assert_eq!(
            verify(0, 0, None, 1, floor, floor, 0, 0),
            SHEKYL_ARCHIVAL_BOND_POST_ERR_NULL_PTR
        );
        assert_eq!(
            verify(0, 99, Some(&shard), 1, floor, floor, 0, 0),
            SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_KIND
        );
        assert_eq!(
            verify(0, 0, None, 0, floor, floor, 0, 0),
            SHEKYL_ARCHIVAL_BOND_POST_ERR_SHARD_SET_EMPTY
        );
        assert_eq!(
            verify(0, 1, Some(&shard), 1, floor, floor, 0, 0),
            SHEKYL_ARCHIVAL_BOND_POST_ERR_COMPLETE_TREE_WITH_SHARDS
        );
        assert_eq!(
            verify(0, 0, Some(&shard), 1, floor, floor, floor, 0),
            SHEKYL_ARCHIVAL_BOND_POST_ERR_BOTH_TERMS
        );
        assert_eq!(
            verify(0, 0, Some(&shard), 1, 0, 0, 1, 0),
            SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_DEBIT_NONZERO
        );
        assert_eq!(
            verify(0, 0, Some(&shard), 1, floor + 1, floor + 1, 0, 0),
            SHEKYL_ARCHIVAL_BOND_POST_ERR_FLOOR_MISMATCH
        );
        assert_eq!(
            verify(0, 0, Some(&shard), 1, floor, floor, 0, 1),
            SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_EXISTS
        );
    }

    #[test]
    fn serve_credit_epoch_ok_ffi_matches_rust() {
        assert_eq!(shekyl_archival_serve_credit_epoch_ok(0, 0), 0);
        assert_eq!(shekyl_archival_serve_credit_epoch_ok(1, 0), 1);
        assert_eq!(
            shekyl_archival_serve_credit_epoch_ok(u64::MAX, u64::MAX - 1),
            1
        );
        assert_eq!(shekyl_archival_serve_credit_epoch_ok(u64::MAX, u64::MAX), 0);
    }

    #[test]
    fn bond_ct_balance_ffi_rejects_null_with_nonzero_count() {
        let code = unsafe {
            shekyl_archival_verify_bond_post_ct_balance(ptr::null(), 1, ptr::null(), 0, 0, 0, 0)
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NULL_PTR);
    }

    #[test]
    fn bond_ct_balance_ffi_rejects_count_overflow() {
        let buf = [0u8; 32];
        let code = unsafe {
            shekyl_archival_verify_bond_post_ct_balance(
                buf.as_ptr(),
                usize::MAX,
                ptr::null(),
                0,
                0,
                0,
                0,
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_INVALID_POINT);
    }

    // The both / neither bond-term rigidity is unrepresentable inside the core
    // `BondTerm`, so it is enforced (and tested) here at the `(credit, debit) ->
    // BondTerm` FFI conversion — the boundary where the untrusted u64s enter.
    #[test]
    fn bond_ct_balance_ffi_rejects_neither_bond_term() {
        // credit = debit = 0 (empty balance) → NO_BOND_TERM, not OK.
        let code = unsafe {
            shekyl_archival_verify_bond_post_ct_balance(ptr::null(), 0, ptr::null(), 0, 0, 0, 0)
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NO_BOND_TERM);
    }

    #[test]
    fn bond_ct_balance_ffi_rejects_both_bond_terms() {
        // credit and debit both non-zero → BOTH_TERMS.
        let code = unsafe {
            shekyl_archival_verify_bond_post_ct_balance(ptr::null(), 0, ptr::null(), 0, 0, 1, 1)
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_BOTH_TERMS);
    }

    #[test]
    fn ffi_rejects_leaf_layer_scalar_count_not_multiple_of_four() {
        let pubkey = [0u8; 32];
        let scalars = [0u8; 32];
        let ctx = ShekylArchivalVerifyCtx {
            current_height: 1,
            settlement_epoch: 0,
            block_hash_at_seal: [0u8; 32],
            registry_segment_subroot_rk: [0u8; 32],
            segment_leaf_count: 1,
            pqc_pubkey_ptr: pubkey.as_ptr(),
            pqc_pubkey_len: pubkey.len(),
            leaf_layer_scalars_ptr: scalars.as_ptr(),
            leaf_layer_scalars_len: scalars.len(),
        };
        let payload = [0u8];
        let code = unsafe {
            shekyl_archival_verify_serve_credit_vin(
                payload.as_ptr(),
                payload.len(),
                std::ptr::from_ref(&ctx),
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_VERIFY_ERR_SCALAR_SHAPE);
    }

    #[test]
    fn good_through_ffi_matches_interval_semantics() {
        // Open-ended slash at epoch 11: good before, bad from 11 on.
        let flat = [11u64, u64::MAX];
        let good = |e: u64| unsafe { shekyl_archival_good_through(0, e, flat.as_ptr(), 1) };
        assert_eq!(good(10), 1);
        assert_eq!(good(11), 0);
        // Pre-E_first epochs are not good.
        assert_eq!(
            unsafe { shekyl_archival_good_through(5, 5, std::ptr::null(), 0) },
            0
        );
        assert_eq!(
            unsafe { shekyl_archival_good_through(5, 6, std::ptr::null(), 0) },
            1
        );
        // Null with nonzero length fails closed.
        assert_eq!(
            unsafe { shekyl_archival_good_through(0, 10, std::ptr::null(), 1) },
            0
        );
    }

    #[test]
    fn epoch_timing_ffi_boundaries() {
        let seb = SETTLEMENT_EPOCH_BLOCKS;
        let mut epoch = u64::MAX;
        assert_eq!(
            unsafe { shekyl_archival_epoch_close_due(0, ptr::from_mut(&mut epoch)) },
            0
        );
        assert_eq!(
            unsafe { shekyl_archival_epoch_close_due(seb, ptr::from_mut(&mut epoch)) },
            1
        );
        assert_eq!(epoch, 0);
        assert_eq!(
            unsafe { shekyl_archival_epoch_close_due(seb + 1, ptr::from_mut(&mut epoch)) },
            0
        );

        assert_eq!(shekyl_archival_settlement_epoch_at_height(seb - 1), 0);
        assert_eq!(shekyl_archival_settlement_epoch_at_height(seb), 1);

        let w = MAX_CLAIM_AGE_W;
        let mut below = u64::MAX;
        assert_eq!(
            unsafe { shekyl_archival_prune_below_epoch(w * seb, ptr::from_mut(&mut below)) },
            0
        );
        assert_eq!(
            unsafe { shekyl_archival_prune_below_epoch((w + 1) * seb, ptr::from_mut(&mut below)) },
            1
        );
        assert_eq!(below, 1);
    }

    #[test]
    fn epoch_close_compute_ffi_full_pipeline() {
        // Two members share shard 7; one slashed bond and one foundation
        // complete-tree contribute neither market count nor work.
        let slashed = [0u64, u64::MAX];
        let bonds = [
            ShekylArchivalEpochCloseBond {
                join_settlement_epoch: 0,
                bad_intervals_ptr: ptr::null(),
                bad_intervals_len: 0,
                is_foundation_complete_tree: 0,
            },
            ShekylArchivalEpochCloseBond {
                join_settlement_epoch: 0,
                bad_intervals_ptr: ptr::null(),
                bad_intervals_len: 0,
                is_foundation_complete_tree: 0,
            },
            ShekylArchivalEpochCloseBond {
                join_settlement_epoch: 0,
                bad_intervals_ptr: slashed.as_ptr(),
                bad_intervals_len: 1,
                is_foundation_complete_tree: 0,
            },
            ShekylArchivalEpochCloseBond {
                join_settlement_epoch: 0,
                bad_intervals_ptr: ptr::null(),
                bad_intervals_len: 0,
                is_foundation_complete_tree: 1,
            },
        ];
        let shards = [ShekylArchivalEpochCloseShard {
            shard_id: 7,
            freeze_height: 0,
            has_segment: 1,
        }];
        let pairs = [
            ShekylArchivalCreditPair {
                bond_idx: 0,
                shard_idx: 0,
            },
            ShekylArchivalCreditPair {
                bond_idx: 1,
                shard_idx: 0,
            },
            ShekylArchivalCreditPair {
                bond_idx: 2,
                shard_idx: 0,
            },
            ShekylArchivalCreditPair {
                bond_idx: 3,
                shard_idx: 0,
            },
        ];
        let mut r_market = [u64::MAX; 1];
        let mut sigma = u64::MAX;
        let code = unsafe {
            shekyl_archival_epoch_close_compute(
                5,
                5 * SETTLEMENT_EPOCH_BLOCKS,
                1,
                bonds.as_ptr(),
                bonds.len(),
                shards.as_ptr(),
                shards.len(),
                pairs.as_ptr(),
                pairs.len(),
                r_market.as_mut_ptr(),
                ptr::from_mut(&mut sigma),
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK);
        assert_eq!(r_market, [2]);

        // Cross-check against the pure crate computation with the same pins.
        let bad: Vec<BadInterval> = vec![BadInterval {
            start_epoch: 0,
            end_exclusive: u64::MAX,
        }];
        let rust_bonds = [
            EpochCloseBond {
                join_settlement_epoch: 0,
                is_foundation_complete_tree: false,
                bad_intervals: &[],
            },
            EpochCloseBond {
                join_settlement_epoch: 0,
                is_foundation_complete_tree: false,
                bad_intervals: &[],
            },
            EpochCloseBond {
                join_settlement_epoch: 0,
                is_foundation_complete_tree: false,
                bad_intervals: &bad,
            },
            EpochCloseBond {
                join_settlement_epoch: 0,
                is_foundation_complete_tree: true,
                bad_intervals: &[],
            },
        ];
        let rust_shards = [EpochCloseShard {
            shard_id: 7,
            has_segment: true,
            freeze_height: 0,
        }];
        let rust_pairs: Vec<CreditPair> = (0..4)
            .map(|bond_idx| CreditPair {
                bond_idx,
                shard_idx: 0,
            })
            .collect();
        let expected = epoch_close_compute(&EpochCloseInputs {
            settlement_epoch: 5,
            close_block_height: 5 * SETTLEMENT_EPOCH_BLOCKS,
            settlement_epoch_blocks: SETTLEMENT_EPOCH_BLOCKS,
            age_weight_milli: ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
            curve: BandedCurveParams {
                plateau_work_milli: ARCHIVAL_REWARD_PLATEAU_WORK_MILLI,
                plateau_value_milli: ARCHIVAL_REWARD_PLATEAU_VALUE_MILLI,
            },
            bonds: &rust_bonds,
            shards: &rust_shards,
            credit_pairs: &rust_pairs,
            frozen_shard_count: 1,
            k_cover: KCover::consensus(),
        })
        .unwrap();
        assert_eq!(sigma, expected.sigma_work_milli);
        assert!(
            sigma > 0,
            "two members with work must produce nonzero Σwork"
        );
    }

    /// M-2 supply-conservation identity at the FFI boundary
    /// (`REWARD_EMISSION_E3_GATING_ROUND.md` §3 item 2): summing
    /// `shekyl_archival_emission_epoch_work`'s capped term over every gathered
    /// bond reproduces the close's persisted `Σwork(E)` exactly. Verify's
    /// per-P numerator and close's denominator come from the same sourcing
    /// function over the same rows, so `Σ_P Curve(work_P) == Σwork` is an
    /// identity, not an approximation; non-members (slashed, foundation
    /// complete-tree) contribute zero to both sides.
    #[test]
    fn emission_epoch_work_sums_to_persisted_sigma() {
        let slashed = [0u64, u64::MAX];
        let bonds = [
            ShekylArchivalEpochCloseBond {
                join_settlement_epoch: 0,
                bad_intervals_ptr: ptr::null(),
                bad_intervals_len: 0,
                is_foundation_complete_tree: 0,
            },
            ShekylArchivalEpochCloseBond {
                join_settlement_epoch: 0,
                bad_intervals_ptr: ptr::null(),
                bad_intervals_len: 0,
                is_foundation_complete_tree: 0,
            },
            ShekylArchivalEpochCloseBond {
                join_settlement_epoch: 0,
                bad_intervals_ptr: slashed.as_ptr(),
                bad_intervals_len: 1,
                is_foundation_complete_tree: 0,
            },
            ShekylArchivalEpochCloseBond {
                join_settlement_epoch: 0,
                bad_intervals_ptr: ptr::null(),
                bad_intervals_len: 0,
                is_foundation_complete_tree: 1,
            },
        ];
        let shards = [
            ShekylArchivalEpochCloseShard {
                shard_id: 7,
                freeze_height: 0,
                has_segment: 1,
            },
            ShekylArchivalEpochCloseShard {
                shard_id: 9,
                freeze_height: 2 * SETTLEMENT_EPOCH_BLOCKS,
                has_segment: 1,
            },
        ];
        // Asymmetric work: bond 0 serves both shards, bond 1 one shard, so
        // the identity is exercised with distinct per-P terms.
        let pairs = [
            ShekylArchivalCreditPair {
                bond_idx: 0,
                shard_idx: 0,
            },
            ShekylArchivalCreditPair {
                bond_idx: 0,
                shard_idx: 1,
            },
            ShekylArchivalCreditPair {
                bond_idx: 1,
                shard_idx: 0,
            },
            ShekylArchivalCreditPair {
                bond_idx: 2,
                shard_idx: 0,
            },
            ShekylArchivalCreditPair {
                bond_idx: 3,
                shard_idx: 1,
            },
        ];

        let mut r_market = [u64::MAX; 2];
        let mut sigma = u64::MAX;
        let code = unsafe {
            shekyl_archival_epoch_close_compute(
                5,
                6 * SETTLEMENT_EPOCH_BLOCKS,
                2,
                bonds.as_ptr(),
                bonds.len(),
                shards.as_ptr(),
                shards.len(),
                pairs.as_ptr(),
                pairs.len(),
                r_market.as_mut_ptr(),
                ptr::from_mut(&mut sigma),
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK);
        assert!(sigma > 0, "fixture must close with nonzero Σwork");

        let snapshot_for = |claimant_bond_idx: usize| ShekylArchivalEmissionEpochSnapshot {
            settlement_epoch: 5,
            close_block_height: 6 * SETTLEMENT_EPOCH_BLOCKS,
            sigma_work_milli: sigma,
            // Numerator-path test: the budget close row is not consulted by
            // the epoch-work FFI (only the vin-verify body divides by it).
            budget_atomic: 0,
            bonds_ptr: bonds.as_ptr(),
            bonds_len: bonds.len(),
            shards_ptr: shards.as_ptr(),
            shards_len: shards.len(),
            credit_pairs_ptr: pairs.as_ptr(),
            credit_pairs_len: pairs.len(),
            claimant_bond_idx,
        };

        let mut capped_terms: Vec<u64> = Vec::with_capacity(bonds.len());
        for idx in 0..bonds.len() {
            let snap = snapshot_for(idx);
            let mut work = u64::MAX;
            let mut capped = u64::MAX;
            let code = unsafe {
                shekyl_archival_emission_epoch_work(
                    ptr::from_ref(&snap),
                    ptr::from_mut(&mut work),
                    ptr::from_mut(&mut capped),
                )
            };
            assert_eq!(code, SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK);
            if idx >= 2 {
                assert_eq!(work, 0, "non-member bond {idx} must have zero work");
                assert_eq!(
                    capped, 0,
                    "non-member bond {idx} must have zero capped term"
                );
            } else {
                assert!(work > 0, "member bond {idx} must have nonzero work");
            }
            capped_terms.push(capped);
        }
        let capped_sum: u64 = capped_terms.iter().sum();
        assert_eq!(
            capped_sum, sigma,
            "sum of per-P capped terms must equal the persisted Σwork(E)"
        );
        // Reuse the per-bond terms already computed above rather than
        // re-invoking the FFI: the two members must differ for the identity to
        // be non-trivial.
        assert_ne!(
            capped_terms[0], capped_terms[1],
            "fixture must produce distinct per-P terms for the identity to be non-trivial"
        );

        // No credit row for P (claimant_bond_idx == SIZE_MAX): zero work by
        // construction, OK status.
        let snap = snapshot_for(usize::MAX);
        let mut work = u64::MAX;
        let mut capped = u64::MAX;
        let code = unsafe {
            shekyl_archival_emission_epoch_work(
                ptr::from_ref(&snap),
                ptr::from_mut(&mut work),
                ptr::from_mut(&mut capped),
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK);
        assert_eq!(work, 0);
        assert_eq!(capped, 0);

        // Out-of-range claimant index (not the SIZE_MAX sentinel) rejects and
        // zeroes outputs.
        let snap = snapshot_for(bonds.len());
        let mut work = u64::MAX;
        let mut capped = u64::MAX;
        let code = unsafe {
            shekyl_archival_emission_epoch_work(
                ptr::from_ref(&snap),
                ptr::from_mut(&mut work),
                ptr::from_mut(&mut capped),
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE);
        assert_eq!(work, 0, "failure path must not leave stale outputs");
        assert_eq!(capped, 0);
    }

    /// The close-processing boundary wrapper single-sources
    /// `consensus_state::epoch_close_height`: `(E+1)·SEB`, one above the
    /// settlement close height, 0 for the overflowing epoch.
    #[test]
    fn epoch_close_processing_height_wrapper() {
        assert_eq!(
            shekyl_archival_epoch_close_processing_height(0),
            SETTLEMENT_EPOCH_BLOCKS
        );
        assert_eq!(
            shekyl_archival_epoch_close_processing_height(5),
            6 * SETTLEMENT_EPOCH_BLOCKS
        );
        assert_eq!(
            shekyl_archival_epoch_close_processing_height(5),
            shekyl_archival_epoch_close_height(5) + 1
        );
        assert_eq!(shekyl_archival_epoch_close_processing_height(u64::MAX), 0);
    }

    #[test]
    fn epoch_close_compute_ffi_rejects_bad_indices_and_zeroes_outputs() {
        let shards = [ShekylArchivalEpochCloseShard {
            shard_id: 7,
            freeze_height: 0,
            has_segment: 1,
        }];
        let pairs = [ShekylArchivalCreditPair {
            bond_idx: 3,
            shard_idx: 0,
        }];
        let mut r_market = [u64::MAX; 1];
        let mut sigma = u64::MAX;
        let code = unsafe {
            shekyl_archival_epoch_close_compute(
                5,
                5 * SETTLEMENT_EPOCH_BLOCKS,
                1,
                ptr::null(),
                0,
                shards.as_ptr(),
                shards.len(),
                pairs.as_ptr(),
                pairs.len(),
                r_market.as_mut_ptr(),
                ptr::from_mut(&mut sigma),
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE);
        assert_eq!(r_market, [0], "failure path must not leave stale outputs");
        assert_eq!(sigma, 0);

        let code = unsafe {
            shekyl_archival_epoch_close_compute(
                5,
                5 * SETTLEMENT_EPOCH_BLOCKS,
                1,
                ptr::null(),
                0,
                shards.as_ptr(),
                shards.len(),
                pairs.as_ptr(),
                pairs.len(),
                ptr::null_mut(),
                ptr::from_mut(&mut sigma),
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR);
    }

    #[test]
    fn claimed_epochs_check_and_set_ffi_write_back_and_polarity() {
        const CAP: usize = MAX_CLAIMED_EPOCH_ENTRIES as usize;
        let mut buf = [0u64; CAP];
        let mut len: usize = 0;

        // Insert into an empty set.
        let code = unsafe {
            shekyl_archival_claimed_epochs_check_and_set(
                buf.as_mut_ptr(),
                ptr::from_mut(&mut len),
                CAP,
                10,
                12,
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_INSERTED);
        assert_eq!(&buf[..len], &[10]);

        // Dedup hit leaves the buffer untouched.
        let code = unsafe {
            shekyl_archival_claimed_epochs_check_and_set(
                buf.as_mut_ptr(),
                ptr::from_mut(&mut len),
                CAP,
                10,
                12,
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ALREADY_CLAIMED);
        assert_eq!(&buf[..len], &[10]);

        // Not-settled and expired map to their own codes without mutation.
        let code = unsafe {
            shekyl_archival_claimed_epochs_check_and_set(
                buf.as_mut_ptr(),
                ptr::from_mut(&mut len),
                CAP,
                12,
                12,
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_NOT_SETTLED);
        let far_future = MAX_CLAIM_AGE_W + 100;
        let code = unsafe {
            shekyl_archival_claimed_epochs_check_and_set(
                buf.as_mut_ptr(),
                ptr::from_mut(&mut len),
                CAP,
                1,
                far_future,
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_EXPIRED);
        assert_eq!(&buf[..len], &[10]);

        // A window-advancing insert prunes stale entries in the write-back:
        // epoch 10 falls below `far_future − W` and is evicted.
        let code = unsafe {
            shekyl_archival_claimed_epochs_check_and_set(
                buf.as_mut_ptr(),
                ptr::from_mut(&mut len),
                CAP,
                far_future - 1,
                far_future,
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_INSERTED);
        assert_eq!(&buf[..len], &[far_future - 1]);

        // Null pointers and a non-increasing buffer reject as invalid.
        let code = unsafe {
            shekyl_archival_claimed_epochs_check_and_set(
                ptr::null_mut(),
                ptr::from_mut(&mut len),
                CAP,
                5,
                12,
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID);
        let mut bad = [7u64, 7u64];
        let mut bad_len: usize = 2;
        let code = unsafe {
            shekyl_archival_claimed_epochs_check_and_set(
                bad.as_mut_ptr(),
                ptr::from_mut(&mut bad_len),
                2,
                5,
                12,
            )
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID);
    }

    // -----------------------------------------------------------------------
    // C-1 emission-vin FFI (`shekyl_archival_emission_vin_extract`,
    // `shekyl_emission_vin_verify`). The honest fixture mirrors the crate KAT
    // (`emission_verify_kat.rs`) but is recomputed with the FFI's own pinned
    // consensus constants (plateau curve, `KCover::consensus()`), so the test
    // exercises the exact operand plumbing the C++ dispatch will use.
    // -----------------------------------------------------------------------

    use shekyl_archival_retention::{
        curve_milli, reward_share_floor, sigma_work_milli, EmissionAuthRole, MembershipOnlyBacking,
        ShardWorkEntry, WorkEpochClaim,
    };
    use shekyl_crypto_pq::derivation::hash_pqc_public_key;
    use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};

    const EM_EPOCH: u64 = 5;
    const EM_BUDGET: u64 = 1_000_000;
    const EM_SHARD_A: u64 = 7;
    const EM_SHARD_B: u64 = 9;

    /// Owned honest-emission scenario: two bonds (idx 0 = claimant on shard A
    /// only; idx 1 on A and B, so `R_market(A) = 2`), real hybrid keypairs and
    /// signatures over the vin's own Q1 role messages, work/reward derived
    /// through the same sourcing functions the FFI verify recomputes with.
    /// The backing proof is garbage bytes — step 6 is pinned positive in
    /// `shekyl-fcmp`'s KATs; here it is the terminal rejection that proves
    /// steps 1–5 and 8 already passed through the marshaling.
    struct EmissionFfiFixture {
        vin_bytes: Vec<u8>,
        p_pubkey: Vec<u8>,
        commits_flat: Vec<u8>,
        tx_hash: [u8; 32],
        reward: u64,
        sigma: u64,
        close: u64,
        ffi_bonds: Vec<ShekylArchivalEpochCloseBond>,
        ffi_shards: Vec<ShekylArchivalEpochCloseShard>,
        ffi_pairs: Vec<ShekylArchivalCreditPair>,
    }

    impl EmissionFfiFixture {
        fn build() -> Self {
            let close = epoch_close_height(EM_EPOCH).expect("fixture epoch closes");
            let curve = BandedCurveParams {
                plateau_work_milli: ARCHIVAL_REWARD_PLATEAU_WORK_MILLI,
                plateau_value_milli: ARCHIVAL_REWARD_PLATEAU_VALUE_MILLI,
            };
            let bonds = [
                EpochCloseBond {
                    join_settlement_epoch: 1,
                    is_foundation_complete_tree: false,
                    bad_intervals: &[],
                },
                EpochCloseBond {
                    join_settlement_epoch: 1,
                    is_foundation_complete_tree: false,
                    bad_intervals: &[],
                },
            ];
            let shards = [
                EpochCloseShard {
                    shard_id: EM_SHARD_A,
                    has_segment: true,
                    freeze_height: close - 5_000,
                },
                EpochCloseShard {
                    shard_id: EM_SHARD_B,
                    has_segment: true,
                    freeze_height: close - 8_000,
                },
            ];
            let pairs = [
                CreditPair {
                    bond_idx: 0,
                    shard_idx: 0,
                },
                CreditPair {
                    bond_idx: 1,
                    shard_idx: 0,
                },
                CreditPair {
                    bond_idx: 1,
                    shard_idx: 1,
                },
            ];
            let inputs = EpochCloseInputs {
                settlement_epoch: EM_EPOCH,
                close_block_height: close,
                settlement_epoch_blocks: SETTLEMENT_EPOCH_BLOCKS,
                age_weight_milli: ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
                curve,
                bonds: &bonds,
                shards: &shards,
                credit_pairs: &pairs,
                frozen_shard_count: 2,
                k_cover: KCover::consensus(),
            };
            let served = as_of_e_served_work(&inputs).expect("well-formed fixture");
            let work = served.work_by_bond[0];
            assert!(served.member[0] && work > 0, "fixture claimant must earn");
            let sigma = sigma_work_milli(&served.work_by_bond, &curve, &served.member);
            let reward = reward_share_floor(EM_BUDGET, curve_milli(work, &curve), sigma);
            assert!(reward > 0, "fixture reward must be wire-encodable (>0)");

            let scheme = HybridEd25519MlDsa;
            let (p_pk, p_sk) = scheme.keypair_generate().expect("P keypair");
            let (b_pk, b_sk) = scheme.keypair_generate().expect("backing keypair");
            let mut vin = ArchivalRewardEmissionVin {
                p_pubkey: p_pk.to_canonical_bytes().expect("canonical P pubkey"),
                holdings: HoldingsDescriptor {
                    kind: HoldingsKind::ShardSetCompact,
                    shard_ids: vec![EM_SHARD_A],
                },
                settlement_epochs: vec![EM_EPOCH],
                work_claim: vec![WorkEpochClaim {
                    epoch: EM_EPOCH,
                    shard_entries: vec![ShardWorkEntry {
                        shard_id: EM_SHARD_A,
                        serve_credit_bit: true,
                        scarcity_milli: u32::try_from(work).expect("fixture scarcity fits u32"),
                    }],
                }],
                backing: MembershipOnlyBacking {
                    proof: vec![0xAB; 64],
                    pseudo_out: [0x22; 32],
                    pqc_pk_hash: [0; 32],
                    backing_pubkey: b_pk.to_canonical_bytes().expect("canonical backing pubkey"),
                    tree_depth: 3,
                },
                reward_amount_plain: vec![reward],
                auth_backing: vec![0x55; SINGLE_SIG_CANONICAL_LEN],
                auth_claim: vec![0x66; SINGLE_SIG_CANONICAL_LEN],
            };
            vin.backing.pqc_pk_hash = hash_pqc_public_key(&vin.backing.backing_pubkey);
            assert_eq!(vin.p_pubkey.len(), SINGLE_KEY_CANONICAL_LEN);

            let commits = [RewardCommit {
                commitment: [0x71; 32],
                amount_plain: reward,
                one_time_key: [0x72; 32],
            }];
            let tx_hash = [0x5F; 32];
            let msgs = vin.auth_msgs(&commits, &tx_hash).expect("role messages");
            vin.auth_backing = scheme
                .sign(&b_sk, &msgs.backing)
                .expect("backing sign")
                .to_canonical_bytes()
                .expect("canonical backing sig");
            vin.auth_claim = scheme
                .sign(&p_sk, &msgs.claim)
                .expect("claim sign")
                .to_canonical_bytes()
                .expect("canonical claim sig");

            let mut commits_flat = Vec::with_capacity(72);
            commits_flat.extend_from_slice(&commits[0].commitment);
            commits_flat.extend_from_slice(&commits[0].amount_plain.to_le_bytes());
            commits_flat.extend_from_slice(&commits[0].one_time_key);

            Self {
                p_pubkey: vin.p_pubkey.clone(),
                vin_bytes: vin.serialize().expect("canonical wire"),
                commits_flat,
                tx_hash,
                reward,
                sigma,
                close,
                ffi_bonds: bonds
                    .iter()
                    .map(|b| ShekylArchivalEpochCloseBond {
                        join_settlement_epoch: b.join_settlement_epoch,
                        bad_intervals_ptr: ptr::null(),
                        bad_intervals_len: 0,
                        is_foundation_complete_tree: 0,
                    })
                    .collect(),
                ffi_shards: shards
                    .iter()
                    .map(|s| ShekylArchivalEpochCloseShard {
                        shard_id: s.shard_id,
                        freeze_height: s.freeze_height,
                        has_segment: 1,
                    })
                    .collect(),
                ffi_pairs: pairs
                    .iter()
                    .map(|p| ShekylArchivalCreditPair {
                        bond_idx: p.bond_idx,
                        shard_idx: p.shard_idx,
                    })
                    .collect(),
            }
        }

        fn snapshot(&self) -> ShekylArchivalEmissionEpochSnapshot {
            ShekylArchivalEmissionEpochSnapshot {
                settlement_epoch: EM_EPOCH,
                close_block_height: self.close,
                sigma_work_milli: self.sigma,
                budget_atomic: EM_BUDGET,
                bonds_ptr: self.ffi_bonds.as_ptr(),
                bonds_len: self.ffi_bonds.len(),
                shards_ptr: self.ffi_shards.as_ptr(),
                shards_len: self.ffi_shards.len(),
                credit_pairs_ptr: self.ffi_pairs.as_ptr(),
                credit_pairs_len: self.ffi_pairs.len(),
                claimant_bond_idx: 0,
            }
        }

        /// One coarse verify crossing with the honest operands, with the two
        /// knobs the negatives vary. Returns `(code, total_reward, epochs)`.
        fn verify(&self, bond_present: u8, tx_hash: &[u8; 32]) -> (u8, u64, Vec<u64>) {
            let snapshots = [self.snapshot()];
            let bond_shard_ids = [EM_SHARD_A];
            let tree_root = [0u8; 32];
            let mut out_total = u64::MAX;
            let mut out_epochs = [u64::MAX; 4];
            let mut out_len = usize::MAX;
            let code = unsafe {
                shekyl_emission_vin_verify(
                    self.vin_bytes.as_ptr(),
                    self.vin_bytes.len(),
                    self.close + 1,
                    self.reward,
                    bond_present,
                    1,
                    HoldingsKind::ShardSetCompact as u8,
                    bond_shard_ids.as_ptr(),
                    bond_shard_ids.len(),
                    ptr::null(),
                    0,
                    snapshots.as_ptr(),
                    snapshots.len(),
                    tree_root.as_ptr(),
                    3,
                    tx_hash.as_ptr(),
                    self.commits_flat.as_ptr(),
                    1,
                    ptr::from_mut(&mut out_total),
                    out_epochs.as_mut_ptr(),
                    out_epochs.len(),
                    ptr::from_mut(&mut out_len),
                )
            };
            assert!(
                out_len <= out_epochs.len(),
                "out_epochs_len must be written"
            );
            (code, out_total, out_epochs[..out_len].to_vec())
        }
    }

    /// Extract roundtrip: the pre-parse call surfaces `P_canonical_id`
    /// (recomputed from `P_pubkey`) and the claimed epochs from the opaque
    /// blob; truncated bytes and an undersized epoch buffer reject with
    /// zeroed outputs.
    #[test]
    fn emission_vin_extract_roundtrip_and_rejects() {
        let fx = EmissionFfiFixture::build();

        let mut pid = [0u8; 32];
        let mut epochs = [u64::MAX; 4];
        let mut epochs_len = usize::MAX;
        let code = unsafe {
            shekyl_archival_emission_vin_extract(
                fx.vin_bytes.as_ptr(),
                fx.vin_bytes.len(),
                pid.as_mut_ptr(),
                epochs.as_mut_ptr(),
                epochs.len(),
                ptr::from_mut(&mut epochs_len),
            )
        };
        assert_eq!(code, SHEKYL_EMISSION_VIN_OK);
        assert_eq!(epochs_len, 1);
        assert_eq!(epochs[0], EM_EPOCH);
        assert_eq!(
            &pid,
            p_canonical_id_from_hybrid_pubkey(&fx.p_pubkey).as_bytes(),
            "extract must key the bond record by the §6.1 canonical id"
        );

        // Truncated wire rejects (and a trailing byte would too: the parse is
        // length-exact).
        let mut epochs_len = usize::MAX;
        let code = unsafe {
            shekyl_archival_emission_vin_extract(
                fx.vin_bytes.as_ptr(),
                fx.vin_bytes.len() - 1,
                pid.as_mut_ptr(),
                epochs.as_mut_ptr(),
                epochs.len(),
                ptr::from_mut(&mut epochs_len),
            )
        };
        assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_WIRE);
        assert_eq!(epochs_len, 0, "failure path must not leave stale lengths");

        // Undersized epoch buffer and null pointers reject.
        let code = unsafe {
            shekyl_archival_emission_vin_extract(
                fx.vin_bytes.as_ptr(),
                fx.vin_bytes.len(),
                pid.as_mut_ptr(),
                epochs.as_mut_ptr(),
                0,
                ptr::from_mut(&mut epochs_len),
            )
        };
        assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_NULL_PTR);
        let code = unsafe {
            shekyl_archival_emission_vin_extract(
                ptr::null(),
                0,
                pid.as_mut_ptr(),
                epochs.as_mut_ptr(),
                epochs.len(),
                ptr::from_mut(&mut epochs_len),
            )
        };
        assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_NULL_PTR);
    }

    /// Block-level (P,E) uniqueness FFI over flattened 40-byte pairs — the
    /// §6.4 KAT-1 shape (same-block double-claim) through the marshaling
    /// boundary, plus the fail-closed null case.
    #[test]
    fn emission_block_claims_unique_ffi() {
        let flat = |pairs: &[([u8; 32], u64)]| -> Vec<u8> {
            let mut out = Vec::with_capacity(pairs.len() * 40);
            for (pid, epoch) in pairs {
                out.extend_from_slice(pid);
                out.extend_from_slice(&epoch.to_le_bytes());
            }
            out
        };
        let p = [0xaa; 32];
        let q = [0xbb; 32];

        // Distinct pairs (same P different E; different P same E) pass.
        let ok = flat(&[(p, 7), (p, 8), (q, 7)]);
        assert_eq!(
            unsafe { shekyl_emission_block_claims_unique(ok.as_ptr(), 3) },
            1
        );

        // Same-block duplicate (P, E) — non-adjacent — rejects.
        let dup = flat(&[(p, 7), (q, 3), (p, 7)]);
        assert_eq!(
            unsafe { shekyl_emission_block_claims_unique(dup.as_ptr(), 3) },
            0
        );

        // Empty block trivially unique; null with non-zero count fails closed.
        assert_eq!(
            unsafe { shekyl_emission_block_claims_unique(ptr::null(), 0) },
            1
        );
        assert_eq!(
            unsafe { shekyl_emission_block_claims_unique(ptr::null(), 1) },
            0
        );
    }

    /// End-to-end coarse verify over the honest fixture: claims (steps 1–5)
    /// and the hybrid auth gate (step 8) pass through the full FFI
    /// marshaling — snapshots, bond record, flattened reward commits — and
    /// the call terminates at step 6 rejecting the garbage backing proof.
    /// Reaching `BACKING_REJECTED` (not any earlier code) is the assertion:
    /// it proves the DoS ordering (auth before backing) and that every
    /// marshaled operand reproduced the crate-level honest fixture.
    #[test]
    fn emission_vin_verify_ffi_marshals_honest_operands_to_step_6() {
        let fx = EmissionFfiFixture::build();

        let (code, total, epochs) = fx.verify(1, &fx.tx_hash);
        assert_eq!(
            code, SHEKYL_EMISSION_VIN_ERR_BACKING_REJECTED,
            "honest claims + auths must reach (and stop at) the garbage proof"
        );
        assert_eq!(total, 0, "rejection must zero the mint output");
        assert!(epochs.is_empty(), "rejection must zero the commit set");

        // Auth-before-backing ordering: a tampered tx context breaks the Q1
        // binding messages, so the same vin now rejects at step 8 — earlier
        // than the backing proof it rejected at above.
        let mut wrong_hash = fx.tx_hash;
        wrong_hash[0] ^= 0x01;
        let (code, total, epochs) = fx.verify(1, &wrong_hash);
        assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_AUTH_REJECTED);
        assert_eq!(total, 0);
        assert!(epochs.is_empty());

        // Step 2: no bond record marshaled (`bond_present == 0`).
        let (code, total, epochs) = fx.verify(0, &fx.tx_hash);
        assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_BOND_MISSING);
        assert_eq!(total, 0);
        assert!(epochs.is_empty());
    }

    /// Marshaling negatives for the coarse verify: truncated wire, null
    /// pointers, and the diagnostic error-code map for the auth variants the
    /// C ABI collapses.
    #[test]
    fn emission_vin_verify_ffi_rejects_bad_marshaling() {
        let fx = EmissionFfiFixture::build();
        let snapshots = [fx.snapshot()];
        let tree_root = [0u8; 32];
        let mut out_total = u64::MAX;
        let mut out_epochs = [u64::MAX; 4];
        let mut out_len = usize::MAX;

        // Truncated vin bytes fail the length-exact parse.
        let code = unsafe {
            shekyl_emission_vin_verify(
                fx.vin_bytes.as_ptr(),
                fx.vin_bytes.len() - 1,
                fx.close + 1,
                fx.reward,
                0,
                0,
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                snapshots.as_ptr(),
                snapshots.len(),
                tree_root.as_ptr(),
                3,
                fx.tx_hash.as_ptr(),
                fx.commits_flat.as_ptr(),
                1,
                ptr::from_mut(&mut out_total),
                out_epochs.as_mut_ptr(),
                out_epochs.len(),
                ptr::from_mut(&mut out_len),
            )
        };
        assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_WIRE);
        assert_eq!(out_total, 0, "failure path must not leave stale outputs");
        assert_eq!(out_len, 0);

        // Null vin pointer rejects before any parse.
        let code = unsafe {
            shekyl_emission_vin_verify(
                ptr::null(),
                0,
                fx.close + 1,
                fx.reward,
                0,
                0,
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                snapshots.as_ptr(),
                snapshots.len(),
                tree_root.as_ptr(),
                3,
                fx.tx_hash.as_ptr(),
                fx.commits_flat.as_ptr(),
                1,
                ptr::from_mut(&mut out_total),
                out_epochs.as_mut_ptr(),
                out_epochs.len(),
                ptr::from_mut(&mut out_len),
            )
        };
        assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_NULL_PTR);

        // The C ABI's collapsed diagnostic map, pinned per auth variant.
        assert_eq!(
            map_emission_vin_error(&EmissionVerifyError::AuthMalformed {
                role: EmissionAuthRole::Claim
            }),
            SHEKYL_EMISSION_VIN_ERR_AUTH_MALFORMED
        );
        assert_eq!(
            map_emission_vin_error(&EmissionVerifyError::AuthRejected {
                role: EmissionAuthRole::Backing
            }),
            SHEKYL_EMISSION_VIN_ERR_AUTH_REJECTED
        );
    }
}
