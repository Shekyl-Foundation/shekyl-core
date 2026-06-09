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
    challenge_fire_height, challenge_seal_height, p_canonical_id_from_hybrid_pubkey,
    verify_bond_post_rct_balance, verify_leaf_index, verify_segment_path,
    ArchivalServeCreditResponse, BondRctBalanceError, WireError, CHALLENGE_RESOLUTION_BLOCKS,
    SETTLEMENT_EPOCH_BLOCKS,
};
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, HybridPublicKey, SignatureScheme};
use shekyl_fcmp::SCALARS_PER_LEAF;

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

/// Bond-post RCT balance sum matches (ARCHIVAL_BOND_GATE4.md §3.2).
pub const SHEKYL_ARCHIVAL_BOND_RCT_BALANCE_OK: u8 = 0;
/// Required pointer was null while count > 0.
pub const SHEKYL_ARCHIVAL_BOND_RCT_BALANCE_ERR_NULL_PTR: u8 = 1;
/// Both `bond_credit` and `bond_debit` are non-zero.
pub const SHEKYL_ARCHIVAL_BOND_RCT_BALANCE_ERR_BOTH_TERMS: u8 = 2;
/// A pseudo-out or output mask is not a valid curve point.
pub const SHEKYL_ARCHIVAL_BOND_RCT_BALANCE_ERR_INVALID_POINT: u8 = 3;
/// Left and right commitment sums differ.
pub const SHEKYL_ARCHIVAL_BOND_RCT_BALANCE_ERR_SUM_MISMATCH: u8 = 4;

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
        std::ptr::copy_nonoverlapping(pid.as_ptr(), out_p_id, 32);
    }
    1
}

/// Global settlement-epoch block span (`SETTLEMENT_EPOCH_BLOCKS`).
#[no_mangle]
pub extern "C" fn shekyl_archival_settlement_epoch_blocks() -> u64 {
    SETTLEMENT_EPOCH_BLOCKS
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

fn map_bond_rct_balance_error(err: BondRctBalanceError) -> u8 {
    match err {
        BondRctBalanceError::BothTermsNonzero => SHEKYL_ARCHIVAL_BOND_RCT_BALANCE_ERR_BOTH_TERMS,
        BondRctBalanceError::InvalidPoint => SHEKYL_ARCHIVAL_BOND_RCT_BALANCE_ERR_INVALID_POINT,
        BondRctBalanceError::SumMismatch => SHEKYL_ARCHIVAL_BOND_RCT_BALANCE_ERR_SUM_MISMATCH,
    }
}

/// Flattened `count × 32` commitment keys from a C pointer; rejects overflow and oversize slices.
fn flat_commitment_keys<'a>(ptr: *const u8, count: usize) -> Result<&'a [u8], u8> {
    if count == 0 {
        return Ok(&[]);
    }
    let Some(byte_len) = count.checked_mul(32) else {
        return Err(SHEKYL_ARCHIVAL_BOND_RCT_BALANCE_ERR_INVALID_POINT);
    };
    if byte_len > isize::MAX as usize {
        return Err(SHEKYL_ARCHIVAL_BOND_RCT_BALANCE_ERR_INVALID_POINT);
    }
    // SAFETY: caller guarantees `ptr` addresses `byte_len` valid bytes when count > 0.
    Ok(unsafe { std::slice::from_raw_parts(ptr, byte_len) })
}

/// Verify bond-post RCT balance: `sum(pseudoOuts) + bond_debit = sum(out masks) + fee + bond_credit`.
///
/// `pseudo_outs_ptr` and `out_masks_ptr` are flattened `N × 32` byte arrays; either pointer may
/// be null when the corresponding count is zero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_verify_bond_post_rct_balance(
    pseudo_outs_ptr: *const u8,
    num_pseudo_outs: usize,
    out_masks_ptr: *const u8,
    num_out_masks: usize,
    txn_fee: u64,
    bond_credit: u64,
    bond_debit: u64,
) -> u8 {
    if num_pseudo_outs > 0 && pseudo_outs_ptr.is_null() {
        return SHEKYL_ARCHIVAL_BOND_RCT_BALANCE_ERR_NULL_PTR;
    }
    if num_out_masks > 0 && out_masks_ptr.is_null() {
        return SHEKYL_ARCHIVAL_BOND_RCT_BALANCE_ERR_NULL_PTR;
    }

    let pseudo_flat = match flat_commitment_keys(pseudo_outs_ptr, num_pseudo_outs) {
        Ok(slice) => slice,
        Err(code) => return code,
    };
    let mask_flat = match flat_commitment_keys(out_masks_ptr, num_out_masks) {
        Ok(slice) => slice,
        Err(code) => return code,
    };

    match verify_bond_post_rct_balance(pseudo_flat, mask_flat, txn_fee, bond_credit, bond_debit) {
        Ok(()) => SHEKYL_ARCHIVAL_BOND_RCT_BALANCE_OK,
        Err(e) => map_bond_rct_balance_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn ffi_constants_match_timing_cluster() {
        assert_eq!(shekyl_archival_settlement_epoch_blocks(), 10_000);
        assert_eq!(shekyl_archival_epoch_open_height(100), 1_000_000);
        assert_eq!(shekyl_archival_epoch_close_height(100), 1_009_999);
    }

    #[test]
    fn ffi_rejects_null_context() {
        let code = unsafe { shekyl_archival_verify_serve_credit_vin(ptr::null(), 0, ptr::null()) };
        assert_eq!(code, SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR);
    }

    #[test]
    fn bond_rct_balance_ffi_rejects_null_with_nonzero_count() {
        let code = unsafe {
            shekyl_archival_verify_bond_post_rct_balance(ptr::null(), 1, ptr::null(), 0, 0, 0, 0)
        };
        assert_eq!(code, SHEKYL_ARCHIVAL_BOND_RCT_BALANCE_ERR_NULL_PTR);
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
}
