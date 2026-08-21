// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Serve-credit vin verification FFI (`ARCHIVAL_RETENTION_GATE2.md` §5.3).

use std::io::Cursor;

use shekyl_archival_retention::{
    challenge_fire_height, challenge_leaf_index, challenged_leaf_bytes,
    challenged_leaf_offset_in_chunk, hybrid_countersignature, verify_segment_path,
    ArchivalServeCreditPruned, ArchivalServeCreditResponse,
};
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, HybridPublicKey, SignatureScheme};
use shekyl_fcmp::SCALARS_PER_LEAF;

use super::codes::*;
use super::schedule::{settlement_epoch_close_height, settlement_epoch_open_height};
use crate::legacy_util::{array_from_ptr, slice_from_ptr};

/// Extract the three fields C++ indexes a serve-credit by — `(P, shard, E)` —
/// from the opaque kept-side vin bytes (`canonical_bytes`, tag byte excluded).
///
/// The Rust codec is the blob's only parser (rule 40, same shape as
/// `shekyl_archival_emission_vin_extract`); C++ reads nothing past the tag.
///
/// # Safety
/// `vin_ptr[..vin_len]` must be readable; `out_p_canonical_id` must point at
/// 32 writable bytes; `out_shard_id` / `out_settlement_epoch` must be valid.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_serve_credit_extract(
    vin_ptr: *const u8,
    vin_len: usize,
    out_p_canonical_id: *mut u8,
    out_shard_id: *mut u64,
    out_settlement_epoch: *mut u64,
) -> u8 {
    if vin_ptr.is_null()
        || vin_len == 0
        || out_p_canonical_id.is_null()
        || out_shard_id.is_null()
        || out_settlement_epoch.is_null()
    {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR;
    }
    let Some(bytes) = (unsafe { slice_from_ptr(vin_ptr, vin_len) }) else {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR;
    };
    let kept = match ArchivalServeCreditResponse::read_payload_exact(&mut Cursor::new(bytes)) {
        Ok(k) => k,
        Err(e) => return map_wire_error(&e),
    };
    unsafe {
        std::ptr::copy_nonoverlapping(kept.p_canonical_id.as_ptr(), out_p_canonical_id, 32);
        *out_shard_id = kept.shard_id;
        *out_settlement_epoch = kept.settlement_epoch;
    }
    SHEKYL_ARCHIVAL_VERIFY_OK
}

/// The verifier-derived challenge leaf index (`RF-D6`: never transported).
///
/// # Safety
/// `p_canonical_id` must point at 32 readable bytes; `out_leaf_index` must be
/// valid.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_challenge_leaf_index(
    p_canonical_id: *const u8,
    shard_id: u64,
    settlement_epoch: u64,
    segment_leaf_count: u64,
    out_leaf_index: *mut u32,
) -> u8 {
    if p_canonical_id.is_null() || out_leaf_index.is_null() {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR;
    }
    if segment_leaf_count == 0 {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_ZERO_GEOMETRY;
    }
    let Some(p_id) = (unsafe { array_from_ptr::<32>(p_canonical_id) }) else {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR;
    };
    let idx = challenge_leaf_index(&p_id, shard_id, settlement_epoch, segment_leaf_count);
    unsafe { *out_leaf_index = idx };
    SHEKYL_ARCHIVAL_VERIFY_OK
}

/// Verify one pass record — kept half (the vin's `canonical_bytes`, tag byte
/// excluded) plus its pruned half (this vin's slice of the prunable region) —
/// for steps 4–9 of gate-2 §5.3. Bond posture, market, and idempotency are
/// C++-side.
///
/// # Safety
/// Both byte ranges and `ctx` (with its pointed-to buffers) must be readable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_verify_serve_credit_vin(
    vin_payload_ptr: *const u8,
    vin_payload_len: usize,
    pruned_ptr: *const u8,
    pruned_len: usize,
    ctx_ptr: *const ShekylArchivalVerifyCtx,
) -> u8 {
    if vin_payload_ptr.is_null() || pruned_ptr.is_null() || ctx_ptr.is_null() {
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
    let Some(pruned_bytes) = (unsafe { slice_from_ptr(pruned_ptr, pruned_len) }) else {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR;
    };
    let pruned = match ArchivalServeCreditPruned::read_exact(&mut Cursor::new(pruned_bytes)) {
        Ok(p) => p,
        Err(e) => return map_wire_error(&e),
    };

    if response.settlement_epoch != ctx.settlement_epoch {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_EPOCH_MISMATCH;
    }

    // RF-D6 / RF-D8: `R_k` and the challenged leaf index are VERIFIER-DERIVED,
    // never read off the vin. `R_k` is the registry's (C++ supplies it in
    // `ctx.registry_segment_subroot_rk` from its own frozen-segment record);
    // the index is `challenge_leaf_index` over public inputs. Before this
    // change both were also transported and compared against these same
    // derivations -- a check that could only ever confirm what the verifier
    // already knew, while leaving a prover-chosen value in the record for a
    // less careful implementation to trust. Now there is nothing on the wire
    // to compare: the derived values go straight into path verification and
    // the signature preimage, so a prover that disagrees with them cannot
    // produce a verifying signature.
    let leaf_index = challenge_leaf_index(
        &response.p_canonical_id,
        response.shard_id,
        response.settlement_epoch,
        ctx.segment_leaf_count,
    );

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

    // RF-D8: the challenged leaf is read from the verifier's own chunk at the
    // derived offset, never from the wire.
    let Some(leaf_offset) =
        challenged_leaf_offset_in_chunk(response.shard_id, u64::from(leaf_index))
    else {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_LEAF_NOT_IN_OPENING;
    };
    let Some(leaf_bytes) = challenged_leaf_bytes(&scalars, leaf_offset) else {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_LEAF_NOT_IN_OPENING;
    };

    if let Err(e) = verify_segment_path(
        &scalars,
        leaf_offset,
        &pruned.path,
        &ctx.registry_segment_subroot_rk,
    ) {
        return map_verify_error(&e);
    }

    let preimage = response.signature_preimage(
        &ctx.registry_segment_subroot_rk,
        leaf_index,
        &leaf_bytes,
        &pruned.path,
    );
    let countersignature = hybrid_countersignature(&response, &pruned);
    let pubkey = unsafe { std::slice::from_raw_parts(ctx.pqc_pubkey_ptr, ctx.pqc_pubkey_len) };
    let pk = match HybridPublicKey::from_canonical_bytes(pubkey) {
        Ok(pk) => pk,
        Err(_) => return SHEKYL_ARCHIVAL_VERIFY_ERR_PQC_DESER,
    };
    // F1 fixed by SA-R-1: under `verify -> Result<()>` there is no `Ok(false)`,
    // so `.is_err()` now correctly rejects a well-formed wrong-key signature
    // (it previously let `Ok(false)` fall through to VERIFY_OK). Surface F domain.
    if HybridEd25519MlDsa
        .verify(
            &pk,
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_SERVE_CREDIT,
            &preimage,
            &countersignature,
        )
        .is_err()
    {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_PQC_VERIFY;
    }

    SHEKYL_ARCHIVAL_VERIFY_OK
}
