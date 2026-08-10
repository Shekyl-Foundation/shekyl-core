// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Serve-credit vin verification FFI (`ARCHIVAL_RETENTION_GATE2.md` §5.3).

use std::io::Cursor;

use shekyl_archival_retention::{
    challenge_fire_height, verify_leaf_index, verify_segment_path, ArchivalServeCreditResponse,
};
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, HybridPublicKey, SignatureScheme};
use shekyl_fcmp::SCALARS_PER_LEAF;

use super::codes::*;
use super::schedule::{settlement_epoch_close_height, settlement_epoch_open_height};

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
    // F1 fixed by SA-R-1: under `verify -> Result<()>` there is no `Ok(false)`,
    // so `.is_err()` now correctly rejects a well-formed wrong-key signature
    // (it previously let `Ok(false)` fall through to VERIFY_OK). Surface F domain.
    if HybridEd25519MlDsa
        .verify(
            &pk,
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_SERVE_CREDIT,
            &preimage,
            &response.hybrid_signature,
        )
        .is_err()
    {
        return SHEKYL_ARCHIVAL_VERIFY_ERR_PQC_VERIFY;
    }

    SHEKYL_ARCHIVAL_VERIFY_OK
}
