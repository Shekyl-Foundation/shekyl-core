// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Settlement-epoch schedule and challenge-timing FFI.

use shekyl_archival_retention::{
    challenge_fire_height, challenge_leaf_chunk_bounds, challenge_seal_height,
    challenge_seal_on_chain, effective_settlement_epoch_blocks, empty_attestation_root,
    epoch_close_height, frozen_segment_count, p_canonical_id_from_hybrid_pubkey,
    ATTESTATION_HEADER_LEN, CHALLENGE_RESOLUTION_BLOCKS, MAX_ATTESTATION_RECORDS,
    MAX_ATTESTATION_WITNESS_BYTES,
};

pub fn settlement_epoch_open_height(e: u64) -> u64 {
    e.saturating_mul(effective_settlement_epoch_blocks())
}

#[must_use]
pub fn settlement_epoch_close_height(e: u64) -> u64 {
    settlement_epoch_open_height(e.saturating_add(1)).saturating_sub(1)
}

#[must_use]
pub fn settlement_epoch_slash_deadline_height(e: u64) -> u64 {
    settlement_epoch_close_height(e).saturating_add(CHALLENGE_RESOLUTION_BLOCKS)
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

// ── Attestation-witness cross-language constant authorities (credit-wire CW-2,
//    gate CW-1b-iv). These expose the Rust-side authoritative values so C++ can
//    assert its own `config::` constants agree — the real gate replacing the "must
//    equal" doc-comment. The block-hash differential is blind to the witness (it is
//    not in the block blob), so these + the byte-pinned witness KAT are the only
//    checks on this surface. ──

/// Genesis-frozen consensus cap on attestation records per block. C++ asserts
/// `config::ARCHIVAL_MAX_ATTESTATION_RECORDS` equals this.
#[no_mangle]
pub extern "C" fn shekyl_archival_max_attestation_records() -> u64 {
    MAX_ATTESTATION_RECORDS as u64
}

/// Canonical length of one kept attestation header (`p_id ‖ s ‖ E ‖ kind`). C++
/// asserts `config::ARCHIVAL_ATTESTATION_HEADER_BYTES` equals this.
#[no_mangle]
pub extern "C" fn shekyl_archival_attestation_header_bytes() -> u64 {
    ATTESTATION_HEADER_LEN as u64
}

/// The EXACT maximum canonical byte length of a block's attestation witness
/// (`r ‖ count ‖ MAX records × HybridSignature`).
///
/// `config::ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES` is defined as this same
/// quantity and C++ asserts equality. Below it, C++ would reject on the wire a
/// witness Rust admits — a consensus split; above it, every block gets that much
/// free padding an attacker may fill. Equality is the only value with neither
/// property, and it makes any drift in either language's operands loud.
#[no_mangle]
pub extern "C" fn shekyl_archival_attestation_witness_max_bytes() -> u64 {
    MAX_ATTESTATION_WITNESS_BYTES as u64
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

/// Is the epoch's challenge seal block committed at `chain_height`? (1 = on
/// chain, 0 = not yet.) `chain_height` is the block count (`m_db->height()`), so
/// the seal (`H_seal = challenge_seal_height(h_open)`) is on chain iff
/// `H_seal < chain_height`. The serve-credit gate calls this before reading
/// `block_hash(H_seal)`, so a future-epoch (attacker-chosen `settlement_epoch`)
/// input is rejected by predicate rather than by catching a `BLOCK_DNE` throw.
#[no_mangle]
pub extern "C" fn shekyl_archival_challenge_seal_on_chain(h_open: u64, chain_height: u64) -> u8 {
    u8::from(challenge_seal_on_chain(h_open, chain_height))
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

/// Empty-set archival attestation root — `attestation_root(&[])`
/// (`ARCHIVAL_CREDIT_WIRE.md` §3). The valid empty commitment a block header
/// carries when it has no pass records; **not** the all-zero `null_hash`.
///
/// # Safety
/// `out_ptr` must be non-null and point at 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_attestation_root_empty(out_ptr: *mut u8) -> bool {
    if out_ptr.is_null() {
        return false;
    }
    let root = empty_attestation_root();
    std::ptr::copy_nonoverlapping(root.as_ptr(), out_ptr, 32);
    true
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
