// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tx-proof and reserve-proof FFI.

use super::legacy_types::*;
use super::legacy_util::*;

// ─── Engine proof FFI exports ────────────────────────────────────────────────
//
// These FFI wrappers delegate to shekyl_proofs::{tx_proof, reserve_proof}.
// The C++ caller gathers wallet/blockchain data into flat byte arrays; Rust
// handles all cryptographic proof generation and verification.

/// Generate outbound transaction proof (sender proves payment).
///
/// Rust re-derives `combined_ss` from `tx_key_secret` + recipient KEM keys,
/// projects to `ProofSecrets`, and builds the Schnorr proof.
///
/// # Safety
/// - `tx_key_secret`, `txid`: 32 bytes each.
/// - `address`: `address_len` bytes.
/// - `message`: `message_len` bytes (may be 0).
/// - `recipient_x25519_pk`: 32 bytes.
/// - `recipient_ml_kem_ek`: `ml_kem_ek_len` bytes.
/// - `output_indices`: `output_count` u64 values.
/// - `proof_out`: writable `ShekylBuffer`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_generate_tx_proof_outbound(
    tx_key_secret: *const u8,
    txid: *const u8,
    address: *const u8,
    address_len: usize,
    message: *const u8,
    message_len: usize,
    recipient_x25519_pk: *const u8,
    recipient_ml_kem_ek: *const u8,
    ml_kem_ek_len: usize,
    output_indices: *const u64,
    output_count: u32,
    proof_out: *mut ShekylBuffer,
) -> bool {
    let Some(tx_key) = arr32_from_ptr(tx_key_secret) else {
        return false;
    };
    let Some(tx_id) = arr32_from_ptr(txid) else {
        return false;
    };
    let Some(addr) = (unsafe { slice_from_ptr(address, address_len) }) else {
        return false;
    };
    let msg = if message_len == 0 {
        &[] as &[u8]
    } else {
        match unsafe { slice_from_ptr(message, message_len) } {
            Some(v) => v,
            None => return false,
        }
    };
    let Some(x25519_pk) = arr32_from_ptr(recipient_x25519_pk) else {
        return false;
    };
    let Some(ml_kem_ek) = (unsafe { slice_from_ptr(recipient_ml_kem_ek, ml_kem_ek_len) }) else {
        return false;
    };
    if proof_out.is_null() || output_count == 0 || output_indices.is_null() {
        return false;
    }

    let indices = std::slice::from_raw_parts(output_indices, output_count as usize);

    match shekyl_proofs::tx_proof::generate_outbound_proof(
        &tx_key, &tx_id, addr, msg, &x25519_pk, ml_kem_ek, indices,
    ) {
        Ok(proof_bytes) => {
            *proof_out = ShekylBuffer::from_vec(proof_bytes);
            true
        }
        Err(e) => {
            let _ = e;
            false
        }
    }
}

/// Verify outbound transaction proof.
///
/// On success, writes verified per-output amounts to `amounts_out`.
///
/// # Safety
/// - `proof_bytes`: `proof_len` bytes.
/// - `txid`, `recipient_spend_pubkey`, `recipient_x25519_pk`: 32 bytes each.
/// - `address`: `address_len` bytes.
/// - `recipient_ml_kem_ek`: `ml_kem_ek_len` bytes.
/// - `output_keys`, `commitments`, `x25519_eph_pks`: `output_count * 32` each.
/// - `enc_amounts`: `output_count * 8` bytes.
/// - `ml_kem_cts`: `ml_kem_cts_len` bytes total (contiguous, evenly divisible).
/// - `amounts_out`: `output_count` u64 values.
#[no_mangle]
pub unsafe extern "C" fn shekyl_verify_tx_proof_outbound(
    proof_bytes: *const u8,
    proof_len: usize,
    txid: *const u8,
    address: *const u8,
    address_len: usize,
    message: *const u8,
    message_len: usize,
    recipient_spend_pubkey: *const u8,
    recipient_x25519_pk: *const u8,
    recipient_ml_kem_ek: *const u8,
    ml_kem_ek_len: usize,
    output_keys: *const u8,
    commitments: *const u8,
    enc_amounts: *const u8,
    x25519_eph_pks: *const u8,
    ml_kem_cts: *const u8,
    ml_kem_cts_len: usize,
    output_count: u32,
    amounts_out: *mut u64,
) -> bool {
    let Some(proof) = (unsafe { slice_from_ptr(proof_bytes, proof_len) }) else {
        return false;
    };
    let Some(tx_id) = arr32_from_ptr(txid) else {
        return false;
    };
    let Some(addr) = (unsafe { slice_from_ptr(address, address_len) }) else {
        return false;
    };
    let msg = if message_len == 0 {
        &[] as &[u8]
    } else {
        match unsafe { slice_from_ptr(message, message_len) } {
            Some(v) => v,
            None => return false,
        }
    };
    let Some(spend_pk) = arr32_from_ptr(recipient_spend_pubkey) else {
        return false;
    };
    let Some(x25519_pk) = arr32_from_ptr(recipient_x25519_pk) else {
        return false;
    };
    let Some(ml_ek) = (unsafe { slice_from_ptr(recipient_ml_kem_ek, ml_kem_ek_len) }) else {
        return false;
    };
    let n = output_count as usize;
    if amounts_out.is_null() || n == 0 {
        return false;
    }

    let Some(okeys) = (unsafe { slice_from_ptr(output_keys, n * 32) }) else {
        return false;
    };
    let Some(comms) = (unsafe { slice_from_ptr(commitments, n * 32) }) else {
        return false;
    };
    let Some(eamts) = (unsafe { slice_from_ptr(enc_amounts, n * 8) }) else {
        return false;
    };
    let Some(eph_pks) = (unsafe { slice_from_ptr(x25519_eph_pks, n * 32) }) else {
        return false;
    };
    let Some(ml_cts) = (unsafe { slice_from_ptr(ml_kem_cts, ml_kem_cts_len) }) else {
        return false;
    };

    if !ml_kem_cts_len.is_multiple_of(n) {
        return false;
    }
    let ct_size = ml_kem_cts_len / n;

    let on_chain: Vec<shekyl_proofs::tx_proof::OnChainOutput> = (0..n)
        .map(|i| {
            let mut ok = [0u8; 32];
            let mut cm = [0u8; 32];
            let mut ea = [0u8; 8];
            let mut ep = [0u8; 32];
            ok.copy_from_slice(&okeys[i * 32..(i + 1) * 32]);
            cm.copy_from_slice(&comms[i * 32..(i + 1) * 32]);
            ea.copy_from_slice(&eamts[i * 8..(i + 1) * 8]);
            ep.copy_from_slice(&eph_pks[i * 32..(i + 1) * 32]);
            shekyl_proofs::tx_proof::OnChainOutput {
                output_key: ok,
                commitment: cm,
                enc_amount: ea,
                x25519_eph_pk: ep,
                ml_kem_ct: ml_cts[i * ct_size..(i + 1) * ct_size].to_vec(),
            }
        })
        .collect();

    match shekyl_proofs::tx_proof::verify_outbound_proof(
        proof, &tx_id, addr, msg, &spend_pk, &x25519_pk, ml_ek, &on_chain,
    ) {
        Ok(verified) => {
            let out_slice = std::slice::from_raw_parts_mut(amounts_out, n);
            for v in &verified {
                if v.output_index < n {
                    out_slice[v.output_index] = v.amount;
                }
            }
            true
        }
        Err(e) => {
            let _ = e;
            false
        }
    }
}

/// Generate inbound transaction proof (recipient proves receipt).
///
/// # Safety
/// - `view_secret_key`, `txid`: 32 bytes each.
/// - `address`: `address_len` bytes.
/// - `proof_secrets`: `output_count * 128` bytes (ho[32]+y[32]+z[32]+k_amount[32]).
/// - `output_indices`: `output_count` u32 vout indices, strictly increasing,
///   entry i pairing with proof-secrets entry i.
/// - `proof_out`: writable `ShekylBuffer`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_generate_tx_proof_inbound(
    view_secret_key: *const u8,
    txid: *const u8,
    address: *const u8,
    address_len: usize,
    message: *const u8,
    message_len: usize,
    proof_secrets_ptr: *const u8,
    output_indices: *const u32,
    output_count: u32,
    proof_out: *mut ShekylBuffer,
) -> bool {
    let Some(vsk) = arr32_from_ptr(view_secret_key) else {
        return false;
    };
    let Some(tx_id) = arr32_from_ptr(txid) else {
        return false;
    };
    let Some(addr) = (unsafe { slice_from_ptr(address, address_len) }) else {
        return false;
    };
    let msg = if message_len == 0 {
        &[] as &[u8]
    } else {
        match unsafe { slice_from_ptr(message, message_len) } {
            Some(v) => v,
            None => return false,
        }
    };
    let n = output_count as usize;
    if proof_out.is_null() || n == 0 {
        return false;
    }

    let Some(ps_bytes) = (unsafe { slice_from_ptr(proof_secrets_ptr, n * 128) }) else {
        return false;
    };
    if output_indices.is_null() {
        return false;
    }
    let indices = unsafe { std::slice::from_raw_parts(output_indices, n) };
    let secrets: Vec<(u32, shekyl_crypto_pq::output::ProofSecrets)> = (0..n)
        .map(|i| {
            let base = i * 128;
            let mut ho = [0u8; 32];
            let mut y = [0u8; 32];
            let mut z = [0u8; 32];
            let mut k_amount = [0u8; 32];
            ho.copy_from_slice(&ps_bytes[base..base + 32]);
            y.copy_from_slice(&ps_bytes[base + 32..base + 64]);
            z.copy_from_slice(&ps_bytes[base + 64..base + 96]);
            k_amount.copy_from_slice(&ps_bytes[base + 96..base + 128]);
            (
                indices[i],
                shekyl_crypto_pq::output::ProofSecrets { ho, y, z, k_amount },
            )
        })
        .collect();

    match shekyl_proofs::tx_proof::generate_inbound_proof(&vsk, &tx_id, addr, msg, &secrets) {
        Ok(proof_bytes) => {
            *proof_out = ShekylBuffer::from_vec(proof_bytes);
            true
        }
        Err(e) => {
            let _ = e;
            false
        }
    }
}

/// Verify inbound transaction proof.
///
/// # Safety
/// - `proof_bytes`: `proof_len` bytes.
/// - `txid`, `view_public_key`, `recipient_spend_pubkey`: 32 bytes each.
/// - `output_keys`, `commitments`, `x25519_eph_pks`: `output_count * 32` each.
/// - `enc_amounts`: `output_count * 8` bytes.
/// - `ml_kem_cts`: `ml_kem_cts_len` bytes total.
/// - `amounts_out`: `output_count` u64 values.
#[no_mangle]
pub unsafe extern "C" fn shekyl_verify_tx_proof_inbound(
    proof_bytes: *const u8,
    proof_len: usize,
    txid: *const u8,
    address: *const u8,
    address_len: usize,
    message: *const u8,
    message_len: usize,
    view_public_key: *const u8,
    recipient_spend_pubkey: *const u8,
    output_keys: *const u8,
    commitments: *const u8,
    enc_amounts: *const u8,
    x25519_eph_pks: *const u8,
    ml_kem_cts: *const u8,
    ml_kem_cts_len: usize,
    output_count: u32,
    amounts_out: *mut u64,
) -> bool {
    let Some(proof) = (unsafe { slice_from_ptr(proof_bytes, proof_len) }) else {
        return false;
    };
    let Some(tx_id) = arr32_from_ptr(txid) else {
        return false;
    };
    let Some(addr) = (unsafe { slice_from_ptr(address, address_len) }) else {
        return false;
    };
    let msg = if message_len == 0 {
        &[] as &[u8]
    } else {
        match unsafe { slice_from_ptr(message, message_len) } {
            Some(v) => v,
            None => return false,
        }
    };
    let Some(vpk) = arr32_from_ptr(view_public_key) else {
        return false;
    };
    let Some(spend_pk) = arr32_from_ptr(recipient_spend_pubkey) else {
        return false;
    };
    let n = output_count as usize;
    if amounts_out.is_null() || n == 0 {
        return false;
    }

    let Some(okeys) = (unsafe { slice_from_ptr(output_keys, n * 32) }) else {
        return false;
    };
    let Some(comms) = (unsafe { slice_from_ptr(commitments, n * 32) }) else {
        return false;
    };
    let Some(eamts) = (unsafe { slice_from_ptr(enc_amounts, n * 8) }) else {
        return false;
    };
    let Some(eph_pks) = (unsafe { slice_from_ptr(x25519_eph_pks, n * 32) }) else {
        return false;
    };
    let Some(ml_cts) = (unsafe { slice_from_ptr(ml_kem_cts, ml_kem_cts_len) }) else {
        return false;
    };

    if !ml_kem_cts_len.is_multiple_of(n) {
        return false;
    }
    let ct_size = ml_kem_cts_len / n;

    let on_chain: Vec<shekyl_proofs::tx_proof::OnChainOutput> = (0..n)
        .map(|i| {
            let mut ok = [0u8; 32];
            let mut cm = [0u8; 32];
            let mut ea = [0u8; 8];
            let mut ep = [0u8; 32];
            ok.copy_from_slice(&okeys[i * 32..(i + 1) * 32]);
            cm.copy_from_slice(&comms[i * 32..(i + 1) * 32]);
            ea.copy_from_slice(&eamts[i * 8..(i + 1) * 8]);
            ep.copy_from_slice(&eph_pks[i * 32..(i + 1) * 32]);
            shekyl_proofs::tx_proof::OnChainOutput {
                output_key: ok,
                commitment: cm,
                enc_amount: ea,
                x25519_eph_pk: ep,
                ml_kem_ct: ml_cts[i * ct_size..(i + 1) * ct_size].to_vec(),
            }
        })
        .collect();

    match shekyl_proofs::tx_proof::verify_inbound_proof(
        proof, &tx_id, addr, msg, &vpk, &spend_pk, &on_chain,
    ) {
        Ok(verified) => {
            let out_slice = std::slice::from_raw_parts_mut(amounts_out, n);
            for v in &verified {
                if v.output_index < n {
                    out_slice[v.output_index] = v.amount;
                }
            }
            true
        }
        Err(e) => {
            let _ = e;
            false
        }
    }
}

/// Generate reserve proof (prove ownership of unspent outputs).
///
/// # Safety
/// - `spend_secret_key`: 32 bytes.
/// - `address`: `address_len` bytes.
/// - `proof_secrets`: `output_count * 128` bytes.
/// - `key_images`, `output_keys`: `output_count * 32` each.
/// - `proof_out`: writable `ShekylBuffer`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_generate_reserve_proof(
    spend_secret_key: *const u8,
    address: *const u8,
    address_len: usize,
    message: *const u8,
    message_len: usize,
    proof_secrets_ptr: *const u8,
    key_images: *const u8,
    output_keys: *const u8,
    output_count: u32,
    proof_out: *mut ShekylBuffer,
) -> bool {
    // Master spend secret: read the C bytes *directly* into a `Zeroizing`
    // buffer so no intermediate plaintext stack copy ever exists (rule 30
    // direct-write; rule 35 wipe-on-drop). `&bsk` deref-coerces to `&[u8; 32]`
    // at the `generate_reserve_proof` call site below.
    let Some(bsk) = zeroizing_arr32_from_ptr(spend_secret_key) else {
        return false;
    };
    let Some(addr) = (unsafe { slice_from_ptr(address, address_len) }) else {
        return false;
    };
    let msg = if message_len == 0 {
        &[] as &[u8]
    } else {
        match unsafe { slice_from_ptr(message, message_len) } {
            Some(v) => v,
            None => return false,
        }
    };
    let n = output_count as usize;
    if proof_out.is_null() || n == 0 {
        return false;
    }

    let Some(ps_bytes) = (unsafe { slice_from_ptr(proof_secrets_ptr, n * 128) }) else {
        return false;
    };
    let Some(ki_bytes) = (unsafe { slice_from_ptr(key_images, n * 32) }) else {
        return false;
    };
    let Some(ok_bytes) = (unsafe { slice_from_ptr(output_keys, n * 32) }) else {
        return false;
    };

    use zeroize::Zeroize;
    let entries: Vec<shekyl_proofs::reserve_proof::ReserveOutputEntry> = (0..n)
        .map(|i| {
            let base = i * 128;
            let mut ho = [0u8; 32];
            let mut y = [0u8; 32];
            let mut z = [0u8; 32];
            let mut k_amount = [0u8; 32];
            ho.copy_from_slice(&ps_bytes[base..base + 32]);
            y.copy_from_slice(&ps_bytes[base + 32..base + 64]);
            z.copy_from_slice(&ps_bytes[base + 64..base + 96]);
            k_amount.copy_from_slice(&ps_bytes[base + 96..base + 128]);

            let mut ki = [0u8; 32];
            let mut ok = [0u8; 32];
            ki.copy_from_slice(&ki_bytes[i * 32..(i + 1) * 32]);
            ok.copy_from_slice(&ok_bytes[i * 32..(i + 1) * 32]);

            let entry = shekyl_proofs::reserve_proof::ReserveOutputEntry {
                proof_secrets: shekyl_crypto_pq::output::ProofSecrets { ho, y, z, k_amount },
                key_image: shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(ki),
                output_key: ok,
            };
            // The entry now owns its own copies; `ProofSecrets` is
            // `ZeroizeOnDrop`. Wipe the plain `[u8; 32]` stack copies of the
            // *secret* inputs (the HKDF scalars) so no unprotected duplicate
            // outlives this iteration; `zeroize()` uses volatile writes the
            // optimizer cannot elide. `ki`/`ok` are public (key image, output
            // key) and need no wipe.
            ho.zeroize();
            y.zeroize();
            z.zeroize();
            k_amount.zeroize();
            entry
        })
        .collect();

    match shekyl_proofs::reserve_proof::generate_reserve_proof(&bsk, addr, msg, &entries) {
        Ok(proof_bytes) => {
            *proof_out = ShekylBuffer::from_vec(proof_bytes);
            true
        }
        Err(e) => {
            let _ = e;
            false
        }
    }
}

/// Verify reserve proof.
///
/// `enc_amounts` MUST be fetched from the blockchain, NOT from the proof.
/// On success, writes total verified amount to `total_amount_out`.
///
/// # Safety
/// - `proof_bytes`: `proof_len` bytes.
/// - `address`: `address_len` bytes.
/// - `spend_pubkey`: 32 bytes.
/// - `output_keys`, `commitments`: `output_count * 32` each.
/// - `enc_amounts`: `output_count * 8` bytes.
/// - `total_amount_out`: writable u64.
#[no_mangle]
pub unsafe extern "C" fn shekyl_verify_reserve_proof(
    proof_bytes: *const u8,
    proof_len: usize,
    address: *const u8,
    address_len: usize,
    message: *const u8,
    message_len: usize,
    spend_pubkey: *const u8,
    output_keys: *const u8,
    commitments: *const u8,
    enc_amounts: *const u8,
    output_count: u32,
    total_amount_out: *mut u64,
) -> bool {
    let Some(proof) = (unsafe { slice_from_ptr(proof_bytes, proof_len) }) else {
        return false;
    };
    let Some(addr) = (unsafe { slice_from_ptr(address, address_len) }) else {
        return false;
    };
    let msg = if message_len == 0 {
        &[] as &[u8]
    } else {
        match unsafe { slice_from_ptr(message, message_len) } {
            Some(v) => v,
            None => return false,
        }
    };
    let Some(spk) = arr32_from_ptr(spend_pubkey) else {
        return false;
    };
    let n = output_count as usize;
    if total_amount_out.is_null() || n == 0 {
        return false;
    }

    let Some(ok_bytes) = (unsafe { slice_from_ptr(output_keys, n * 32) }) else {
        return false;
    };
    let Some(cm_bytes) = (unsafe { slice_from_ptr(commitments, n * 32) }) else {
        return false;
    };
    let Some(ea_bytes) = (unsafe { slice_from_ptr(enc_amounts, n * 8) }) else {
        return false;
    };

    let on_chain: Vec<shekyl_proofs::reserve_proof::ReserveOnChainOutput> = (0..n)
        .map(|i| {
            let mut ok = [0u8; 32];
            let mut cm = [0u8; 32];
            let mut ea = [0u8; 8];
            ok.copy_from_slice(&ok_bytes[i * 32..(i + 1) * 32]);
            cm.copy_from_slice(&cm_bytes[i * 32..(i + 1) * 32]);
            ea.copy_from_slice(&ea_bytes[i * 8..(i + 1) * 8]);
            shekyl_proofs::reserve_proof::ReserveOnChainOutput {
                output_key: ok,
                commitment: cm,
                enc_amount: ea,
            }
        })
        .collect();

    match shekyl_proofs::reserve_proof::verify_reserve_proof(proof, addr, msg, &spk, &on_chain) {
        Ok(verified) => {
            let total: u64 = verified.iter().map(|v| v.amount).sum();
            *total_amount_out = total;
            true
        }
        Err(e) => {
            let _ = e;
            false
        }
    }
}
