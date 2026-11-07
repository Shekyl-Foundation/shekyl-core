// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::multisig::verify_multisig;
use shekyl_types::SigningPayloadHash;

/// The message is a 64-byte signing payload hash, so the fuzzed surface is
/// the key and signature blobs: whatever input is left after them fills the
/// payload, zero-padded or cut to its width.
fn payload(rest: &[u8]) -> SigningPayloadHash {
    let mut bytes = [0u8; 64];
    let take = rest.len().min(64);
    bytes[..take].copy_from_slice(&rest[..take]);
    SigningPayloadHash::from_bytes(bytes)
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        let _ = verify_multisig(0, &[], &[], &payload(&[]));
        return;
    }

    let scheme_id = data[0];
    let mut i = 1usize;

    if data.len() < i + 2 {
        let _ = verify_multisig(scheme_id, &[], &[], &payload(&data[i..]));
        return;
    }

    let key_blob_len = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
    i += 2;

    let key_available = data.len().saturating_sub(i);
    let key_take = key_blob_len.min(key_available);
    let key_blob = &data[i..i + key_take];
    i += key_take;

    if data.len() < i + 2 {
        let _ = verify_multisig(scheme_id, key_blob, &[], &payload(&data[i..]));
        return;
    }

    let sig_blob_len = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
    i += 2;

    let sig_available = data.len().saturating_sub(i);
    let sig_take = sig_blob_len.min(sig_available);
    let sig_blob = &data[i..i + sig_take];
    i += sig_take;

    let _ = verify_multisig(scheme_id, key_blob, sig_blob, &payload(&data[i..]));
});
