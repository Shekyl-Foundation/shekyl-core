// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::multisig::verify_multisig;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        let _ = verify_multisig(0, &[], &[], &[], None);
        return;
    }

    let scheme_id = data[0];
    let mut i = 1usize;

    if data.len() < i + 2 {
        let _ = verify_multisig(scheme_id, &[], &[], &data[i..], None);
        return;
    }

    let key_blob_len = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
    i += 2;

    let key_available = data.len().saturating_sub(i);
    let key_take = key_blob_len.min(key_available);
    let key_blob = &data[i..i + key_take];
    i += key_take;

    if data.len() < i + 2 {
        let _ = verify_multisig(scheme_id, key_blob, &[], &data[i..], None);
        return;
    }

    let sig_blob_len = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
    i += 2;

    let sig_available = data.len().saturating_sub(i);
    let sig_take = sig_blob_len.min(sig_available);
    let sig_blob = &data[i..i + sig_take];
    i += sig_take;

    let tail = &data[i..];

    if tail.len() >= 32 {
        let msg_len = tail.len() - 32;
        let message = &tail[..msg_len];
        let mut group_id = [0u8; 32];
        group_id.copy_from_slice(&tail[msg_len..]);
        let _ = verify_multisig(scheme_id, key_blob, sig_blob, message, Some(&group_id));
    } else {
        let _ = verify_multisig(scheme_id, key_blob, sig_blob, tail, None);
    }
});
