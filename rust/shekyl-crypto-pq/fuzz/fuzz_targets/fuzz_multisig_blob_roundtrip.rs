// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A ceremony blob seals and opens to its payload for any secret, context,
//! header and payload; and any bytes at all, opened as a blob, are refused
//! or opened without a panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};
use shekyl_crypto_pq::multisig_blob::{open_blob, seal_blob, BlobContext};

fuzz_target!(|data: &[u8]| {
    if data.len() < 98 {
        return;
    }
    let secret: [u8; 32] = data[..32].try_into().unwrap();
    let context = BlobContext {
        intent_hash: data[32..64].try_into().unwrap(),
        message_type: data[64],
        sender_index: data[65],
    };
    let seed: [u8; 32] = data[66..98].try_into().unwrap();
    let rest = &data[98..];
    let (aad, payload) = rest.split_at(rest.len() / 4);

    let sealed = seal_blob(&secret, &context, aad, payload, &mut StdRng::from_seed(seed)).unwrap();
    assert_eq!(
        open_blob(&secret, &context, aad, &sealed).unwrap().as_slice(),
        payload
    );
    let _ = open_blob(&secret, &context, aad, rest);
});
