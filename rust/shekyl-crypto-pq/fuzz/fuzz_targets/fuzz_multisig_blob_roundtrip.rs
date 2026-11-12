// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A ceremony blob seals and opens to its payload for any secret, header
//! and payload; and any bytes at all, opened as a blob, are refused or
//! opened without a panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};
use shekyl_crypto_pq::multisig_blob::{
    open_blob, seal_blob, BlobHeader, ADDRESS_FINGERPRINT_LEN, INTENT_HASH_LEN,
};

fuzz_target!(|data: &[u8]| {
    // secret ‖ intent ‖ type ‖ sender ‖ version ‖ fingerprint ‖ seed ‖ payload
    const HEAD: usize = 32 + INTENT_HASH_LEN + 1 + 1 + 1 + ADDRESS_FINGERPRINT_LEN + 32;
    if data.len() < HEAD {
        return;
    }
    let mut at = 0;
    let take = |at: &mut usize, n: usize| {
        let start = *at;
        *at += n;
        &data[start..start + n]
    };
    let secret: [u8; 32] = take(&mut at, 32).try_into().unwrap();
    let intent_hash: [u8; INTENT_HASH_LEN] = take(&mut at, INTENT_HASH_LEN).try_into().unwrap();
    let message_type = take(&mut at, 1)[0];
    let sender_index = take(&mut at, 1)[0];
    let version = take(&mut at, 1)[0];
    let fingerprint: [u8; ADDRESS_FINGERPRINT_LEN] =
        take(&mut at, ADDRESS_FINGERPRINT_LEN).try_into().unwrap();
    let seed: [u8; 32] = take(&mut at, 32).try_into().unwrap();
    let header = BlobHeader {
        version,
        address_fingerprint: &fingerprint,
        intent_hash: &intent_hash,
        message_type,
        sender_index,
    };
    let payload = &data[at..];

    let sealed = seal_blob(&secret, &header, payload, &mut StdRng::from_seed(seed)).unwrap();
    assert_eq!(
        open_blob(&secret, &header, &sealed).unwrap().as_slice(),
        payload
    );
    let _ = open_blob(&secret, &header, data);
});
