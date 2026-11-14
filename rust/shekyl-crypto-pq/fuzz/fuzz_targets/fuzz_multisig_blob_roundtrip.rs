// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A ceremony file seals and opens to its plaintext for any secret and
//! plaintext; and any bytes at all, opened as a file, are refused or opened
//! without a panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};
use shekyl_crypto_pq::multisig_blob::{open_blob, seal_blob};

fuzz_target!(|data: &[u8]| {
    // secret ‖ seed ‖ plaintext
    const HEAD: usize = 32 + 32;
    if data.len() < HEAD {
        return;
    }
    let secret: [u8; 32] = data[..32].try_into().unwrap();
    let seed: [u8; 32] = data[32..HEAD].try_into().unwrap();
    let plaintext = &data[HEAD..];

    let file = seal_blob(&secret, plaintext, &mut StdRng::from_seed(seed)).unwrap();
    assert_eq!(open_blob(&secret, &file).unwrap().as_slice(), plaintext);
    let _ = open_blob(&secret, data);
});
