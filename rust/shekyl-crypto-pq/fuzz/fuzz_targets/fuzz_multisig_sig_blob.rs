// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::multisig::MultisigSigContainer;

fuzz_target!(|data: &[u8]| {
    let _ = MultisigSigContainer::from_canonical_bytes(data);
});
