// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::multisig::{multisig_group_id, MultisigKeyContainer};

fuzz_target!(|data: &[u8]| {
    if let Ok(container) = MultisigKeyContainer::from_canonical_bytes(data) {
        let _ = multisig_group_id(&container);
    }
});
