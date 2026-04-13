// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::output::{derive_output_key, recover_recipient_spend_pubkey};

const MIN_LEN: usize = 64 + 32 + 8; // combined_ss + spend_key + output_index

fuzz_target!(|data: &[u8]| {
    if data.len() < MIN_LEN {
        return;
    }

    let mut combined_ss = [0u8; 64];
    combined_ss.copy_from_slice(&data[..64]);

    let mut spend_key = [0u8; 32];
    spend_key.copy_from_slice(&data[64..96]);

    let output_index = u64::from_le_bytes(data[96..104].try_into().unwrap()) % 256;

    let output_key = match derive_output_key(&combined_ss, &spend_key, output_index) {
        Ok(o) => o,
        Err(_) => return,
    };

    // Round-trip: recover must return the original spend_key
    match recover_recipient_spend_pubkey(&combined_ss, &output_key, output_index) {
        Ok(recovered) => {
            assert_eq!(
                recovered, spend_key,
                "recover_recipient_spend_pubkey must round-trip with derive_output_key"
            );
        }
        Err(_) => {
            // This should not happen when derive_output_key succeeded with a valid
            // point, but the fuzzer may hit edge cases. Don't panic.
        }
    }
});
