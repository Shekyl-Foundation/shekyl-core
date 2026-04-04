// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::address::ShekylAddress;

fuzz_target!(|data: &[u8]| {
    // Interpret fuzz data as a UTF-8 string and attempt address decoding.
    // Test wrong version bytes, truncated segments, invalid checksums.
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let _ = ShekylAddress::decode(input);

    // Also test with segment separators injected at various positions
    if data.len() > 4 {
        let mut with_slashes = String::with_capacity(input.len() + 4);
        let third = input.len() / 3;
        with_slashes.push_str(&input[..third]);
        with_slashes.push('/');
        with_slashes.push_str(&input[third..third * 2]);
        with_slashes.push('/');
        with_slashes.push_str(&input[third * 2..]);
        let _ = ShekylAddress::decode(&with_slashes);
    }

    // Test single-segment decode (classical only)
    if !input.contains('/') {
        let _ = ShekylAddress::decode(input);
    }

    // If we can construct a valid address, verify encode-decode roundtrip
    if let Ok(addr) = ShekylAddress::decode(input) {
        if addr.has_pqc_segment() {
            if let Ok(encoded) = addr.encode() {
                let decoded = ShekylAddress::decode(&encoded).expect("roundtrip must succeed");
                assert_eq!(addr, decoded);
            }
        }
    }
});
