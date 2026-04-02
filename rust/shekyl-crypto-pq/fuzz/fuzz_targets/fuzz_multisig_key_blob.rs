// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::multisig::{MultisigKeyContainer, MAX_MULTISIG_PARTICIPANTS, SINGLE_KEY_CANONICAL_LEN};

fuzz_target!(|data: &[u8]| {
    let _ = MultisigKeyContainer::from_canonical_bytes(data);

    if data.len() >= 2 {
        let n_total = (data[0] % MAX_MULTISIG_PARTICIPANTS) + 1;
        let m_required = (data[1] as usize % n_total as usize) as u8 + 1;

        let payload_len = (n_total as usize).saturating_mul(SINGLE_KEY_CANONICAL_LEN);
        let total = 2usize.saturating_add(payload_len);

        let mut buf = Vec::with_capacity(total);
        buf.push(n_total);
        buf.push(m_required);

        let tail = &data[2..];
        for j in 0..payload_len {
            let b = if tail.is_empty() {
                0u8
            } else {
                tail[j % tail.len()]
            };
            buf.push(b);
        }

        let _ = MultisigKeyContainer::from_canonical_bytes(&buf);

        if buf.len() > 2 {
            let idx = if data.len() > 2 {
                (data[2] as usize) % buf.len()
            } else {
                0
            };
            buf[idx] ^= 0x5A;
            let _ = MultisigKeyContainer::from_canonical_bytes(&buf);
        }
    }
});
