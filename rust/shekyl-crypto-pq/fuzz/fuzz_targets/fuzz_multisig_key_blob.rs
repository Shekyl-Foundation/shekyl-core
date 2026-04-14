// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::multisig::{
    MultisigKeyContainer, MAX_MULTISIG_PARTICIPANTS, MULTISIG_CONTAINER_VERSION,
    SINGLE_KEY_CANONICAL_LEN, SPEND_AUTH_PUBKEY_LEN,
};

fuzz_target!(|data: &[u8]| {
    let _ = MultisigKeyContainer::from_canonical_bytes(data);

    // V3.1 wire format: version(1) || n_total(1) || m_required(1) || keys || spend_auth_pks
    if data.len() >= 3 {
        let n_total = (data[0] % MAX_MULTISIG_PARTICIPANTS) + 1;
        let m_required = (data[1] as usize % n_total as usize) as u8 + 1;

        let key_payload_len = (n_total as usize).saturating_mul(SINGLE_KEY_CANONICAL_LEN);
        let sa_payload_len = (n_total as usize).saturating_mul(SPEND_AUTH_PUBKEY_LEN);
        let total = 3usize
            .saturating_add(key_payload_len)
            .saturating_add(sa_payload_len);

        let mut buf = Vec::with_capacity(total);
        buf.push(MULTISIG_CONTAINER_VERSION);
        buf.push(n_total);
        buf.push(m_required);

        let tail = &data[3..];
        for j in 0..(key_payload_len + sa_payload_len) {
            let b = if tail.is_empty() {
                0u8
            } else {
                tail[j % tail.len()]
            };
            buf.push(b);
        }

        let _ = MultisigKeyContainer::from_canonical_bytes(&buf);

        if buf.len() > 3 {
            let idx = if data.len() > 3 {
                (data[3] as usize) % buf.len()
            } else {
                0
            };
            buf[idx] ^= 0x5A;
            let _ = MultisigKeyContainer::from_canonical_bytes(&buf);
        }
    }
});
