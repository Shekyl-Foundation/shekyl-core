// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::multisig::{
    MultisigCommittedForm, MultisigKeyBlob, MAX_MULTISIG_PARTICIPANTS, MULTISIG_CONTAINER_VERSION,
};
use shekyl_crypto_pq::signature::pqc_leaf_key_bytes;

fuzz_target!(|data: &[u8]| {
    let _ = MultisigKeyBlob::from_canonical_bytes(data);
    let _ = MultisigCommittedForm::from_bytes(data);
    let _ = pqc_leaf_key_bytes(2, data);

    // A blob of the right length for a fuzzed (n, m), its body filled from
    // the input, so the bitmap, hash and key parses are reached and not
    // only the length gate: version(1) ‖ n ‖ m ‖ n·32 ‖ bitmap ‖ m·1996.
    if data.len() >= 3 {
        let n_total = (data[0] % MAX_MULTISIG_PARTICIPANTS) + 1;
        let m_required = (data[1] % n_total) + 1;
        let total = MultisigKeyBlob::expected_len(n_total, m_required);

        let mut buf = Vec::with_capacity(total);
        buf.push(MULTISIG_CONTAINER_VERSION);
        buf.push(n_total);
        buf.push(m_required);
        let tail = &data[2..];
        while buf.len() < total {
            buf.push(tail[(buf.len() - 3) % tail.len()]);
        }

        let _ = MultisigKeyBlob::from_canonical_bytes(&buf);
        let _ = pqc_leaf_key_bytes(2, &buf);

        let idx = usize::from(data[2]) % buf.len();
        buf[idx] ^= 0x5A;
        let _ = MultisigKeyBlob::from_canonical_bytes(&buf);
        let _ = pqc_leaf_key_bytes(2, &buf);
    }
});
