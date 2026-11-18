// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Phase 4a integration test module: functional, adversarial, and
//! cross-platform determinism tests for V3.1 multisig.

mod adversarial;
mod determinism;
mod functional;

use shekyl_address::multisig_address::{MultisigAddressPayload, HYBRID_KEM_PUBKEY_LEN};
use shekyl_address::{Network, ShekylAddress, MSG_SIGN_PK_LEN, PQC_PAYLOAD_LEN};

/// A payable single-signer address on `network`. Decoding checks its
/// layout, not its points.
pub(crate) fn single_address(network: Network) -> String {
    ShekylAddress::new(
        network,
        [0x11; 32],
        [0x22; 32],
        [0x33; MSG_SIGN_PK_LEN],
        vec![0x44; PQC_PAYLOAD_LEN],
    )
    .encode()
    .unwrap()
}

/// A 2-of-2 group's payload on `network`, its keys `fill`ed: parsing
/// checks lengths and distinct KEM keys, not points.
pub(crate) fn group_payload(network: Network, fill: u8) -> MultisigAddressPayload {
    MultisigAddressPayload::new(
        network,
        2,
        2,
        [fill; 32],
        [fill; 32],
        vec![fill; HYBRID_KEM_PUBKEY_LEN],
        (1..=2)
            .map(|k| vec![fill.wrapping_add(k); HYBRID_KEM_PUBKEY_LEN])
            .collect(),
    )
    .unwrap()
}
