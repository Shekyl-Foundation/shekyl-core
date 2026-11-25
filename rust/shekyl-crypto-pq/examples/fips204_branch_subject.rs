// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The binary `scripts/ci/check_fips204_branch_counts.py` reads: one shipped
//! ML-DSA-65 transaction signature and its verification, so a release build
//! links fips204's coefficient helpers as the wallet and the validator do.
//!
//! Its output is not used. The check reads the machine code.

use core::hint::black_box;

use shekyl_crypto_pq::kem::SHARED_SECRET_LEN;
use shekyl_crypto_pq::output::sign_pqc_auth_for_output;
use shekyl_crypto_pq::signature::{
    verify_pqc_auth, HYBRID_SCHEME_ID_ED25519_ML_DSA_65, SCHEME_DOMAIN_PQC_AUTH_TX,
};
use shekyl_types::SigningPayloadHash;

/// A fixed input: this binary is read, and what it signs does not matter.
const SHARED_SECRET: [u8; SHARED_SECRET_LEN] = [0x5A; SHARED_SECRET_LEN];
const PAYLOAD: [u8; SigningPayloadHash::LEN] = [0xA5; SigningPayloadHash::LEN];
const NETWORK: [u8; 16] = [0x3C; 16];

fn main() {
    let payload = SigningPayloadHash::from_bytes(black_box(PAYLOAD));
    let signed = sign_pqc_auth_for_output(
        black_box(&SHARED_SECRET),
        0,
        SCHEME_DOMAIN_PQC_AUTH_TX,
        &payload.to_bytes(),
    )
    .expect("a derived key signs");
    verify_pqc_auth(
        HYBRID_SCHEME_ID_ED25519_ML_DSA_65,
        black_box(&signed.hybrid_public_key),
        black_box(&signed.signature),
        &payload,
        black_box(&NETWORK),
    )
    .expect("its own signature verifies");
}
