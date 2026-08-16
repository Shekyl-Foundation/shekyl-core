// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Emitter for a valid current-format regtest (FAKECHAIN) mining address, used to
//! regenerate `tests/vectors/regtest_coinbase_h{1,2}.block` via
//! `capture_coinbase.py`. Fakechain mirrors Mainnet address encoding, so the
//! address parses on the FAKECHAIN daemon (`account.rs::to_address_network`).
//! Deterministic from the fixed seed so the corpus is reproducible.
//!
//! ```text
//! cargo test -p shekyl-wire --test emit_regtest_addr -- --ignored --nocapture
//! ```

#[test]
#[ignore = "prints a regtest mining address for vector regeneration"]
fn emit_regtest_mining_address() {
    use shekyl_address::{Network, ShekylAddress};
    use shekyl_crypto_pq::account::{generate_account_from_raw_seed, DerivationNetwork};

    let (_seed, blob) = generate_account_from_raw_seed(&[0x11u8; 32], DerivationNetwork::Fakechain)
        .expect("derive fakechain account");
    let spend: [u8; 32] = blob.classical_address_bytes[1..33]
        .try_into()
        .expect("spend key slice");
    let view: [u8; 32] = blob.classical_address_bytes[33..65]
        .try_into()
        .expect("view key slice");
    let addr = ShekylAddress::new(
        Network::Mainnet,
        spend,
        view,
        *blob.msg_sign_pk(),
        blob.ml_kem_ek.to_vec(),
    );
    let encoded = addr.encode().expect("encode address");
    // Round-trip through the decoder the daemon uses, as a sanity gate.
    assert!(ShekylAddress::decode(&encoded).is_ok(), "must decode");
    println!("REGTEST_MINING_ADDR={encoded}");
}
