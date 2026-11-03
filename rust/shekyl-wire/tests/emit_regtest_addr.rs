// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Emitter for a valid current-format regtest mining address, used to
//! regenerate `tests/vectors/regtest_coinbase_h{1,2}.block` via
//! `capture_coinbase.py`. Regtest has its own address prefixes
//! (`NETWORK_IDENTITY.md` NI-R1), so the address is derived and encoded for
//! regtest and decoded the way the regtest daemon decodes it.
//! Deterministic from the fixed seed so the corpus is reproducible.
//!
//! ```text
//! cargo test -p shekyl-wire --test emit_regtest_addr -- --ignored --nocapture
//! ```

#[test]
#[ignore = "prints a regtest mining address for vector regeneration"]
fn emit_regtest_mining_address() {
    use shekyl_address::{Network, ShekylAddress};
    use shekyl_crypto_pq::account::account_from_seed;

    let (_seed, blob) =
        account_from_seed(&[0x11u8; 32], Network::Regtest).expect("derive regtest account");
    let addr = blob.to_address(Network::Regtest);
    let encoded = addr.encode().expect("encode address");
    // Round-trip through the decoder the daemon uses, as a sanity gate.
    assert!(
        ShekylAddress::decode_for_network(&encoded, Network::Regtest).is_ok(),
        "must decode as a regtest address"
    );
    println!("REGTEST_MINING_ADDR={encoded}");
}
