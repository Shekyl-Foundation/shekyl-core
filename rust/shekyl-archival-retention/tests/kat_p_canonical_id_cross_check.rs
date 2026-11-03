// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `p_canonical_id` cross-check against the `ARCHIVAL_P_DERIVE_V2` KAT.
//!
//! `shekyl-crypto-pq`'s KAT pins `p_canonical_id` via an inline cSHAKE256. This
//! test derives the same persona through `crypto_pq::archival_p` and recomputes
//! the id through this crate's `id::p_canonical_id_from_hybrid_pubkey` (the
//! single-source implementation). Both must equal the pinned value, proving the
//! two cSHAKE256 paths agree — a divergence here is a consensus fault between
//! wallet derivation and the retention verify surface
//! (`ARCHIVAL_FIREWALL_GATE6.md` §9.5).
//!
//! The pinned hexes mirror `docs/test_vectors/ARCHIVAL_P_DERIVE_V2/vectors.json`.
//! A deliberate derivation-version bump that regenerates that corpus must update
//! these constants in lockstep; that lockstep is exactly the tripwire.

use shekyl_archival_retention::id::{
    p_canonical_id_from_hybrid_pubkey, P_CANONICAL_ID_CUSTOMIZATION,
};
use shekyl_crypto_pq::account::{Network, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::{
    derive_archival_p_keys, derive_p_hs_id_seed, ARCHIVAL_P_HS_ID_INFO,
};

/// `(master_byte, network, p_slot, expected_p_canonical_id_hex)`,
/// copied from the crypto-pq KAT Tier-2 corpus.
const CASES: &[(u8, Network, u32, &str)] = &[
    (
        0x33,
        Network::Mainnet,
        0,
        "37aab54549688d7d1953956953b9d79b108a13175d41c1ec6308cb9890281577",
    ),
    (
        0x33,
        Network::Mainnet,
        7,
        "776bc822b44e94bd4ce2d085dbe22d7a79ad0ba63b91b98dab133fc5f4ff3a6c",
    ),
    (
        0x44,
        Network::Testnet,
        0,
        "a981bf31acf778058c863c4bfb39d3cf7ae1985d4ab9aba78403d26dbda3e511",
    ),
    (
        0x33,
        Network::Stagenet,
        3,
        "1b999d783111dfd97a4f9e0da7caa8a3c1fb5aa73787b6f1aea7f95e728a52ee",
    ),
    (
        0x44,
        Network::Regtest,
        2,
        "c446ee45b74f8b02fbcbb78cf4a370cf47f461c69006c91c0df15cc7fcc50351",
    ),
];

#[test]
fn id_rs_reproduces_the_kat_pinned_p_canonical_id() {
    for &(master_byte, net, p_slot, expected_hex) in CASES {
        let master = [master_byte; MASTER_SEED_BYTES];
        let keys = derive_archival_p_keys(&master, net, p_slot)
            .expect("derive_archival_p_keys for cross-check");

        let bond_bytes = keys
            .hybrid_bond_id()
            .to_canonical_bytes()
            .expect("hybrid_bond_id canonical bytes");
        let id = p_canonical_id_from_hybrid_pubkey(&bond_bytes);

        assert_eq!(
            hex::encode(id),
            expected_hex,
            "p_canonical_id mismatch for {net:?}/slot{p_slot}: \
             id.rs cSHAKE diverged from the crypto-pq KAT pin"
        );
    }
}

/// Domain separation between the **public, on-chain** `P_canonical_id` and the
/// persona's **serving** GF-9 HS-identity seed.
///
/// This invariant moved here from `shekyl-sp-t3-spike::onion_key` when SPIKE-F-4
/// relocated the onion-key derivation onto the production path: the property is
/// now about two production constructions (`P_CANONICAL_ID_CUSTOMIZATION` in this
/// crate, `ARCHIVAL_P_HS_ID_INFO` in `crypto-pq`), so it belongs where both are
/// visible and the crate is not disposable — not in a spike that may be deleted.
///
/// The requirement is one-directional: an observer holding `P_canonical_id`
/// (public, appears on chain) must get **no** path to the serving onion key. The
/// copy-paste failure that would couple them is a shared domain separator; the
/// two are also produced by different primitives (HKDF-SHA-512 vs cSHAKE256),
/// but the separator distinctness is the assertable guard.
#[test]
fn hs_id_seed_is_domain_separated_from_p_canonical_id() {
    // The two domain separators must differ, and neither may be a prefix of the
    // other (the §9.3 non-prefix-free safety family the hyphen convention keeps).
    assert_ne!(
        ARCHIVAL_P_HS_ID_INFO, P_CANONICAL_ID_CUSTOMIZATION,
        "the HS-id HKDF label must not equal the canonical-id cSHAKE customization"
    );
    assert!(
        !ARCHIVAL_P_HS_ID_INFO.starts_with(P_CANONICAL_ID_CUSTOMIZATION)
            && !P_CANONICAL_ID_CUSTOMIZATION.starts_with(ARCHIVAL_P_HS_ID_INFO),
        "neither separator may be a prefix of the other"
    );

    // And end-to-end on a concrete persona: the derived HS seed and the derived
    // canonical id are distinct 32-byte values. A shared separator (the failure
    // this guards) would have collapsed the two maps.
    let master = [0x33u8; MASTER_SEED_BYTES];
    let hs_id = derive_p_hs_id_seed(&master, Network::Mainnet, 0);
    let keys = derive_archival_p_keys(&master, Network::Mainnet, 0)
        .expect("derive_archival_p_keys for domain-separation check");
    let bond_bytes = keys
        .hybrid_bond_id()
        .to_canonical_bytes()
        .expect("hybrid_bond_id canonical bytes");
    let pid = p_canonical_id_from_hybrid_pubkey(&bond_bytes);
    assert_ne!(
        &hs_id[..],
        pid.as_bytes(),
        "the serving HS seed must not equal the public canonical id"
    );
}
