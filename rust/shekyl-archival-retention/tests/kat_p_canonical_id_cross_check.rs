// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `p_canonical_id` cross-check against the `ARCHIVAL_P_DERIVE_V1` KAT.
//!
//! `shekyl-crypto-pq`'s KAT pins `p_canonical_id` via an inline cSHAKE256. This
//! test derives the same persona through `crypto_pq::archival_p` and recomputes
//! the id through this crate's `id::p_canonical_id_from_hybrid_pubkey` (the
//! single-source implementation). Both must equal the pinned value, proving the
//! two cSHAKE256 paths agree — a divergence here is a consensus fault between
//! wallet derivation and the retention verify surface
//! (`ARCHIVAL_FIREWALL_GATE6.md` §9.5).
//!
//! The pinned hexes mirror `docs/test_vectors/ARCHIVAL_P_DERIVE_V1/vectors.json`.
//! A deliberate derivation-version bump that regenerates that corpus must update
//! these constants in lockstep; that lockstep is exactly the tripwire.

use shekyl_archival_retention::id::{
    p_canonical_id_from_hybrid_pubkey, P_CANONICAL_ID_CUSTOMIZATION,
};
use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::{
    derive_archival_p_keys, derive_p_hs_id_seed, ARCHIVAL_P_HS_ID_INFO,
};

/// `(master_byte, network, seed_format, p_slot, expected_p_canonical_id_hex)`,
/// copied from the crypto-pq KAT Tier-2 corpus.
const CASES: &[(u8, DerivationNetwork, SeedFormat, u32, &str)] = &[
    (
        0x33,
        DerivationNetwork::Mainnet,
        SeedFormat::Bip39,
        0,
        "0e6217a54d726f602ff5500fb8d0a3a8f8392d7a9afc4918b3c9a6a3bc098df5",
    ),
    (
        0x33,
        DerivationNetwork::Mainnet,
        SeedFormat::Bip39,
        7,
        "e121a43aff5b08a89a12d99c8889cccb7028f5992565d7e63c142f2feae76b9a",
    ),
    (
        0x44,
        DerivationNetwork::Testnet,
        SeedFormat::Raw32,
        0,
        "87f678800c747ad7f7b2cdc301dddf3ceed2340b8490ab9f2d47bd98cee8227c",
    ),
    (
        0x33,
        DerivationNetwork::Stagenet,
        SeedFormat::Bip39,
        3,
        "8036a0a34c57d5be66b9bd35ca545208d431da9b1d2edf0d435b1e7b5cf80f81",
    ),
];

#[test]
fn id_rs_reproduces_the_kat_pinned_p_canonical_id() {
    for &(master_byte, net, fmt, p_slot, expected_hex) in CASES {
        let master = [master_byte; MASTER_SEED_BYTES];
        let keys = derive_archival_p_keys(&master, net, fmt, p_slot)
            .expect("derive_archival_p_keys for cross-check");

        let bond_bytes = keys
            .hybrid_bond_id()
            .to_canonical_bytes()
            .expect("hybrid_bond_id canonical bytes");
        let id = p_canonical_id_from_hybrid_pubkey(&bond_bytes);

        assert_eq!(
            hex::encode(id),
            expected_hex,
            "p_canonical_id mismatch for {net:?}/{fmt:?}/slot{p_slot}: \
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
    let hs_id = derive_p_hs_id_seed(&master, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0);
    let keys = derive_archival_p_keys(&master, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0)
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
