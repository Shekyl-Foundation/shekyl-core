// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Round-trip KAT: construct a JoinMarket bond post and check it against the
//! `shekyl-archival-retention` verify side (`ARCHIVAL_BOND_CONSTRUCTION.md` §3).
//!
//! This is the honest milestone for PR 0–1: construction validated against
//! verify in a unit-test round-trip with a **synthetic** balance witness. It is
//! *not* a bond on a real chain — the FCMP++ membership proofs over the real
//! curve tree are CT-5 work (§8). The two verify entrypoints exercised here —
//! `verify_join_market_bond_post` (vin semantics) and
//! `verify_bond_post_ct_balance` (commitment sum) — are exactly the §3 KAT
//! targets and neither consults a membership proof.

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};

use shekyl_archival_bond_builder::{build_join_market_vin, verify_credit_funding, BondBuildError};
use shekyl_archival_retention::{
    bond_floor, verify_bond_post_ct_balance, verify_join_market_bond_post, BondCtBalanceError,
    BondTerm, HoldingsDescriptor, HoldingsKind,
};
use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::derive_archival_p_keys;
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, SignatureScheme};
use shekyl_ct_balance::amount_commitment;
use shekyl_units::{AtomicUnits, NonZeroAtomicUnits};

const MASTER: [u8; MASTER_SEED_BYTES] = [0x33u8; MASTER_SEED_BYTES];
const TX_PREFIX_HASH: [u8; 32] = [0xCDu8; 32];

/// `mask * G + amount * H`, the masked commitment the verify side decompresses
/// and sums. Built inline here (the synthetic witness); in the real path the
/// prover (`shekyl-tx-builder::sign_transaction_with_terms`) emits these.
fn commit(amount: u64, mask: &Scalar) -> [u8; 32] {
    (mask * G + amount_commitment(AtomicUnits::from_raw(amount)))
        .compress()
        .to_bytes()
}

fn shard_set(shard_ids: Vec<u64>) -> HoldingsDescriptor {
    HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids,
    }
}

#[test]
fn join_market_construct_verifies_against_retention() {
    let keys = derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0)
        .expect("derive P keys");
    let holdings = shard_set(vec![7, 42]);
    let floor = bond_floor(&holdings);
    assert!(floor > 0);

    // --- construct: vin + hybrid signature ---
    let built = build_join_market_vin(&keys, holdings.clone(), &TX_PREFIX_HASH)
        .expect("build JoinMarket vin");

    // The vin is shaped exactly as the credit-path verify side requires.
    assert_eq!(built.vin().bonded_total_atomic, floor);
    assert_eq!(built.vin().bond_credit, floor);
    assert_eq!(built.vin().bond_debit, 0);

    // --- verify (1/2): vin semantics, record does not yet exist ---
    verify_join_market_bond_post(built.vin(), false).expect("verify accepts fresh JoinMarket post");

    // The hybrid signature is valid under P_pubkey over the post preimage.
    let preimage = built.vin().signature_preimage(&TX_PREFIX_HASH);
    let sig_ok = HybridEd25519MlDsa
        .verify(keys.hybrid_bond_id(), &preimage, built.signature())
        .expect("verify hybrid signature");
    assert!(sig_ok, "JoinMarket signature must verify under P_pubkey");

    // --- construct the synthetic RCT credit witness ---
    // One funding input committing F = change + fee + floor; one change output.
    // A shared mask makes the pseudo-out and output masks cancel, leaving only
    // the cleartext amount balance the verify side checks.
    const CHANGE: u64 = 1_000_000;
    const FEE: u64 = 2_000;
    let funding = CHANGE + FEE + floor;
    verify_credit_funding(
        AtomicUnits::from_raw(funding),
        AtomicUnits::from_raw(CHANGE),
        AtomicUnits::from_raw(FEE),
        &built,
    )
    .expect("credit funding rule holds");

    let mask = Scalar::from_bytes_mod_order([0x5Au8; 32]);
    let pseudo_outs = commit(funding, &mask);
    let out_masks = commit(CHANGE, &mask);

    // --- verify (2/2): CT cleartext balance, bond_credit = floor on output ---
    verify_bond_post_ct_balance(
        &pseudo_outs,
        &out_masks,
        FEE,
        BondTerm::Credit(
            NonZeroAtomicUnits::new(AtomicUnits::from_raw(floor)).expect("bond floor is non-zero"),
        ),
    )
    .expect("bond-post CT balance closes with bond_credit = floor");
}

#[test]
fn imbalanced_funding_is_rejected_before_proving() {
    let keys = derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0)
        .expect("derive P keys");
    let built = build_join_market_vin(&keys, shard_set(vec![1]), &TX_PREFIX_HASH)
        .expect("build JoinMarket vin");

    // Funding short by 1 atomic unit: caught at the amount level.
    let result = verify_credit_funding(
        AtomicUnits::from_raw(99),
        AtomicUnits::from_raw(50),
        AtomicUnits::from_raw(10),
        &built,
    );
    assert!(matches!(
        result,
        Err(BondBuildError::CreditImbalance { .. })
    ));
}

#[test]
fn wrong_credit_amount_breaks_the_balance() {
    let keys = derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0)
        .expect("derive P keys");
    let holdings = shard_set(vec![7, 42]);
    let floor = bond_floor(&holdings);
    let built =
        build_join_market_vin(&keys, holdings, &TX_PREFIX_HASH).expect("build JoinMarket vin");

    const CHANGE: u64 = 1_000_000;
    const FEE: u64 = 2_000;
    let funding = CHANGE + FEE + floor;
    let mask = Scalar::from_bytes_mod_order([0x5Au8; 32]);
    let pseudo_outs = commit(funding, &mask);
    let out_masks = commit(CHANGE, &mask);

    // Claiming a bond_credit other than the funded floor must not balance.
    let result = verify_bond_post_ct_balance(
        &pseudo_outs,
        &out_masks,
        FEE,
        BondTerm::Credit(
            NonZeroAtomicUnits::new(AtomicUnits::from_raw(floor - 1))
                .expect("bond floor is non-zero"),
        ),
    );
    assert_eq!(result, Err(BondCtBalanceError::SumMismatch));
    assert_eq!(built.vin().bond_credit, floor);
}
