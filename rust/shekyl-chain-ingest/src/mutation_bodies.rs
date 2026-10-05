// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Archival bodies the mutation family lists in duplicate.
//!
//! Each one is the rules harness's balanced shape with the vin the census
//! row collides on. They live beside [`crate::mutation`] rather than inside
//! it: the mutation enum is one exhaustive match, and these builders are
//! the fixtures that match feeds.

use shekyl_archival_retention::{
    ArchivalRewardEmissionVin, ArchivalServeCreditResponse, HoldingsDescriptor, HoldingsKind,
    MembershipOnlyBacking, ShardSet, ShardWorkEntry, WorkEpochClaim,
};
use shekyl_chain_rules::harness::fixture;
use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};
use shekyl_wire::transaction::PQC_HYBRID_SINGLE_KEY_LEN;
use shekyl_wire::{BondPost, BondPostKind, Holdings, Input, Transaction};

/// A **serve-credit-only** body (CEN-H20's shape, the harness's
/// `serve_credit_only`) whose one vin **parses** as the kept half of a pass
/// record for `(p, shard, epoch)` — the key CEN-G7 collides on. No
/// `pqc_auths`, no signature slot: the mutation family can twin it by
/// moving its `unlock_time` and the twin is still a valid body under every
/// landed row (the countersignature is CEN-J10's, pending).
pub fn serve_credit_body(p: [u8; 32], shard: u64, epoch: u64) -> Transaction {
    let kept = ArchivalServeCreditResponse {
        p_canonical_id: p,
        shard_id: shard,
        settlement_epoch: epoch,
        ed25519_countersignature: [0x5c; 64],
    };
    let mut tx = fixture::serve_credit_only([0; 32]);
    tx.prefix.inputs = vec![Input::ServeCredit {
        canonical_bytes: kept.serialize().expect("a kept half serializes"),
    }];
    tx
}

/// A spend of `key_image` that posts `p`'s **JoinMarket** — the harness's
/// `join_market`, the body that opens the record a [`serve_credit_body`]
/// for `p` is judged against (CEN-J4 reads it off the view before the
/// credit's block, so the join lists in a block below the credit's).
/// Unanchored and unsigned like every body `chain_listing_with` places.
pub fn join_body(key_image: [u8; 32], p: [u8; 32]) -> Transaction {
    fixture::join_market(key_image, p)
}

/// A spend of `key_image` that also posts a bond for `p` — the harness's
/// balanced bond post (CEN-H21's shape), unanchored and unsigned like every
/// body `chain_listing_with` places: anchoring signs it. Two calls with two
/// key images and one `p` are the pair CEN-G10 refuses.
pub fn bond_post_body(key_image: [u8; 32], p: [u8; 32]) -> Transaction {
    fixture::balanced_bond_post(
        key_image,
        BondPost {
            hybrid_public_key: vec![0xb1; PQC_HYBRID_SINGLE_KEY_LEN],
            p_canonical_id: shekyl_types::PCanonicalId::from_bytes(p),
            kind: BondPostKind::Other(2),
            holdings: Holdings::CompleteTree,
            bonded_total_atomic: 0,
            bond_credit: 0,
            bond_debit: 0,
        },
    )
}

/// A spend of `key_image` that also carries an emission claim by the
/// persona whose hybrid pubkey is `p_pubkey_fill` repeated, for `epochs` —
/// one `(P, E)` pair per epoch, CEN-G9's keys — the harness's balanced
/// emission (CEN-H22's shape) paying a reward of one atomic unit. The vin
/// is the `emission_wire` round-trip shape, one work claim and one amount
/// per epoch; the emission rows that judge its content are slice 8's.
pub fn emission_claim_body(key_image: [u8; 32], p_pubkey_fill: u8, epochs: &[u64]) -> Transaction {
    let vin = ArchivalRewardEmissionVin {
        p_pubkey: vec![p_pubkey_fill; SINGLE_KEY_CANONICAL_LEN],
        holdings: HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7]).expect("one shard"),
        },
        settlement_epochs: epochs.to_vec(),
        work_claim: epochs
            .iter()
            .map(|&epoch| WorkEpochClaim {
                epoch,
                shard_entries: vec![ShardWorkEntry {
                    shard_id: 7,
                    serve_credit_bit: true,
                    scarcity_micro: 1_000,
                }],
            })
            .collect(),
        backing: MembershipOnlyBacking {
            proof: vec![0xee; 64],
            pseudo_out: [0x22; 32],
            backing_pubkey: vec![0xb2; SINGLE_KEY_CANONICAL_LEN],
            tree_depth: 3,
        },
        reward_amount_plain: epochs.iter().map(|_| 1_000_000).collect(),
        auth_backing: vec![0xc3; SINGLE_SIG_CANONICAL_LEN],
        auth_claim: vec![0xd4; SINGLE_SIG_CANONICAL_LEN],
    };
    fixture::balanced_emission(
        key_image,
        vin.serialize().expect("an emission vin serializes"),
        1,
    )
}
