// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Pinned known-answer vectors for the emission-vin consensus surfaces
//! (`EMISSION_AUTH_MSG_V1`): the two role auth digests (`auth_msg`, the R1.A
//! `emission_auth_msg` inventory under the Q1 role customizations) and the
//! serialized wire bytes of the same fixture vin.
//!
//! Differential tests (stability / role-separation / non-replay) cannot catch a
//! refactor that changes the digest *for both roles at once* — field reordering,
//! a framing-width change, a customization edit, or an XOF-read change all keep
//! the differential suite green while silently forking the consensus digest.
//! These absolute pins are the tripwire (`30-cryptography.mdc`: "vectors define
//! consensus and cannot drift silently"; same discipline as
//! `kat_p_canonical_id_cross_check.rs` / `ARCHIVAL_P_DERIVE_V1`).
//!
//! The pinned hexes mirror `docs/test_vectors/EMISSION_AUTH_MSG_V1/vectors.json`.
//! A deliberate digest/wire-format change (pre-genesis only!) must regenerate
//! that corpus and update these constants in lockstep; the lockstep is the
//! tripwire.

use shekyl_archival_retention::hash::cshake256_32;
use shekyl_archival_retention::{
    ArchivalRewardEmissionVin, EmissionAuthRole, HoldingsDescriptor, HoldingsKind,
    MembershipOnlyBacking, RewardCommit, ShardWorkEntry, WorkEpochClaim,
};
use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};

/// Expected 64-byte `auth_msg` digest, stake-side (`Backing`) customization.
const EXPECTED_BACKING_HEX: &str = "5ffd5095e5249f59abc299f9d87a1fdb8ed88362dabab6515f91acdb7437691c2ef4fe8e6b73a48eef3a337b3d02712e64e2c552a8a7b76b263f1c47f708e74d";
/// Expected 64-byte `auth_msg` digest, claim-side (`Claim`) customization.
const EXPECTED_CLAIM_HEX: &str = "c468f442754b1fcd670b65433e445ebae9a82dca6682a7070898dd7279d5975b12369a1a64c6effe676ba0ca8875b498cdc8f249d4a51e9325bf29e8976e2cdf";
/// Expected serialized wire length of the fixture vin.
const EXPECTED_WIRE_LEN: usize = 10_930;
/// Expected `cshake256_32("shekyl/emission-wire-kat-v1", wire_bytes)` of the
/// fixture vin's full serialization (tag included) — pins the wire layout.
const EXPECTED_WIRE_DIGEST_HEX: &str =
    "e70926ece926316a1c9d9663cb856e1a2820e3473bbeaa569de499ff6e590308";

/// Fully deterministic fixture — every byte fixed, no RNG, so the vectors are
/// reproducible from this source alone.
fn fixture_vin() -> ArchivalRewardEmissionVin {
    ArchivalRewardEmissionVin {
        p_pubkey: vec![0x5A; SINGLE_KEY_CANONICAL_LEN],
        holdings: HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: vec![7, 42],
        },
        settlement_epochs: vec![11, 12, 15],
        work_claim: vec![
            WorkEpochClaim {
                epoch: 11,
                shard_entries: vec![
                    ShardWorkEntry {
                        shard_id: 7,
                        serve_credit_bit: true,
                        scarcity_milli: 850,
                    },
                    ShardWorkEntry {
                        shard_id: 42,
                        serve_credit_bit: false,
                        scarcity_milli: 0,
                    },
                ],
            },
            WorkEpochClaim {
                epoch: 12,
                shard_entries: vec![ShardWorkEntry {
                    shard_id: 7,
                    serve_credit_bit: true,
                    scarcity_milli: 1_000,
                }],
            },
            WorkEpochClaim {
                epoch: 15,
                shard_entries: vec![],
            },
        ],
        backing: MembershipOnlyBacking {
            proof: vec![0xEE; 64],
            pseudo_out: [0x22; 32],
            pqc_pk_hash: [0x33; 32],
            backing_pubkey: vec![0xB2; SINGLE_KEY_CANONICAL_LEN],
            tree_depth: 3,
        },
        reward_amount_plain: vec![1_000_000, 2_000_000, 0],
        auth_backing: vec![0xC3; SINGLE_SIG_CANONICAL_LEN],
        auth_claim: vec![0xD4; SINGLE_SIG_CANONICAL_LEN],
    }
}

fn fixture_commits() -> Vec<RewardCommit> {
    vec![RewardCommit {
        commitment: [0x55; 32],
        amount_plain: 3_000_000,
        one_time_key: [0x66; 32],
    }]
}

const FIXTURE_TX_HASH: [u8; 32] = [0x42; 32];

#[test]
fn emission_auth_msg_matches_pinned_vectors() {
    let vin = fixture_vin();
    let commits = fixture_commits();

    let backing = vin
        .auth_msg(&commits, &FIXTURE_TX_HASH, EmissionAuthRole::Backing)
        .expect("fixture is valid");
    let claim = vin
        .auth_msg(&commits, &FIXTURE_TX_HASH, EmissionAuthRole::Claim)
        .expect("fixture is valid");

    assert_eq!(
        hex::encode(backing),
        EXPECTED_BACKING_HEX,
        "backing auth digest moved — consensus fault unless a deliberate \
         pre-genesis format bump regenerated EMISSION_AUTH_MSG_V1"
    );
    assert_eq!(
        hex::encode(claim),
        EXPECTED_CLAIM_HEX,
        "claim auth digest moved — consensus fault unless a deliberate \
         pre-genesis format bump regenerated EMISSION_AUTH_MSG_V1"
    );
}

#[test]
fn emission_wire_bytes_match_pinned_vector() {
    let wire = fixture_vin().serialize().expect("fixture is valid");
    assert_eq!(
        wire.len(),
        EXPECTED_WIRE_LEN,
        "fixture wire length moved — wire-format change"
    );
    assert_eq!(
        hex::encode(cshake256_32(b"shekyl/emission-wire-kat-v1", &wire)),
        EXPECTED_WIRE_DIGEST_HEX,
        "fixture wire digest moved — wire-format change to the frozen 0x04 vin"
    );
}
