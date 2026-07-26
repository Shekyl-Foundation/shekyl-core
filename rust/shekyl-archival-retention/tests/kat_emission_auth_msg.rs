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
//!
//! **Regenerated for the D1 micro-precision fix** (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`
//! F-E): the auth customizations bumped `-v1 → -v2` because the digested
//! work-claim entries changed meaning (scarcity-milli → scarcity-micro), so both
//! role digests moved.
//!
//! **The corpus *name* is historical.** `EMISSION_AUTH_MSG_V1` is a directory
//! label fixed at the corpus's birth; the **active customizations are `-v2`**.
//! The path was deliberately not renamed — renaming it would churn every
//! reference for no tripwire benefit — so read `V1` as "corpus rev 1", never as
//! "customization v1".
//!
//! **What "values unchanged" does and does not mean.** The fixture's scarcity
//! numbers are **retained operands**, not micro-unit recomputes: the same
//! integers are now *interpreted* as micro where they were milli, which is why
//! the wire bytes — and `EXPECTED_WIRE_LEN` / `EXPECTED_WIRE_DIGEST_HEX` — did
//! not move and the only movement is the isolated `-v2` auth change. They are
//! **not** the ×1000-scaled values a physical micro recompute would produce
//! (other fixtures *were* rescaled where their arithmetic is under test). Holding
//! the operands fixed is deliberate: it keeps the wire digest a stable tripwire
//! so an unintended *format* change cannot hide behind an intended *semantic*
//! one.

use shekyl_archival_retention::hash::cshake256_32;
use shekyl_archival_retention::{
    ArchivalRewardEmissionVin, EmissionAuthRole, HoldingsDescriptor, HoldingsKind,
    MembershipOnlyBacking, RewardCommit, ShardSet, ShardWorkEntry, WorkEpochClaim,
};
use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};

/// Expected 64-byte `auth_msg` digest, stake-side (`Backing`) customization.
const EXPECTED_BACKING_HEX: &str = "c975235c70fa6c9bd80b429e8a92f06dea988a22edb6d6af38e53d62fdb7943270947bbcd8320ca7061e0e9b6c3161fdf93dfbfc4116d208287f8d54ac73c901";
/// Expected 64-byte `auth_msg` digest, claim-side (`Claim`) customization.
const EXPECTED_CLAIM_HEX: &str = "dd39154467976ebd6ca98456ffde6934cbcd29adee749e8621903e7908230fbc28ceeca5dd693e9b571fe7965bc64987ed684e320d46ab5d62f8858eb338b6f5";
/// Expected serialized wire length of the fixture vin.
const EXPECTED_WIRE_LEN: usize = 10_933;
/// Expected `cshake256_32("shekyl/emission-wire-kat-v1", wire_bytes)` of the
/// fixture vin's full serialization (tag included) — pins the wire layout.
const EXPECTED_WIRE_DIGEST_HEX: &str =
    "5ce06d80fcb61ace96c63c196751752f93cf70874c1451d4e2fd8b713f509ff9";

/// Fully deterministic fixture — every byte fixed, no RNG, so the vectors are
/// reproducible from this source alone.
fn fixture_vin() -> ArchivalRewardEmissionVin {
    ArchivalRewardEmissionVin {
        p_pubkey: vec![0x5A; SINGLE_KEY_CANONICAL_LEN],
        holdings: HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
        },
        settlement_epochs: vec![11, 12, 15],
        work_claim: vec![
            WorkEpochClaim {
                epoch: 11,
                shard_entries: vec![
                    ShardWorkEntry {
                        shard_id: 7,
                        serve_credit_bit: true,
                        scarcity_micro: 850,
                    },
                    ShardWorkEntry {
                        shard_id: 42,
                        serve_credit_bit: false,
                        scarcity_micro: 0,
                    },
                ],
            },
            WorkEpochClaim {
                epoch: 12,
                shard_entries: vec![ShardWorkEntry {
                    shard_id: 7,
                    serve_credit_bit: true,
                    scarcity_micro: 1_000,
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
        // Strictly positive per ARCHIVAL_REWARD_GATE_M1.md §2.3 wire
        // positivity (the pre-gate corpus carried a trailing 0; the vectors
        // were regenerated in lockstep at the gate's implementation PR).
        reward_amount_plain: vec![1_000_000, 2_000_000, 3_000_000],
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
