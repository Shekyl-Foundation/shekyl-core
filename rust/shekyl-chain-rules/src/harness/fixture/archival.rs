// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Archival transaction fixtures: the bond floor, a serve-credit vin, the
//! JoinMarket that opens a persona's record, the serve-credit-only body
//! that follows it, and a parseable emission claim for a persona.

use shekyl_crypto_pq::multisig::SINGLE_SIG_CANONICAL_LEN;
use shekyl_types::PCanonicalId;
use shekyl_wire::transaction::PQC_HYBRID_SINGLE_KEY_LEN;
use shekyl_wire::{
    BondPost, BondPostKind, Ct, CtBase, Holdings, Input, Prunable, Transaction, TxPrefix,
};

use super::{balanced_bond_post, UNRECORDED_REFERENCE};

/// The persona a `[fill; LEN]` hybrid pubkey derives to — the emission
/// vin's persona is derived from its `p_pubkey`, so a [`join_market`] for
/// `claimant(fill)` is the record an [`emission_vin`] built with `fill`
/// claims against.
#[must_use]
pub fn claimant(p_pubkey_fill: u8) -> [u8; 32] {
    *shekyl_archival_retention::p_canonical_id_from_hybrid_pubkey(&vec![
        p_pubkey_fill;
        PQC_HYBRID_SINGLE_KEY_LEN
    ])
    .as_bytes()
}

/// A parseable **emission-claim vin** for the persona [`claimant`]`(fill)`
/// claiming `epochs`, one shard-7 serve-credit entry per epoch, a
/// membership-only backing and filler auths: enough for CEN-L7's claim
/// arm to read the persona and the epochs (and for the block-level G9,
/// which reads the claims). Nothing here verifies the backing or the
/// auths. [`balanced_emission`](super::balanced_emission) puts it in a
/// body CEN-H22 balances.
pub fn emission_vin(p_pubkey_fill: u8, epochs: &[u64]) -> Input {
    use shekyl_archival_retention::{
        ArchivalRewardEmissionVin, HoldingsDescriptor, HoldingsKind, MembershipOnlyBacking,
        ShardSet, ShardWorkEntry, WorkEpochClaim,
    };
    let vin = ArchivalRewardEmissionVin {
        p_pubkey: vec![p_pubkey_fill; PQC_HYBRID_SINGLE_KEY_LEN],
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
            backing_pubkey: vec![0xb2; PQC_HYBRID_SINGLE_KEY_LEN],
            tree_depth: 3,
        },
        reward_amount_plain: epochs.iter().map(|_| 1_000_000).collect(),
        auth_backing: vec![0xc3; SINGLE_SIG_CANONICAL_LEN],
        auth_claim: vec![0xd4; SINGLE_SIG_CANONICAL_LEN],
    };
    Input::ArchivalRewardEmission {
        canonical_bytes: vin.serialize().expect("an emission vin serializes"),
    }
}

/// The bond floor a [`join_market`] posts and is bonded at — the
/// complete-tree floor, one bond (`bond_floor_of(CompleteTree, _)`).
pub const BOND_FLOOR: u64 = shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;

/// A parseable **serve-credit vin** — the kept half of the response
/// (`RF-D1`) crediting persona `p` for `shard` in `settlement_epoch`, its
/// countersignature filler (CEN-J10 reads that; nothing here does).
pub fn serve_credit_vin(p: [u8; 32], shard: u64, settlement_epoch: u64) -> Input {
    let kept = shekyl_archival_retention::ArchivalServeCreditResponse {
        p_canonical_id: p,
        shard_id: shard,
        settlement_epoch,
        ed25519_countersignature: [0x5c; 64],
    };
    Input::ServeCredit {
        canonical_bytes: kept.serialize().expect("a kept half serializes"),
    }
}

/// A **JoinMarket bond post** for persona `p` (CEN-H21's shape on
/// [`balanced_bond_post`]): a complete-tree holding bonded at
/// [`BOND_FLOOR`], funded by the spend of `key_image`. The one archival
/// body that connects on a chain with **no archival state** — it creates
/// `p`'s record — so it is what precedes a serve credit or a claim for `p`
/// in a block (CEN-L7 refuses either for a persona without a record).
pub fn join_market(key_image: [u8; 32], p: [u8; 32]) -> Transaction {
    balanced_bond_post(
        key_image,
        BondPost {
            hybrid_public_key: vec![0xb1; PQC_HYBRID_SINGLE_KEY_LEN],
            p_canonical_id: PCanonicalId::from_bytes(p),
            kind: BondPostKind::JoinMarket {
                bond_spend_pk: vec![0xb5; PQC_HYBRID_SINGLE_KEY_LEN],
                endpoint: [0xe0; 32],
            },
            holdings: Holdings::CompleteTree,
            bonded_total_atomic: BOND_FLOOR,
            bond_credit: BOND_FLOOR,
            bond_debit: 0,
        },
    )
}

/// The pruned half of one pass record in the serve-credit fixtures: a
/// non-empty opaque blob inside the wire's length bound. CEN-H20 counts the
/// records and the wire bounds their length; what one holds is CEN-J10's,
/// and no fixture claims to satisfy it.
pub const PRUNED_PASS_RECORD: [u8; 8] = [0xA5; 8];

/// A **serve-credit-only** transaction (CEN-H20's shape: serve-credit
/// inputs and nothing else, no outputs, zero fee, no spend material, and the
/// `RF-D1` prunable region holding one pruned pass record per serve-credit
/// vin — [`PRUNED_PASS_RECORD`], a marker no verifier reads)
/// crediting persona `p` for shard 0 in settlement epoch 0 — the open
/// epoch on any chain shorter than one (every fixture chain is). The one
/// legal non-coinbase shape with **no key image** — what a test needs
/// when it must list the same body twice (SI-3) without tripping the
/// spent-key-image set. It connects only behind [`join_market`] for `p`
/// (CEN-L7 / SI-15: a credit names a persona with a record), which is why
/// [`TxShape::ServeCreditOnly`] lists at `Listed(1)` with the join as its
/// precedent; alone it is a body for `tx_form`, not for `validate`.
pub fn serve_credit_only(p: [u8; 32]) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![serve_credit_vin(p, 0, 0)],
            outputs: Vec::new(),
            extra: Vec::new(),
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: UNRECORDED_REFERENCE,
            base: CtBase {
                enc_amounts: Vec::new(),
                enc_labels: Vec::new(),
                commitments: Vec::new(),
            },
            pqc_auths: Vec::new(),
            prunable: Some(Prunable {
                bulletproofs: Vec::new(),
                tree_depth: 0,
                fcmp_proof: Vec::new(),
                pseudo_outs: Vec::new(),
                serve_credit_pruned: vec![PRUNED_PASS_RECORD.to_vec()],
            }),
        },
    }
}
