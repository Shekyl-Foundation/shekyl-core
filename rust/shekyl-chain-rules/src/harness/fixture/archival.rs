// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Archival transaction fixtures: the bond floor, a serve-credit vin, the
//! JoinMarket that opens a persona's record, and the serve-credit-only body
//! that follows it.

use shekyl_types::PCanonicalId;
use shekyl_wire::transaction::PQC_HYBRID_SINGLE_KEY_LEN;
use shekyl_wire::{BondPost, BondPostKind, Ct, CtBase, Holdings, Input, Transaction, TxPrefix};

use super::{balanced_bond_post, UNRECORDED_REFERENCE};

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

/// A **serve-credit-only** transaction (CEN-H20's shape: serve-credit
/// inputs and nothing else, no outputs, zero fee, no spend material)
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
            prunable: None,
        },
    }
}
