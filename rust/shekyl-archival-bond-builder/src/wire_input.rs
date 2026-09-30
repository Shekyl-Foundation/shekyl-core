// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one map from a retention [`ArchivalBondPostVin`] onto the consensus
//! [`Input::BondPost`](shekyl_wire::Input::BondPost).
//!
//! JoinMarket copies `bond_spend_pk` and the serving endpoint onto
//! [`BondPostKind::JoinMarket`](shekyl_wire::BondPostKind::JoinMarket).
//! Reinstate and Release are [`BondPostKind::Other`](shekyl_wire::BondPostKind::Other)
//! of [`BondKind::tag`]. A compact holdings descriptor copies its shard ids;
//! a complete tree is [`Holdings::CompleteTree`](shekyl_wire::Holdings::CompleteTree).
//!
//! Which of those kinds a wallet will produce is the wallet's decision,
//! applied before it calls [`bond_post_input`]. This function maps every
//! kind the retention vocabulary can spell.

use shekyl_archival_retention::{ArchivalBondPostVin, BondKind, HoldingsDescriptor, HoldingsKind};
use shekyl_types::PCanonicalId;
use shekyl_wire::{BondPost, BondPostKind, Holdings, Input};

/// Map `vin` onto the consensus prefix input.
///
/// Every [`BondKind`] has an image. The serving-endpoint arrays are the
/// same length on both sides of the edge, so the JoinMarket endpoint copies
/// as a value.
#[must_use]
pub fn bond_post_input(vin: &ArchivalBondPostVin) -> Input {
    let kind = match &vin.kind {
        BondKind::JoinMarket {
            bond_spend_pk,
            endpoint,
        } => BondPostKind::JoinMarket {
            bond_spend_pk: bond_spend_pk.clone(),
            endpoint: *endpoint,
        },
        BondKind::Reinstate | BondKind::Release => BondPostKind::Other(vin.kind.tag() as u8),
    };
    Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vin.hybrid_public_key.clone(),
        p_canonical_id: PCanonicalId::from_bytes(vin.p_canonical_id),
        kind,
        holdings: wire_holdings(&vin.holdings),
        bonded_total_atomic: vin.bonded_total_atomic,
        bond_credit: vin.bond_credit,
        bond_debit: vin.bond_debit,
    }))
}

/// The wire holdings a descriptor declares.
///
/// A compact set copies `shard_ids` in their insertion order. A complete
/// tree carries no shard list.
fn wire_holdings(holdings: &HoldingsDescriptor) -> Holdings {
    match holdings.kind {
        HoldingsKind::ShardSetCompact => {
            Holdings::ShardSetCompact(holdings.shard_ids.as_slice().to_vec())
        }
        HoldingsKind::CompleteTree => Holdings::CompleteTree,
    }
}

#[cfg(test)]
mod tests {
    use shekyl_archival_retention::{
        BondKind, BondPostKind as PostKind, HoldingsDescriptor, HoldingsKind, ShardSet,
    };
    use shekyl_wire::{BondPostKind, Holdings, Input};

    use super::*;

    fn vin(kind: BondKind, holdings: HoldingsDescriptor) -> ArchivalBondPostVin {
        ArchivalBondPostVin {
            hybrid_public_key: vec![0x11, 0x22],
            p_canonical_id: [0x33; 32],
            kind,
            holdings,
            bonded_total_atomic: 7,
            bond_credit: 8,
            bond_debit: 9,
        }
    }

    fn compact(ids: Vec<u64>) -> HoldingsDescriptor {
        HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(ids).expect("distinct ids under the cap"),
        }
    }

    fn tree() -> HoldingsDescriptor {
        HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: ShardSet::empty(),
        }
    }

    fn post(vin: &ArchivalBondPostVin) -> BondPost {
        let Input::BondPost(post) = bond_post_input(vin) else {
            panic!("a bond vin maps to a bond post");
        };
        *post
    }

    #[test]
    fn every_kind_maps_and_the_amounts_copy() {
        let join = post(&vin(
            BondKind::JoinMarket {
                bond_spend_pk: vec![0xAB; 4],
                endpoint: [0xE0; 32],
            },
            tree(),
        ));
        assert_eq!(
            join.kind,
            BondPostKind::JoinMarket {
                bond_spend_pk: vec![0xAB; 4],
                endpoint: [0xE0; 32],
            }
        );
        assert_eq!(join.holdings, Holdings::CompleteTree);
        assert_eq!(join.p_canonical_id.as_bytes(), &[0x33; 32]);
        assert_eq!(join.bonded_total_atomic, 7);
        assert_eq!(join.bond_credit, 8);
        assert_eq!(join.bond_debit, 9);
        assert_eq!(join.hybrid_public_key, vec![0x11, 0x22]);

        let reinstated = post(&vin(BondKind::Reinstate, tree()));
        assert_eq!(
            reinstated.kind,
            BondPostKind::Other(PostKind::Reinstate as u8)
        );

        let released = post(&vin(BondKind::Release, compact(vec![4, 9])));
        assert_eq!(released.kind, BondPostKind::Other(PostKind::Release as u8));
        assert_eq!(released.holdings, Holdings::ShardSetCompact(vec![4, 9]));
    }
}
