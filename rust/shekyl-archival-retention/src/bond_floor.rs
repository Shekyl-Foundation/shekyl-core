// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `bond_floor(holdings)` per gate-4 §3.2 / §8.1 (G4-7).

include!(concat!(
    env!("OUT_DIR"),
    "/archival_bond_floor_generated.rs"
));

use crate::bond_wire::{HoldingsDescriptor, HoldingsKind, MAX_HOLDINGS_SHARDS};

/// Minimum bonded collateral for `holdings` at join-Market (gate-4 §3.2 `== bond_floor` pin),
/// at `params`' floor.
///
/// Returns `0` when holdings are structurally invalid (empty shard set, count overflow).
#[must_use]
pub fn bond_floor(holdings: &HoldingsDescriptor, params: &crate::ArchivalParams) -> u64 {
    bond_floor_of(holdings.kind, holdings.shard_ids.len(), params)
}

/// [`bond_floor`] from the holdings' `(kind, shard count)` alone — the floor
/// never reads shard-id *values*, so a caller that only knows the count (the
/// `Release` connect fold, whose C++ caller need not marshal the record's
/// shard-id array across the FFI) shares the one implementation.
#[must_use]
pub fn bond_floor_of(
    kind: HoldingsKind,
    shard_count: usize,
    params: &crate::ArchivalParams,
) -> u64 {
    if kind == HoldingsKind::CompleteTree {
        return params.bond_floor_atomic;
    }
    if shard_count == 0 || shard_count > MAX_HOLDINGS_SHARDS {
        return 0;
    }
    params
        .bond_floor_atomic
        .checked_mul(shard_count as u64)
        .unwrap_or(0)
}

// The gate-4 pin (750 000 000) is a test on the shipped set
// (`params.rs`, `the_shipped_bond_floor_is_the_gate4_pin`).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bond_wire::HoldingsKind;
    use crate::bond_wire::ShardSet;

    #[test]
    fn floor_scales_with_shard_count() {
        let holdings = HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![1, 2, 3]).unwrap(),
        };
        assert_eq!(
            bond_floor(&holdings, &crate::ArchivalParams::SHIPPED),
            3 * ARCHIVAL_BOND_FLOOR_ATOMIC
        );
    }

    #[test]
    fn complete_tree_is_single_floor() {
        let holdings = HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: ShardSet::empty(),
        };
        assert_eq!(
            bond_floor(&holdings, &crate::ArchivalParams::SHIPPED),
            ARCHIVAL_BOND_FLOOR_ATOMIC
        );
    }

    #[test]
    fn empty_shard_set_yields_zero() {
        let holdings = HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::empty(),
        };
        assert_eq!(bond_floor(&holdings, &crate::ArchivalParams::SHIPPED), 0);
    }
}
