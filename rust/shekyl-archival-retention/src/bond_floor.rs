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

/// Minimum bonded collateral for `holdings` at join-Market (gate-4 §3.2 `== bond_floor` pin).
///
/// Returns `0` when holdings are structurally invalid (empty shard set, count overflow).
#[must_use]
pub fn bond_floor(holdings: &HoldingsDescriptor) -> u64 {
    if holdings.kind == HoldingsKind::CompleteTree {
        return ARCHIVAL_BOND_FLOOR_ATOMIC;
    }
    let shard_count = holdings.shard_ids.len();
    if shard_count == 0 || shard_count > MAX_HOLDINGS_SHARDS {
        return 0;
    }
    ARCHIVAL_BOND_FLOOR_ATOMIC
        .checked_mul(shard_count as u64)
        .unwrap_or(0)
}

const _: () = assert!(
    ARCHIVAL_BOND_FLOOR_ATOMIC == 750_000_000,
    "ARCHIVAL_BOND_FLOOR_ATOMIC diverged from gate-4 pin"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bond_wire::HoldingsKind;

    #[test]
    fn floor_scales_with_shard_count() {
        let holdings = HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: vec![1, 2, 3],
        };
        assert_eq!(bond_floor(&holdings), 3 * ARCHIVAL_BOND_FLOOR_ATOMIC);
    }

    #[test]
    fn complete_tree_is_single_floor() {
        let holdings = HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: Vec::new(),
        };
        assert_eq!(bond_floor(&holdings), ARCHIVAL_BOND_FLOOR_ATOMIC);
    }

    #[test]
    fn empty_shard_set_yields_zero() {
        let holdings = HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: Vec::new(),
        };
        assert_eq!(bond_floor(&holdings), 0);
    }
}
