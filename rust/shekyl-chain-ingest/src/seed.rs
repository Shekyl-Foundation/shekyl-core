// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The driver's seed claim: what `form` is told the RandomX seed is
//! (CEN-D3), from the chain the driver is replaying — never guessed.
//!
//! `form` runs ahead of `connect`, in parallel, on blocks the store has not
//! recorded yet; the seed for a block at `h` is the id of the block at
//! `seedheight(h)` on the chain it connects onto (RD-Q13: the
//! *post-rewind* chain). The driver knows that chain — it has read the
//! blocks from its source — so it keeps a [`SeedLedger`] of the hashes it
//! has seen and claims from it. `validate` then checks the claim against
//! the store (D3): agreement is the normal case, and a disagreement is a
//! **driver defect** in replay (RD-Q5, RD-F10) — the ledger and the store
//! described different chains — surfaced on first occurrence, not retried
//! away.
//!
//! The schedule is a value, not a constant: the mainnet epoch/lag pair is
//! [`SeedSchedule::MAINNET`], and Fakechain runs hand `form` a clamped
//! override (RD-Q7, commit 6b) the same way the FFI does.

use std::collections::BTreeMap;

use shekyl_difficulty::{seedheight, SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG};
use shekyl_types::{BlockHash, BlockHeight};

/// The seed-epoch schedule `seedheight` runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedSchedule {
    /// Blocks per seed epoch.
    pub blocks: u64,
    /// Seed lag in blocks.
    pub lag: u64,
}

impl SeedSchedule {
    /// The public networks' schedule.
    pub const MAINNET: Self = Self {
        blocks: SEEDHASH_EPOCH_BLOCKS,
        lag: SEEDHASH_EPOCH_LAG,
    };

    /// The height whose block seeds the cache for a block at `connecting`.
    #[must_use]
    pub const fn seed_height(self, connecting: BlockHeight) -> BlockHeight {
        BlockHeight::from_raw(seedheight(connecting.to_raw(), self.blocks, self.lag))
    }
}

/// Block hashes the driver has seen, by height, for claiming seeds.
#[derive(Clone, Debug, Default)]
pub struct SeedLedger {
    hashes: BTreeMap<u64, BlockHash>,
}

impl SeedLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the hash of the block at `height` as the source delivered it.
    /// A later record at the same height replaces the earlier one (a source
    /// that re-delivers after a rewind).
    pub fn record(&mut self, height: BlockHeight, hash: BlockHash) {
        self.hashes.insert(height.to_raw(), hash);
    }

    /// Forget every height above `to` — the post-rewind chain (RD-Q13).
    pub fn rewind_to(&mut self, to: BlockHeight) {
        self.hashes.split_off(&to.to_raw().saturating_add(1));
    }

    /// Forget heights below `floor`: seed heights are non-decreasing in the
    /// connecting height, so nothing below the current seed height is asked
    /// for again. Keeps the ledger a window, not a chain.
    pub fn forget_below(&mut self, floor: BlockHeight) {
        let keep = self.hashes.split_off(&floor.to_raw());
        self.hashes = keep;
    }

    /// The seed to claim for a block connecting at `connecting`: the null
    /// hash for genesis, else the recorded hash at the schedule's seed
    /// height. `None` when the ledger has not seen that block — the caller
    /// asks the store, which recorded it before this replay began.
    #[must_use]
    pub fn claim(&self, schedule: SeedSchedule, connecting: BlockHeight) -> Option<BlockHash> {
        if connecting.is_zero() {
            return Some(BlockHash::NULL);
        }
        self.hashes
            .get(&schedule.seed_height(connecting).to_raw())
            .copied()
    }

    /// Heights recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Whether nothing is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u64) -> BlockHeight {
        BlockHeight::from_raw(n)
    }

    fn hash(n: u8) -> BlockHash {
        BlockHash::from_bytes([n; 32])
    }

    #[test]
    fn genesis_claims_null_and_early_heights_claim_the_genesis_hash() {
        let mut ledger = SeedLedger::new();
        assert_eq!(
            ledger.claim(SeedSchedule::MAINNET, h(0)),
            Some(BlockHash::NULL)
        );
        assert_eq!(
            ledger.claim(SeedSchedule::MAINNET, h(1)),
            None,
            "genesis unseen"
        );
        ledger.record(h(0), hash(0xa0));
        // Below blocks + lag the seed height is 0.
        assert_eq!(ledger.claim(SeedSchedule::MAINNET, h(1)), Some(hash(0xa0)));
        assert_eq!(
            ledger.claim(
                SeedSchedule::MAINNET,
                h(SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG)
            ),
            Some(hash(0xa0))
        );
    }

    #[test]
    fn past_the_first_epoch_the_claim_follows_the_schedule_and_a_rewind_drops_the_fork() {
        let sched = SeedSchedule::MAINNET;
        let mut ledger = SeedLedger::new();
        let connecting = h(SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG + 1);
        let seed_height = sched.seed_height(connecting);
        assert_eq!(
            seed_height,
            h(SEEDHASH_EPOCH_BLOCKS),
            "(h − lag − 1) & !(blocks − 1)"
        );
        ledger.record(seed_height, hash(0x11));
        assert_eq!(ledger.claim(sched, connecting), Some(hash(0x11)));
        // A rewind below the seed height forgets it; the re-delivered fork
        // block replaces it.
        ledger.rewind_to(h(SEEDHASH_EPOCH_BLOCKS - 1));
        assert_eq!(ledger.claim(sched, connecting), None);
        ledger.record(seed_height, hash(0x22));
        assert_eq!(ledger.claim(sched, connecting), Some(hash(0x22)));
    }

    #[test]
    fn forget_below_keeps_the_ledger_a_window() {
        let mut ledger = SeedLedger::new();
        for n in 0..10u8 {
            ledger.record(h(u64::from(n)), hash(n));
        }
        ledger.forget_below(h(7));
        assert_eq!(ledger.len(), 3);
        assert_eq!(
            ledger.claim(SeedSchedule::MAINNET, h(1)),
            None,
            "genesis forgotten"
        );
    }
}
