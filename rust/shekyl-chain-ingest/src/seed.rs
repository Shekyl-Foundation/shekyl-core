// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The driver's seed claim: what `form` is told the RandomX seed is
//! (CEN-D3), from the chain the driver is replaying — never guessed.
//!
//! `form` runs ahead of `connect`, in parallel, on blocks the store has not
//! recorded yet; the seed for a block at `h` is the id of the block at
//! [`seed_height`]`(h)` on the chain it connects onto (RD-Q13: the
//! *post-rewind* chain). Two places know that chain:
//!
//! - the [`SeedLedger`] — the hashes of the blocks the driver has **read**
//!   from its source, a window around the connecting height, so a claim
//!   for a block still in flight names a block the store has not recorded;
//! - the **store** — every block already connected, which is where a seed
//!   height lands once the ledger's window has moved past it, and where it
//!   lands again after a rewind moves the connecting height *backwards*
//!   over a seed-epoch step (the window had legitimately forgotten it).
//!
//! The ledger answers what it has and says [`SeedClaim::Unread`] otherwise;
//! the driver then asks the store through the connector and records the
//! answer, so each seed height is fetched once. `validate` checks every
//! claim against the store (D3): agreement is the normal case, and a
//! disagreement is a **driver defect** in replay (RD-Q5, RD-F10) — the
//! ledger and the store described different chains — surfaced on first
//! occurrence, not retried away.
//!
//! The schedule is the validator's, [`seed_height`]: the mainnet constants
//! at every nettype, no environment (slice 2 F5, CEN-D3). The claim and the
//! check call one function, so they cannot spell the schedule differently.

use std::collections::BTreeMap;

use shekyl_chain_rules::seed_height;
use shekyl_types::{BlockHash, BlockHeight};

/// What the ledger can say about a block's seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedClaim {
    /// The seed: the null hash at genesis admission, else the recorded
    /// hash at the schedule's seed height.
    Known(BlockHash),
    /// The ledger has not read the block at `seed_height`; the store has
    /// it (module docs), and the caller records the store's answer.
    Unread {
        /// The height whose hash is the seed.
        seed_height: BlockHeight,
    },
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

    /// Record the hash of the block at `height` as the source delivered it
    /// (or as the store answered for it). A later record at the same
    /// height replaces the earlier one (a source that re-delivers after a
    /// rewind).
    pub fn record(&mut self, height: BlockHeight, hash: BlockHash) {
        self.hashes.insert(height.to_raw(), hash);
    }

    /// Forget every height above `to` — the post-rewind chain (RD-Q13).
    /// What is at or below `to` is unchanged by a pop and stays.
    pub fn rewind_to(&mut self, to: BlockHeight) {
        self.hashes.split_off(&to.to_raw().saturating_add(1));
    }

    /// Forget heights below `floor`: between rewinds, seed heights are
    /// non-decreasing in the connecting height, so nothing below the
    /// current seed height is asked for again — and if a rewind does ask,
    /// the store answers (module docs). Keeps the ledger a window, not a
    /// chain.
    pub fn forget_below(&mut self, floor: BlockHeight) {
        let keep = self.hashes.split_off(&floor.to_raw());
        self.hashes = keep;
    }

    /// The seed to claim for a block connecting at `connecting`.
    #[must_use]
    pub fn claim(&self, connecting: BlockHeight) -> SeedClaim {
        let Some(seed_height) = seed_height(connecting) else {
            return SeedClaim::Known(BlockHash::NULL);
        };
        match self.hashes.get(&seed_height.to_raw()) {
            Some(hash) => SeedClaim::Known(*hash),
            None => SeedClaim::Unread { seed_height },
        }
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
    use shekyl_difficulty::{SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG};

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
        assert_eq!(ledger.claim(h(0)), SeedClaim::Known(BlockHash::NULL));
        assert_eq!(
            ledger.claim(h(1)),
            SeedClaim::Unread { seed_height: h(0) },
            "genesis unseen: the store is asked"
        );
        ledger.record(h(0), hash(0xa0));
        // Below blocks + lag the seed height is 0.
        assert_eq!(ledger.claim(h(1)), SeedClaim::Known(hash(0xa0)));
        assert_eq!(
            ledger.claim(h(SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG)),
            SeedClaim::Known(hash(0xa0))
        );
    }

    #[test]
    fn past_the_first_epoch_the_claim_follows_the_schedule_and_a_rewind_drops_the_fork() {
        let mut ledger = SeedLedger::new();
        let connecting = h(SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG + 1);
        let seed_height = h(SEEDHASH_EPOCH_BLOCKS);
        assert_eq!(
            ledger.claim(connecting),
            SeedClaim::Unread { seed_height },
            "(h − lag − 1) & !(blocks − 1)"
        );
        ledger.record(seed_height, hash(0x11));
        assert_eq!(ledger.claim(connecting), SeedClaim::Known(hash(0x11)));
        // A rewind below the seed height forgets it; the re-delivered fork
        // block replaces it.
        ledger.rewind_to(h(SEEDHASH_EPOCH_BLOCKS - 1));
        assert_eq!(ledger.claim(connecting), SeedClaim::Unread { seed_height });
        ledger.record(seed_height, hash(0x22));
        assert_eq!(ledger.claim(connecting), SeedClaim::Known(hash(0x22)));
    }

    #[test]
    fn forget_below_keeps_the_ledger_a_window_and_the_store_is_asked_for_the_rest() {
        let mut ledger = SeedLedger::new();
        for n in 0..10u8 {
            ledger.record(h(u64::from(n)), hash(n));
        }
        ledger.forget_below(h(7));
        assert_eq!(ledger.len(), 3);
        assert_eq!(
            ledger.claim(h(1)),
            SeedClaim::Unread { seed_height: h(0) },
            "genesis forgotten: the store has it"
        );
    }
}
