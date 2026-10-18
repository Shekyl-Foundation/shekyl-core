// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`ChainReadFacts`]: the chain reads behind the eight methods the store
//! flip moves off the C++ table (`DRS_X_STORE_FLIP.md` DX-Q3, PR 3) —
//! `get_alt_blocks_hashes`, `get_alternate_chains`, `get_coinbase_tx_sum`,
//! `calc_pow`, `get_curve_tree_info`, `get_curve_tree_checkpoint`,
//! `get_archival_emission_claim_source` and `get_archival_shard_coverage`.
//!
//! **Staged.** One implementor, [`StoreFacts`](crate::store_facts::StoreFacts),
//! over the Rust chain store; the handlers in [`crate::read_methods`] are
//! built and tested and not routed. The server answers these methods from
//! the C++ table until the flip connects the store (PR 2's router, then the
//! flip), and no FFI implementor is written: the C++ side is deleted at the
//! flip, so a second implementor here would be built only to be removed.
//!
//! The values are typed chain facts. The handlers own the wire: hex, the
//! 128-bit triples, the status strings and the refusals.

use shekyl_archival_retention::ShardCoverageIn;
use shekyl_chain_rules::EmissionEpochFacts;
use shekyl_types::archival::HoldingsKind;
use shekyl_types::{
    BlockHash, BlockHeight, ChainCount, CurveTreeRoot, PCanonicalId, PowHash, SettlementEpoch,
    ShardId,
};
use shekyl_units::AtomicUnits;

use crate::chain_facts::FactsFault;

/// One alternative chain: a tip no alt block extends, and every alt block
/// below it, down to the first block that names a parent the alt table does
/// not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltChainFacts {
    /// The chain's blocks, tip first. Never empty: the tip is one.
    pub blocks: Vec<BlockHash>,
    /// The tip's height.
    pub tip_height: BlockHeight,
    /// The tip's cumulative difficulty along its chain.
    pub cumulative_difficulty: u128,
    /// The parent the lowest block names — where the chain leaves the
    /// blocks this node holds as alternatives. A main-chain block: every
    /// stored alternative chain reaches the main chain (the store's
    /// invariant, `shekyl-chain-store`'s `store/alt.rs`).
    pub parent: BlockHash,
}

/// The curve tree after one block: what the store recorded for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurveTreeFacts {
    /// The block the tree is after.
    pub after: BlockHeight,
    /// The tree's root.
    pub root: CurveTreeRoot,
    /// Layers less one; `0` for an empty tree. A function of `leaf_count`.
    pub depth: u8,
    /// Leaves in the tree.
    pub leaf_count: u64,
}

/// What a block range emitted and what its transactions paid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CoinbaseSum {
    /// Coins the range's blocks generated: the supply accumulator's growth
    /// across the range — each block's paid reward, its miner and its
    /// staker legs.
    pub emission: u128,
    /// Fees the range's listed transactions paid, burned share and staker
    /// share included.
    pub fees: u128,
}

/// A range `get_coinbase_tx_sum` sums, or the refusal it answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinbaseRange {
    /// The range is inside the chain; here is its sum.
    Summed(CoinbaseSum),
    /// The start is at or past the chain count, or the count exceeds it.
    TooLarge,
}

/// The seed a `calc_pow` hash is computed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowSeed {
    /// The caller named it.
    Given(BlockHash),
    /// The chain's seed for a block at this height (CEN-D3's schedule).
    AtHeight(BlockHeight),
}

/// A `calc_pow` answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowAt {
    /// RandomX over the bytes under the seed.
    Hashed(PowHash),
    /// The seed height is above the tip: the chain has no block there, so
    /// there is no seed to hash under.
    SeedAboveTip {
        /// The seed height the schedule names.
        seed_height: BlockHeight,
        /// The tip the snapshot holds.
        tip: BlockHeight,
    },
    /// The daemon's cache store does not hold this seed's cache.
    /// `calc_pow` hashes only under a held cache and never derives one
    /// (ruled 2026-10-17): a derivation is a 256 MiB fill that would
    /// evict the validator's spare cache, and an RPC caller names the
    /// seed.
    SeedNotHeld {
        /// The seed asked for, given or named by the height.
        seed: BlockHash,
    },
}

/// A claimant's bond record, as the claim source reports it: what the
/// wallet's exit and claim checks read of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimantBond {
    pub join_settlement_epoch: SettlementEpoch,
    pub holdings_kind: HoldingsKind,
    /// The held shards, in the record's order; empty for a complete tree.
    pub held_shards: Vec<ShardId>,
    pub claimed_settlement_epochs: Vec<SettlementEpoch>,
    pub bonded_total: AtomicUnits,
    pub bad_interval_count: usize,
    /// The record's last-served epoch, folded over its shards by the
    /// release verify's own fold (`whole_record_last_served`); `None` for
    /// a record that never served.
    pub last_served: Option<u64>,
    /// The slash scheduler's watermark; `None` before any slash epoch
    /// settled.
    pub last_settled_slash: Option<SettlementEpoch>,
}

/// What a persona's claim is built from: the chain count, the settled
/// epoch, its record, and every epoch of the claim window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimSource {
    pub chain_height: ChainCount,
    pub current_settled_epoch: SettlementEpoch,
    pub bond: Option<ClaimantBond>,
    /// Every epoch of the claim window, ascending, as the claim verify's
    /// own gather reads it (`emission_epoch_facts`, CEN-J23): an epoch its
    /// citing gate admits — budget, `Σwork` and close height all present —
    /// carries the snapshot; any other carries none and is unclaimable
    /// (`SO-D11d`, `SO-D11g`).
    pub epochs: Vec<EmissionEpochFacts>,
}

/// The coverage list's operands: the shards a join can hold, unranked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardCoverage {
    /// The tip the list is as of.
    pub as_of: BlockHeight,
    /// Leaves in the curve tree after the tip.
    pub leaf_count: u64,
    /// The last settled epoch as of the tip.
    pub settled_epoch: SettlementEpoch,
    pub budget: Option<u64>,
    pub sigma_work_milli: Option<u64>,
    /// One row per closed and final shard, in shard order.
    pub shards: Vec<ShardCoverageIn>,
}

/// The chain reads behind the store flip's eight native read methods
/// (module docs). Every method reads one committed snapshot.
pub trait ChainReadFacts: Send + Sync {
    /// Every alt block's identity, in the alt table's key order.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] on an empty store; the store's faults.
    fn alt_block_hashes(&self) -> Result<Vec<BlockHash>, FactsFault>;

    /// Every alternative chain, by tip, in the alt table's key order of
    /// the tips.
    ///
    /// # Errors
    ///
    /// As [`alt_block_hashes`](Self::alt_block_hashes).
    fn alternate_chains(&self) -> Result<Vec<AltChainFacts>, FactsFault>;

    /// The curve tree after the top block.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] on an empty store; the store's faults.
    fn curve_tree(&self) -> Result<CurveTreeFacts, FactsFault>;

    /// The curve tree after the block at `height`; `None` above the tip.
    ///
    /// # Errors
    ///
    /// As [`curve_tree`](Self::curve_tree).
    fn curve_tree_after(&self, height: BlockHeight) -> Result<Option<CurveTreeFacts>, FactsFault>;

    /// What `count` blocks from `start` emitted and paid.
    ///
    /// # Errors
    ///
    /// As [`curve_tree`](Self::curve_tree); [`FactsFault::Inconsistent`]
    /// when a listed transaction or a block in range is missing.
    fn coinbase_sum(&self, start: BlockHeight, count: u64) -> Result<CoinbaseRange, FactsFault>;

    /// RandomX over `pow_blob` under `seed`, under a cache the daemon's
    /// cache store already holds; [`PowAt::SeedNotHeld`] for any other.
    /// Never derives a cache.
    ///
    /// # Errors
    ///
    /// As [`curve_tree`](Self::curve_tree) when the seed is read off the
    /// chain.
    fn pow_hash(&self, pow_blob: &[u8], seed: PowSeed) -> Result<PowAt, FactsFault>;

    /// What `persona`'s emission claim is built from (`ClaimSource`).
    ///
    /// # Errors
    ///
    /// As [`curve_tree`](Self::curve_tree); [`FactsFault::Inconsistent`]
    /// when a derivation finds the store contradicting itself.
    fn emission_claim_source(&self, persona: &PCanonicalId) -> Result<ClaimSource, FactsFault>;

    /// The shard coverage list's operands (`ShardCoverage`).
    ///
    /// # Errors
    ///
    /// As [`emission_claim_source`](Self::emission_claim_source).
    fn shard_coverage(&self) -> Result<ShardCoverage, FactsFault>;
}
