// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The handles the composition root hands the RPC (`DRS_X_STORE_FLIP.md`
//! DX-Q3, N1). Each is the [`OptionsHandle`](crate::options::OptionsHandle)
//! shape: a trait object, and an absent value that answers
//! [`FactsFault::NotReady`].
//!
//! **Nothing here is routed.** The live handlers still read the C++ core.
//! The handles are on [`crate::server::AppState`] so the flip's edit is
//! which source a handler calls, and a Rust test can already call them
//! over a real node. An absent handle never answers with a zero or an
//! empty list (RK-D23): those are what a live, empty node reports.

use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::sync::Arc;

use shekyl_rpc_types::errors::Diagnostic;

use shekyl_types::{BlockHash, BlockHeight, KeyImage, PCanonicalId, TxHash};

use crate::chain_facts::{
    BlockAt, BlockHashAt, BlockHeaderAt, BlockLookup, ChainFacts, ChainTip, DaemonIdentity,
    FactsFault, FeeEstimate,
};
use crate::info_facts::{
    InfoChainFacts, InfoFacts, InfoStatusFacts, PeerFacts, PoolCounts, PoolScope, SessionCounts,
};
use crate::mining_facts::{LocalOutcome, MiningState, Pending, PopOutcome, PostedTemplate};
use crate::read_facts::{
    AltChainFacts, BlocksAt, ChainReadFacts, ClaimSource, CoinbaseRange, CurveTreeFacts, PowAt,
    PowSeed, ShardCoverage, SpentAt,
};

/// The chain reads that replace `FfiChainFacts`, `FfiInfoFacts` and
/// `ChainReadFacts`' production sources at the flip. One object, the
/// three traits those handlers already call.
pub trait ChainRead: ChainFacts + InfoFacts + ChainReadFacts {}

impl<T> ChainRead for T where T: ChainFacts + InfoFacts + ChainReadFacts {}

/// A chain-read handle.
pub type ChainReadHandle = Arc<dyn ChainRead>;

/// One pool entry, as a listing reads it: never when it arrived (S7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolEntryFacts {
    /// Its id.
    pub id: TxHash,
    /// The transaction, serialized.
    pub blob: Vec<u8>,
    /// Its weight.
    pub weight: u64,
    /// Its fee, in atomic units.
    pub fee: u64,
    /// Whether the node shows it; `false` is its stem phase.
    pub shown: bool,
    /// The key images it spends.
    pub key_images: Vec<KeyImage>,
}

/// The pool, as the RPC will read it. A live empty pool reports `0`; an
/// absent handle does not.
pub trait PoolFacts: Send + Sync {
    /// How many entries the node shows.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no pool was supplied.
    fn broadcast_count(&self) -> Result<u64, FactsFault>;

    /// The entries `scope` may see: the shown ones, or every one for the
    /// host's administrator (`RPC_CHANNEL.md` RT-O9.3).
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no pool was supplied.
    fn entries(&self, scope: PoolScope) -> Result<Vec<PoolEntryFacts>, FactsFault>;

    /// Remove `ids` from the pool, or every entry when `ids` is empty
    /// (`flush_txpool`); the removed ids.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no pool was supplied;
    /// [`FactsFault::StoreUnreadable`] when the pool file faults.
    fn flush(&self, ids: &[TxHash]) -> Result<Vec<TxHash>, FactsFault>;

    /// Offer the node's own `ids` to the relay again (`relay_tx`); the ids
    /// offered. The relay driver is RD's; until it is wired, not ready.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] until a relay driver is supplied.
    fn relay(&self, _ids: &[TxHash]) -> Result<Vec<TxHash>, FactsFault> {
        Err(FactsFault::NotReady)
    }
}

/// A pool handle.
pub type PoolHandle = Arc<dyn PoolFacts>;

/// The ingest door, as the RPC will offer a local block through it.
pub trait DoorFacts: Send + Sync {
    /// Seats the door reports now. This crate does not name the ingest
    /// door: the composition root's implementor does.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no door was supplied. A closed door
    /// is `Ok(0)`: the node is up and is not accepting.
    fn room(&self) -> Result<usize, FactsFault>;

    /// Offer `block` through the node's local-arrival entry (b4): wait for
    /// the local seat, offer it, and await its one reply. Its listed
    /// bodies come from the pool.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no door was supplied.
    fn offer_local(&self, block: Vec<u8>) -> Pending<'_, LocalOutcome>;

    /// Pop `count` blocks from the tip, returning their bodies to the pool
    /// (`pop_blocks`, DX-Q3, Q7). A pop below the lowest poppable height is
    /// refused before any pop.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no door was supplied or the node is
    /// stopping.
    fn pop(&self, count: u64) -> Pending<'_, PopOutcome>;

    /// Resolve once the tip is at `height` or above.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no door was supplied, or when the node
    /// stops first.
    fn tip_at_least(&self, height: BlockHeight) -> Pending<'_, ()>;
}

/// A door handle.
pub type DoorHandle = Arc<dyn DoorFacts>;

/// Mining control and the node's posted template (N2). An absent handle
/// is not ready.
pub trait MiningFacts: Send + Sync {
    /// Whether this node is mining.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no mining control was supplied.
    fn running(&self) -> Result<bool, FactsFault>;

    /// The posted template, or why none is posted.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no mining control was supplied.
    fn template(&self) -> Result<Result<PostedTemplate, Diagnostic>, FactsFault>;

    /// Start the built-in miner with `threads` workers, or the host's
    /// parallelism less one. The inner error is the node's refusal.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no mining control was supplied.
    fn start(&self, threads: Option<NonZeroUsize>) -> Result<Result<(), Diagnostic>, FactsFault>;

    /// Stop the built-in miner; `false` when it was not running. The node
    /// keeps running.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no mining control was supplied.
    fn stop(&self) -> Result<bool, FactsFault>;

    /// The miner, the posted job, and why none is posted.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no mining control was supplied.
    fn status(&self) -> Result<MiningState, FactsFault>;
}

/// A mining handle.
pub type MiningHandle = Arc<dyn MiningFacts>;

/// What a ban names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanTargetFacts {
    /// One host.
    Host(IpAddr),
    /// An IPv4 subnet: its network address and prefix length.
    Subnet {
        /// The network address.
        network: Ipv4Addr,
        /// The prefix length, 0 to 32.
        prefix: u8,
    },
}

/// How long a ban has left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanLeftFacts {
    /// Until it is lifted.
    Permanent,
    /// Whole seconds until its deadline, rounded up.
    Seconds(u64),
}

/// One ban in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BanRow {
    /// What it names.
    pub target: BanTargetFacts,
    /// How long it has left.
    pub left: BanLeftFacts,
}

/// The node's ban table: through the bound hub while there is one, which
/// closes the sockets a new ban drops; otherwise the node's socket table
/// (`DRS_X_STORE_FLIP.md` DX-Q3, Q11). Tor inbound is never banned: it has
/// no address to ban (`shekyl-transport-layer`'s admission).
pub trait BansFacts: Send + Sync {
    /// Ban `target` for `seconds`, or until it is lifted when `None`.
    /// `Ok(false)` when the deadline does not fit the clock; nothing is
    /// banned then.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no table was supplied.
    fn ban(&self, target: BanTargetFacts, seconds: Option<u64>) -> Result<bool, FactsFault>;

    /// Lift `target`'s ban; `Ok(false)` when there was none.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no table was supplied.
    fn lift(&self, target: BanTargetFacts) -> Result<bool, FactsFault>;

    /// How long `host`'s longest ban has left; `None` when it is not
    /// banned.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no table was supplied: no table is not
    /// "this host is allowed".
    fn remaining(&self, host: IpAddr) -> Result<Option<BanLeftFacts>, FactsFault>;

    /// Every ban in force.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no table was supplied.
    fn list(&self) -> Result<Vec<BanRow>, FactsFault>;
}

/// A bans handle.
pub type BansHandle = Arc<dyn BansFacts>;

/// The one stop latch. The handler asks; it does not stop anything itself.
pub trait StopFacts: Send + Sync {
    /// Ask the composition root to stop.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when no latch was supplied. The call then
    /// does not request a stop.
    fn request_stop(&self) -> Result<(), FactsFault>;
}

/// A stop handle.
pub type StopHandle = Arc<dyn StopFacts>;

/// The six handles, absent unless the composition root supplied a node.
#[derive(Clone)]
pub struct Handles {
    /// Chain reads.
    pub chain: ChainReadHandle,
    /// The pool.
    pub pool: PoolHandle,
    /// The ingest door.
    pub door: DoorHandle,
    /// Mining control.
    pub mining: MiningHandle,
    /// The ban table.
    pub bans: BansHandle,
    /// The stop latch.
    pub stop: StopHandle,
}

impl Default for Handles {
    fn default() -> Self {
        Self::absent()
    }
}

impl Handles {
    /// Every handle absent: each call is [`FactsFault::NotReady`].
    #[must_use]
    pub fn absent() -> Self {
        Self {
            chain: Arc::new(ChainReadAbsent),
            pool: Arc::new(PoolAbsent),
            door: Arc::new(DoorAbsent),
            mining: Arc::new(MiningAbsent),
            bans: Arc::new(BansAbsent),
            stop: Arc::new(StopAbsent),
        }
    }
}

/// No chain reads were supplied.
pub struct ChainReadAbsent;

impl ChainFacts for ChainReadAbsent {
    fn chain_tip(&self) -> Result<ChainTip, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn identity(&self) -> Result<DaemonIdentity, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn block_hash_at(&self, _height: BlockHeight) -> Result<BlockHashAt, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn block_header_at(
        &self,
        _at: BlockLookup,
        _fill_pow_hash: bool,
    ) -> Result<BlockHeaderAt, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn fee_estimate(&self) -> Result<FeeEstimate, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn block_at(&self, _at: BlockLookup, _fill_pow_hash: bool) -> Result<BlockAt, FactsFault> {
        Err(FactsFault::NotReady)
    }
}

impl InfoFacts for ChainReadAbsent {
    fn chain(&self) -> Result<InfoChainFacts, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn pool_counts(&self, _scope: PoolScope) -> Result<PoolCounts, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn store_size(&self) -> Result<u64, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn status(&self) -> Result<InfoStatusFacts, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn peers(&self) -> Result<PeerFacts, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn sessions(&self) -> Result<SessionCounts, FactsFault> {
        Err(FactsFault::NotReady)
    }
}

impl ChainReadFacts for ChainReadAbsent {
    fn blocks_by_height(&self, _heights: &[BlockHeight]) -> Result<BlocksAt, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn output_indices(&self, _txid: &TxHash) -> Result<Option<Vec<u64>>, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn key_images_spent(&self, _key_images: &[KeyImage]) -> Result<Vec<SpentAt>, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn alt_block_hashes(&self) -> Result<Vec<BlockHash>, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn alternate_chains(&self) -> Result<Vec<AltChainFacts>, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn curve_tree(&self) -> Result<CurveTreeFacts, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn curve_tree_after(&self, _height: BlockHeight) -> Result<Option<CurveTreeFacts>, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn coinbase_sum(&self, _start: BlockHeight, _count: u64) -> Result<CoinbaseRange, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn pow_hash(&self, _pow_blob: &[u8], _seed: PowSeed) -> Result<PowAt, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn emission_claim_source(&self, _persona: &PCanonicalId) -> Result<ClaimSource, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn shard_coverage(&self) -> Result<ShardCoverage, FactsFault> {
        Err(FactsFault::NotReady)
    }
}

struct PoolAbsent;

impl PoolFacts for PoolAbsent {
    fn broadcast_count(&self) -> Result<u64, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn entries(&self, _scope: PoolScope) -> Result<Vec<PoolEntryFacts>, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn flush(&self, _ids: &[TxHash]) -> Result<Vec<TxHash>, FactsFault> {
        Err(FactsFault::NotReady)
    }
}

struct DoorAbsent;

impl DoorFacts for DoorAbsent {
    fn room(&self) -> Result<usize, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn offer_local(&self, _block: Vec<u8>) -> Pending<'_, LocalOutcome> {
        Box::pin(async { Err(FactsFault::NotReady) })
    }

    fn tip_at_least(&self, _height: BlockHeight) -> Pending<'_, ()> {
        Box::pin(async { Err(FactsFault::NotReady) })
    }

    fn pop(&self, _count: u64) -> Pending<'_, PopOutcome> {
        Box::pin(async { Err(FactsFault::NotReady) })
    }
}

struct MiningAbsent;

impl MiningFacts for MiningAbsent {
    fn running(&self) -> Result<bool, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn template(&self) -> Result<Result<PostedTemplate, Diagnostic>, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn start(&self, _threads: Option<NonZeroUsize>) -> Result<Result<(), Diagnostic>, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn stop(&self) -> Result<bool, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn status(&self) -> Result<MiningState, FactsFault> {
        Err(FactsFault::NotReady)
    }
}

struct BansAbsent;

impl BansFacts for BansAbsent {
    fn ban(&self, _target: BanTargetFacts, _seconds: Option<u64>) -> Result<bool, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn lift(&self, _target: BanTargetFacts) -> Result<bool, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn remaining(&self, _host: IpAddr) -> Result<Option<BanLeftFacts>, FactsFault> {
        Err(FactsFault::NotReady)
    }

    fn list(&self) -> Result<Vec<BanRow>, FactsFault> {
        Err(FactsFault::NotReady)
    }
}

struct StopAbsent;

impl StopFacts for StopAbsent {
    fn request_stop(&self) -> Result<(), FactsFault> {
        Err(FactsFault::NotReady)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_handle_is_not_ready_and_never_a_zero_or_an_empty_list() {
        let handles = Handles::absent();
        assert_eq!(handles.chain.chain_tip(), Err(FactsFault::NotReady));
        assert_eq!(handles.chain.alt_block_hashes(), Err(FactsFault::NotReady));
        assert_eq!(
            handles.chain.store_size(),
            Err(FactsFault::NotReady),
            "a missing store is not a size of 0"
        );
        assert_eq!(handles.pool.broadcast_count(), Err(FactsFault::NotReady));
        assert_eq!(handles.door.room(), Err(FactsFault::NotReady));
        assert_eq!(handles.mining.running(), Err(FactsFault::NotReady));
        assert_eq!(
            handles.bans.remaining(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Err(FactsFault::NotReady),
            "no table is not 'this host is allowed'"
        );
        assert_eq!(handles.bans.list(), Err(FactsFault::NotReady));
        assert_eq!(handles.stop.request_stop(), Err(FactsFault::NotReady));
    }
}
