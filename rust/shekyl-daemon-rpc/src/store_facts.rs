// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The store-backed facts: [`ChainFacts`] and [`InfoFacts`] over the Rust
//! chain store (`DRS_X_STORE_FLIP.md` DX-Q3; RK-D7's second
//! implementation). **Staged:** built and tested here, connected at the
//! flip. The server keeps [`FfiChainFacts`](crate::chain_facts::FfiChainFacts)
//! and [`FfiInfoFacts`](crate::info_facts::FfiInfoFacts) until then.
//!
//! **One snapshot per facts call.** Every method opens one
//! [`ReadSnapshot`] and reads everything it returns from it, so a reply
//! never mixes two tips: the chain count a refusal names, the block it
//! names and the tip they are measured from are one committed state.
//!
//! **One source per value.** Every height and count comes from the
//! snapshot's tip. Every chain-derived value is the rules crate's own
//! derivation over a [`SnapshotView`] — the next block's target
//! (`target_claim`, CEN-D4), the medians and the weight limit
//! (`effective_median_at`, CEN-G6/G6b), the volume window
//! (`tx_volume_window`), the served fee ladder (`fee_ladder_at`, DX-Q10) —
//! never a second copy here. A block's proof-of-work hash is the one this
//! node recorded when it first judged the block (`recorded_pow`, the alt
//! row's), never hashed again.
//!
//! **What the store does not hold is an input, not a guess.** Sync state
//! (the sync owner's, DRS-X PR 2), the pool's counts (PR-b's pool), the p2p
//! board, the data volume's free space and the clock come through
//! [`NodeFacts`]; the process's constants (network, build, start time)
//! are a [`NodeIdentity`] value; the rule set in force at a height is a
//! [`RulesAt`]. The flip's composition root supplies all three.
//!
//! Tested over real chains in `shekyl-chain-ingest`'s
//! `rpc_store_facts_tests.rs`, which holds the scenario driver and the
//! captured chains with their E2 traces.

use std::path::PathBuf;
use std::sync::Arc;

use shekyl_chain_rules::{
    effective_median_at, fee_ladder_at, mtp_median_at, target_claim, tx_volume_window, AtHeight,
    Fault, RuleSet, ViewRead,
};
use shekyl_chain_store::store::{ChainStore, ReadSnapshot, SnapshotView, StoreError};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, ChainCount, KeyImage, TxHash};
use shekyl_wire::Block;

use crate::chain_facts::{
    BlockAt, BlockFacts, BlockHashAt, BlockHeaderAt, BlockHeaderFacts, BlockLookup, ChainFacts,
    ChainTip, DaemonIdentity, FactsFault, FeeEstimate,
};
use crate::info_facts::{
    store_file_size, InfoChainFacts, InfoFacts, InfoStatusFacts, PeerFacts, PoolCounts, PoolScope,
    SessionCounts,
};

/// The node's state that the chain store does not hold, read per call.
///
/// Each method names its owner; the flip's composition root implements the
/// trait over them. A method that cannot answer faults — it never reports
/// a default that would read as a fact.
pub trait NodeFacts: Send + Sync {
    /// The sync owner's view (DRS-X PR 2's `TipChanged` consumer).
    fn sync(&self) -> Result<SyncFacts, FactsFault>;
    /// The pool's population (PR-b's Rust pool).
    fn pool_counts(&self, scope: PoolScope) -> Result<PoolCounts, FactsFault>;
    /// Whether a transaction the pool shows spends each of `key_images`,
    /// in order. A stem-phase spend answers `false` (S6).
    fn pool_spends(&self, key_images: &[KeyImage]) -> Result<Vec<bool>, FactsFault>;
    /// The Peers part: transport and peerlist detail (the p2p layer).
    fn peers(&self) -> Result<PeerFacts, FactsFault>;
    /// One snapshot of the seam board's handshaken sessions.
    fn sessions(&self) -> Result<SessionCounts, FactsFault>;
    /// Free space on the data directory's volume, in bytes.
    fn free_space(&self) -> Result<u64, FactsFault>;
    /// The wall clock, Unix seconds.
    fn now(&self) -> u64;
}

/// What the sync owner and the writer report about the node's progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncFacts {
    /// The height the node is syncing towards, as a chain count; `None`
    /// when it has none.
    pub target: Option<ChainCount>,
    /// Whether the node considers itself caught up.
    pub synchronized: bool,
    /// Whether a sync is in progress.
    pub busy_syncing: bool,
    /// Whether the node was started offline.
    pub offline: bool,
    /// Whether the writer refused a switch at the prune watermark and now
    /// follows a degraded chain (C2-R1b F-1(a)).
    pub following_degraded: bool,
}

/// The process's constants: fixed for its life, supplied once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    /// The network this daemon runs.
    pub nettype: shekyl_rpc_types::DaemonNetwork,
    /// Whether this is a release build.
    pub release_build: bool,
    /// The build's version string.
    pub version: String,
    /// When the process started, Unix seconds.
    pub start_time: u64,
    /// The p2p protocol version this build speaks.
    pub protocol_version: u64,
}

/// The rule set in force at a height — the run's schedule, supplied by the
/// composition root that knows the network and its levers.
pub trait RulesAt: Send + Sync {
    /// The rule set in force at `height`.
    fn in_force(&self, height: BlockHeight) -> RuleSet;
}

impl<F> RulesAt for F
where
    F: Fn(BlockHeight) -> RuleSet + Send + Sync,
{
    fn in_force(&self, height: BlockHeight) -> RuleSet {
        self(height)
    }
}

/// [`ChainFacts`] and [`InfoFacts`] over the chain store (module docs).
pub struct StoreFacts {
    store: Arc<ChainStore>,
    store_file: PathBuf,
    rules: Arc<dyn RulesAt>,
    node: Arc<dyn NodeFacts>,
    identity: NodeIdentity,
    caches: Arc<shekyl_pow_randomx::CacheStore>,
    /// The daemon's one hasher budget: `calc_pow` hashes under a permit.
    budget: shekyl_hash_budget::Budget,
}

impl StoreFacts {
    /// The facts over `store`, whose data file is `store_file`. `calc_pow`
    /// hashes under the caches `caches` already holds — the daemon's one
    /// cache store, the validator's — and never derives one, each hash
    /// under a permit from `budget` in `calc_pow`'s class (PR2-Q3).
    pub fn new(
        store: Arc<ChainStore>,
        store_file: PathBuf,
        rules: Arc<dyn RulesAt>,
        node: Arc<dyn NodeFacts>,
        identity: NodeIdentity,
        caches: Arc<shekyl_pow_randomx::CacheStore>,
        budget: shekyl_hash_budget::Budget,
    ) -> Self {
        Self {
            store,
            store_file,
            rules,
            node,
            identity,
            caches,
            budget,
        }
    }

    fn snapshot(&self) -> Result<ReadSnapshot<'_>, FactsFault> {
        self.store.begin_read().map_err(store_fault)
    }
}

#[path = "store_read_facts.rs"]
mod reads;

/// A store error as the facts layer reports it: a row the store holds
/// broken is this node's inconsistency, never a fact about the request;
/// anything else is an internal failure.
fn store_fault(error: StoreError) -> FactsFault {
    match error {
        StoreError::InvariantViolated(row) => {
            tracing::error!(%row, "the chain store contradicted itself under a facts read");
            FactsFault::Inconsistent
        }
        other => {
            tracing::error!(error = %other, "a facts read of the chain store failed");
            FactsFault::Internal
        }
    }
}

/// A rules-crate derivation's fault, as the facts layer reports it.
fn derivation_fault(fault: ViewRead<StoreError>) -> FactsFault {
    match fault {
        ViewRead::View(error) => store_fault(error),
        ViewRead::Corrupt(corrupt) => {
            tracing::error!(%corrupt, "a chain derivation found the store inconsistent");
            FactsFault::Inconsistent
        }
    }
}

/// `target_claim`'s fault: the view's, or a row it found broken. A claim
/// is never stale; a stale arm here is a defect of the derivation.
fn claim_fault(fault: Fault<StoreError>) -> FactsFault {
    match fault {
        Fault::View(error) => store_fault(error),
        Fault::Corrupt(corrupt) => {
            tracing::error!(%corrupt, "the target derivation found the store inconsistent");
            FactsFault::Inconsistent
        }
        Fault::Stale(stale) => {
            tracing::error!(%stale, "a target derivation reported a stale claim");
            FactsFault::Internal
        }
    }
}

/// The snapshot's tip: its height and identity. An empty store is a daemon
/// that has not connected genesis yet — the flip connects it before the
/// RPC serves (DX-Q6) — so there is no tip to describe: not ready.
fn tip_of(snap: &ReadSnapshot<'_>) -> Result<(BlockHeight, BlockHash), FactsFault> {
    match snap.tip().map_err(store_fault)?.recorded {
        Some(tip) => Ok((tip.height, tip.hash)),
        None => Err(FactsFault::NotReady),
    }
}

/// The chain count a tip at `height` describes: the tip's height plus one.
fn count_at(height: BlockHeight) -> ChainCount {
    ChainCount::from_raw(height.to_raw().saturating_add(1))
}

/// The height the next block connects at.
fn connecting(tip: BlockHeight) -> BlockHeight {
    BlockHeight::from_raw(tip.to_raw().saturating_add(1))
}

/// The miner transaction's outputs summed: a block's reward as the RPC has
/// always reported it (`get_outs_money_amount(miner_tx)`). An overflow is a
/// block no conforming chain holds.
fn reward_of(block: &Block) -> Result<u64, FactsFault> {
    block
        .miner_transaction
        .prefix
        .outputs
        .iter()
        .try_fold(0u64, |sum, out| sum.checked_add(out.amount))
        .ok_or(FactsFault::Inconsistent)
}

/// A recorded cumulative difficulty at `height`.
fn cumulative_at(snap: &ReadSnapshot<'_>, height: BlockHeight) -> Result<u128, FactsFault> {
    match snap.block_info(height).map_err(store_fault)? {
        AtHeight::Recorded(info) => Ok(info.cumulative_difficulty.to_raw()),
        AtHeight::AboveTip => Err(FactsFault::Inconsistent),
    }
}

/// A block's own difficulty: its cumulative difficulty less its parent's —
/// the parent wherever it is, on the main chain or among the alt rows.
/// Genesis has no parent and its own difficulty is its cumulative one.
fn difficulty_of(
    snap: &ReadSnapshot<'_>,
    block: &Block,
    height: BlockHeight,
    cumulative: u128,
) -> Result<u128, FactsFault> {
    let Some(parent_height) = height.to_raw().checked_sub(1) else {
        return Ok(cumulative);
    };
    let parent = &block.header.previous;
    let parent_cumulative = if snap.height_of(parent).map_err(store_fault)?.is_some() {
        cumulative_at(snap, BlockHeight::from_raw(parent_height))?
    } else {
        match snap.alt_block(parent).map_err(store_fault)? {
            Some(alt) => alt.cumulative_difficulty().to_raw(),
            None => return Err(FactsFault::Inconsistent),
        }
    };
    cumulative
        .checked_sub(parent_cumulative)
        .ok_or(FactsFault::Inconsistent)
}

/// A main-chain block's header facts at `height`, read off `snap` whose tip
/// is `tip`.
fn main_header(
    snap: &ReadSnapshot<'_>,
    tip: BlockHeight,
    height: BlockHeight,
    fill_pow_hash: bool,
) -> Result<Option<(BlockHeaderFacts, Block)>, FactsFault> {
    let body = match snap.block(height).map_err(store_fault)? {
        AtHeight::Recorded(body) => body,
        AtHeight::AboveTip => return Ok(None),
    };
    let info = match snap.block_info(height).map_err(store_fault)? {
        AtHeight::Recorded(info) => info,
        AtHeight::AboveTip => return Err(FactsFault::Inconsistent),
    };
    let pow_hash = if fill_pow_hash {
        match snap.recorded_pow(height).map_err(store_fault)? {
            AtHeight::Recorded(pow) => Some(pow.pow.to_bytes()),
            AtHeight::AboveTip => return Err(FactsFault::Inconsistent),
        }
    } else {
        None
    };
    let block = body.block;
    let header = header_facts(
        snap,
        &block,
        HeaderPlace {
            hash: body.hash,
            height,
            depth: BlockCount::from_raw(tip.to_raw() - height.to_raw()),
            pow_hash,
            cumulative_difficulty: info.cumulative_difficulty.to_raw(),
            block_weight: info.weight.to_raw(),
            long_term_weight: Some(info.long_term_weight.to_raw()),
            orphan_status: false,
        },
    )?;
    Ok(Some((header, block)))
}

/// An alt block's header facts: every value from its own row, never from
/// the main chain at the same height. It has no confirmations on the main
/// chain (`depth` 0) and no long-term weight until a chain carrying it
/// records its medians.
fn alt_header(
    snap: &ReadSnapshot<'_>,
    id: BlockHash,
    fill_pow_hash: bool,
) -> Result<Option<(BlockHeaderFacts, Block)>, FactsFault> {
    let Some(alt) = snap.alt_block(&id).map_err(store_fault)? else {
        return Ok(None);
    };
    let block = alt.block().clone();
    let header = header_facts(
        snap,
        &block,
        HeaderPlace {
            hash: id,
            height: alt.height(),
            depth: BlockCount::from_raw(0),
            pow_hash: fill_pow_hash.then(|| alt.pow().pow.to_bytes()),
            cumulative_difficulty: alt.cumulative_difficulty().to_raw(),
            block_weight: alt.block_weight().to_raw(),
            long_term_weight: None,
            orphan_status: true,
        },
    )?;
    Ok(Some((header, block)))
}

/// Where a block sits for the header reply. The block supplies its own
/// bytes; these are the values the main chain and an alt row do not share.
/// A value, copied into the facts: every field already is.
#[derive(Clone, Copy)]
struct HeaderPlace {
    hash: BlockHash,
    height: BlockHeight,
    /// Confirmations behind the main-chain tip. Zero for an alt block:
    /// nothing on the main chain confirms it.
    depth: BlockCount,
    pow_hash: Option<[u8; 32]>,
    cumulative_difficulty: u128,
    block_weight: u64,
    /// `None` for an alt block. A long-term weight is a function of the
    /// chain the block sits on, and an alt row's chain has no recorded
    /// medians. The wire omits a zero, and `None` is that omission.
    long_term_weight: Option<u64>,
    orphan_status: bool,
}

/// The header facts of `block` at `place`. The difficulty and the reward
/// are read here, so the two callers cannot each grow a copy.
fn header_facts(
    snap: &ReadSnapshot<'_>,
    block: &Block,
    place: HeaderPlace,
) -> Result<BlockHeaderFacts, FactsFault> {
    Ok(BlockHeaderFacts {
        hash: place.hash,
        prev_hash: block.header.previous,
        miner_tx_hash: block.miner_transaction.hash(),
        curve_tree_root: block.header.curve_tree_root,
        attestation_root: block.header.attestation_root,
        pow_hash: place.pow_hash,
        height: place.height,
        depth: place.depth,
        timestamp: block.header.timestamp,
        difficulty: difficulty_of(snap, block, place.height, place.cumulative_difficulty)?,
        cumulative_difficulty: place.cumulative_difficulty,
        reward: reward_of(block)?,
        block_weight: place.block_weight,
        long_term_weight: place.long_term_weight,
        num_txes: u64::try_from(block.transaction_hashes.len()).unwrap_or(u64::MAX),
        nonce: block.header.nonce,
        major_version: block.header.major_version,
        minor_version: block.header.minor_version,
        orphan_status: place.orphan_status,
    })
}

/// The header facts `at` names, main chain first; by hash, an alt block
/// when the main chain does not hold it.
fn header_for(
    snap: &ReadSnapshot<'_>,
    tip: BlockHeight,
    at: BlockLookup,
    fill_pow_hash: bool,
) -> Result<Option<(BlockHeaderFacts, Block)>, FactsFault> {
    match at {
        BlockLookup::Height(height) => main_header(snap, tip, height, fill_pow_hash),
        BlockLookup::Hash(bytes) => {
            let id = BlockHash::from_bytes(bytes);
            match snap.height_of(&id).map_err(store_fault)? {
                Some(height) => match main_header(snap, tip, height, fill_pow_hash)? {
                    Some(found) => Ok(Some(found)),
                    // `height_of` named a height the snapshot cannot read.
                    None => Err(FactsFault::Inconsistent),
                },
                None => alt_header(snap, id, fill_pow_hash),
            }
        }
    }
}

/// The adjusted time `get_info` reports for the block connecting at
/// `connecting`: the newer of nothing and the older of the projected median
/// and the tip's timestamp plus one target, as the C++ `get_adjusted_time`
/// defined it — a report, not a rule. Before the window fills there is no
/// median, and the reply is the clock. The median is the rules crate's
/// (CEN-C3's window); only the projection is here.
fn adjusted_time(
    view: &SnapshotView<'_>,
    connecting: BlockHeight,
    tip_timestamp: u64,
    now: u64,
) -> Result<u64, FactsFault> {
    if connecting.to_raw() < shekyl_difficulty::MTP_WINDOW {
        return Ok(now);
    }
    let Some(median) = mtp_median_at(view, connecting).map_err(derivation_fault)? else {
        return Ok(now);
    };
    let projected = median
        .to_raw()
        .saturating_add((shekyl_difficulty::MTP_WINDOW + 1) * shekyl_difficulty::T_SECONDS / 2);
    let next = tip_timestamp.saturating_add(shekyl_difficulty::T_SECONDS);
    Ok(projected.min(next))
}

impl ChainFacts for StoreFacts {
    fn chain_tip(&self) -> Result<ChainTip, FactsFault> {
        let snap = self.snapshot()?;
        let (height, hash) = tip_of(&snap)?;
        let sync = self.node.sync()?;
        Ok(ChainTip {
            chain_height: count_at(height),
            top_hash: hash,
            target_height: sync.target,
            synchronized: sync.synchronized,
            release_build: self.identity.release_build,
        })
    }

    fn identity(&self) -> Result<DaemonIdentity, FactsFault> {
        let snap = self.snapshot()?;
        let genesis_hash = match snap.block_info(BlockHeight::ZERO).map_err(store_fault)? {
            AtHeight::Recorded(info) => info.hash,
            AtHeight::AboveTip => return Err(FactsFault::NotReady),
        };
        Ok(DaemonIdentity {
            nettype: self.identity.nettype,
            genesis_hash,
        })
    }

    fn block_hash_at(&self, height: BlockHeight) -> Result<BlockHashAt, FactsFault> {
        let snap = self.snapshot()?;
        let (tip, _) = tip_of(&snap)?;
        let hash = match snap.block_info(height).map_err(store_fault)? {
            AtHeight::Recorded(info) => Some(info.hash),
            AtHeight::AboveTip => None,
        };
        Ok(BlockHashAt {
            hash,
            chain_height: count_at(tip),
        })
    }

    fn block_header_at(
        &self,
        at: BlockLookup,
        fill_pow_hash: bool,
    ) -> Result<BlockHeaderAt, FactsFault> {
        let snap = self.snapshot()?;
        let (tip, _) = tip_of(&snap)?;
        Ok(BlockHeaderAt {
            header: header_for(&snap, tip, at, fill_pow_hash)?.map(|(header, _)| header),
            chain_height: count_at(tip),
        })
    }

    fn fee_estimate(&self) -> Result<FeeEstimate, FactsFault> {
        let snap = self.snapshot()?;
        let (tip, _) = tip_of(&snap)?;
        let view = SnapshotView::new(&snap);
        match fee_ladder_at(&view, connecting(tip)).map_err(derivation_fault)? {
            AtHeight::Recorded(ladder) => Ok(FeeEstimate {
                fees: [ladder.economy, ladder.standard, ladder.priority],
            }),
            // The connecting height is the tip's successor on this same
            // snapshot; it cannot be above the tip.
            AtHeight::AboveTip => Err(FactsFault::Inconsistent),
        }
    }

    fn block_at(&self, at: BlockLookup, fill_pow_hash: bool) -> Result<BlockAt, FactsFault> {
        let snap = self.snapshot()?;
        let (tip, _) = tip_of(&snap)?;
        let block = header_for(&snap, tip, at, fill_pow_hash)?.map(|(header, block)| {
            let tx_hashes: Vec<TxHash> = block.transaction_hashes.clone();
            BlockFacts {
                header,
                blob: block.serialize(),
                json: None,
                tx_hashes,
            }
        });
        Ok(BlockAt {
            block,
            chain_height: count_at(tip),
        })
    }
}

impl InfoFacts for StoreFacts {
    fn chain(&self) -> Result<InfoChainFacts, FactsFault> {
        let snap = self.snapshot()?;
        let (tip, top_hash) = tip_of(&snap)?;
        let info = match snap.block_info(tip).map_err(store_fault)? {
            AtHeight::Recorded(info) => info,
            AtHeight::AboveTip => return Err(FactsFault::Inconsistent),
        };
        let view = SnapshotView::new(&snap);
        let next = connecting(tip);
        let difficulty =
            match target_claim(&view, next, &self.rules.in_force(next)).map_err(claim_fault)? {
                Ok(target) => target.difficulty().to_raw(),
                Err(refused) => {
                    // CEN-D6 on the chain's own headers: the next block has no
                    // target, which no conforming chain derives.
                    tracing::error!(%refused, "the next block's target does not derive");
                    return Err(FactsFault::Inconsistent);
                }
            };
        let medians = effective_median_at(&view, next).map_err(derivation_fault)?;
        let sync = self.node.sync()?;
        Ok(InfoChainFacts {
            chain_height: count_at(tip),
            top_hash,
            difficulty,
            cumulative_difficulty: info.cumulative_difficulty.to_raw(),
            difficulty_target: shekyl_difficulty::T_SECONDS,
            total_transactions: snap.tx_count().map_err(store_fault)?,
            block_weight_limit: medians.limit().to_raw(),
            block_weight_median: medians.effective_median.to_raw(),
            adjusted_time: adjusted_time(&view, next, info.timestamp.to_raw(), self.node.now())?,
            already_generated_coins: info.coins_generated,
            total_burned: snap.total_burned().map_err(store_fault)?,
            tx_volume: tx_volume_window(&view, next).map_err(derivation_fault)?,
            core_target_height: sync.target,
            synchronized: sync.synchronized,
            busy_syncing: sync.busy_syncing,
            offline: sync.offline,
            following_degraded: sync.following_degraded,
            protocol_version: self.identity.protocol_version,
        })
    }

    fn pool_counts(&self, scope: PoolScope) -> Result<PoolCounts, FactsFault> {
        self.node.pool_counts(scope)
    }

    fn store_size(&self) -> Result<u64, FactsFault> {
        store_file_size(&self.store_file)
    }

    fn status(&self) -> Result<InfoStatusFacts, FactsFault> {
        let snap = self.snapshot()?;
        Ok(InfoStatusFacts {
            start_time: self.identity.start_time,
            free_space: self.node.free_space()?,
            alt_blocks_count: snap.alt_block_count().map_err(store_fault)?,
            version: self.identity.version.clone(),
        })
    }

    fn peers(&self) -> Result<PeerFacts, FactsFault> {
        self.node.peers()
    }

    fn sessions(&self) -> Result<SessionCounts, FactsFault> {
        self.node.sessions()
    }
}
