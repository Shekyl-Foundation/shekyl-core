// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain-tip facts — the store-agnostic seam behind the RK-1 handlers
//! (`docs/design/DAEMON_RPC_KV_CUTOVER.md` §3.2–§3.3, RK-D3 / RK-D7).
//!
//! A handler never touches the FFI: it asks a [`ChainFacts`] for what it
//! needs and decides the rest itself. [`FfiChainFacts`] is today's only
//! implementation, reading the C++ core through `shekyl_rpc_chain_tip` /
//! `shekyl_rpc_hardforks` (`src/rpc/rpc_facts_ffi.h`). When the Rust chain
//! store lands (DRS-E) a second implementation reads it directly and this
//! one is deleted; the handlers and their tests do not move.
//!
//! The shim holds **no policy**: it converts PODs to typed facts and maps
//! return codes onto [`FactsFault`]. "Synchronized ⇒ target height is 0" is
//! the handler's rule, applied in `methods`, not here.

use std::sync::Arc;

use shekyl_types::{BlockHash, BlockHeight, TxHash};

use crate::core::{ConnectionsSnapshot, CoreRpc, PeerFacts, SyncSpansSnapshot};
use crate::ffi;

/// What the chain tip looks like right now, plus the one build fact
/// (`release_build`) that rides the same POD because `get_version` reports
/// it and C++'s build system is its only owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTip {
    /// Chain height: top block height **plus one**.
    pub chain_height: BlockHeight,
    /// Hash of the top block.
    pub top_hash: BlockHash,
    /// Height the node is syncing towards, as the core reports it (raw —
    /// the "0 when synchronized" rule is the handler's).
    pub target_height: BlockHeight,
    /// Whether the protocol layer considers this node synchronized.
    pub synchronized: bool,
    /// `SHEKYL_VERSION_IS_RELEASE`.
    pub release_build: bool,
}

/// What the chain holds at one height: the block's hash, or `None` when — and
/// only when — the height is at or past the tip. An in-range height the store
/// cannot produce a block for is [`FactsFault::Inconsistent`], not `None`, so
/// `None` always means exactly one thing to the handler. `chain_height` is the tip as of the same
/// read, so a refusal can name the top height without a second call (and
/// without a window in which the two disagree).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHashAt {
    pub hash: Option<BlockHash>,
    pub chain_height: BlockHeight,
}

/// One block's header, as the facts layer reads it: raw values, typed —
/// hex rendering and the wire's three-field difficulty split are the
/// handler's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeaderFacts {
    pub hash: BlockHash,
    pub prev_hash: BlockHash,
    /// The miner transaction's id — a [`TxHash`], not a [`BlockHash`]: typing
    /// it as the latter is exactly the confusion `shekyl-types`' hash
    /// newtypes exist to prevent.
    pub miner_tx_hash: TxHash,
    /// Raw bytes, like `shekyl-wire::BlockHeader`: neither root has a domain
    /// newtype in this tree, and minting one here would be pre-provisioning
    /// (rule 18 — byte layout at the boundary, names where they are known).
    pub curve_tree_root: [u8; 32],
    pub attestation_root: [u8; 32],
    /// `None` unless the caller asked for it and was entitled to. Raw bytes:
    /// a proof-of-work hash is not any block's identity.
    pub pow_hash: Option<[u8; 32]>,
    pub height: BlockHeight,
    pub depth: u64,
    pub timestamp: u64,
    pub difficulty: u128,
    pub cumulative_difficulty: u128,
    pub reward: u64,
    pub block_weight: u64,
    pub long_term_weight: u64,
    pub num_txes: u64,
    pub nonce: u32,
    pub major_version: u8,
    pub minor_version: u8,
    pub orphan_status: bool,
}

/// The header at one height, with the tip as of the same read — `None` when,
/// and only when, the height is at or past the tip. An in-range height the
/// store cannot produce a block for is [`FactsFault::Inconsistent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeaderAt {
    pub header: Option<BlockHeaderFacts>,
    pub chain_height: BlockHeight,
}

/// One row of the hard-fork schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardFork {
    pub version: u8,
    pub height: BlockHeight,
}

/// Why a facts read could not be served. Each variant is a distinct C return
/// code (rule 40: codes, not booleans), so the transport can choose between
/// "try again" and "this daemon is broken".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactsFault {
    /// The core handle was null — the server is torn down.
    NullHandle,
    /// The core is not initialized yet (`BUSY` on the wire).
    NotReady,
    /// A core / P2P read threw inside the C++ shim (logged there with the
    /// exception text); the shim's exception barrier turned it into a
    /// code instead of an unwind across the C ABI.
    Internal,
    /// The store contradicted itself, and the shim refused to paper over it
    /// (it logs which read disagreed). This daemon's data is inconsistent —
    /// never reported to the caller as a fact about their request.
    ///
    /// Three reads raise it today: a height whose block the store cannot
    /// produce; a transaction the chain holds with no prunable hash beside it;
    /// and a transaction whose output-index record disagrees with the
    /// transaction found under the same lock. They share one property worth
    /// stating, because it is what makes the variant earn its place — each has
    /// a plausible-looking fallback (an absent block, a zero hash, an empty
    /// index list) that would reach the caller as a fact about their request
    /// rather than a fault of this node.
    Inconsistent,
    /// A code outside the documented set — a contract violation, never a
    /// guessed fact.
    Unknown(i32),
}

impl FactsFault {
    pub(crate) fn from_code(code: i32) -> Self {
        match code {
            ffi::SHEKYL_RPC_FACTS_ERR_NULL => Self::NullHandle,
            ffi::SHEKYL_RPC_FACTS_ERR_NOT_READY => Self::NotReady,
            ffi::SHEKYL_RPC_FACTS_ERR_INTERNAL => Self::Internal,
            ffi::SHEKYL_RPC_FACTS_ERR_INCONSISTENT => Self::Inconsistent,
            other => Self::Unknown(other),
        }
    }
}

/// The facts the chain-tip / version handlers consume.
///
/// **Why a trait with one implementation.** It earns its keep today, before
/// any second impl exists: it is the seam that makes handler logic testable
/// without standing up a `core_rpc_server` over a live chain, which is what
/// keeps the unit tests fast enough to run per-assertion and the regtest
/// harness reserved for what genuinely needs a daemon. That is the whole
/// reason the handler tests in `methods` can exist at all.
///
/// It is *also* where a Rust store would plug in when DRS-E lands (RK-D7),
/// and the deletion register schedules the FFI shims for that moment — but
/// that is the second reason, not the first. Stated the other way round, a
/// one-impl trait reads as speculative generality to a rule-15 pass, against
/// a program that is not yet scoped.
pub trait ChainFacts: Send + Sync {
    fn chain_tip(&self) -> Result<ChainTip, FactsFault>;
    fn hardforks(&self) -> Result<Vec<HardFork>, FactsFault>;
    /// The block hash at `height`, with the tip as of the same read.
    /// Absence is data ([`BlockHashAt::hash`] is `None`), not a fault.
    fn block_hash_at(&self, height: BlockHeight) -> Result<BlockHashAt, FactsFault>;
    /// The whole header projection at `height`. `fill_pow_hash` is both the
    /// request and the entitlement — the caller has already applied the
    /// restricted-listener rule — and computing it is the expensive part.
    fn block_header_at(
        &self,
        at: BlockLookup,
        fill_pow_hash: bool,
    ) -> Result<BlockHeaderAt, FactsFault>;
    /// Hard-fork voting info for one version. `requested` is `None` for
    /// "the next fork" — the daemon resolves it and reports which it chose,
    /// so the sentinel never reaches a caller.
    fn hard_fork_info(&self, requested: Option<u8>) -> Result<HardForkInfo, FactsFault>;
    /// The dynamic base-fee estimate. A `grace_blocks` above
    /// [`Self::fee_grace_blocks_max`] is refused by the caller first; the
    /// facts layer refuses it too rather than letting the estimator throw.
    fn fee_estimate(&self, grace_blocks: u64) -> Result<FeeEstimate, FactsFault>;
    /// The ceiling `grace_blocks` must not exceed.
    ///
    /// **On the trait, not a free function reaching into the FFI.** As a free
    /// function it read the C++ constant directly, which meant the unit-test
    /// link stub answered 0 and every request was refused under test — the
    /// refusal test then passed for the wrong reason, asserting a bound it
    /// had not exercised. Here the production impl still single-sources the
    /// constant from C++ and a double can state one.
    fn fee_grace_blocks_max(&self) -> u64;
    /// A whole block, named either way. Absence is data ([`BlockAt::block`]
    /// is `None`) for both lookups; the caller knows which it asked for and
    /// so which refusal to produce.
    fn block_at(&self, at: BlockLookup, fill_pow_hash: bool) -> Result<BlockAt, FactsFault>;
}

/// How a caller named the block it wants.
///
/// A hash reaches blocks off the main chain too, which is why
/// [`BlockFacts::header`]'s `orphan_status` is a real value and not the
/// constant [`BlockHeaderAt`]'s is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockLookup {
    Hash([u8; 32]),
    Height(BlockHeight),
}

/// A whole block and the chain bound it was read against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockAt {
    /// `None` when there is no such block: past the tip, in range but
    /// unproducible, or a hash the chain does not have.
    pub block: Option<BlockFacts>,
    /// Chain height as of the same read — reported even when absent, so a
    /// height refusal can name the top block.
    pub chain_height: BlockHeight,
}

/// The block itself: RK-3's header projection plus what only `get_block`
/// carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockFacts {
    pub header: BlockHeaderFacts,
    /// The block in its consensus encoding. Hex is the handler's job.
    pub blob: Vec<u8>,
    /// epee's rendering of the whole block, produced in C++ and carried
    /// through untouched (RK-D11).
    pub json: String,
    pub tx_hashes: Vec<TxHash>,
}

/// The facts the p2p handlers consume (`sync_info`, `/get_net_stats`,
/// `/get_peer_list`, `get_connections`).
///
/// Separate from [`ChainFacts`] because the two have no overlap and no shared
/// lock domain: these read `m_p2p` and the global throttle, and none of them
/// touches the blockchain. `sync_info` needs both and takes both, which makes
/// the fact that it reads two unsynchronised sources visible at its
/// signature rather than buried in a handler.
///
/// The values are the C++ objects' **raw** fields; every elapsed time and
/// rate on the wire is derived from them in [`crate::methods`].
pub trait P2pFacts: Send + Sync {
    fn net_stats(&self) -> Result<NetStats, FactsFault>;
    /// The live connections and the single instant they were read at.
    fn connections(&self) -> Result<ConnectionsSnapshot, FactsFault>;
    /// The block-download queue and the stripe this node wants next.
    fn sync_spans(&self) -> Result<SyncSpansSnapshot, FactsFault>;
    /// The peerlist, white entries then gray. `public_only` selects a
    /// different p2p call, not a filter over one result.
    fn peer_list(&self, public_only: bool) -> Result<Vec<PeerFacts>, FactsFault>;
}

/// Hard-fork voting info, carried verbatim.
///
/// Nothing here is re-derived: CEN-B2/B3 are bucket-4 rows reserved for the R4
/// round that owns the hard-fork subsystem, so a Rust reimplementation of the
/// threshold accounting would be work that round has to undo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardForkInfo {
    /// The version the fields below describe — resolved, so the request's
    /// "next fork" sentinel never reaches a reader.
    pub queried_version: u8,
    /// The chain's current fork version. Not the subject of the fields below.
    pub active_version: u8,
    pub enabled: bool,
    pub window: u32,
    pub votes: u32,
    pub threshold: u32,
    pub voting: u8,
    pub state: u32,
    pub earliest_height: u64,
}

/// The dynamic base-fee estimate: four tiers and the quantization mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeEstimate {
    pub fees: [u64; 4],
    pub quantization_mask: u64,
}

/// Throttle counters and the core's start time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetStats {
    /// Unix seconds.
    pub start_time: u64,
    pub total_packets_in: u64,
    pub total_bytes_in: u64,
    pub total_packets_out: u64,
    pub total_bytes_out: u64,
}

/// Production [`ChainFacts`] over the C++ core, sharing the daemon's live
/// [`CoreRpc`] handle. Both reads block briefly on the C++ side; the
/// transport dispatches them via `spawn_blocking`.
pub struct FfiChainFacts {
    core: Arc<CoreRpc>,
}

impl FfiChainFacts {
    pub fn new(core: Arc<CoreRpc>) -> Self {
        Self { core }
    }
}

/// One place where a header POD becomes typed facts.
///
/// Two exports fill this same POD — `shekyl_rpc_block_header_at` and
/// `shekyl_rpc_block_at` — and a second copy of nineteen field assignments
/// is a second thing to forget when a field is added.
fn header_facts_from_pod(pod: &ffi::BlockHeaderFactsFfi) -> BlockHeaderFacts {
    BlockHeaderFacts {
        hash: BlockHash::from_bytes(pod.hash),
        prev_hash: BlockHash::from_bytes(pod.prev_hash),
        miner_tx_hash: TxHash::from_bytes(pod.miner_tx_hash),
        curve_tree_root: pod.curve_tree_root,
        attestation_root: pod.attestation_root,
        pow_hash: (pod.pow_hash_filled != 0).then_some(pod.pow_hash),
        height: BlockHeight::from_raw(pod.height),
        depth: pod.depth,
        timestamp: pod.timestamp,
        difficulty: u128::from(pod.difficulty_hi) << 64 | u128::from(pod.difficulty_lo),
        cumulative_difficulty: u128::from(pod.cumulative_difficulty_hi) << 64
            | u128::from(pod.cumulative_difficulty_lo),
        reward: pod.reward,
        block_weight: pod.block_weight,
        long_term_weight: pod.long_term_weight,
        num_txes: pod.num_txes,
        nonce: pod.nonce,
        major_version: pod.major_version,
        minor_version: pod.minor_version,
        orphan_status: pod.orphan_status != 0,
    }
}

/// Production [`P2pFacts`] over the same live handle.
pub struct FfiP2pFacts {
    core: Arc<CoreRpc>,
}

impl FfiP2pFacts {
    pub fn new(core: Arc<CoreRpc>) -> Self {
        Self { core }
    }
}

impl P2pFacts for FfiP2pFacts {
    fn net_stats(&self) -> Result<NetStats, FactsFault> {
        let pod = self.core.net_stats().map_err(FactsFault::from_code)?;
        Ok(NetStats {
            start_time: pod.start_time,
            total_packets_in: pod.total_packets_in,
            total_bytes_in: pod.total_bytes_in,
            total_packets_out: pod.total_packets_out,
            total_bytes_out: pod.total_bytes_out,
        })
    }

    fn connections(&self) -> Result<ConnectionsSnapshot, FactsFault> {
        self.core.connections().map_err(FactsFault::from_code)
    }

    fn sync_spans(&self) -> Result<SyncSpansSnapshot, FactsFault> {
        self.core.sync_spans().map_err(FactsFault::from_code)
    }

    fn peer_list(&self, public_only: bool) -> Result<Vec<PeerFacts>, FactsFault> {
        self.core
            .peer_list(public_only)
            .map_err(FactsFault::from_code)
    }
}

impl ChainFacts for FfiChainFacts {
    fn chain_tip(&self) -> Result<ChainTip, FactsFault> {
        let pod = self.core.chain_tip().map_err(FactsFault::from_code)?;
        Ok(ChainTip {
            chain_height: BlockHeight::from_raw(pod.chain_height),
            top_hash: BlockHash::from_bytes(pod.top_hash),
            target_height: BlockHeight::from_raw(pod.target_height),
            synchronized: pod.synchronized != 0,
            release_build: pod.release_build != 0,
        })
    }

    fn hard_fork_info(&self, requested: Option<u8>) -> Result<HardForkInfo, FactsFault> {
        let pod = self
            .core
            .hard_fork_info(requested.unwrap_or(0))
            .map_err(FactsFault::from_code)?;
        Ok(HardForkInfo {
            queried_version: pod.queried_version,
            active_version: pod.active_version,
            enabled: pod.enabled != 0,
            window: pod.window,
            votes: pod.votes,
            threshold: pod.threshold,
            voting: pod.voting,
            state: pod.state,
            earliest_height: pod.earliest_height,
        })
    }

    fn fee_grace_blocks_max(&self) -> u64 {
        // The C++ constant, single-sourced: `CRYPTONOTE_REWARD_BLOCKS_WINDOW`
        // behind a handle-free export, never restated here.
        // SAFETY: a compile-time constant, no handle, no allocation.
        unsafe { ffi::shekyl_rpc_fee_grace_blocks_max() }
    }

    fn fee_estimate(&self, grace_blocks: u64) -> Result<FeeEstimate, FactsFault> {
        let pod = self
            .core
            .fee_estimate(grace_blocks)
            .map_err(FactsFault::from_code)?;
        Ok(FeeEstimate {
            fees: pod.fees,
            quantization_mask: pod.quantization_mask,
        })
    }

    fn block_hash_at(&self, height: BlockHeight) -> Result<BlockHashAt, FactsFault> {
        let pod = self
            .core
            .block_hash_at(height.to_raw())
            .map_err(FactsFault::from_code)?;
        Ok(BlockHashAt {
            hash: (pod.found != 0).then(|| BlockHash::from_bytes(pod.hash)),
            chain_height: BlockHeight::from_raw(pod.chain_height),
        })
    }

    fn block_header_at(
        &self,
        at: BlockLookup,
        fill_pow_hash: bool,
    ) -> Result<BlockHeaderAt, FactsFault> {
        let (hash, height) = match at {
            BlockLookup::Hash(h) => (Some(h), 0),
            BlockLookup::Height(h) => (None, h.to_raw()),
        };
        let pod = self
            .core
            .block_header_at(hash.as_ref(), height, fill_pow_hash)
            .map_err(FactsFault::from_code)?;
        let chain_height = BlockHeight::from_raw(pod.chain_height);
        if pod.found == 0 {
            return Ok(BlockHeaderAt {
                header: None,
                chain_height,
            });
        }
        Ok(BlockHeaderAt {
            header: Some(header_facts_from_pod(&pod)),
            chain_height,
        })
    }

    fn block_at(&self, at: BlockLookup, fill_pow_hash: bool) -> Result<BlockAt, FactsFault> {
        let (hash, height) = match at {
            BlockLookup::Hash(h) => (Some(h), 0),
            BlockLookup::Height(h) => (None, h.to_raw()),
        };
        let (pod, blob, json, tx_hashes) = self
            .core
            .block_at(hash.as_ref(), height, fill_pow_hash)
            .map_err(FactsFault::from_code)?;
        let chain_height = BlockHeight::from_raw(pod.chain_height);
        if pod.found == 0 {
            return Ok(BlockAt {
                block: None,
                chain_height,
            });
        }
        Ok(BlockAt {
            block: Some(BlockFacts {
                header: header_facts_from_pod(&pod),
                blob,
                json,
                tx_hashes: tx_hashes.into_iter().map(TxHash::from_bytes).collect(),
            }),
            chain_height,
        })
    }

    fn hardforks(&self) -> Result<Vec<HardFork>, FactsFault> {
        let rows = self.core.hardforks().map_err(FactsFault::from_code)?;
        Ok(rows
            .into_iter()
            .map(|r| HardFork {
                version: r.version,
                height: BlockHeight::from_raw(r.height),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_codes_map_one_to_one_and_unknown_is_never_guessed() {
        assert_eq!(
            FactsFault::from_code(ffi::SHEKYL_RPC_FACTS_ERR_NULL),
            FactsFault::NullHandle
        );
        assert_eq!(
            FactsFault::from_code(ffi::SHEKYL_RPC_FACTS_ERR_NOT_READY),
            FactsFault::NotReady
        );
        assert_eq!(
            FactsFault::from_code(ffi::SHEKYL_RPC_FACTS_ERR_INTERNAL),
            FactsFault::Internal
        );
        assert_eq!(
            FactsFault::from_code(ffi::SHEKYL_RPC_FACTS_ERR_INCONSISTENT),
            FactsFault::Inconsistent
        );
        assert_eq!(FactsFault::from_code(-77), FactsFault::Unknown(-77));
    }
}
