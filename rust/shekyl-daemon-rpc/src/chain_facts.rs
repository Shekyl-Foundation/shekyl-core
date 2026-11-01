// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain-tip facts — the store-agnostic seam behind the RK-1 handlers
//! (`docs/completed/DAEMON_RPC_KV_CUTOVER.md` §3.2–§3.3, RK-D3; RK-D7 is
//! carried in `docs/design/RPC_WIRE.md`).
//!
//! A handler never touches the FFI: it asks a [`ChainFacts`] for what it
//! needs and decides the rest itself. The live implementation is
//! [`crate::store_facts::StoreFacts`]. [`FfiP2pFacts`] is the sync half
//! that still reads the C++ protocol handler (connections, sync spans,
//! net stats) until chain sync's cutover.
//!
//! A core-reported `0` target is C5's
//! sentinel and decodes as `None` — never [`ChainCount::from_raw`]`(0)`.
//! `get_version` and `sync_info` forward that count, so `0` on their wire is
//! only `None`. `get_info` still writes `0` when the node is synchronized,
//! and that rule lives in the C++ handler, not here.
//!
//! ```compile_fail
//! // HEIGHT_SEMANTICS.md C9: `ChainTip.chain_height` is COUNT, not ordinal.
//! use shekyl_daemon_rpc::chain_facts::ChainTip;
//! use shekyl_types::{BlockHash, BlockHeight};
//! let _ = ChainTip {
//!     chain_height: BlockHeight::from_raw(1),
//!     top_hash: BlockHash::from_bytes([0u8; 32]),
//!     target_height: None,
//!     synchronized: true,
//!     release_build: false,
//! };
//! ```
//!
//! ```compile_fail
//! // HEIGHT_SEMANTICS.md C9: `target_height` is `Option<ChainCount>`, not ordinal.
//! use shekyl_daemon_rpc::chain_facts::ChainTip;
//! use shekyl_types::{BlockHash, BlockHeight, ChainCount};
//! let _ = ChainTip {
//!     chain_height: ChainCount::from_raw(1),
//!     top_hash: BlockHash::from_bytes([0u8; 32]),
//!     target_height: Some(BlockHeight::from_raw(1)),
//!     synchronized: false,
//!     release_build: false,
//! };
//! ```

//! ```compile_fail
//! // HEIGHT_SEMANTICS.md C9: `BlockHeaderFacts.depth` is a span, not an ordinal.
//! use shekyl_daemon_rpc::chain_facts::BlockHeaderFacts;
//! use shekyl_types::{AttestationRoot, BlockHash, BlockHeight, CurveTreeRoot, TxHash};
//! let _ = BlockHeaderFacts {
//!     hash: BlockHash::from_bytes([0u8; 32]),
//!     prev_hash: BlockHash::from_bytes([0u8; 32]),
//!     miner_tx_hash: TxHash::from_bytes([0u8; 32]),
//!     curve_tree_root: CurveTreeRoot::from_bytes([0u8; 32]),
//!     attestation_root: AttestationRoot::from_bytes([0u8; 32]),
//!     pow_hash: None,
//!     height: BlockHeight::from_raw(1),
//!     depth: BlockHeight::from_raw(0),
//!     timestamp: 0,
//!     difficulty: 0,
//!     cumulative_difficulty: 0,
//!     reward: 0,
//!     block_weight: 0,
//!     long_term_weight: None,
//!     num_txes: 0,
//!     nonce: 0,
//!     major_version: 0,
//!     minor_version: 0,
//!     orphan_status: false,
//! };
//! ```

use std::sync::Arc;

use shekyl_types::{
    AttestationRoot, BlockCount, BlockHash, BlockHeight, ChainCount, CurveTreeRoot, TxHash,
};

use crate::core::{ConnectionsSnapshot, CoreRpc, P2pRead, PeerEntry, SyncSpansSnapshot};
use crate::ffi;

/// What this daemon **is**: the two identity facts a client checks at
/// connect that are not tip facts (VC-2).
///
/// Separate from [`ChainTip`] because these are process-lifetime constants —
/// `nettype` is fixed at daemon start, the genesis hash per network — while
/// the tip changes every block, and five of `chain_tip`'s six callers want a
/// tip (`VC-R17`). The rules digest is not here: it is compiled into this
/// image from `config/`, so the handler reads its own constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonIdentity {
    /// The network this daemon runs.
    pub nettype: shekyl_rpc_types::DaemonNetwork,
    /// Hash of block 0.
    pub genesis_hash: BlockHash,
}

/// What the chain tip looks like right now, plus the one build fact
/// (`release_build`) that rides the same POD because `get_version` reports
/// it and C++'s build system is its only owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTip {
    /// Chain **count**: top block height **plus one** (`m_db->height()`).
    /// COUNT, not ordinal — wrapping this in [`BlockHeight`] is the Phase 1
    /// defect (`HEIGHT_SEMANTICS.md` C3). Name kept (C7).
    pub chain_height: ChainCount,
    /// Hash of the top block.
    pub top_hash: BlockHash,
    /// The core's target count. `None` when the core reported `0`: that
    /// raw value is an absence, not a [`ChainCount`] (C5). Synchronization
    /// is [`Self::synchronized`]. `get_version` and `sync_info` forward this
    /// count, and write `None` as `null`; `get_info` reports the same fact
    /// from its own snapshot.
    pub target_height: Option<ChainCount>,
    /// Whether the protocol layer considers this node synchronized.
    pub synchronized: bool,
    /// `SHEKYL_VERSION_IS_RELEASE`.
    pub release_build: bool,
}

/// What the chain holds at one height: the block's hash, or `None` when — and
/// only when — the height is at or past the tip. An in-range height the store
/// cannot produce a block for is [`FactsFault::Inconsistent`], not `None`, so
/// `None` always means exactly one thing to the handler. `chain_height` is
/// the chain **count** as of the same read, so a refusal can name the top
/// via [`ChainCount::tip`] without a second call (and without a window in
/// which the two disagree).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHashAt {
    pub hash: Option<BlockHash>,
    /// Chain **count** as of the same read (C3), so a refusal can name the
    /// bound without a second call.
    pub chain_height: ChainCount,
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
    /// The header's two committed roots, as the types `shekyl-wire::BlockHeader`
    /// carries them (RTN-7). The C ABI POD they are read from is raw (rule
    /// 40); the facts layer is where each root's kind is known, so it is
    /// named here and stays named until the handler renders hex.
    pub curve_tree_root: CurveTreeRoot,
    pub attestation_root: AttestationRoot,
    /// `None` unless the caller asked for it and was entitled to. Raw bytes:
    /// a proof-of-work hash is not any block's identity.
    pub pow_hash: Option<[u8; 32]>,
    pub height: BlockHeight,
    /// Confirmations behind the tip. DIFFERENCE (`HEIGHT_SEMANTICS.md` C4).
    pub depth: BlockCount,
    pub timestamp: u64,
    pub difficulty: u128,
    pub cumulative_difficulty: u128,
    pub reward: u64,
    pub block_weight: u64,
    /// `None` for a block that is not on the main chain: a long-term weight
    /// is a function of the chain the block sits on (CEN-G6), and an alt
    /// block's chain has no recorded medians until it is promoted. The wire
    /// omits a zero long-term weight, and `None` is that omission.
    pub long_term_weight: Option<u64>,
    pub num_txes: u64,
    pub nonce: u32,
    pub major_version: u8,
    pub minor_version: u8,
    pub orphan_status: bool,
}

/// The header at one height, with the chain **count** as of the same read —
/// `None` when, and only when, the height is at or past the tip. An in-range
/// height the store cannot produce a block for is [`FactsFault::Inconsistent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeaderAt {
    pub header: Option<BlockHeaderFacts>,
    /// Chain **count** as of the same read (C3).
    pub chain_height: ChainCount,
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
    /// The chain store's data file could not be read for its size. Raised on
    /// this side, by [`crate::info_facts::store_file_size`], and never
    /// reported as a size of `0` — an empty store is `0`, and a store that
    /// cannot be read is not that (RK-D23).
    StoreUnreadable,
    /// The p2p hub is not up in this process, so there is no board to count
    /// sessions on. Raised by [`crate::info_facts::sessions`],
    /// and never reported as zero sessions: a node whose p2p layer has not
    /// started is not a node with no peers, and a reader told "no peers"
    /// raises an alarm an operator would act on (RK-D23).
    HubAbsent,
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

/// C5: a reported target of `0` is not a chain count. Inland never wraps
/// `0` as [`ChainCount`]. The absence is the core reporting no target;
/// synchronization is [`ChainTip::synchronized`].
#[cfg(test)]
pub(crate) fn decode_target_count(raw: u64) -> Option<ChainCount> {
    (raw != 0).then(|| ChainCount::from_raw(raw))
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
/// [`crate::store_facts::StoreFacts`] is the production implementation
/// (RK-D7). The trait stays because the handler tests drive a double, not
/// because a second production implementation is still owed.
pub trait ChainFacts: Send + Sync {
    fn chain_tip(&self) -> Result<ChainTip, FactsFault>;
    /// The daemon's identity facts (`nettype`, genesis hash). Constant for
    /// the process's life, so a caller may read it once per connection.
    fn identity(&self) -> Result<DaemonIdentity, FactsFault>;
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
    /// The dynamic base-fee estimate: a function of chain state alone
    /// (FL-R20, FL-R26), so it takes no parameter.
    fn fee_estimate(&self) -> Result<FeeEstimate, FactsFault>;
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
    /// Chain **count** as of the same read — reported even when absent, so a
    /// height refusal can name the bound without a second call.
    pub chain_height: ChainCount,
}

/// The block itself: RK-3's header projection plus what only `get_block`
/// carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockFacts {
    pub header: BlockHeaderFacts,
    /// The block in its consensus encoding. Hex is the handler's job.
    pub blob: Vec<u8>,
    /// epee's rendering of the whole block, produced in C++ and carried
    /// through untouched (RK-D11). `None` from a reader with no epee
    /// renderer — the store-backed facts (`DRS_X_STORE_FLIP.md` DX-Q3):
    /// the field duplicates `blob`, and RK-W retires it.
    pub json: Option<String>,
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
    /// [`P2pRead::Offline`] for a daemon started offline.
    fn peer_list(&self, public_only: bool) -> Result<P2pRead<Vec<PeerEntry>>, FactsFault>;
    /// Whether P2P runs, from the daemon's configuration: read before a
    /// method that reads no peer list answers about peers or connections.
    fn p2p_state(&self) -> Result<P2pRead<()>, FactsFault>;
}

/// The dynamic base-fee estimate: three priced tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeEstimate {
    pub fees: [u64; 3],
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

/// Production [`P2pFacts`] over the C++ protocol handler. The chain reads
/// go through [`crate::store_facts::StoreFacts`].
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

    fn peer_list(&self, public_only: bool) -> Result<P2pRead<Vec<PeerEntry>>, FactsFault> {
        self.core
            .peer_list(public_only)
            .map_err(FactsFault::from_code)
    }

    fn p2p_state(&self) -> Result<P2pRead<()>, FactsFault> {
        CoreRpc::p2p_state().map_err(FactsFault::from_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi;

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
