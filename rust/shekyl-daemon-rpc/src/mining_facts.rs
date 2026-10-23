// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the mining methods read from the node and ask of it
//! (`DRS_X_STORE_FLIP.md` DX-Q3, N1, N2), in this crate's own types: the
//! RPC names neither the ingest service nor the miner.

use std::future::Future;
use std::pin::Pin;

use shekyl_rpc_types::errors::Diagnostic;
use shekyl_types::{BlockHash, BlockHeight, TxHash};

use crate::chain_facts::FactsFault;

/// A handle's answer that waits: a boxed future, so the trait stays
/// object-safe.
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, FactsFault>> + Send + 'a>>;

/// One body the posted template lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BacklogEntry {
    /// The transaction's id.
    pub id: TxHash,
    /// Its weight.
    pub weight: u64,
    /// Its fee, in atomic units.
    pub fee: u64,
}

/// The node's posted template (N2): what `get_block_template` and
/// `get_miner_data` read. It is built by the node, never by the RPC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostedTemplate {
    /// The block, serialized.
    pub block: Vec<u8>,
    /// What its longhash is computed over.
    pub hashing_blob: Vec<u8>,
    /// The header's major version.
    pub major_version: u8,
    /// The height it connects at.
    pub height: BlockHeight,
    /// The tip it extends.
    pub prev_hash: BlockHash,
    /// The difficulty its longhash must meet.
    pub difficulty: u128,
    /// Where the coinbase's reserved extra nonce sits in `block`.
    pub extra_nonce_offset: u64,
    /// Where the header nonce sits in `block` and in `hashing_blob`.
    pub nonce_offset: u64,
    /// What the coinbase pays the miner, in atomic units.
    pub reward: u64,
    /// The RandomX seed: the id of the block at `seed_height`.
    pub seed: BlockHash,
    /// The seed block's height.
    pub seed_height: BlockHeight,
    /// The next epoch's seed, once the chain has it and it differs.
    pub next_seed: Option<BlockHash>,
    /// The effective median block weight it was priced against.
    pub median_weight: u64,
    /// The gross emission before it, in atomic units.
    pub already_generated: u64,
    /// The bodies it lists, in block order.
    pub backlog: Vec<BacklogEntry>,
}

/// The posted job, as `mining_status` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostedSummary {
    /// The height it connects at.
    pub height: BlockHeight,
    /// Its difficulty.
    pub difficulty: u128,
    /// Its coinbase's payment to the miner.
    pub reward: u64,
}

/// The built-in miner while it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinerState {
    /// Worker threads.
    pub threads: u32,
    /// Hashes per second over the miner's window, whole hashes.
    pub hashes_per_second: u64,
}

/// What `mining_status` reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MiningState {
    /// The miner, while it runs.
    pub miner: Option<MinerState>,
    /// The `mine-address` row, as written.
    pub address: Option<String>,
    /// The posted job.
    pub posted: Option<PostedSummary>,
    /// The pool file faulted.
    pub pool_retired: bool,
    /// Why no job is posted, when none is.
    pub absent: Option<Diagnostic>,
}

/// What became of a block offered through the node's local-arrival entry
/// (b4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalOutcome {
    /// It connected.
    Connected {
        /// Where.
        height: BlockHeight,
        /// Its id.
        hash: BlockHash,
    },
    /// It is the new tip, after a switch onto its branch.
    Switched {
        /// The new tip's height.
        height: BlockHeight,
    },
    /// A consensus rule refused it.
    Refused {
        /// The rule's row, such as `CEN-D1`.
        rule: String,
    },
    /// Listed bodies neither the request carried nor the pool shows, by
    /// their index in the block's list.
    MissingBodies {
        /// The indices, ascending.
        indices: Vec<usize>,
    },
    /// Its parent chain reaches no block this node holds.
    Unlinked,
    /// This node holds it already.
    AlreadyHeld,
    /// Stored as an alternative block; the tip did not change.
    Held,
    /// Its fork is deeper than the reorganisation cap.
    BeyondCap,
    /// It extends a heavier chain this node cannot follow.
    CannotFollow,
    /// It is larger than any valid block near the tip.
    Oversize,
    /// The node is stopping; it was not taken.
    Stopped,
}
