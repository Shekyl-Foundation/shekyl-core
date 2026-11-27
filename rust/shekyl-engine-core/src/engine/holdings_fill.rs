// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fill first, then post — as a type (`WSS-Q4`, `WSS-Q15`;
//! `docs/design/WALLET_SIDE_STORE.md` §6.5.3, §6.5.9).
//!
//! A bond post obligates its persona to serve the shards it owes, and
//! consensus checks no bond for possession at admission: challenges test it
//! afterwards. So the wallet refuses to post a bond whose shards its body
//! store does not hold. [`FilledHoldings`] is how that refusal is
//! structural: [`Engine::assemble_bond_post`] and the stake engine's two
//! vin-building messages take it instead of a bare holdings descriptor, and
//! the only production mints are the two fills here, each of which returns
//! it after every owed shard is held. The pattern is
//! [`DurableTxBytes`](super::dispatch_durability::DurableTxBytes)': a private
//! field, no `Clone`, one hand-off per completed fill.
//!
//! **What is owed, and when it is final.** A shard is final once its close
//! sits at least the reorg cap below the tip the daemon claims — consensus's
//! `ClosedUniverse::final_before` for the next block
//! (`shekyl-chain-rules/src/archival/close.rs`), computed from the persona
//! scan's checked fold, with the cap the process's schedule latch holds (the
//! genesis pin, or a regtest harness's armed lever). A `CompleteTree` bond
//! owes every final shard, so its fill needs the scan to have verified the
//! chain up to that horizon; a market bond owes the shards it names, each of
//! which must be final.
//!
//! **Where the bytes come from.** The wallet's own node, on the persona's
//! loopback transport ([`LocalNodeRpc`]); a non-loopback daemon is a typed
//! refusal. A shard the node has already discarded answers `archived`
//! (`SB-Q2`), and its bodies come back only through the node's recovery
//! fetch (§6.5.4, the `WSS-Q9` handoff), which is not built, so it is a
//! refusal that says so.
//!
//! A shard the store already holds is not re-fetched: its body is the
//! reconcile's to check (`WSS-Q17`).

use std::time::Duration;

use shekyl_archival_retention::{
    effective_archival_reorg_depth_blocks, HoldingsDescriptor, HoldingsKind,
};
use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pscan_cursor::ArchivalFold;
use shekyl_rpc_transport::DaemonTarget;
use shekyl_types::{BlockCount, BlockHeight, ShardId};
use tokio::sync::RwLock;

use std::sync::Arc;

use super::prpc::LocalNodeRpc;
use super::pscan::block_source::{daemon_claimed_tip, BlockSourceError};
use super::pscan::start::load_pscan_state_for_engine;
use super::signer::EngineSignerKind;
use super::stake_engine::body_store_actor::BodyStoreHandle;
use super::stake_engine::fill::{fill_shard, ShardFillError};
use super::traits::{DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine};
use super::Engine;

/// The loopback transport's per-request timeout for the fill's reads. A
/// `tx_list` of a hundred whole bodies from the wallet's own node.
const FILL_RPC_TIMEOUT: Duration = Duration::from_secs(60);

/// Holdings whose every owed shard the persona body store holds: the only
/// holdings a bond post is assembled from.
///
/// Minted only by [`Engine::fill_complete_tree`] and the test-built
/// `Engine::fill_market` after their fill completes. Deliberately **not** `Clone`: one completed
/// fill authorizes one assembly; a retry fills again (held shards are
/// skipped, so a second fill costs a held check per shard).
pub(crate) struct FilledHoldings(HoldingsDescriptor);

impl std::fmt::Debug for FilledHoldings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FilledHoldings").field(&self.0.kind).finish()
    }
}

impl FilledHoldings {
    /// The holdings, for the reads that size or describe the post (the bond
    /// floor, the vin).
    pub(crate) fn descriptor(&self) -> &HoldingsDescriptor {
        &self.0
    }
}

/// A fill failure shared by both postures. Nothing was posted; any shard
/// that completed before the failure stays held, whole (each shard is one
/// store write).
#[derive(Debug, thiserror::Error)]
pub enum FillFailure {
    /// The fill reads the wallet's own node on loopback, and this wallet's
    /// daemon is elsewhere.
    #[error(
        "filling the persona body store needs the wallet's own node on this computer: {detail}"
    )]
    LocalNodeRequired {
        /// The transport constructor's refusal.
        detail: String,
    },
    /// The node reports that it is still synchronizing, so it has no tip to
    /// judge finality against.
    #[error("the node is still synchronizing; retry once it has caught up")]
    DaemonSyncing,
    /// The node could not be read.
    #[error("the node could not be read: {detail}")]
    DaemonUnreachable {
        /// The transport's reason.
        detail: String,
    },
    /// The persona scan's sealed state would not load.
    #[error("the persona scan's state could not be read: {detail}")]
    ScanStateUnreadable {
        /// The load's reason.
        detail: String,
    },
    /// The node has discarded the shard's bodies at its horizon, and the
    /// recovery fetch that would bring them back is not built, so the shard
    /// cannot be filled.
    #[error(
        "the node has already discarded shard {shard}'s bodies; they come back only through \
         the node's recovery fetch, which does not exist yet, so this bond cannot be posted \
         until it does"
    )]
    Discarded {
        /// The discarded shard.
        shard: ShardId,
    },
    /// The node's reply does not match the chain the persona scan verified.
    #[error("the node's reply for shard {shard} does not match the verified chain: {detail}")]
    DaemonMismatch {
        /// The shard being filled.
        shard: ShardId,
        /// What disagreed.
        detail: String,
    },
    /// The persona body store could not write the shard.
    #[error("the persona body store could not write shard {shard}: {detail}")]
    StoreFailed {
        /// The shard being written.
        shard: ShardId,
        /// The store's reason.
        detail: String,
    },
}

/// Why a `CompleteTree` fill did not complete.
#[derive(Debug, thiserror::Error)]
pub enum CompleteTreeFillError {
    /// The persona scan has not yet verified the chain up to the finality
    /// horizon, so the set of final shards is not known yet.
    #[error(
        "the persona scan has verified the chain to block {scanned} and must reach block \
         {needed} before the shards this bond owes are known; retry once it has"
    )]
    ScanBehind {
        /// The scan's frontier (the first height it has not verified).
        scanned: BlockHeight,
        /// The frontier the fill needs.
        needed: BlockHeight,
    },
    /// A failure both postures share.
    #[error(transparent)]
    Fill(#[from] FillFailure),
}

/// Why a market fill did not complete. Only the market path reaches these;
/// a `CompleteTree` fill never names a shard.
///
/// Reached through `Engine::fill_market`, which signing a market plan at its
/// due block calls (`ARCHIVAL_BOND_POST_DELAY.md` BD-Q3). The request
/// refuses the market posture (`FirstStakeError::NoShardsAvailable`) until
/// shard selection exists (`COMPLETETREE_ACTIVATION.md` §10 item 1), so no
/// production request plans one yet; the emission walk's market-bond fixture
/// plans and fills through it.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MarketFillError {
    /// The scan has not reached a named shard's close, and it is behind the
    /// finality horizon, so whether the shard is final is not known yet.
    #[error("the persona scan has not reached shard {shard}'s close yet")]
    ScanBehind {
        /// The shard named.
        shard: ShardId,
    },
    /// A named shard is open, or closed within the reorg cap of the tip.
    #[error("shard {shard} is not final; a bond names only final shards")]
    NotFinal {
        /// The shard named.
        shard: ShardId,
    },
    /// A failure both postures share.
    #[error(transparent)]
    Fill(#[from] FillFailure),
}

/// What a fill reads before it fills: the loopback transport, the store, the
/// scan's fold and frontier, and the finality horizon. The reconcile
/// (`body_reconcile`) reads the same, so the two cannot disagree about what
/// is final or where a shard's blocks are.
pub(crate) struct FillContext {
    rpc: LocalNodeRpc,
    pub(crate) bodies: BodyStoreHandle,
    pub(crate) fold: ArchivalFold,
    pub(crate) scanned: BlockHeight,
    /// Exclusive: a shard whose close is below this is final.
    pub(crate) final_horizon: BlockHeight,
}

impl FillContext {
    /// The persona's loopback transport to the wallet's own node.
    pub(crate) fn rpc(&self) -> &LocalNodeRpc {
        &self.rpc
    }

    /// Whether `shard` is closed and final, by the scan's fold.
    pub(crate) fn is_final(&self, shard: ShardId) -> bool {
        self.fold
            .close(shard)
            .is_some_and(|close| close.height < self.final_horizon)
    }

    /// Every final shard, ascending: what a `CompleteTree` bond owes.
    pub(crate) fn final_shards(&self) -> Vec<ShardId> {
        (0..self.fold.closed_count())
            .map(ShardId::from_raw)
            .take_while(|shard| self.is_final(*shard))
            .collect()
    }

    /// Fill each of `shards` the store does not already hold.
    async fn fill(&self, shards: &[ShardId]) -> Result<(), FillFailure> {
        for &shard in shards {
            let held = self
                .bodies
                .holds(shard)
                .await
                .map_err(|detail| FillFailure::StoreFailed { shard, detail })?;
            if held {
                continue;
            }
            self.fill_one(shard).await?;
        }
        Ok(())
    }

    /// Fill `shard` from the node, whether or not the store holds it: a
    /// held row is replaced whole (`put_shard` is one transaction). The
    /// reconcile's refill; [`Self::fill`] skips held shards before it.
    pub(crate) async fn fill_one(&self, shard: ShardId) -> Result<(), FillFailure> {
        let span = self.fold.span(shard).ok_or(FillFailure::DaemonMismatch {
            shard,
            detail: "the scan's fold has no record of this shard's close".to_owned(),
        })?;
        fill_shard(&self.rpc, &self.bodies, shard, span)
            .await
            .map_err(failure_of)
    }
}

fn failure_of(e: ShardFillError) -> FillFailure {
    match e {
        ShardFillError::Daemon { source, .. } => FillFailure::DaemonUnreachable {
            detail: source.to_string(),
        },
        ShardFillError::Discarded { shard } => FillFailure::Discarded { shard },
        ShardFillError::Mismatch { shard, kind } => FillFailure::DaemonMismatch {
            shard,
            detail: kind.to_string(),
        },
        ShardFillError::Store { shard, detail } => FillFailure::StoreFailed { shard, detail },
    }
}

#[allow(private_bounds)] // same Engine-trait privacy posture as assemble_bond_post
impl<S, D, L, E, R, P> Engine<S, D, L, E, R, P, WalletFile>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Self: Send + Sync,
{
    /// Read what a fill needs: the loopback transport to `daemon`, the
    /// stake engine's body store, the scan's sealed fold, and the finality
    /// horizon at the daemon's claimed tip.
    pub(crate) async fn fill_context(
        self_arc: Arc<RwLock<Self>>,
        daemon: &DaemonTarget,
    ) -> Result<FillContext, FillFailure> {
        let rpc = LocalNodeRpc::new(daemon, FILL_RPC_TIMEOUT)
            .await
            .map_err(|e| FillFailure::LocalNodeRequired {
                detail: e.to_string(),
            })?;
        let bodies = {
            let g = self_arc.read().await;
            g.stake_handle()
                .map(|stake| stake.bodies.clone())
                .ok_or_else(|| FillFailure::ScanStateUnreadable {
                    detail: "no stake engine is running".to_owned(),
                })?
        };
        let (fold, scanned) = match load_pscan_state_for_engine(self_arc).await.map_err(|e| {
            FillFailure::ScanStateUnreadable {
                detail: e.to_string(),
            }
        })? {
            Some(state) => (state.cursor().archival().clone(), state.synced_height()),
            None => (ArchivalFold::genesis(), BlockHeight::ZERO),
        };
        let claimed = daemon_claimed_tip(&rpc).await.map_err(|e| match e {
            BlockSourceError::DaemonSyncing => FillFailure::DaemonSyncing,
            BlockSourceError::Source(detail) => FillFailure::DaemonUnreachable { detail },
        })?;
        // The P-scan's own horizon expression, with consensus's cap: a close
        // below it sits at least the cap under the claimed tip.
        let final_horizon = claimed
            .saturating_sub_count(BlockCount::from_raw(effective_archival_reorg_depth_blocks()))
            .next_height();
        Ok(FillContext {
            rpc,
            bodies,
            fold,
            scanned,
            final_horizon,
        })
    }

    /// Fill every final shard a `CompleteTree` bond owes (`WSS-Q15`) and
    /// return `holdings` as the holdings to post.
    ///
    /// # Panics
    ///
    /// If `holdings` is not `CompleteTree` holdings: the caller converts a
    /// posture once ([`planned_holdings`](super::bond_orchestrator::planned_holdings)) and
    /// hands that conversion here, so another kind is this crate's bug.
    ///
    /// # Errors
    ///
    /// [`CompleteTreeFillError`]; nothing is posted on any of them.
    pub(crate) async fn fill_complete_tree(
        self_arc: Arc<RwLock<Self>>,
        daemon: &DaemonTarget,
        holdings: HoldingsDescriptor,
    ) -> Result<FilledHoldings, CompleteTreeFillError> {
        assert_eq!(
            holdings.kind,
            HoldingsKind::CompleteTree,
            "fill_complete_tree takes CompleteTree holdings"
        );
        let ctx = Self::fill_context(self_arc, daemon).await?;
        if ctx.scanned < ctx.final_horizon {
            return Err(CompleteTreeFillError::ScanBehind {
                scanned: ctx.scanned,
                needed: ctx.final_horizon,
            });
        }
        ctx.fill(&ctx.final_shards()).await?;
        Ok(FilledHoldings(holdings))
    }

    /// Fill the shards a market bond names and return `holdings` as the
    /// holdings to post. Every named shard must be final. Test-built, for
    /// the reason [`MarketFillError`] gives.
    ///
    /// # Panics
    ///
    /// If `holdings` is not a shard set, for the reason
    /// [`Self::fill_complete_tree`] gives.
    ///
    /// # Errors
    ///
    /// [`MarketFillError`]; nothing is posted on any of them.
    pub(crate) async fn fill_market(
        self_arc: Arc<RwLock<Self>>,
        daemon: &DaemonTarget,
        holdings: HoldingsDescriptor,
    ) -> Result<FilledHoldings, MarketFillError> {
        assert_eq!(
            holdings.kind,
            HoldingsKind::ShardSetCompact,
            "fill_market takes shard-set holdings"
        );
        let ctx = Self::fill_context(self_arc, daemon).await?;
        let shards: Vec<ShardId> = holdings
            .shard_ids
            .as_slice()
            .iter()
            .copied()
            .map(ShardId::from_raw)
            .collect();
        for &shard in &shards {
            if ctx.is_final(shard) {
                continue;
            }
            return Err(
                if ctx.fold.close(shard).is_none() && ctx.scanned < ctx.final_horizon {
                    MarketFillError::ScanBehind { shard }
                } else {
                    MarketFillError::NotFinal { shard }
                },
            );
        }
        ctx.fill(&shards).await?;
        Ok(FilledHoldings(holdings))
    }
}
