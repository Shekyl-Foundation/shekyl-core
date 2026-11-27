// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Signing a stake at its due block, and draining a persona whose plan ended
//! (`ARCHIVAL_BOND_POST_DELAY.md` BD-Q3, §3.6). The dispatch driver decides
//! **when** (`pscan/dispatch.rs`); this module does the work through the
//! engine, and every secret stays inside the stake actor (rule 36). The
//! request's half, the plan, is `bond_orchestrator.rs`.

use std::sync::Arc;

use shekyl_curve_tree::{AssembleInput, ClientError, ReferenceBlock};
use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pending_post_block::{
    PendingBondPost, PendingPostState, PlanWait, PlannedPosture, SignAdmission,
};
use shekyl_rpc_transport::DaemonTarget;
use shekyl_tx_builder::{LeafEntry, TreeContext};
use shekyl_types::{BlockHeight, ChainCount, PCanonicalId, PSlot};
use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use super::bond_assembly::{
    BondAssemblyError, FundingInputContext, FundingSelection, SpentRecordsDurablyPruned,
};
use super::bond_orchestrator::{p_lane_floor_fee, planned_holdings};
use super::bond_plan::canonical_reference;
use super::curve_tree_actor::{CurveTreeHandle, CurveTreeHandleError};
use super::drain_orchestrator::{DrainIntent, NoExitOwed};
use super::fee_policy::FeeEstimatorError;
use super::fee_snapshot::map_daemon_engine_fee_error;
use super::holdings_fill::{CompleteTreeFillError, FilledHoldings, MarketFillError};
use super::pscan::block_source::daemon_claimed_tip;
use super::pscan::dispatch::PlanAttempt;
use super::pscan::start::pending_post_store_for_engine;
use super::signer::EngineSignerKind;
use super::stake_engine::{AssembledBondPost, PersonaHandle, StakeEngineError, StakeEngineHandle};
use super::stake_persist::PersistedBondTicket;
use super::traits::{DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine};
use super::Engine;

/// Why signing a stake at its due block did not complete: a reason the plan
/// waits on, or an ending. Mapped once, here, from the fill, the sweep and
/// the actor (BD-Q3 as ruled 2026-11-26).
#[derive(Debug)]
pub(crate) enum DueBlock {
    /// The plan waits; the reason is recorded.
    Wait(PlanWait),
    /// The shards the bond owes can no longer be bonded.
    Unbondable,
}

impl DueBlock {
    /// A failure the wallet cannot name a better reason for: the post could
    /// not be assembled. Logged with its cause, and limited, so a plan that
    /// can never be assembled ends at its maximum and its funding returns.
    pub(crate) fn assembly(context: &'static str, cause: impl std::fmt::Display) -> Self {
        tracing::warn!(context, %cause, "staking: a due stake could not be assembled");
        Self::Wait(PlanWait::AssemblyFailed)
    }

    pub(crate) fn into_attempt(self) -> PlanAttempt {
        match self {
            Self::Wait(wait) => PlanAttempt::Wait(wait),
            Self::Unbondable => PlanAttempt::Unbondable,
        }
    }

    /// The fill's failures (`holdings_fill`): a node that discarded the
    /// bodies ends the plan; a node that is not local, disagrees with the
    /// scan, or a store that cannot write are limited; the rest are
    /// temporary.
    pub(crate) fn from_fill(e: CompleteTreeFillError) -> Self {
        use super::holdings_fill::FillFailure;
        match e {
            CompleteTreeFillError::ScanBehind { .. } => Self::Wait(PlanWait::WalletBehind),
            CompleteTreeFillError::Fill(f) => match f {
                FillFailure::Discarded { .. } => Self::Unbondable,
                FillFailure::LocalNodeRequired { .. } => Self::Wait(PlanWait::NodeNotLocal),
                FillFailure::DaemonSyncing => Self::Wait(PlanWait::NodeSyncing),
                FillFailure::DaemonUnreachable { .. } => Self::Wait(PlanWait::NodeUnreachable),
                FillFailure::ScanStateUnreadable { .. } => Self::Wait(PlanWait::WalletBehind),
                FillFailure::DaemonMismatch { .. } => Self::Wait(PlanWait::NodeMismatch),
                FillFailure::StoreFailed { .. } => Self::Wait(PlanWait::StoreFailed),
            },
        }
    }

    /// The market fill's failures: a named shard the scan has not reached is
    /// temporary; a named shard that is not final is limited (it can become
    /// final); the shared failures map as the complete-tree fill's do.
    pub(crate) fn from_market_fill(e: MarketFillError) -> Self {
        match e {
            MarketFillError::ScanBehind { .. } => Self::Wait(PlanWait::WalletBehind),
            MarketFillError::NotFinal { .. } => Self::Wait(PlanWait::AssemblyFailed),
            MarketFillError::Fill(f) => Self::from_fill(CompleteTreeFillError::Fill(f)),
        }
    }

    /// The sweep's refusals: funding short of the bond plus the live fee is
    /// the fee case; a tree or ledger behind is temporary.
    pub(crate) fn from_sweep(e: BondAssemblyError) -> Self {
        match e {
            BondAssemblyError::InsufficientFunding { .. } => Self::Wait(PlanWait::FeeAboveFunding),
            BondAssemblyError::ReferenceResyncing { .. } => Self::Wait(PlanWait::WalletBehind),
            other => Self::assembly("funding sweep", other),
        }
    }

    pub(crate) fn from_engine(e: StakeEngineError) -> Self {
        match e {
            StakeEngineError::Assembly(BondAssemblyError::InsufficientFunding { .. }) => {
                Self::Wait(PlanWait::FeeAboveFunding)
            }
            StakeEngineError::Assembly(BondAssemblyError::OutputNotYetDrained { .. }) => {
                Self::Wait(PlanWait::WalletBehind)
            }
            other => Self::assembly("bond assembly", other),
        }
    }
}

#[allow(private_bounds)] // same Engine-trait privacy posture as start_pscan_with
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
    /// Sign `persona`'s stake at its due block (`ARCHIVAL_BOND_POST_DELAY.md`
    /// BD-Q3): fill the shards the bond owes, quote the fee at the live rate,
    /// sweep the funding at a fresh canonical reference, assemble, prove and
    /// sign inside the actor, and seal the signed post in place of the plan.
    /// The same path re-signs a post never sent whose reference has aged
    /// (Rule 1). The dispatch driver sends the sealed post in the same tick.
    ///
    /// The post is signed only at the canonical reference for `tip`, the
    /// daemon-claimed clock the driver sends on, so its first send carries
    /// reference age 6. A wallet whose scan, tree or ledger is behind that
    /// clock waits (a temporary reason) rather than sign at an older one.
    ///
    /// Assembly runs outside the pending lock; the seal is checked
    /// ([`PendingPostBlock::sign_plan`]): a plan withdrawn while the post was
    /// proved wins, and the signed bytes are dropped unsent.
    pub(crate) async fn sign_bond_at_due(
        self_arc: Arc<RwLock<Self>>,
        node: &DaemonTarget,
        persona: PCanonicalId,
        tip: ChainCount,
    ) -> PlanAttempt {
        match Self::try_sign_bond_at_due(self_arc, node, persona, tip).await {
            Ok(attempt) => attempt,
            Err(blocked) => blocked.into_attempt(),
        }
    }

    async fn try_sign_bond_at_due(
        self_arc: Arc<RwLock<Self>>,
        node: &DaemonTarget,
        persona: PCanonicalId,
        tip: ChainCount,
    ) -> Result<PlanAttempt, DueBlock> {
        let (daemon, pending_gate) = {
            let g = self_arc.read().await;
            (g.daemon().clone(), g.pending_gate.clone())
        };
        let store = pending_post_store_for_engine(self_arc.clone(), pending_gate);

        // What is being signed: the plan, or the post never sent.
        let held = store
            .read(|block| {
                block
                    .plans()
                    .iter()
                    .find(|p| p.persona == persona)
                    .map(|p| {
                        (
                            p.p_slot,
                            p.posture.clone(),
                            p.funding_gindexes.clone(),
                            None,
                        )
                    })
                    .or_else(|| {
                        block
                            .posts()
                            .iter()
                            .find(|p| p.persona == persona)
                            .map(|p| {
                                (
                                    p.p_slot,
                                    p.posture.clone(),
                                    p.funding_gindexes.clone(),
                                    Some(p.due),
                                )
                            })
                    })
            })
            .await
            .map_err(|e| DueBlock::assembly("pending read", e))?;
        let Some((p_slot, posture, own, signed_due)) = held else {
            return Ok(PlanAttempt::Raced);
        };
        let canonical = canonical_reference(tip).ok_or(DueBlock::Wait(PlanWait::WalletBehind))?;

        // The fee at the live rate (the P-lane floor; PR A moves it to the
        // post's own weight).
        let estimates = daemon
            .get_fee_estimates()
            .await
            .map_err(|_| DueBlock::Wait(PlanWait::NodeUnreachable))?;
        let fee = p_lane_floor_fee(estimates).map_err(|e| match e {
            FeeEstimatorError::DaemonFeeUnreasonable(_) => {
                DueBlock::Wait(PlanWait::FeeAboveFunding)
            }
            _ => DueBlock::Wait(PlanWait::NodeUnreachable),
        })?;

        // Every shard the bond owes at this block, in the body store before
        // anything is signed (WSS-Q4): shards closed while the plan waited
        // are owed too. First, because it can take blocks: everything read
        // about the chain is read after it.
        let holdings = planned_holdings(&posture)
            .map_err(|e| DueBlock::assembly("planned holdings", format!("{e:?}")))?;
        let filled = match &posture {
            PlannedPosture::SupportCompleteTree => {
                Self::fill_complete_tree(self_arc.clone(), node, holdings.clone())
                    .await
                    .map_err(DueBlock::from_fill)?
            }
            PlannedPosture::Market { .. } => {
                Self::fill_market(self_arc.clone(), node, holdings.clone())
                    .await
                    .map_err(DueBlock::from_market_fill)?
            }
        };

        // The chain as it stands after the fill.
        let (stake, curve_tree, chain_tip, tip_hash_at, bonded) = {
            let g = self_arc.read().await;
            let stake = g
                .stake_handle()
                .ok_or(DueBlock::Wait(PlanWait::WalletBehind))?;
            let snap = g.ledger.snapshot();
            let chain_tip = g.ledger.synced_height();
            let tip_hash_at = move |h: BlockHeight| snap.block_hash_at(h);
            (
                stake,
                g.curve_tree.clone(),
                chain_tip,
                tip_hash_at,
                g.ledger.bonded_slots(),
            )
        };

        // The funding, swept at this block's reference. The plan's own
        // reservation is its to spend, so it does not count against it.
        let witness = SpentRecordsDurablyPruned::arm1_watch_pruning_live();
        let (selection, reference, snapshot_generation) = Self::sweep_bond_funding(
            self_arc.clone(),
            &store,
            &curve_tree,
            chain_tip,
            tip_hash_at,
            p_slot,
            &holdings,
            fee,
            &witness,
            &own,
        )
        .await
        .map_err(DueBlock::from_sweep)?;
        // Signed only at the canonical reference for the clock the driver
        // sends on, so the first send carries reference age 6. A wallet behind
        // that clock waits; a wallet ahead of it means the tick's tip is stale,
        // and the next tick signs against the newer one.
        match reference.height.cmp(&canonical) {
            std::cmp::Ordering::Less => return Err(DueBlock::Wait(PlanWait::WalletBehind)),
            std::cmp::Ordering::Greater => return Ok(PlanAttempt::Raced),
            std::cmp::Ordering::Equal => {}
        }
        let funded_through = selection
            .records
            .iter()
            .map(|r| r.height)
            .max()
            .unwrap_or(BlockHeight::ZERO);

        // The durable bond record the request wrote is the ticket's witness.
        let ticket = PersistedBondTicket::for_recorded_slot(&bonded, p_slot)
            .ok_or_else(|| DueBlock::assembly("bond record", "the plan's slot is not recorded"))?;
        let handle = stake
            .mint_handle(p_slot)
            .await
            .map_err(|e| DueBlock::assembly("persona handle", e))?;
        let assembled = Self::assemble_signed_bond(
            &curve_tree,
            &stake,
            handle,
            ticket,
            filled,
            selection,
            reference,
            fee,
        )
        .await
        .map_err(DueBlock::from_engine)?;

        // Proving takes time too: a tip that moved since the tick would send
        // these bytes at an age above 6, so they are dropped and the next
        // tick signs again.
        let now = daemon_claimed_tip(&daemon)
            .await
            .map_err(|_| DueBlock::Wait(PlanWait::NodeUnreachable))?;
        if now != tip {
            return Ok(PlanAttempt::Raced);
        }

        let post = PendingBondPost {
            p_slot,
            persona: *assembled.bound_tx.persona(),
            tx_bytes: assembled.bound_tx.bytes().to_vec(),
            posture,
            due: signed_due.unwrap_or(tip),
            funded_through,
            funding_gindexes: assembled.funding_gindexes,
            state: PendingPostState::Pending,
            reference_height: reference.height,
            terminal: None,
        };
        if post.persona != persona {
            return Err(DueBlock::assembly(
                "persona",
                "the signed post names another persona",
            ));
        }
        let resign = signed_due.is_some();
        let admission = store
            .mutate(|block| {
                let admission = if resign {
                    block.resign_post(post, snapshot_generation)
                } else {
                    block.sign_plan(post, snapshot_generation)
                };
                (admission == SignAdmission::Signed, admission)
            })
            .await
            .map_err(|e| DueBlock::assembly("pending seal", e))?;
        Ok(match admission {
            SignAdmission::Signed => PlanAttempt::Signed,
            SignAdmission::PlanGone
            | SignAdmission::AlreadySent
            | SignAdmission::Stale
            | SignAdmission::InputRaced => PlanAttempt::Raced,
        })
    }

    /// Send the drain that empties a persona whose planned stake ended without
    /// a bond (BD-Q3 as ruled 2026-11-26): the terminal sweep, to zero, with
    /// no exit-fee reserve, under a [`NoExitOwed`] witness minted from the
    /// pending block's [`EndedPlan`](shekyl_engine_state::EndedPlan). Any
    /// refusal — a fee above the funding, a drain already in flight, a node
    /// that cannot be read — waits for the next tick: there is no maximum,
    /// because nothing else can return these funds.
    pub(crate) async fn drain_ended_persona(
        self_arc: Arc<RwLock<Self>>,
        p_slot: PSlot,
        persona: PCanonicalId,
    ) {
        let (daemon, pending_gate) = {
            let g = self_arc.read().await;
            (g.daemon().clone(), g.pending_gate.clone())
        };
        let store = pending_post_store_for_engine(self_arc.clone(), pending_gate);
        let witness = match store
            .read(|block| NoExitOwed::for_ended_plan(block, persona))
            .await
        {
            Ok(Some(witness)) => witness,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(%error, "staking: the ended stake's record could not be read");
                return;
            }
        };
        let fee = match daemon.get_fee_estimates().await {
            Ok(estimates) => match p_lane_floor_fee(estimates) {
                Ok(fee) => fee,
                Err(error) => {
                    tracing::info!(%error, "staking: the returning funds wait for a usable fee");
                    return;
                }
            },
            Err(error) => {
                tracing::info!(
                    error = %map_daemon_engine_fee_error(error),
                    "staking: the returning funds wait for the node"
                );
                return;
            }
        };
        let pruning = SpentRecordsDurablyPruned::arm1_watch_pruning_live();
        match Self::submit_drain(
            self_arc,
            p_slot,
            DrainIntent::TerminalSweep(witness),
            fee,
            &pruning,
        )
        .await
        {
            Ok(_) => {
                tracing::info!("staking: an ended stake's funds were sent back to this wallet")
            }
            Err(error) => tracing::info!(
                %error,
                "staking: an ended stake's funds could not be sent back this tick; retrying"
            ),
        }
    }

    /// Path-assemble the swept funding at `reference` and have the actor
    /// assemble, prove and sign the post — the shared tail of signing at due.
    #[allow(clippy::too_many_arguments)] // the assembly's whole public input
    async fn assemble_signed_bond(
        curve_tree: &CurveTreeHandle,
        stake: &StakeEngineHandle,
        handle: PersonaHandle,
        ticket: PersistedBondTicket,
        holdings: FilledHoldings,
        selection: FundingSelection,
        reference: ReferenceBlock,
        fee: AtomicUnits,
    ) -> Result<AssembledBondPost, StakeEngineError> {
        // SA-R1-c (GF4b-2): the common-case bond consumes exactly ONE
        // structured funding input; multi-tranche is a consciously LOGGED
        // exception, never a silent one.
        if selection.records.len() > 1 {
            tracing::warn!(
                swept_inputs = selection.records.len(),
                "multi-input bond post: the common case is one structured stake_in \
                 output; this post reveals its funding-input count on-chain (GF4b-2 \
                 / SA-R1-c consciously-logged exception)"
            );
        }
        let assemble_inputs: Vec<AssembleInput> = selection
            .records
            .iter()
            .map(crate::engine::ownership::p_assemble_input)
            .collect();
        let paths = curve_tree
            .assemble_tx(reference, assemble_inputs)
            .await
            .map_err(|e| match e {
                // The one retryable path-assembly refusal, kept typed across
                // the boundary.
                CurveTreeHandleError::Client(ClientError::OutputNotDrained { gindex, .. }) => {
                    BondAssemblyError::OutputNotYetDrained {
                        gindex: gindex.to_raw(),
                    }
                }
                other => BondAssemblyError::build("assemble_tx", format!("{other:?}")),
            })?;
        // One path per input asked for, in that order, all to one tree: the
        // batch's own properties (R-26), so the records zip with its paths.
        let tree = paths.tree();
        let tree_ctx = TreeContext {
            reference_block: tree.reference_block,
            tree_root: tree.tree_root,
            tree_depth: tree.tree_depth,
        };
        let funding: Vec<FundingInputContext> = selection
            .records
            .into_iter()
            .zip(paths.into_paths().map(|(_, path)| path.into_parts()))
            .map(|(record, path)| FundingInputContext {
                record,
                leaf_chunk: path
                    .leaf_chunk
                    .iter()
                    .map(|cl| LeafEntry {
                        output_key: cl.output_key.to_bytes(),
                        key_image_gen: cl.key_image_gen,
                        commitment: cl.commitment.to_bytes(),
                        cm_x: cl.cm_x,
                    })
                    .collect(),
                c1_layers: path.c1_layers,
                c2_layers: path.c2_layers,
            })
            .collect();
        stake
            .assemble_bond(handle, ticket, holdings, funding, tree_ctx, fee.to_raw())
            .await
    }
}

#[cfg(test)]
#[path = "bond_due_tests.rs"]
mod tests;
