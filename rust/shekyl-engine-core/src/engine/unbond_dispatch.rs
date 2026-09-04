// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `submit_unbond` dispatch seam — the Engine-side terminal-exit
//! **request path** (`PRINCIPAL_STAKE_LIFECYCLE.md` PR-P4; the claim/drain
//! sibling).
//!
//! [`AssembleUnbond`] is the production assembler and deliberately returns
//! its reply **unbroadcast** (the CB-3 discipline: the builder never
//! self-schedules). This module is the other half of that routing: one
//! explicit exit intent in, one assembled `Unbond` dispatched through the
//! audited posture→submitter choke point ([`BroadcastSubmitter::local`] →
//! [`submit_bound`]) out — **immediately**. The exit draws no decorrelation
//! offset and takes no dispatch plan: the event it follows — a release
//! cooldown expiring — is already public on-chain, so a delay would defer an
//! irreversible operation the user asked for and hide nothing (the ruling on
//! [`AssembleUnbond`]). That immediacy is why the sealed record is a
//! [`PendingUnbond`], never a `PendingBondPost`: it must not enter WI-3's
//! due-check, and its confirmation observable is its reservation settling
//! (`remove_settled`), not a pscan bond-post match.
//!
//! Mirrors [`Engine::submit_drain`](super::drain_dispatch)'s shape: a
//! self-arc method that clones its actor handles under one brief read lock,
//! loads the sealed P-scan state and the live reservation set through the
//! same independent stores, and hands everything to the assembler. Secrets
//! stay inside the stake actor (rule 36); this seam touches public material
//! only.
//!
//! ## The record facts ride the persona-isolated transport
//!
//! The exit's readiness operands (`bonded_total`, the interval log, the
//! cooldown anchor, the slash watermark) are the daemon's bond-record row,
//! fetched as ONE read view through [`fetch_claim_source_for`] — the binding
//! form, which pairs the response with the `P` it was requested for so a
//! caller cannot answer readiness from one persona's record and build
//! another's post. The transport is [`PersonaIsolatedTransport`]-bound for
//! the same §7.4 reason as the claim fetch: a `P`-keyed query on the
//! principal's daemon session would draw the P↔principal edge off-chain.
//!
//! ## Persist-before-dispatch
//!
//! The bond path's load-bearing invariant holds here too: no exit bytes
//! reach any submitter unless a sealed [`PendingUnbond`] already holds them
//! (pin P-2's sibling). The record carries the funding-input reservation (it
//! feeds the shared
//! [`reserved_gindexes`](shekyl_engine_state::PendingPostBlock::reserved_gindexes)
//! union, so no bond sweep, claim fee sweep, or drain can double-spend an
//! input while the exit is in flight — and because the exit sweeps the
//! persona's whole eligible pool, any concurrent same-persona spender
//! collides on the union and refuses). One live exit per persona: the exit
//! debits the record's whole bonded total, so a second is doomed by
//! construction and "wait" is its only correct remedy. Retirement is the
//! dispatch driver's reservation-settlement pass, exactly as for a drain.
//!
//! **Failure disposition, and the recovery residue this lane shares.** A
//! definite FIRST-send refusal (`RejectedTerminal`, or the pre-transport
//! `PersonaMismatch`) releases the seal it just took — see the dispatch
//! site: the bytes were never admitted or relayed, so the record could
//! never settle and holding it would brick the lane. A retryable or
//! ambiguous failure, and a crash between seal and send, HOLD the record:
//! funds-safe (reservation intact, stored bytes the only re-sendable
//! form), not yet live — no driver resubmits claims, drains, or unbonds
//! today, and that is the registered dispatch-driver slice
//! (`docs/FOLLOWUPS.md`: terminal-reject prune + byte-identical resubmit,
//! #572), which cannot land piecemeal because the prune half is a
//! SECURITY item (the retained bytes are a replay channel; resubmit
//! without the prune widens it). Until it lands, the stall alarm names a
//! stuck record in the operator log — funds-safety over liveness, the
//! posture all three reservation-observed lanes share.
//!
//! ## Reachability (the gate PR-C lifted)
//!
//! This seam stays `pub(crate)`; its production caller is
//! [`StakeFacade::unstake`](super::unstake_facade) — the composed `unstake`
//! verb (PR-C), which lifted the exit lane's reachability gate
//! (`docs/api/wallet_rpc.yaml`: `unstake` shipped, no longer RESERVED) and
//! retired the staging allow this seam carried. What protects the
//! irreversible path now that it is reachable: the consensus-ordered
//! readiness refusal below, the engine-side persona resolution (no wire
//! slot), the CLI-side confirmation, and the funds-safe seal semantics —
//! see the façade's module docs.
//!
//! [`submit_bound`]: BroadcastSubmitter::submit_bound

use std::sync::Arc;

use shekyl_curve_tree::{AssembleInput, ClientError, Gindex};
use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pending_post_block::{PendingPostState, PendingUnbond, SealAdmission};
use shekyl_engine_state::pscan_state::PFundingOutputRecord;
use shekyl_types::BlockHeight;
use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use super::bond_assembly::{
    sweep_funding_outputs, BondAssemblyError, FundingInputContext, SpentRecordsDurablyPruned,
    SweepOverflowPolicy,
};
use super::bond_orchestrator::{anchored_reference_block, p_lane_floor_fee};
use super::curve_tree_actor::CurveTreeHandleError;
use super::emission_source::{fetch_claim_source_for, EmissionSourceError};
use super::fee_policy::FeeEstimatorError;
use super::prpc::PersonaIsolatedTransport;
use super::pscan::block_source::daemon_claimed_tip;
use super::pscan::seal_basis::{load_seal_basis, SealBasisError};
use super::pscan::start::pending_post_store_for_engine;
use super::signer::EngineSignerKind;
use super::signing_assembly::{leaf_entry_from_chunk, tree_context_from};
use super::stake_engine::{
    AssembleUnbond, AssembledUnbondPost, PSlot, StakeEngineError, UnbondRecordState,
};
use super::traits::{DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine};
use super::transaction_submitter::{
    BroadcastSubmitError, BroadcastSubmitter, SubmitSuccess, SubmitterError,
};
use super::Engine;

/// What one dispatched terminal exit did: the assembled exit's public facts
/// plus the network verdict. Secrets never cross the boundary — the contained
/// [`PBoundBytes`](super::bond_assembly::PBoundBytes) redacts its own `Debug`.
/// The production reader landed with PR-C: the exit façade
/// ([`unstake_facade`](super::unstake_facade)) projects [`Self::submit`] into
/// the public [`UnstakeOutcome`](super::unstake_facade::UnstakeOutcome).
#[derive(Debug)]
pub(crate) struct UnbondReceipt {
    /// The dispatched exit exactly as assembled (bytes + funding
    /// reservation) — the actor's reply embedded whole, not field-restated.
    // Staging (not tolerated dead code, `15-deletion-and-debt.mdc`): this
    // field's production reader is the dispatch driver's recovery slice
    // (terminal-reject prune + byte-identical resubmit, `docs/FOLLOWUPS.md`)
    // — the same reader `DrainReceipt::drain` stages for; the daemon-walk
    // regtest e2e is the test consumer. The façade reads only `submit`.
    #[allow(dead_code)]
    pub unbond: AssembledUnbondPost,
    /// The daemon's submit verdict (network-exposed / already mined).
    pub submit: SubmitSuccess,
}

/// Why the exit request refused, at any rung: before assembly (no stake
/// engine, the fee quote, state reads, the record fetch), inside it (the
/// actor's own refusals, which carry the consensus-ordered
/// `UnbondNotReady` causes), or at the dispatch choke point. Every arm is
/// caller-actionable per rule 82 — this path's confirmation fires the
/// irreversible persona-key wipe, so a refusal must name *which* condition
/// and, where it can, when it lifts.
///
/// **Rendering posture — bond-path parity, NOT the drain's scalar-free
/// contract, and deliberately so.** The `Stake` arm renders
/// `BondAssemblyError` operands (funding totals, gindexes), exactly as the
/// bond entry's own errors do. `DrainRequestError` commits to a scalar-free
/// rendering because the drain is the firewall's **P→principal value-out
/// leg** — its refusals must not carry `P`-side placement across that edge.
/// The exit never draws that edge: it pays `P`'s own base address, and its
/// refusals describe `P`-side state to the `P`-side caller deciding a
/// `P`-side operation, the same trust domain the bond path's errors already
/// inhabit. Scrubbing here would trade rule-82 actionability (a funding
/// shortfall must say how short) for a boundary this path never crosses.
#[derive(Debug, thiserror::Error)]
pub(crate) enum UnbondRequestError {
    /// This wallet runs no stake engine — it is not a staker, and the exit
    /// path does not exist here.
    #[error("this wallet is not a staker: no stake engine is running")]
    NotStaker,
    /// A stake-actor call refused — handle mint, or the assembly itself,
    /// whose arms carry the record-state causes (`UnbondNotReady`), the
    /// persona-binding refusal (`RecordPersonaMismatch`), and the
    /// funding/construction failures.
    #[error("stake engine: {0}")]
    Stake(#[from] StakeEngineError),
    /// The canonical P-lane floor fee could not be quoted — the daemon's
    /// answer was refused ([`FeeEstimatorError::DaemonFeeUnreasonable`]) or
    /// malformed. The exit pays the same single fee decision every P-lane
    /// spend quotes ([`p_lane_floor_fee`]); there is no caller override to
    /// fall back to.
    #[error("P-lane floor fee: {0}")]
    Fee(#[from] FeeEstimatorError),
    /// A **local** sealed-state read failed (the P-scan seal, the
    /// pending-post seal) — fail-closed, never an invented-empty set over a
    /// bad seal. This is our own store, so a failure here is internal
    /// corruption, not a reachable-daemon condition: distinct from
    /// [`DaemonUnreachable`], which the caller can retry.
    #[error("engine state read ({context}): {detail}")]
    State {
        /// Which read refused.
        context: &'static str,
        /// The store's own rendering of the failure.
        detail: String,
    },
    /// A daemon query needed to *prepare* the exit failed transiently — the
    /// dispatch-tip clock read here. Every such site is **before** the seal,
    /// so nothing was assembled or propagated and the caller may retry at
    /// will. Kept distinct from [`State`] (a local sealed-store read) so
    /// wallet-RPC can name a reachable daemon outage as retryable rather than
    /// an opaque internal fault (review-5).
    #[error("daemon unreachable ({context}): {detail}")]
    DaemonUnreachable {
        /// Which daemon query failed.
        context: &'static str,
        /// The transport's own rendering of the failure.
        detail: String,
    },
    /// The record-facts fetch failed on the persona-isolated transport. Its
    /// [`EmissionSourceError`] inner class decides the disposition at the
    /// façade: `Rpc`/`Status` are a reachable daemon outage (retryable),
    /// `Malformed` is an untrusted-response rejection (internal).
    #[error("bond record fetch: {0}")]
    Fetch(#[from] EmissionSourceError),
    /// The daemon holds no bond record for this persona — there is no exit
    /// to assess. Reported as its own condition rather than an error bucket:
    /// the remedy (this persona never bonded, or its record lives on a chain
    /// this daemon does not have) is not the remedy for any refusal below.
    #[error("the daemon holds no bond record for this persona; there is nothing to unbond")]
    NoBondRecord,
    /// A live pending exit already exists for this persona. One live exit
    /// per persona: the exit debits the whole bonded total, so a second is
    /// doomed by construction — wait for the pending exit to settle.
    #[error("a pending unbond exit already exists for this persona; one live exit per persona")]
    UnbondPending,
    /// A live pending **bond post** exists for this persona. Its connect
    /// will change the bonded total this exit must debit exactly, so an exit
    /// assembled now is doomed at the chain (`DebitNotFull`) — wait for the
    /// post to confirm, then exit against the settled balance. A courtesy
    /// fast-fail: the chain's exact-debit rule is the authoritative refusal.
    #[error(
        "a pending bond post is in flight for this persona; its connect changes the \
         bonded total the exit debits — wait for it to confirm, then unbond"
    )]
    BondPostPending,
    /// This exit's funding inputs are no longer selectable: a concurrent
    /// record now reserves one of them (`SealAdmission::InputRaced`), or a
    /// reservation was released between the pre-assembly snapshot and the
    /// seal (`SealAdmission::Stale`). Both refuse **before** sealing, and
    /// both take the same remedy: retry against a fresh snapshot.
    #[error(
        "this exit's funding inputs are no longer current — another live record \
         holds one, or a reservation was released mid-assembly; retry"
    )]
    InputRaced,
    /// The assembled bytes' dispatch failed at (or behind) the submit choke
    /// point; the exit was assembled and sealed, and its network fate is the
    /// error's to name. **What happened to the sealed record depends on the
    /// verdict class** (the dispatch site's disposition match):
    /// a definite first-send refusal — [`SubmitterError::RejectedTerminal`]
    /// or the pre-transport [`BroadcastSubmitError::PersonaMismatch`] — has
    /// already RELEASED it (the bytes were never admitted or relayed, so
    /// the record could never settle), and the caller may rebuild and retry
    /// at will; a retryable or ambiguous failure HOLDS it (the bytes may
    /// have propagated), and the one-live-exit lane stays shut until the
    /// record settles or the recovery slice (`docs/FOLLOWUPS.md`,
    /// dispatch-driver prune + resubmit) disposes of it.
    #[error("unbond broadcast: {0}")]
    Submit(#[from] BroadcastSubmitError),
}

impl UnbondRequestError {
    /// A fail-closed **local** sealed-state read refusal, context named.
    fn state(context: &'static str, detail: impl std::fmt::Display) -> Self {
        Self::State {
            context,
            detail: detail.to_string(),
        }
    }

    /// A transient **daemon** query failure (pre-seal), context named.
    fn daemon_unreachable(context: &'static str, detail: impl std::fmt::Display) -> Self {
        Self::DaemonUnreachable {
            context,
            detail: detail.to_string(),
        }
    }
}

/// Whether a first-send submit failure proves the bytes never propagated —
/// the release predicate for the seal the seam just took.
///
/// `true` exactly for the two classes whose contract says nothing reached
/// any pool or relay: a definite terminal daemon verdict
/// ([`SubmitterError::RejectedTerminal`] — "release-and-rebuild",
/// `DAEMON_SUBMIT_VERDICT.md` §2.5) and the pre-transport pairing refusal
/// ([`BroadcastSubmitError::PersonaMismatch`]). `false` for
/// [`SubmitterError::RejectedRetryable`] (a definite verdict whose remedy
/// PRESERVES the selection — the record must stay sealed for the
/// byte-identical resubmit) and [`SubmitterError::Ambiguous`] (no verdict;
/// the bytes may have propagated — Two Generals — so releasing could free
/// inputs a live transaction spends).
///
/// A pure function so the disposition is testable outcome-by-outcome
/// without driving the engine to the dispatch stage; the seam's tripwire
/// pins that the release call sits behind exactly this predicate.
fn released_on_first_send_failure(e: &BroadcastSubmitError) -> bool {
    matches!(
        e,
        BroadcastSubmitError::PersonaMismatch { .. }
            | BroadcastSubmitError::Submit(SubmitterError::RejectedTerminal { .. })
    )
}

#[allow(private_bounds)] // same Engine-trait privacy posture as submit_drain
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
    /// Assemble and dispatch the terminal `Unbond` exit for the persona at
    /// `p_slot` — the exit's request path (module docs).
    ///
    /// **Takes a slot, not the active persona, on purpose** — the anti-shape
    /// is `drain_to_principal`'s `active_persona()` resolution, which is
    /// right for a `P`-lane spend and would brick unbonding every
    /// retired-but-bonded persona here (see [`ClaimSourceFor`]'s note: the
    /// persona being exited is routinely *not* the active one).
    ///
    /// **Takes no fee** — the exit pays the canonical weight-priced P-lane
    /// floor ([`p_lane_floor_fee`], the same single fee decision the bond
    /// post and drain quote; §3.5 rule 3: a tunable fee on a `P`-attributed
    /// transaction is a wallet-fingerprint channel in a cleartext field).
    ///
    /// **Sweeps the persona's eligible funding pool, bounded at the vin
    /// headroom.** The exit is the terminal post, so it is the one
    /// constructor permitted to spend below the exit-fee reserve — that
    /// reserve exists to keep *this* transaction fundable — and the sweep
    /// consolidates the pool into the exit's two payout outputs (to `P`'s
    /// own base address), which is what the composed `unstake`'s
    /// decorrelated drain then sweeps to zero for the funded-gated
    /// retirement. A pool fragmented past
    /// [`MAX_RETENTION_FUNDING_INPUTS`](super::bond_assembly::MAX_RETENTION_FUNDING_INPUTS)
    /// (the consensus vin cap minus the exit's own `Unbond` vin) caps to
    /// the largest subset rather than refusing
    /// ([`SweepOverflowPolicy::CapLargest`]) — leftovers stay spendable for
    /// the drain's own capped passes. The sweep's shortfall bound is the
    /// fee beyond the released collateral (zero in practice: the debit is
    /// at least the bond floor); the actor's `verify_debit_funding` is the
    /// authoritative sufficiency check.
    ///
    /// `unbond_rpc` is the persona-isolated transport the record fetch rides
    /// (§7.4 pin: the principal's daemon session cannot be passed here — it
    /// does not implement the marker). `pruning_landed` is the shared SP-R0
    /// witness every funding-output spender takes; tests pass
    /// [`SpentRecordsDurablyPruned::for_test`].
    ///
    /// [`ClaimSourceFor`]: super::emission_source::ClaimSourceFor
    // The `dead_code` staging allow retired with PR-C: the production caller
    // the rule-21 note reserved landed as
    // [`StakeFacade::unstake`](super::unstake_facade), which calls this seam.
    pub(crate) async fn submit_unbond<T: PersonaIsolatedTransport>(
        self_arc: Arc<RwLock<Self>>,
        unbond_rpc: &T,
        p_slot: PSlot,
        pruning_landed: &SpentRecordsDurablyPruned,
    ) -> Result<UnbondReceipt, UnbondRequestError> {
        // Brief read: clone the actor handles + the ledger snapshot the
        // assembly needs (same discipline as submit_drain). The exit anchors
        // off the wallet's own synced tip, like a bond post.
        let (daemon, stake, curve_tree, pending_write_lock, chain_tip, snapshot) = {
            let g = self_arc.read().await;
            let stake = g.stake_handle().ok_or(UnbondRequestError::NotStaker)?;
            (
                g.daemon().clone(),
                stake,
                g.curve_tree.clone(),
                g.pending_write_lock.clone(),
                g.ledger.synced_height(),
                g.ledger.snapshot(),
            )
        };
        let block_hash_at = move |h: u64| snapshot.block_hash_at(h);
        let store = pending_post_store_for_engine(self_arc.clone(), pending_write_lock);

        // Canonical P-lane floor fee — the shared single fee decision (doc
        // comment). BOTH halves stay typed through the `Fee` arm so the RPC
        // layer keeps the -29109 (refused answer) vs -29102 (failed query)
        // remedy split: the query-transport failure was previously wrapped
        // as a `State` read error, which routed a reachable daemon-down
        // condition to -32603 (review-2).
        let fee = p_lane_floor_fee(
            daemon
                .get_fee_estimates()
                .await
                .map_err(|_| UnbondRequestError::Fee(FeeEstimatorError::DaemonUnreachable))?,
        )?;

        // Two independent reads, joined: the persona canonical id (a pure
        // actor projection over the resident keys — never a caller-supplied
        // id that could disagree with the slot; the same ask `submit_drain`
        // uses) and the seal basis. The basis is ONE ordered read — pending
        // block, then pscan seal (`load_seal_basis`: reading them
        // concurrently pairs stale funding with a current generation and
        // reopens the race the counter closes). The id stays concurrent
        // because it touches neither store.
        let (p_canonical_id, basis) = tokio::join!(
            stake.persona_canonical_id(p_slot),
            load_seal_basis(self_arc.clone(), &store),
        );
        let p_canonical_id = p_canonical_id?;
        let basis = basis.map_err(|e| match e {
            SealBasisError::Pending(e) => UnbondRequestError::state("reserved gindexes", e),
            SealBasisError::PScan(e) => UnbondRequestError::state("pscan state load", e),
        })?;

        // Borrowed from the loaded seal, like both sibling seams — no copy
        // of the wallet's whole funding history on a request path.
        let funding_records: &[PFundingOutputRecord] = basis
            .pscan()
            .map(shekyl_engine_state::pscan_state::PScanState::funding_outputs)
            .unwrap_or(&[]);
        let snapshot_generation = basis.generation();
        let reserved = basis.reserved();

        // Optimistic fast-fails, of two different strengths. One live exit
        // per persona IS authoritatively serialized — by `seal_unbond` under
        // the write lock at the seal below, which re-checks it atomically.
        // The bond-post condition is a COURTESY fast-fail only (`classify_seal`
        // never re-checks it; the chain's exact-debit rule is the
        // authoritative refusal): a post's connect changes the bonded total
        // this exit must debit exactly, so assembling now builds a post the
        // chain rejects — refusing early just saves the wasted proof work.
        let (live_exit, live_post) = store
            .read(|block| {
                (
                    block.has_live_unbond_for(&p_canonical_id),
                    block.has_live_post_for(&p_canonical_id),
                )
            })
            .await
            .map_err(|e| UnbondRequestError::state("pending-unbond read", e))?;
        if live_exit {
            return Err(UnbondRequestError::UnbondPending);
        }
        if live_post {
            return Err(UnbondRequestError::BondPostPending);
        }

        // The record facts, as ONE read view bound to the persona they were
        // requested for (the binding fetch — never the bare form, which
        // returns facts with no record of whose they are). `None` means the
        // daemon holds no bond record: nothing to exit, its own condition.
        let fetched = fetch_claim_source_for(unbond_rpc, p_canonical_id).await?;
        let record = UnbondRecordState::from_claim_source(&fetched)
            .ok_or(UnbondRequestError::NoBondRecord)?;

        // Readiness BEFORE any curve-tree work, with consensus's own
        // predicates in consensus's own order — so a zero-balance record
        // refuses as `NothingToUnbond` here rather than as a funding
        // shortfall three stages later. The actor re-runs the same function
        // on the same operands at assembly (`ensure_exit_ready` is called,
        // not restated, at both sites, so the two verdicts cannot drift).
        record.ensure_exit_ready().map_err(StakeEngineError::from)?;

        // Anchor + sweep + membership paths (the WI-2 shape). The sweep
        // body is the bond path's own (`sweep_funding_outputs`): everything
        // eligible, oldest-first, reserved and immature records excluded —
        // bounded at the vin headroom by the sweep's own overflow policy.
        // `required` is what the sources must cover beyond the released
        // collateral: the debit is a SOURCE on the exit (`sum(funding) +
        // debit == outputs + fee`), and the payout splits across TWO
        // outputs the tx builder refuses at zero, so the sources owe
        // `fee + 2` (one atomic unit per mandatory vout), not `fee` alone —
        // without the `+ 2`, a record within two units of the fee passes
        // every named check and then fails in the builder as a zero-amount
        // vout, an unnamed refusal on the one path rule 82 most cares about.
        let reference = anchored_reference_block(&curve_tree, chain_tip, block_hash_at)
            .await
            .map_err(StakeEngineError::from)?;
        let reference_height = BlockHeight::from_raw(reference.height.0);
        let required = AtomicUnits::from_raw(
            fee.to_raw()
                .saturating_add(2)
                .saturating_sub(record.bonded_total_atomic()),
        );
        // CapLargest: the exit owes no consume-everything invariant, so a
        // pool fragmented past the vin headroom caps to the largest subset
        // (see `SweepOverflowPolicy`) instead of refusing — leftovers go to
        // the retired persona's drain.
        let selection = sweep_funding_outputs(
            pruning_landed,
            funding_records,
            p_slot,
            reserved,
            required,
            reference_height,
            SweepOverflowPolicy::CapLargest,
        )
        .map_err(StakeEngineError::from)?;

        let assemble_inputs: Vec<AssembleInput> = selection
            .records
            .iter()
            .map(|r| AssembleInput {
                gindex: Gindex(r.gindex.to_raw()),
                output_key: r.output_key,
                commitment: r.commitment,
            })
            .collect();
        let paths = curve_tree
            .assemble_tx(reference, assemble_inputs)
            .await
            .map_err(|e| match e {
                // The one retryable path-assembly refusal, kept typed across
                // the boundary (same as the bond path).
                CurveTreeHandleError::Client(ClientError::OutputNotDrained { gindex, .. }) => {
                    BondAssemblyError::OutputNotYetDrained { gindex: gindex.0 }
                }
                other => BondAssemblyError::build("assemble_tx", format!("{other:?}")),
            })
            .map_err(StakeEngineError::from)?;
        if paths.len() != selection.records.len() {
            return Err(StakeEngineError::from(BondAssemblyError::build(
                "assemble_tx",
                format!(
                    "expected {} paths, got {}",
                    selection.records.len(),
                    paths.len()
                ),
            ))
            .into());
        }
        // Non-empty: the sweep refuses an empty eligible set structurally.
        let first = paths.first().ok_or_else(|| {
            StakeEngineError::from(BondAssemblyError::build(
                "assemble_tx",
                "assemble_tx returned no paths",
            ))
        })?;
        let tree_ctx = tree_context_from(&first.tree);
        let funding: Vec<FundingInputContext> = selection
            .records
            .into_iter()
            .zip(paths)
            .map(|(record, path)| FundingInputContext {
                record,
                leaf_chunk: path.leaf_chunk.iter().map(leaf_entry_from_chunk).collect(),
                c1_layers: path.c1_layers,
                c2_layers: path.c2_layers,
            })
            .collect();

        // Assemble inside the actor — the reply comes back unbroadcast; the
        // handler re-proves the record↔handle persona binding and re-runs
        // the readiness predicates before anything is built.
        let handle = stake.mint_handle(p_slot).await?;
        let assembled = stake
            .assemble_unbond(AssembleUnbond {
                handle,
                record,
                funding,
                tree_ctx,
                fee: fee.to_raw(),
            })
            .await?;

        // Persist-before-dispatch (module docs; pin P-2's sibling): seal the
        // exit record — bytes and funding reservation — and its Dispatched
        // transition in ONE mutation, before any network send. A crash
        // between this seal and the send below resumes as "maybe sent":
        // FUNDS-safe by construction (the reservation holds, nothing can
        // double-spend the inputs, and the stored bytes are the only thing
        // a future re-send may carry — pin P-2), but not yet LIVE — no
        // driver resubmits a reservation-observed record today, so the lane
        // stays held (stall-alarmed) until the shared dispatch-driver
        // recovery slice lands (module docs: the same registered residue
        // the claim and drain lanes carry). `at` reads the same named
        // daemon-claimed-tip clock as the bond/claim/drain dispatch.
        let dispatch_tip = daemon_claimed_tip(&daemon)
            .await
            .map_err(|e| UnbondRequestError::daemon_unreachable("dispatch tip", e))?;
        let persona = *assembled.bound_tx.persona();
        let sealed = PendingUnbond {
            persona,
            tx_bytes: assembled.bound_tx.bytes().to_vec(),
            funding_gindexes: assembled.funding_gindexes.clone(),
            state: PendingPostState::Pending,
        };
        let admission = store
            .mutate(move |block| {
                // One locked decision, shared with the bond-post/claim/drain
                // seams: persona dedup first (remedy: wait), then cross-kind
                // gindex overlap (remedy: retry), then the generation guard.
                let admission = block.seal_unbond(sealed, dispatch_tip, snapshot_generation);
                (admission == SealAdmission::Admit, admission)
            })
            .await
            .map_err(|e| UnbondRequestError::state("pending-unbond seal", e))?;
        match admission {
            SealAdmission::Admit => {}
            SealAdmission::PersonaLive => return Err(UnbondRequestError::UnbondPending),
            // Same remedy — retry against a fresh snapshot — so both map to
            // the one retryable refusal, whose message names every cause.
            SealAdmission::InputRaced | SealAdmission::Stale => {
                return Err(UnbondRequestError::InputRaced)
            }
        }

        // Dispatch through the pre-bound ① `Local` posture (the audited
        // posture→submitter choke point) — the privacy default: loopback on
        // the operator's own box.
        //
        // The failure disposition follows the submit taxonomy's own remedies
        // (`SubmitterError`, `DAEMON_SUBMIT_VERDICT.md` §2.5), and this seam
        // can apply the terminal one where the claim/drain seams cannot:
        // this is provably the record's FIRST and only send (the seal
        // happened in this call, and no driver resubmits unbonds), so a
        // definite `RejectedTerminal` verdict means the bytes were never
        // admitted to any pool and never relayed — the transaction CANNOT
        // confirm, and holding its reservation would brick the persona's
        // one-live-exit lane forever (`remove_settled` retires only records
        // whose inputs get SPENT). The sealed record is therefore released
        // (`remove_unbond`: byte-prune + reservation release + generation
        // bump in one seal) before the refusal propagates — release-and-
        // rebuild, the remedy the taxonomy names. A `PersonaMismatch`
        // refusal never reached a transport at all, so it releases too.
        // `RejectedRetryable` and `Ambiguous` keep the record live — a
        // retryable verdict preserves the selection by contract, and an
        // ambiguous one means the bytes MAY have propagated (Two Generals);
        // the driver's reservation settlement / stall alarm owns their fate.
        let submitter = BroadcastSubmitter::local(persona, Arc::new(daemon));
        match submitter.submit_bound(assembled.bound_tx.clone()).await {
            Ok(submit) => Ok(UnbondReceipt {
                unbond: assembled,
                submit,
            }),
            Err(e) => {
                if released_on_first_send_failure(&e) {
                    store
                        .mutate(|block| {
                            let removed = block.remove_unbond(&persona);
                            (removed.is_some(), ())
                        })
                        .await
                        .map_err(|e| UnbondRequestError::state("terminal-reject release", e))?;
                }
                Err(e.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use shekyl_types::PCanonicalId;

    use super::super::error::{AmbiguousErrorKind, RetryableRejectCause, TerminalErrorKind};
    use super::super::transaction_submitter::{BroadcastSubmitError, SubmitterError};
    use super::released_on_first_send_failure;

    /// The release predicate, outcome by outcome — the behavioral half of
    /// the terminal-reject disposition (the tripwire below pins that the
    /// seam's release call sits behind exactly this predicate). Releases
    /// ONLY the two never-propagated classes: a definite terminal verdict,
    /// and the pre-transport pairing refusal. A retryable verdict preserves
    /// the selection by contract; an ambiguous outcome may have propagated,
    /// and releasing it could free inputs a live transaction spends.
    #[test]
    fn only_never_propagated_failures_release_the_seal() {
        let terminal = BroadcastSubmitError::Submit(SubmitterError::RejectedTerminal {
            kind: TerminalErrorKind::DoubleSpend,
        });
        assert!(released_on_first_send_failure(&terminal));

        let mismatch = BroadcastSubmitError::PersonaMismatch {
            bytes_persona: PCanonicalId::from_bytes([1; 32]),
            submitter_persona: PCanonicalId::from_bytes([2; 32]),
        };
        assert!(released_on_first_send_failure(&mismatch));

        let retryable = BroadcastSubmitError::Submit(SubmitterError::RejectedRetryable {
            cause: RetryableRejectCause::StaleRoot,
        });
        assert!(
            !released_on_first_send_failure(&retryable),
            "a retryable verdict preserves the selection by contract — the record must hold"
        );

        let ambiguous = BroadcastSubmitError::Submit(SubmitterError::Ambiguous {
            kind: AmbiguousErrorKind::DaemonTimeout,
        });
        assert!(
            !released_on_first_send_failure(&ambiguous),
            "an ambiguous outcome may have propagated (Two Generals) — the record must hold"
        );
    }

    /// The seam's structural pins, `wire.rs`-tripwire style (drop the
    /// trailing test module so these needles cannot self-match; drop
    /// comment-only lines so doc mentions of forbidden tokens cannot trip
    /// the negative guards):
    ///
    /// 1. the record facts enter ONLY through the binding fetch
    ///    (`fetch_claim_source_for`) — never the bare
    ///    `fetch_emission_claim_source`, which returns facts with no record
    ///    of whose they are;
    /// 2. the fee is ONLY the shared canonical P-lane floor quote
    ///    (`p_lane_floor_fee`) — the fee-uniformity contract pin;
    /// 3. the funding sweep is ONLY the bond path's own body
    ///    (`sweep_funding_outputs`) — one sweep implementation, no local
    ///    re-derivation of eligibility;
    /// 4. dispatch rides ONLY the audited posture→submitter choke point
    ///    (`BroadcastSubmitter::local` + `submit_bound`) — never a bare
    ///    submitter and never a raw `DaemonClient` (T-DS-2);
    /// 5. persist-before-dispatch: the pending-unbond seal (`seal_unbond`)
    ///    textually precedes the network send.
    #[test]
    fn seam_routes_through_the_pipeline_and_the_submit_choke_point() {
        let production = include_str!("unbond_dispatch.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("unbond_dispatch.rs has a production section");
        // Code-only view: drop comment-only lines (`//`, `///`, `//!`).
        let code: String = production
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        let binding_fetch = "fetch_claim_source_for(";
        assert!(
            code.contains(binding_fetch),
            "the record facts must enter through the binding fetch"
        );
        let bare_fetch = "fetch_emission_claim_source(";
        assert!(
            !code.contains(bare_fetch),
            "the bare fetch loses the persona binding the exit path requires"
        );

        let fee_quote = "p_lane_floor_fee(";
        assert!(
            code.contains(fee_quote),
            "the fee must be the shared canonical P-lane floor quote"
        );

        let sweep = "sweep_funding_outputs(";
        assert!(
            code.contains(sweep),
            "the funding sweep must be the bond path's own body"
        );

        let choke_construct = "BroadcastSubmitter::local(";
        assert!(
            code.contains(choke_construct),
            "submitter construction must stay on the audited choke point"
        );
        let choke_submit = ".submit_bound(";
        assert!(
            code.contains(choke_submit),
            "dispatch must ride submit_bound's persona-pairing check"
        );
        let bare_submit = ".submit(";
        assert!(
            !code.contains(bare_submit),
            "no bare TransactionSubmitter::submit around the persona-pairing check (T-DS-2)"
        );
        let raw_client = "DaemonClient";
        assert!(
            !code.contains(raw_client),
            "the exit must not reach for a raw daemon client to broadcast (T-DS-2)"
        );

        // Terminal-reject release: the taxonomy's release-and-rebuild remedy
        // must stay wired — a definite first-send refusal releases the seal
        // it just took, or the one-live-exit lane bricks on a transaction
        // that cannot confirm.
        let terminal_arm = "RejectedTerminal";
        assert!(
            code.contains(terminal_arm),
            "the seam must classify the terminal verdict"
        );
        let release_call = ".remove_unbond(";
        assert!(
            code.contains(release_call),
            "a terminal first-send refusal must release the sealed record"
        );
        let guard = "if released_on_first_send_failure(&e) {";
        let guard_at = code
            .find(guard)
            .expect("the release must be gated on the tested predicate, not inlined");
        let release_at = code.find(release_call).expect("checked non-empty above");
        assert!(
            guard_at < release_at,
            "the release call must sit behind the predicate the behavioral test covers"
        );

        // Persist-before-dispatch ordering pin.
        let seal_call = ".seal_unbond(";
        let seal_at = code
            .find(seal_call)
            .expect("the seam must seal a pending unbond");
        let submit_at = code.find(choke_submit).expect("checked non-empty above");
        assert!(
            seal_at < submit_at,
            "the pending-unbond seal must precede the network send"
        );
    }
}
