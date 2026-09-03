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
//! ## What this seam does NOT lift
//!
//! `pub(crate)`, no RPC method, no CLI verb: the reachability gate on the
//! exit lane (`docs/api/wallet_rpc.yaml`, RESERVED `unstake`) is **narrowed,
//! not lifted** — the dispatch seam now exists, and its only caller outside
//! this crate's tests is nothing at all. Lifting the gate is PR-C's composed
//! `unstake` verb (post + a *decorrelated* drain), which is also the
//! rule-21 retirement condition for the staging allow on [`Engine::submit_unbond`].
//!
//! [`submit_bound`]: BroadcastSubmitter::submit_bound

use std::sync::Arc;

use shekyl_curve_tree::{AssembleInput, ClientError, Gindex};
use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pending_post_block::{PendingPostState, PendingUnbond, SealAdmission};
use shekyl_engine_state::pscan_state::PFundingOutputRecord;
use shekyl_tx_builder::MAX_INPUTS;
use shekyl_types::BlockHeight;
use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use super::bond_assembly::{
    sweep_funding_outputs, BondAssemblyError, FundingInputContext, FundingSelection,
    SpentRecordsDurablyPruned,
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
// Staging (not tolerated dead code, `15-deletion-and-debt.mdc`): the receipt's
// production reader is PR-C's composed `unstake` verb — the same rule-21
// retirement condition as `submit_unbond`'s allow; the daemon-walk regtest e2e
// is the test consumer.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct UnbondReceipt {
    /// The dispatched exit exactly as assembled (bytes + funding
    /// reservation) — the actor's reply embedded whole, not field-restated.
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
    /// A sealed-state read failed (the P-scan seal, the pending-post seal,
    /// or the daemon tip/fee query behind them) — fail-closed, never an
    /// invented-empty set over a bad seal.
    #[error("engine state read ({context}): {detail}")]
    State {
        /// Which read refused.
        context: &'static str,
        /// The store's own rendering of the failure.
        detail: String,
    },
    /// The record-facts fetch failed on the persona-isolated transport.
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
    /// error's to name. The sealed record stays live — the bytes may have
    /// reached the network.
    #[error("unbond broadcast: {0}")]
    Submit(#[from] BroadcastSubmitError),
}

impl UnbondRequestError {
    /// A fail-closed sealed-state read refusal, context named.
    fn state(context: &'static str, detail: impl std::fmt::Display) -> Self {
        Self::State {
            context,
            detail: detail.to_string(),
        }
    }
}

/// Cap the exit's sweep at the consensus per-tx input limit
/// ([`MAX_INPUTS`], CEN-I4 — a limit the curve-tree actor also enforces, so
/// an uncapped selection would surface as an opaque `assemble_tx` refusal
/// instead of assembling at all).
///
/// The bond sweep's "consume everything" rule does NOT carry to the exit:
/// that rule is GF-4b's structural-emptiness argument on the **entry** path
/// (nothing raw may survive backing-eligible), while the exit is the
/// terminal post — records left behind by the cap stay spendable and the
/// composed `unstake`'s drain sweeps a retired persona to zero (in as many
/// passes as its own input cap needs). So a fragmented pool (>8 eligible
/// records) caps to a subset rather than refusing the exit and telling the
/// user to consolidate, which would be protocol knowledge (rule 81) on the
/// one verb that must not demand any.
///
/// The subset is the [`MAX_INPUTS`] **largest** records (ties broken
/// `(height, gindex)` ascending — fully deterministic), then restored to
/// the sweep's oldest-first order for the wire. Largest-first for the same
/// reason the drain planner selects largest-first, plus two exit-specific
/// ones: the greedy-max subset covers `required` whenever ANY subset of
/// that size does — an oldest-first truncation could select eight dust
/// records, refuse `InsufficientFunding`, and then refuse identically on
/// every retry while a single newer record would have covered it — and the
/// terminal post should carry out the most value per transaction, leaving
/// the least behind for the drain's own passes.
///
/// The sweep checked sufficiency against the FULL eligible total, so the
/// capped subset must be re-checked: refusing here (fail-closed, named)
/// beats assembling a post the actor then refuses — and because the subset
/// is greedy-max, that refusal now means no admissible subset covers.
/// `required` is normally zero (the released collateral covers the fee), so
/// the re-check bites only in the slashed-to-dust corner.
fn cap_exit_sweep(
    selection: &mut FundingSelection,
    required: AtomicUnits,
) -> Result<(), BondAssemblyError> {
    if selection.records.len() <= MAX_INPUTS {
        return Ok(());
    }
    // Largest-first selection (ties oldest-first), then oldest-first order.
    // `sort_by` is stable, but the comparator is total anyway: distinct
    // records have distinct gindexes.
    selection.records.sort_by(|a, b| {
        b.amount
            .cmp(&a.amount)
            .then(a.height.cmp(&b.height))
            .then(a.gindex.cmp(&b.gindex))
    });
    selection.records.truncate(MAX_INPUTS);
    selection.records.sort_by_key(|r| (r.height, r.gindex));
    let mut total = AtomicUnits::ZERO;
    for record in &selection.records {
        total = total
            .checked_add(record.amount)
            .ok_or(BondAssemblyError::AmountOverflow)?;
    }
    selection.total = total;
    if total < required {
        return Err(BondAssemblyError::InsufficientFunding {
            available: total.to_raw(),
            required: required.to_raw(),
        });
    }
    Ok(())
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
    /// **Sweeps the persona's whole eligible funding pool.** The exit is the
    /// terminal post, so it is the one constructor permitted to spend below
    /// the exit-fee reserve — that reserve exists to keep *this* transaction
    /// fundable — and sweeping everything consolidates the pool into the
    /// exit's two payout outputs (to `P`'s own base address), which is what
    /// the composed `unstake`'s decorrelated drain then sweeps to zero for
    /// the funded-gated retirement. The sweep's shortfall bound is the fee
    /// beyond the released collateral (zero in practice: the debit is at
    /// least the bond floor); the actor's `verify_debit_funding` is the
    /// authoritative sufficiency check.
    ///
    /// `unbond_rpc` is the persona-isolated transport the record fetch rides
    /// (§7.4 pin: the principal's daemon session cannot be passed here — it
    /// does not implement the marker). `pruning_landed` is the shared SP-R0
    /// witness every funding-output spender takes; tests pass
    /// [`SpentRecordsDurablyPruned::for_test`].
    ///
    /// [`ClaimSourceFor`]: super::emission_source::ClaimSourceFor
    // Staging (not tolerated dead code, `15-deletion-and-debt.mdc`): the
    // production caller is PR-C's composed `unstake` verb (wallet-RPC
    // RESERVED entry, `docs/api/wallet_rpc.yaml`) — the rule-21 retirement
    // condition for this allow; the daemon-walk regtest e2e
    // (`e2e_unbond_accepted_and_connected`) is the test consumer.
    #[allow(dead_code)]
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

        // Canonical P-lane floor fee — the shared single fee decision
        // (doc comment); typed refusal preserved for the RPC layer's
        // -29109 vs -29102 remedy split.
        let fee = p_lane_floor_fee(
            daemon
                .get_fee_estimates()
                .await
                .map_err(|e| UnbondRequestError::state("fee estimates", e.into()))?,
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
        // then capped at the consensus input limit (`cap_exit_sweep`).
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
        let mut selection = sweep_funding_outputs(
            pruning_landed,
            funding_records,
            p_slot,
            reserved,
            required,
            reference_height,
        )
        .map_err(StakeEngineError::from)?;
        cap_exit_sweep(&mut selection, required).map_err(StakeEngineError::from)?;

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
        // transition in ONE mutation, before any network send. A crash after
        // this seal resumes as "maybe sent", which is safe because every
        // resend is byte-identical. `at` reads the same named
        // daemon-claimed-tip clock as the bond/claim/drain dispatch.
        let dispatch_tip = daemon_claimed_tip(&daemon)
            .await
            .map_err(|e| UnbondRequestError::state("dispatch tip", e))?;
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
                let never_propagated = matches!(
                    e,
                    BroadcastSubmitError::PersonaMismatch { .. }
                        | BroadcastSubmitError::Submit(SubmitterError::RejectedTerminal { .. })
                );
                if never_propagated {
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
    use shekyl_engine_state::pscan_state::PFundingOutputRecord;
    use shekyl_tx_builder::MAX_INPUTS;
    use shekyl_types::{GlobalOutputIndex, PSlot};
    use shekyl_units::AtomicUnits;

    use super::super::bond_assembly::{BondAssemblyError, FundingSelection};
    use super::cap_exit_sweep;

    fn rec(gindex: u64, amount: u64) -> PFundingOutputRecord {
        PFundingOutputRecord {
            p_slot: PSlot::from_raw(0),
            index_in_transaction: 0,
            gindex: GlobalOutputIndex::from_raw(gindex),
            output_key: [0u8; 32],
            commitment: [0u8; 32],
            ciphertext_x25519: [0u8; 32],
            ciphertext_ml_kem: Vec::new(),
            amount: AtomicUnits::from_raw(amount),
            height: shekyl_types::BlockHeight::from_raw(gindex),
            epoch: shekyl_types::SettlementEpoch::from_raw(0),
            spendable_height: shekyl_types::BlockHeight::from_raw(0),
            lineage: shekyl_engine_state::pscan_state::MintLineageOutput::ExternalTransfer,
        }
    }

    fn selection_of(n: u64) -> FundingSelection {
        let records: Vec<_> = (0..n).map(|g| rec(g, 10)).collect();
        let total = AtomicUnits::from_raw(10 * n);
        FundingSelection { records, total }
    }

    /// A fragmented pool caps to a [`MAX_INPUTS`]-record subset instead of
    /// refusing the exit — the consensus input limit would otherwise
    /// surface as an opaque `assemble_tx` refusal (the curve-tree actor
    /// enforces the same bound). Equal amounts: the tie-break keeps the
    /// oldest, and the kept subset stays in wire (oldest-first) order.
    #[test]
    fn a_fragmented_pool_caps_to_max_inputs_ties_oldest() {
        let mut selection = selection_of(MAX_INPUTS as u64 + 3);
        cap_exit_sweep(&mut selection, AtomicUnits::ZERO).expect("cap admits");
        assert_eq!(selection.records.len(), MAX_INPUTS);
        assert_eq!(
            selection.records[0].gindex,
            GlobalOutputIndex::from_raw(0),
            "equal amounts tie-break oldest-first"
        );
        assert!(
            selection
                .records
                .windows(2)
                .all(|w| w[0].gindex < w[1].gindex),
            "the kept subset must be restored to oldest-first wire order"
        );
        assert_eq!(
            selection.total,
            AtomicUnits::from_raw(10 * MAX_INPUTS as u64),
            "the total must be re-summed over the capped subset, not left stale"
        );
    }

    /// The selection under the cap is largest-first, so a `required` that
    /// any admissible subset covers IS covered — eight old dust records
    /// must not shadow the one newer record that funds the exit (an
    /// oldest-first truncation refused this exact shape forever, since
    /// every retry re-selected the same dust).
    #[test]
    fn a_covering_record_is_selected_over_older_dust() {
        let mut records: Vec<_> = (0..MAX_INPUTS as u64 + 2).map(|g| rec(g, 1)).collect();
        // The newest record is the only one that can cover `required`.
        let whale_gindex = MAX_INPUTS as u64 + 2;
        records.push(rec(whale_gindex, 1_000));
        let total = AtomicUnits::from_raw(MAX_INPUTS as u64 + 2 + 1_000);
        let mut selection = FundingSelection { records, total };
        cap_exit_sweep(&mut selection, AtomicUnits::from_raw(900)).expect("the whale covers");
        assert_eq!(selection.records.len(), MAX_INPUTS);
        assert!(
            selection
                .records
                .iter()
                .any(|r| r.gindex == GlobalOutputIndex::from_raw(whale_gindex)),
            "largest-first selection must include the covering record"
        );
        assert!(
            selection.total >= AtomicUnits::from_raw(900),
            "the capped subset must cover required when any subset does"
        );
    }

    /// A selection at or under the cap passes through untouched.
    #[test]
    fn an_uncapped_selection_is_untouched() {
        let mut selection = selection_of(MAX_INPUTS as u64);
        let before_total = selection.total;
        cap_exit_sweep(&mut selection, AtomicUnits::ZERO).expect("cap admits");
        assert_eq!(selection.records.len(), MAX_INPUTS);
        assert_eq!(selection.total, before_total);
    }

    /// The sweep's sufficiency check ran against the FULL eligible total,
    /// so the capped subset must be re-checked — a shortfall the cap
    /// creates refuses by name (fail-closed), never assembles.
    #[test]
    fn a_shortfall_created_by_the_cap_refuses_by_name() {
        let mut selection = selection_of(MAX_INPUTS as u64 + 3);
        // Full total (110) covers; capped total (80) does not.
        let required = AtomicUnits::from_raw(10 * MAX_INPUTS as u64 + 5);
        let err = cap_exit_sweep(&mut selection, required).expect_err("must refuse");
        assert!(
            matches!(
                err,
                BondAssemblyError::InsufficientFunding {
                    available,
                    required: r,
                } if available == 10 * MAX_INPUTS as u64 && r == required.to_raw()
            ),
            "got {err:?}"
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
