// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CB-3 dispatch seam — the Engine-side emission-claim **request path**
//! (`EMISSION_CLAIM_BUILDER.md` §8 PR-4; the 2c-2b sibling).
//!
//! [`orchestrate_emission_claim`] is the production preparer+assembler and
//! deliberately returns its reply **unbroadcast** (CB-3: the builder never
//! self-schedules). This module is the other half of that routing: one
//! explicit claim intent in, one assembled claim dispatched through the
//! audited posture→submitter choke point
//! ([`BroadcastSubmitter::for_posture`] → [`submit_bound`]) out. Scheduling
//! policy — which epochs, when, batched how — stays external (the GF-4
//! seam grades cadence jointly with amount + holdings stratum; this method
//! fires once per caller intent, never on a loop of its own).
//!
//! Mirrors [`Engine::assemble_bond_post`](super::bond_orchestrator)'s shape:
//! a self-arc method that clones its actor handles under one brief read
//! lock, loads the sealed P-scan state and the live reservation set through
//! the same independent stores the bond path uses, and hands everything to
//! the pipeline. Secrets stay inside the stake actor (rule 36); this seam
//! touches public material only.
//!
//! ## Persist-before-dispatch
//!
//! The bond path's load-bearing invariant holds here too: no claim bytes
//! reach any submitter unless a sealed [`PendingEmissionClaim`] already
//! holds them (pin P-2's sibling). The record carries the fee-gindex
//! reservation (it feeds the shared
//! [`reserved_gindexes`](shekyl_engine_state::PendingPostBlock::reserved_gindexes)
//! union, so neither a bond sweep nor a second claim sweep can double-spend
//! the fee inputs while the claim is in flight) and the claimed epochs; one
//! live claim per persona is the in-flight epoch dedup. Retirement
//! (confirmation observe / terminal-reject prune, and byte-identical
//! resubmit) is the claim dispatch driver — the WI-3 sibling slice this
//! seam's record shape already serves.
//!
//! ## The claimant identity
//!
//! The pipeline's fetch and bond-post filter need the claimant's canonical
//! id **before** assembly, and the id is derivable only from the persona's
//! public identity key — actor-held state. The seam derives it from the
//! actor's read-only projection
//! ([`StakeEngineHandle::persona_identity`]) rather than a caller-supplied
//! id that could disagree with the slot (a mismatch would fetch one
//! persona's epochs and sign with another's keys — a claim the daemon
//! rejects, but a foot-gun the seam can simply not have). Deliberately
//! **not** an activation: a claim is a read-and-sign operation, and
//! moving the active slot on it would invalidate every in-flight
//! operation's handles and wipe a retired ephemeral persona as a side
//! effect of an unrelated request.
//!
//! [`submit_bound`]: BroadcastSubmitter::submit_bound

use std::sync::Arc;

use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pending_post_block::{PendingEmissionClaim, PendingPostState};
use shekyl_engine_state::pscan_state::{BondPostRecord, PFundingOutputRecord};
use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use super::bond_assembly::SpentRecordsDurablyPruned;
use super::claim_orchestrator::{
    orchestrate_emission_claim, ClaimAssemblyContext, ClaimOrchestrationError,
};
use super::prpc::PersonaIsolatedTransport;
use super::pscan::block_source::daemon_claimed_tip;
use super::pscan::start::{load_pscan_state_for_engine, pending_post_store_for_engine};
use super::signer::EngineSignerKind;
use super::stake_engine::{AssembledEmissionClaim, PSlot, StakeEngineError};
use super::traits::{DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine};
use super::transaction_submitter::{BroadcastSubmitError, BroadcastSubmitter, SubmitSuccess};
use super::Engine;

/// What one dispatched emission claim did: the assembled claim's public
/// facts plus the network verdict. Secrets never cross the boundary — the
/// contained [`PBoundBytes`](super::bond_assembly::PBoundBytes) redacts its
/// own `Debug`.
// Staging (not tolerated dead code, `15-deletion-and-debt.mdc`): the receipt's
// production reader is the RPC stake entry (rule-21, same retirement condition
// as `assemble_bond_post`'s allow); the PR-4 regtest e2e is the test consumer.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct EmissionClaimReceipt {
    /// The dispatched claim exactly as assembled (bytes, fee reservation,
    /// claimed/deferred epochs, total reward) — the actor's reply embedded
    /// whole, not field-restated.
    pub claim: AssembledEmissionClaim,
    /// The daemon's submit verdict (network-exposed / already mined).
    pub submit: SubmitSuccess,
}

/// Why the claim request refused, at any rung: before the pipeline (no
/// stake engine, actor refusals, state reads), inside it
/// ([`ClaimOrchestrationError`]), or at the dispatch choke point. Every arm
/// is caller-actionable per rule 82.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EmissionClaimRequestError {
    /// This wallet runs no stake engine — it is not a staker, and the claim
    /// path does not exist here.
    #[error("this wallet is not a staker: no stake engine is running")]
    NotStaker,
    /// A stake-actor call **outside** the assembly itself refused (handle
    /// mint or persona activation); assembly-time refusals arrive as
    /// [`Self::Claim`].
    #[error("stake engine: {0}")]
    Stake(#[from] StakeEngineError),
    /// The activated persona's public identity key failed canonical
    /// encoding — a corrupted resident key; fail closed.
    #[error("persona identity encoding: {0}")]
    Identity(shekyl_crypto_pq::CryptoError),
    /// A sealed-state read failed (the P-scan seal or the pending-post
    /// seal) — fail-closed, never an invented-empty set over a bad seal.
    #[error("engine state read ({context}): {detail}")]
    State {
        /// Which read refused.
        context: &'static str,
        /// The store's own rendering of the failure.
        detail: String,
    },
    /// A live pending emission claim already exists for this persona. One
    /// live claim per persona: the live record IS the in-flight fee
    /// reservation and epoch dedup — a second claim would re-derive and
    /// re-claim the same epochs. Wait for the pending claim to confirm or
    /// fail before re-claiming.
    #[error(
        "a pending emission claim already exists for this persona; one live claim per persona"
    )]
    ClaimPending,
    /// The claim pipeline refused (fetch, anchor, designation, sweep, path
    /// assembly, or the actor's assembly itself).
    #[error(transparent)]
    Claim(#[from] ClaimOrchestrationError),
    /// The assembled bytes' dispatch failed at (or behind) the submit
    /// choke point; the claim was assembled but its network fate is the
    /// error's to name.
    #[error("claim broadcast: {0}")]
    Submit(#[from] BroadcastSubmitError),
}

impl EmissionClaimRequestError {
    /// A fail-closed sealed-state read refusal, context named.
    fn state(context: &'static str, detail: impl std::fmt::Display) -> Self {
        Self::State {
            context,
            detail: detail.to_string(),
        }
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
    /// Assemble and dispatch one emission claim for the persona at `p_slot`
    /// — the CB-3 request path (module docs).
    ///
    /// `claim_rpc` is the persona-isolated transport the claim-source fetch
    /// rides (§7.4 pin: the principal's daemon session cannot be passed
    /// here — it does not implement the marker). `fee` is the claim tx's
    /// fee, funded from swept `ToKey` inputs (structurally mandatory: the
    /// reward is fully consumed by the loud vout). Go-live remains
    /// compile-blocked on a production [`SpentRecordsDurablyPruned`] mint
    /// (SP-R0), exactly as the bond path; tests pass
    /// [`SpentRecordsDurablyPruned::for_test`].
    // Staging (not tolerated dead code, `15-deletion-and-debt.mdc`): the
    // production caller is the RPC stake entry — the same rule-21 retirement
    // condition `assemble_bond_post` carries; the PR-4 regtest e2e (this
    // PR's commit 8) is the test consumer.
    #[allow(dead_code)]
    pub(crate) async fn submit_emission_claim<T: PersonaIsolatedTransport>(
        self_arc: Arc<RwLock<Self>>,
        claim_rpc: &T,
        p_slot: PSlot,
        fee: AtomicUnits,
        pruning_landed: &SpentRecordsDurablyPruned,
    ) -> Result<EmissionClaimReceipt, EmissionClaimRequestError> {
        // Brief read: clone the actor handles + the ledger snapshot the
        // pipeline needs (same discipline as assemble_bond_post).
        let (daemon, stake, curve_tree, pending_write_lock, snapshot) = {
            let g = self_arc.read().await;
            let stake = g
                .stake_handle()
                .ok_or(EmissionClaimRequestError::NotStaker)?;
            (
                g.daemon().clone(),
                stake,
                g.curve_tree.clone(),
                g.pending_write_lock.clone(),
                g.ledger.snapshot(),
            )
        };
        let block_hash_at = move |h: u64| snapshot.block_hash_at(h);
        let store = pending_post_store_for_engine(self_arc.clone(), pending_write_lock);

        // Three independent reads, joined: the claimant identity (a pure
        // actor projection — module docs; never a caller-supplied id that
        // could disagree with the slot), the sealed P-scan state, and the
        // live gindex reservations (outputs committed to in-flight bond
        // posts OR live claims must not be swept as claim fee inputs —
        // WI-2 F-1: an independent store over the engine-held write lock).
        let (identity, pscan_state, reserved) = tokio::join!(
            stake.persona_identity(p_slot),
            load_pscan_state_for_engine(self_arc.clone()),
            store.read(shekyl_engine_state::PendingPostBlock::reserved_gindexes),
        );
        let identity = identity?;
        let bond_id_bytes = identity
            .bond_id
            .to_canonical_bytes()
            .map_err(EmissionClaimRequestError::Identity)?;
        let p_canonical_id = p_canonical_id_from_hybrid_pubkey(&bond_id_bytes);

        // Sealed funding records + confirmed bond-post matches, borrowed
        // from the loaded seal (empty sets when no P-scan seal exists yet —
        // a wallet that never scanned has nothing to claim WITH, and the
        // pipeline refuses loudly downstream).
        let pscan_state =
            pscan_state.map_err(|e| EmissionClaimRequestError::state("pscan state load", e))?;
        let (funding_records, bond_posts): (&[PFundingOutputRecord], &[BondPostRecord]) =
            pscan_state
                .as_ref()
                .map(|s| (s.funding_outputs(), s.bond_post_matches()))
                .unwrap_or((&[], &[]));
        let reserved =
            reserved.map_err(|e| EmissionClaimRequestError::state("reserved gindexes", e))?;

        // Optimistic fast-fail on a live claim (one live claim per persona —
        // the in-flight epoch dedup). The AUTHORITATIVE serialization is
        // `push_claim` under the write lock at the seal below, which rejects
        // atomically even if two same-persona requests race past this gate;
        // this read only saves the wasted proof work.
        let already = store
            .read(|block| block.has_live_claim_for(&p_canonical_id))
            .await
            .map_err(|e| EmissionClaimRequestError::state("pending-claim read", e))?;
        if already {
            return Err(EmissionClaimRequestError::ClaimPending);
        }

        let handle = stake.mint_handle(p_slot).await?;

        // Assemble through the production pipeline — the reply comes back
        // unbroadcast (CB-3); routing it is the step below, not the builder's.
        let assembled = orchestrate_emission_claim(
            claim_rpc,
            handle,
            ClaimAssemblyContext {
                stake: &stake,
                tree: &curve_tree,
                pruning_landed,
                funding_records,
                bond_posts,
                reserved: &reserved,
                p_canonical_id,
                fee: fee.to_raw(),
            },
            block_hash_at,
        )
        .await?;

        // Persist-before-dispatch (module docs; pin P-2's sibling): seal the
        // claim record — bytes, fee reservation, claimed epochs — and its
        // Dispatched transition in ONE mutation, before any network send. A
        // crash after this seal resumes as "maybe sent", which is safe
        // because every resend is byte-identical. `at` reads the same named
        // daemon-claimed-tip clock as the bond dispatch (WI-3 R2-1).
        let dispatch_tip = daemon_claimed_tip(&daemon)
            .await
            .map_err(|e| EmissionClaimRequestError::state("dispatch tip", e))?;
        let persona = *assembled.bound_tx.persona();
        let sealed = PendingEmissionClaim {
            persona,
            tx_bytes: assembled.bound_tx.bytes().to_vec(),
            fee_gindexes: assembled.fee_gindexes.clone(),
            state: PendingPostState::Pending,
        };
        let pushed = store
            .mutate(move |block| {
                let ok = block.push_claim(sealed)
                    && block
                        .mark_claim_dispatched(&persona, dispatch_tip)
                        .is_some();
                (ok, ok)
            })
            .await
            .map_err(|e| EmissionClaimRequestError::state("pending-claim seal", e))?;
        if !pushed {
            return Err(EmissionClaimRequestError::ClaimPending);
        }

        // Dispatch through the pre-bound ① `Local` posture (the audited
        // posture→submitter choke point) — the privacy default: loopback on
        // the operator's own box, same as the WI-3 driver's
        // `LocalBondBroadcast`. The operator's explicit ② posture choice
        // plugs in via the 2c config-source slice, which swaps this call,
        // not this seam. A submit failure leaves the sealed record live —
        // the bytes may have reached the network, and the claim driver's
        // byte-identical resubmit / terminal-reject retire owns its fate.
        let submitter = BroadcastSubmitter::local(persona, Arc::new(daemon));
        let submit = submitter.submit_bound(assembled.bound_tx.clone()).await?;

        Ok(EmissionClaimReceipt {
            claim: assembled,
            submit,
        })
    }
}

#[cfg(test)]
mod tests {
    /// The seam's three structural pins, `wire.rs`-tripwire style (drop the
    /// trailing test module so these needles cannot self-match):
    ///
    /// 1. assembly enters ONLY through the production pipeline
    ///    (`orchestrate_emission_claim`) — never a direct actor
    ///    `assemble_emission_claim` ask that would skip the designation-
    ///    event seal's mint;
    /// 2. dispatch rides ONLY the audited posture→submitter choke point
    ///    (the pre-bound `BroadcastSubmitter::local` construction +
    ///    `submit_bound`) — never a bare submitter;
    /// 3. persist-before-dispatch: the pending-claim seal (`push_claim`)
    ///    textually precedes the network send — the invariant is exercised
    ///    at runtime by the store, but the ordering pin catches a refactor
    ///    that moves the seal after the submit.
    #[test]
    fn seam_routes_through_the_pipeline_and_the_submit_choke_point() {
        let seam = include_str!("claim_dispatch.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("claim_dispatch.rs has a production section");

        // Split needles so doc-comment mentions alone cannot satisfy them —
        // the live call sites must remain.
        let pipeline_call = concat!("orchestrate_emission", "_claim(");
        assert!(
            seam.contains(pipeline_call),
            "the seam must assemble only via the production pipeline"
        );
        let direct_ask = concat!(".assemble_emission", "_claim(");
        assert!(
            !seam.contains(direct_ask),
            "the seam must not ask the actor directly (the pipeline owns the mint)"
        );

        let choke_construct = concat!("BroadcastSubmitter::", "local(");
        assert!(
            seam.contains(choke_construct),
            "submitter construction must stay on the audited choke point"
        );
        let choke_submit = concat!(".submit_", "bound(");
        assert!(
            seam.contains(choke_submit),
            "dispatch must ride submit_bound's pairing check"
        );
        // A plain literal is safe here: the split above already excluded this
        // test module from the searched text, so the needle cannot self-match.
        let bare_submit = ".submit(";
        assert!(
            !seam.contains(bare_submit),
            "no bare TransactionSubmitter::submit around the pairing check"
        );

        // Persist-before-dispatch ordering pin.
        let seal_call = concat!(".push_", "claim(");
        let seal_at = seam
            .find(seal_call)
            .expect("the seam must seal a pending claim");
        let submit_at = seam.find(choke_submit).expect("checked non-empty above");
        assert!(
            seal_at < submit_at,
            "the pending-claim seal must precede the network send"
        );
    }
}
