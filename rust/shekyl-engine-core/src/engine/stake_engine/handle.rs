// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `StakeEngineHandle` capability object.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use kameo::actor::{ActorRef, Spawn};
use kameo::error::SendError;
use shekyl_archival_retention::HoldingsDescriptor;
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_scanner::ScannableBlock;
#[cfg(feature = "gf7-hooks")]
use shekyl_standoff::gf7::NoOpObserver;
use shekyl_tor::onion_identity::OnionIdentity;
use shekyl_tx_builder::TreeContext;
use shekyl_types::PCanonicalId;

use super::actor::StakeEngine;
use super::bond::{AssembleBond, AssembledBondPost};
use super::claim::{AssembleEmissionClaim, AssembledEmissionClaim};
use super::persona::{
    ActivatePersona, ActivePersona, ActivePersonaReceiveAddress, BondPostPlacement,
    MintPersonaHandle, PersonaIdentityOf, PersonaOnionIdentityOf, PlanBondPost,
};
use super::retire::{ProjectPersonaCanonicalId, RetireBondedPersona};
use shekyl_archival_bond_builder::UnbondVin;

use super::types::*;
use super::unbond::AssembleUnbond;
use crate::engine::bond_assembly::FundingInputContext;
use crate::engine::drain_assembly::{AssembleDrain, AssembledDrain};
use crate::engine::pscan::scan_step::{BlockRange, FundingOutputMatch, ScanStep, ScanStepResult};
use crate::engine::{Network, ShekylAddress};

// ---------------------------------------------------------------------------

/// `Clone` handle the orchestrator holds in place of an inline `StakeEngine`.
///
/// **Capability object.** Holding a `StakeEngineHandle` *is* the authority to
/// drive the staking actor. It is `pub(crate)` and never exported to the RPC
/// tier; that confinement is the control, made a compile-time guarantee by the
/// visibility bound (mirrors [`KeyEngineHandle`](super::key_actor::KeyEngineHandle)).
#[derive(Clone)]
pub(crate) struct StakeEngineHandle {
    /// Strong reference to the stake actor's mailbox.
    pub(crate) actor: ActorRef<StakeEngine>,
}

impl StakeEngineHandle {
    /// Spawn the StakeEngine over the pre-derived derive-forward set.
    ///
    /// The bundles were derived at `assemble()` while the master seed was
    /// transiently borrowed; the seed is dropped there and never reaches the
    /// actor (Model D). `bonded` tags which held slots carry a live bond
    /// (activation never wipes them); `active` is the initial current slot.
    ///
    /// **Runtime hosting — require-ambient.** A [`StakeEngine`] is an async
    /// task; spawning one *requires* a Tokio runtime. `spawn` asserts an ambient
    /// runtime is present rather than hosting an engine-owned nested runtime
    /// (the drop-panic / abandoned-task hazard documented for
    /// [`KeyEngineHandle::spawn`](super::key_actor::KeyEngineHandle::spawn)).
    ///
    /// # Panics
    ///
    /// Panics if called with no ambient Tokio runtime; the message names the fix.
    pub(crate) fn spawn(
        bundles: BTreeMap<PSlot, ArchivalPKeys>,
        bonded: BTreeSet<PSlot>,
        active: Option<PSlot>,
    ) -> Self {
        assert!(
            tokio::runtime::Handle::try_current().is_ok(),
            "StakeEngineHandle::spawn requires an ambient Tokio runtime: the \
             StakeEngine is an async task and must be spawned inside a runtime. \
             Tests must use #[tokio::test] (or wrap the call in one). See \
             ARCHIVAL_BOND_CONSTRUCTION.md §10.1."
        );

        let actor = StakeEngine::spawn(StakeEngineArgs {
            bundles,
            bonded,
            active,
            // A non-test `conformance` build always grades the real OsRng adapter
            // (no field); in `test + conformance` the default is `Skip` so
            // unrelated stake tests are not flaked by the grade. The dedicated S6
            // tests build args directly with their mode.
            #[cfg(all(test, feature = "conformance"))]
            self_cert: TestSelfCert::Skip,
            // GF-7 hooks-spec §6.1: production construction injects the no-op.
            // A recording observer enters only via a direct `StakeEngineArgs`
            // (sim/tests), never through this spawn path.
            #[cfg(feature = "gf7-hooks")]
            observer: Box::new(NoOpObserver),
        });
        Self { actor }
    }

    /// S6 — block until the actor's `on_start` self-cert completes, returning the
    /// **structured** [`StakeSelfCertFailure`] on failure (the grade's
    /// `CertifyReport` is preserved, not stringified). Conformance build only —
    /// the **eager** observation path ([`ActorRef::wait_for_startup_result`], S6
    /// plan §2.1). `Ok(())` means the actor started and the CSPRNG graded
    /// conformant.
    #[cfg(feature = "conformance")]
    pub(crate) async fn wait_for_self_cert(
        &self,
    ) -> Result<(), crate::engine::error::StakeSelfCertFailure> {
        use super::actor::StakeEngineStartError;
        use crate::engine::error::StakeSelfCertFailure;
        use kameo::error::HookError;
        match self.actor.wait_for_startup_result().await {
            Ok(()) => Ok(()),
            // Match the inner error generically rather than by variant, so a
            // future `StakeEngineStartError` variant (2d-1's always-on startup
            // failures) does not force a refactor here. Today the only variant is
            // `RngSelfCertFailed`, whose `CertifyReport` is kept structured; any
            // other (future) start error renders via `Debug`.
            Err(HookError::Error(start_err)) => match start_err {
                StakeEngineStartError::RngSelfCertFailed(report) => {
                    Err(StakeSelfCertFailure::NonConformant(report))
                }
                #[allow(unreachable_patterns)]
                other => Err(StakeSelfCertFailure::StartupFailed(format!("{other:?}"))),
            },
            Err(HookError::Panicked(p)) => Err(StakeSelfCertFailure::StartupFailed(format!(
                "on_start panicked (likely the OS entropy source failed mid-draw): {p:?}"
            ))),
        }
    }

    /// Mint an operation-scoped [`PersonaHandle`] for `p_slot` (the single
    /// held-set membership check). Errors with
    /// [`StakeEngineError::LookaheadExhausted`] when the slot is not held.
    pub(crate) async fn mint_handle(
        &self,
        p_slot: PSlot,
    ) -> Result<PersonaHandle, StakeEngineError> {
        self.actor
            .ask(MintPersonaHandle { p_slot })
            .await
            .map_err(collapse_send_error)
    }

    /// Project the public canonical id of held slot `p_slot` (no activation,
    /// no rotation side effects — an identity read for the first-stake
    /// W2/confirmed split and reconcile lookups).
    pub(crate) async fn persona_canonical_id(
        &self,
        p_slot: PSlot,
    ) -> Result<PCanonicalId, StakeEngineError> {
        self.actor
            .ask(ProjectPersonaCanonicalId { p_slot })
            .await
            .map_err(collapse_send_error)
    }

    /// Activate the persona named by `handle` and return its public identity.
    /// Activation (with ephemeral-only wipe) when a different slot is active.
    #[allow(dead_code)] // 2c-2a: the production caller lands with the assemble wiring; today's callers are all `cfg(test)`.
    pub(crate) async fn activate_persona(
        &self,
        handle: PersonaHandle,
    ) -> Result<PersonaIdentity, StakeEngineError> {
        self.actor
            .ask(ActivatePersona { handle })
            .await
            .map_err(collapse_send_error)
    }

    /// The public identity of the currently-active persona, or `None` when idle.
    pub(crate) async fn active_persona(&self) -> Result<Option<PersonaIdentity>, StakeEngineError> {
        self.actor
            .ask(ActivePersona)
            .await
            .map_err(collapse_send_error)
    }

    /// The currently-active persona's public [`ShekylAddress`], or `None` when
    /// idle — the funding side of `Engine::stake_in`. The reply is structurally
    /// public-only (rule 36); `network` is the principal's network.
    pub(crate) async fn active_persona_receive_address(
        &self,
        network: Network,
    ) -> Result<Option<ShekylAddress>, StakeEngineError> {
        self.actor
            .ask(ActivePersonaReceiveAddress { network })
            .await
            .map_err(collapse_send_error)
    }

    /// The public identity of the held persona at `p_slot` — a pure
    /// projection: no activation, no retired-slot wipe, no generation advance
    /// (see [`PersonaIdentityOf`]).
    pub(crate) async fn persona_identity(
        &self,
        p_slot: PSlot,
    ) -> Result<PersonaIdentity, StakeEngineError> {
        self.actor
            .ask(PersonaIdentityOf { p_slot })
            .await
            .map_err(collapse_send_error)
    }

    /// The onion serving credential for the held persona at `p_slot` — the
    /// SH-2b handoff into `PersonaServingHost`.
    ///
    /// Yields an `OnionIdentity` and never the seed: see
    /// [`PersonaOnionIdentityOf`] for the §7.2(iii) custody ruling that decides
    /// which secret is allowed to cross into a serving role.
    pub(crate) async fn persona_onion_identity(
        &self,
        p_slot: PSlot,
    ) -> Result<OnionIdentity, StakeEngineError> {
        self.actor
            .ask(PersonaOnionIdentityOf { p_slot })
            .await
            .map_err(collapse_send_error)
    }

    /// Construct a JoinMarket archival bond-post vin for the persona named by
    /// `handle` (Bond-PR 2c-2b), returning the constructed vin **paired with**
    /// its block-timed placement plan ([`BondPostPlacement`]). No on-vin
    /// signature (SA-2b); surface-A signing is the assemble path.
    ///
    /// Consumes both `handle` (operation-scoped capability, typed contract #2)
    /// and `ticket` (persist-before-use witness, typed contract #1) by value,
    /// so "construct before persist" and "construct for an unheld persona" are
    /// uncallable.
    ///
    /// See [`PlanBondPost`] for the full caller workflow.
    ///
    /// # Errors
    ///
    /// - [`StakeEngineError::StakeActorUnavailable`] — actor stopped (terminal).
    /// - [`StakeEngineError::StaleHandle`] — the handle is from a prior
    ///   generation *or* its slot is no longer in the held set. Both collapse to
    ///   `StaleHandle` in `validate_handle` (a wipe advances the generation, so a
    ///   stale-generation handle and a no-longer-held slot are the same failure).
    ///   `LookaheadExhausted` is *not* reachable here — it is a `mint_handle`
    ///   error; construction only validates an already-minted handle.
    /// - [`StakeEngineError::SlotMismatch`] — `handle.p_slot != ticket.p_slot`.
    /// - [`StakeEngineError::RngSourceFailed`] — OS entropy source unavailable.
    /// - [`StakeEngineError::RngDegeneracy`] — timing draw degenerate; retry.
    /// - [`StakeEngineError::BondBuild`] — bond construction failed (see inner).
    #[allow(dead_code)] // 2c-2b: the production caller lands with the request path; today's callers are all `cfg(test)`.
    pub(crate) async fn plan_bond_post(
        &self,
        handle: PersonaHandle,
        ticket: crate::engine::stake_persist::PersistedBondTicket,
        holdings: HoldingsDescriptor,
    ) -> Result<BondPostPlacement, StakeEngineError> {
        self.actor
            .ask(PlanBondPost {
                handle,
                ticket,
                holdings,
            })
            .await
            .map_err(collapse_send_error)
    }

    /// Ask the actor to assemble the full, broadcast-ready JoinMarket bond
    /// (`AssembleBond`). Engine-side caller is [`Engine::assemble_bond_post`]
    /// (WI-2 §3.3), so this carries no suppression. Go-live still needs
    /// **both** SP-R0 / 2d-1 pruning **and** the RPC stake entry — neither
    /// alone (half (a) landed 2026-07-18 with SP-R0 arm #1; half (b) remains).
    pub(crate) async fn assemble_bond(
        &self,
        handle: PersonaHandle,
        ticket: crate::engine::stake_persist::PersistedBondTicket,
        holdings: HoldingsDescriptor,
        funding: Vec<FundingInputContext>,
        tree_ctx: TreeContext,
        fee: u64,
    ) -> Result<AssembledBondPost, StakeEngineError> {
        self.actor
            .ask(AssembleBond {
                handle,
                ticket,
                holdings,
                funding,
                tree_ctx,
                fee,
            })
            .await
            .map_err(collapse_send_error)
    }

    /// Ask the actor to assemble the `Unbond` post's vin ([`AssembleUnbond`]).
    ///
    /// **`pub(crate)`, and deliberately not wired to any RPC method or CLI verb.**
    /// The gate on this lane is reachability, not existence: the producer has to
    /// exist before slice 3's regtest walk can exercise the retire path at all,
    /// but nothing on the exit path becomes user-callable until that walk has
    /// observed the wipe, the funded gate, and the seal-then-act crash ordering.
    /// This is the engine-internal seam the walk drives — and the seam an
    /// actor-level test uses to prove the handler's persona-binding refusal is
    /// reachable, which a unit test on `UnbondRecordState` cannot do.
    #[allow(dead_code)] // PR-P4 slice 2b: the production caller lands with the walk; today's caller is `cfg(test)`.
    pub(crate) async fn assemble_unbond(
        &self,
        msg: AssembleUnbond,
    ) -> Result<UnbondVin, StakeEngineError> {
        self.actor.ask(msg).await.map_err(collapse_send_error)
    }

    /// Assemble the full, broadcast-ready emission-claim transaction
    /// ([`AssembleEmissionClaim`]) — the emission sibling of the bond
    /// assembly path. Return-bytes-only: broadcast timing is the GF-4
    /// dispatch seam, outside this builder.
    pub(crate) async fn assemble_emission_claim(
        &self,
        msg: AssembleEmissionClaim,
    ) -> Result<AssembledEmissionClaim, StakeEngineError> {
        self.actor.ask(msg).await.map_err(collapse_send_error)
    }

    /// Assemble the full, broadcast-ready `P`→principal drain transaction
    /// ([`AssembleDrain`], F-D2 DS-PR-1) — the value-out sibling of the bond
    /// and emission assembly paths. Return-bytes-only: broadcast timing and
    /// the pending-drain record are the orchestrator's (DS-PR-2), outside this
    /// builder.
    ///
    /// The assembly is wired, so this carries no suppression; the Engine
    /// orchestrator entry (DS-PR-2) and the RPC drain entry are the remaining
    /// consumers (rule-21).
    pub(crate) async fn assemble_drain(
        &self,
        msg: AssembleDrain,
    ) -> Result<AssembledDrain, StakeEngineError> {
        self.actor.ask(msg).await.map_err(collapse_send_error)
    }

    /// Run one bounded, offloaded P-scan step over `blocks` (SP-3/SP-5).
    ///
    /// The actor dual-extracts with the bonded union's keys — view-key funding
    /// (per-epoch deltas) + cleartext bond-post matches — and returns **only
    /// public** [`ScanStepResult`]; `view_sk` never crosses the boundary. The
    /// driving P-scan task (PR-B) calls this once per bounded batch, advancing the
    /// cursor over the returned range. `blocks[i]` must be the block at
    /// `range.start + i`.
    pub(crate) async fn scan_step(
        &self,
        range: BlockRange,
        blocks: Vec<ScannableBlock>,
        held_funding: Arc<[FundingOutputMatch]>,
    ) -> Result<ScanStepResult, StakeEngineError> {
        self.actor
            .ask(ScanStep {
                range,
                blocks,
                held_funding,
            })
            .await
            .map_err(collapse_send_error)
    }

    /// Retire a now-terminal bonded persona from the scan union (DQ8), wiping its
    /// key. The `witness` proves eligibility (`Unbond` + `W`-lapse + finality-deep)
    /// — the actor cannot re-verify, so the witness is the guard. `funded_slots`
    /// carries the caller's set of slots still holding unspent funding: the actor
    /// resolves the witness to a slot and, if funded, defers the wipe
    /// ([`RetireOutcome::SkippedFunded`], the funded-gate) rather than strand the
    /// funds. Idempotent: a persona already gone returns [`RetireOutcome::NotHeld`].
    /// The SP-5 task calls this when it confirms a persona is terminal.
    pub(crate) async fn retire_bonded_persona(
        &self,
        witness: RetirementWitness,
        funded_slots: std::sync::Arc<FundedSlots>,
    ) -> Result<RetireOutcome, StakeEngineError> {
        self.actor
            .ask(RetireBondedPersona {
                witness,
                funded_slots,
            })
            .await
            .map_err(collapse_send_error)
    }
}

/// Collapse a kameo `ask` [`SendError`] into a [`StakeEngineError`].
///
/// A `HandlerError` carries the real error the handler returned (e.g.
/// [`StakeEngineError::LookaheadExhausted`] / [`StakeEngineError::StaleHandle`])
/// and is surfaced as-is. `ActorNotRunning` / `ActorStopped` are exactly the
/// fail-stop / closed-actor states the terminal
/// [`StakeEngineError::StakeActorUnavailable`] names.
///
/// `MailboxFull` and `Timeout` are present only for match exhaustiveness and are
/// **unreachable on this path**: the actor uses kameo's default *unbounded*
/// mailbox (so the awaiting `ask` back-pressures the sender rather than
/// returning `MailboxFull`, mirroring [`KeyEngine`](super::key_actor)) and the
/// handle sets no `ask` timeout (so no `Timeout` is produced). Collapsing them
/// to the terminal error is therefore a dead arm, not a misclassification of a
/// live transient. **Reversion clause:** if PR 2c+ introduces a bounded mailbox
/// or an ask-timeout, that arm becomes reachable and must split into its own
/// *retryable* `StakeEngineError` variant rather than collapse here.
fn collapse_send_error<M>(err: SendError<M, StakeEngineError>) -> StakeEngineError {
    match err {
        SendError::HandlerError(e) => e,
        SendError::ActorNotRunning(_)
        | SendError::ActorStopped
        | SendError::MailboxFull(_)
        | SendError::Timeout(_) => StakeEngineError::StakeActorUnavailable,
    }
}
