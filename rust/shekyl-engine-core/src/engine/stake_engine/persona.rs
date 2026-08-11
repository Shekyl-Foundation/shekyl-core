// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Persona lifecycle messages (mint, activate, identity, PlanBondPost).

use kameo::message::{Context, Message};

use shekyl_archival_bond_builder::{build_join_market_vin, JoinMarketVin};
use shekyl_archival_retention::HoldingsDescriptor;

use crate::engine::{Network, ShekylAddress};

use super::actor::StakeEngine;
use super::types::*;

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Mint a [`PersonaHandle`] for slot `p_slot` — the single slot→handle boundary
/// (typed contract #2). Succeeds iff the slot is in the held derive-forward set;
/// an unheld slot is [`StakeEngineError::LookaheadExhausted`] (reopen to extend
/// the lookahead). The minted handle carries the current activation generation, so
/// it is valid only until the next activation (operation-scoped).
#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
pub(crate) struct MintPersonaHandle {
    pub p_slot: PSlot,
}

impl Message<MintPersonaHandle> for StakeEngine {
    type Reply = Result<PersonaHandle, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: MintPersonaHandle,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if self.held.contains_key(&msg.p_slot) {
            Ok(PersonaHandle {
                p_slot: msg.p_slot,
                generation: self.generation,
            })
        } else {
            Err(StakeEngineError::LookaheadExhausted {
                requested: msg.p_slot,
            })
        }
    }
}

/// Activate the persona named by `handle`, returning its public identity.
///
/// No derivation happens — the bundle is already held (Model D). If a different
/// slot is active this is an **activation**: a single assignment installs the new
/// active slot, the retired slot is wiped iff ephemeral (typed contract #4), and
/// the generation advances (invalidating every prior handle). There is never a
/// window with two active personas and never a gap with none (§10.1 #2 / §10.9).
#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
pub(crate) struct ActivatePersona {
    pub handle: PersonaHandle,
}

impl Message<ActivatePersona> for StakeEngine {
    type Reply = Result<PersonaIdentity, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: ActivatePersona,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.validate_handle(&msg.handle)?;
        let target = msg.handle.p_slot;

        // Idempotent: already active for this slot → return its identity, no
        // activation, no generation advance.
        if self.active == Some(target) {
            return Ok(self.identity_of(target));
        }

        // Single atomic transition: install the new active slot first, then wipe
        // the retired slot (iff ephemeral). The new persona is already held, so
        // there is never a moment with two *active* personas and never a gap.
        let retired = self.active.replace(target);
        if let Some(retired) = retired {
            self.wipe_retired_if_ephemeral(retired);
        }
        // The active slot changed, so this activation is an operation boundary:
        // advance the generation to invalidate every handle minted before it
        // (typed contract #2 — handles are single-activation). The handle just
        // consumed was validated above against the pre-activation generation, so
        // the ordering is correct.
        self.generation = self.generation.saturating_add(1);

        Ok(self.identity_of(target))
    }
}

/// Report the public identity of the **held** persona at `p_slot` — a pure
/// projection, like [`ActivePersona`]: no activation, no retired-slot wipe, no
/// generation advance, so every outstanding handle stays valid. The claim
/// request path (CB-3) uses this to derive the claimant's canonical id from
/// actor-held state without the lifecycle side effects of
/// [`ActivatePersona`] — a claim is a read-and-sign operation, and activating
/// on it would both invalidate any in-flight operation's handles and wipe a
/// retired ephemeral persona as a side effect of an unrelated request.
/// An unheld slot is [`StakeEngineError::LookaheadExhausted`], exactly as
/// at the mint boundary.
#[allow(dead_code)] // inert until the RPC stake entry (same retirement as the claim seam)
pub(crate) struct PersonaIdentityOf {
    pub p_slot: PSlot,
}

impl Message<PersonaIdentityOf> for StakeEngine {
    type Reply = Result<PersonaIdentity, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: PersonaIdentityOf,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if self.held.contains_key(&msg.p_slot) {
            Ok(self.identity_of(msg.p_slot))
        } else {
            Err(StakeEngineError::LookaheadExhausted {
                requested: msg.p_slot,
            })
        }
    }
}

/// Report the public identity of the currently-active persona, or `None` when
/// idle. Inspection only — never the secret bundle.
#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
pub(crate) struct ActivePersona;

impl Message<ActivePersona> for StakeEngine {
    type Reply = Result<Option<PersonaIdentity>, StakeEngineError>;

    async fn handle(
        &mut self,
        _msg: ActivePersona,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.active.map(|slot| self.identity_of(slot)))
    }
}

/// Project the currently-active persona's public
/// [`ShekylAddress`](shekyl_address::ShekylAddress), or `None` when idle — the
/// funding side of `Engine::stake_in`. The reply is structurally public-only (an
/// address cannot carry a secret; rule 36) and built **in-actor** from the live
/// bundle. Distinct from [`ActivePersona`], which reports the *identity*
/// (`bond_id`, a signing key), not an address. `network` is the principal
/// wallet's network, supplied by the caller (the actor is network-agnostic).
pub(crate) struct ActivePersonaReceiveAddress {
    pub network: Network,
}

impl Message<ActivePersonaReceiveAddress> for StakeEngine {
    type Reply = Result<Option<ShekylAddress>, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: ActivePersonaReceiveAddress,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .active
            .map(|slot| self.receive_address_of(slot, msg.network)))
    }
}

/// Request the StakeEngine to construct a JoinMarket archival bond-post vin
/// and draw its placement, consuming the persist-before-use typestate
/// (Bond-PR 2c-2b, S1/S2). Formerly `SignBond`; renamed when SA-2b deleted
/// on-vin signing — the handler constructs and plans, it signs nothing
/// (surface-A signing is the assemble path).
///
/// Both `handle` and `ticket` must name the same persona slot: the handle
/// proves the slot is currently held at the generation this message was minted
/// for; the ticket proves its live-bond record was durably committed before
/// construction. This structural pairing makes "construct before persist" and
/// "construct for an unheld persona" unexpressible (typed contracts #1 and #2).
///
/// The entry-gap timing draw runs inside the handler (S4/S5): the OS entropy
/// source is preflighted via `try_fill_bytes` (fail-loud on source failure —
/// no silent fallback to a weaker source), then the draw is taken and checked
/// for the double-jitter degeneracy pattern. A degenerate draw is rejected;
/// a correct CSPRNG produces consecutive equal spreads with probability ≈ 1/601,
/// so a single retry resolves an unlucky-but-correct draw.
///
/// The `ArchivalPKeys` bundle is borrowed inside the actor and never crosses
/// the actor boundary (rule 36-secret-locality). `build_join_market_vin` is
/// called here with **public** key halves only; the reply is a
/// [`BondPostPlacement`] carrying the constructed `JoinMarketVin` **and** the
/// bond-post placement offset from this request's entry-gap draw — the caller
/// receives the placement offset with the bytes it places, so the draw cannot
/// be lost between construction and scheduling. On-vin signing is gone (SA-2b);
/// surface-A `pqc_auths` signing happens later in assemble.
///
/// Does **not** advance the activation generation — this path does not change
/// the active slot or wipe any persona.
///
/// # Caller workflow
///
/// ```text
/// stake.mint_handle(slot)      → handle1
/// stake.activate_persona(handle1)           (sets active slot; handle1 consumed)
/// engine.persist_bond_record(slot) → ticket (durable; Engine, not actor)
/// stake.mint_handle(slot)      → handle2
/// stake.plan_bond_post(handle2, ticket, holdings) → BondPostPlacement
/// ```
#[allow(dead_code)] // inert until 2c-2b request path is wired end-to-end
pub(crate) struct PlanBondPost {
    /// Operation-scoped capability proving the slot is currently held (typed
    /// contract #2). Must match `ticket.p_slot()`.
    pub handle: PersonaHandle,
    /// Proof that the live-bond record was durably persisted for this slot
    /// before construction (typed contract #1). Must match `handle.p_slot()`.
    pub ticket: crate::engine::stake_persist::PersistedBondTicket,
    /// Holdings to compute `bond_floor` from. Passed to
    /// [`build_join_market_vin`] inside the actor.
    pub holdings: HoldingsDescriptor,
}

/// Reply of [`PlanBondPost`]: the constructed bond vin **and** the block-timed
/// placement offset derived from the same request's entry-gap draw.
///
/// Pairing them in one reply is the seam discipline: the caller that receives
/// the bytes to place also receives *where to place them* (blocks from its
/// private intent anchor `t0`), so the placement offset cannot be lost between
/// construction and scheduling. The offset is relative; the anchor itself never
/// leaves the caller. The vin carries no on-vin signature (SA-2b).
#[allow(dead_code)] // inert until the 2c-2a assemble / 2d dispatch consumer lands
#[derive(Debug)]
pub(crate) struct BondPostPlacement {
    /// The constructed JoinMarket bond vin, ready for transaction assembly.
    /// Authorization is the later surface-A `pqc_auths` slot, not an on-vin blob.
    pub vin: JoinMarketVin,
    /// Blocks from the private-intent anchor `t0` to the bond-post broadcast —
    /// the drawn entry-gap spread. (No entry offset: only the bond post is
    /// chain-attributable, so there is no second event to place.)
    pub bond_post_offset_blocks: u64,
}

impl Message<PlanBondPost> for StakeEngine {
    type Reply = Result<BondPostPlacement, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: PlanBondPost,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Steps 1–5 (validate + slot cross-check + entropy preflight + guarded
        // draw + entry-seam plan + GF-7 hooks) are the shared bond-handler
        // prologue; see `validate_and_draw_bond_offset`.
        //
        // GF-7 SCOPE (`ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md` §4): the jitter that
        // prologue draws decorrelates the bond-post from `P`'s own observable
        // funding/entry event (the funding-seam ordering prior) **only** — NOT
        // from the principal's lifecycle timeline, nor from `P`'s other
        // broadcasts. That correlation (GATE6 §10.12 GF-7) remains a **genesis
        // gate**; the measurement pipeline that will quantify it is the
        // `gf7-hooks` observer seam the prologue emits to
        // (`ARCHIVAL_BOND_2C_GF7_HOOKS.md`), evaluated in `shekyl-staking-sim`.
        //
        // TODO(2d) — the write-side *seam* the plan will drive is built:
        // `PTransactionSubmitter` (per-`P` CX-2) + `BroadcastPosture`
        // (no-③-by-type) in `transaction_submitter.rs` / `posture.rs` (SP-T4a).
        // The remaining CONSUMER wiring is the 2c-2a assemble / 2d dispatch path
        // (see `AssembleBond`); this handler plans + constructs the vin, it does not
        // broadcast.
        let (handle_slot, bond_post_offset_blocks) =
            self.validate_and_draw_bond_offset(&msg.handle, msg.ticket.p_slot())?;

        // 6. Borrow the held bundle — slot membership confirmed by step 1.
        let keys = self
            .held
            .get(&handle_slot)
            .expect("validate_handle confirmed slot is held")
            .keys();

        // 7. Construct the JoinMarket vin inside the actor (public keys only;
        //    SA-2b — no on-vin signature). `ArchivalPKeys` is borrowed here and
        //    never returned to the caller (rule 36-secret-locality): only the
        //    constructed `JoinMarketVin` (paired with its placement offset)
        //    crosses the actor boundary.
        let vin = build_join_market_vin(keys.bond_post_keys(), msg.holdings)
            .map_err(StakeEngineError::BondBuild)?;
        Ok(BondPostPlacement {
            vin,
            bond_post_offset_blocks,
        })
    }
}
