// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Persona lifecycle messages (mint, activate, identity, PlanBondPost).

use kameo::message::{Context, Message};

use shekyl_archival_retention::PassTranscript;
use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridSignature;
use shekyl_tor_control_wallet::service::OnionIdentity;

use shekyl_crypto_pq::archival_p::PersonaDestination;

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

/// Stop the persona at `p_slot` being the active one, if it is: its planned
/// stake ended without a bond (`ARCHIVAL_BOND_POST_DELAY.md` BD-Q3 as ruled
/// 2026-11-26), so it must never receive a second funding, and staking again
/// is a new persona. The persona stays held (its drain is signed with its
/// keys); only the active slot is cleared, and the generation advances
/// because the active slot changed (typed contract #2). Idempotent: a slot
/// that is not active changes nothing.
pub(crate) struct DeactivateEndedPersona {
    /// The slot whose plan ended.
    pub p_slot: PSlot,
}

impl Message<DeactivateEndedPersona> for StakeEngine {
    type Reply = Result<(), StakeEngineError>;

    async fn handle(
        &mut self,
        msg: DeactivateEndedPersona,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if self.active == Some(msg.p_slot) {
            self.active = None;
            self.generation = self.generation.saturating_add(1);
        }
        Ok(())
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

/// Mint the persona's **onion serving credential** — the SH-2b handoff.
///
/// Returns an [`OnionIdentity`], built from the persona's onion keypair, and
/// that is the custody ruling rather than a convenience. §7.2(iii): the
/// wallet's HKDF siblings all descend from `master_seed`, so a serving role
/// holding a seed is one edit away from holding `bond_spend`'s authority. The
/// seed never exists outside `shekyl-crypto-pq`: the actor's [`ArchivalPKeys`](shekyl_crypto_pq::archival_p::ArchivalPKeys)
/// holds the keypair, and what crosses the actor boundary is a value
/// authorizing exactly one thing: publishing this onion.
///
/// The keypair stays in the bundle for the persona's life, on the heap and
/// wiped when the bundle drops, and under the `on_stop` wipe. Each request
/// takes `shekyl_onion_key::OnionKeypair::duplicate`, a second owner of the
/// same key. The bytes Tor receives are a separate copy:
/// `OnionIdentity::mint_onion_key` reads `expanded_secret` into one
/// `ED25519-V3` blob. [`OnionIdentity`] is deliberately not `Clone`: holding
/// the expanded bytes *is* the persona on the network, so every copy is named
/// where it is made.
///
/// A read-only projection like [`PersonaIdentityOf`]: no activation, no
/// retired-slot wipe, no generation advance. An unheld slot is
/// [`StakeEngineError::LookaheadExhausted`], as at every other slot boundary.
pub(crate) struct PersonaOnionIdentityOf {
    pub p_slot: PSlot,
}

impl Message<PersonaOnionIdentityOf> for StakeEngine {
    type Reply = Result<OnionIdentity, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: PersonaOnionIdentityOf,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let held = self
            .held
            .get(&msg.p_slot)
            .ok_or(StakeEngineError::LookaheadExhausted {
                requested: msg.p_slot,
            })?;
        Ok(OnionIdentity::from_keypair(
            held.keys().onion_keypair().duplicate(),
        ))
    }
}

/// Sign one pass transcript with the held persona's **receipt key** —
/// Ed25519 + FN-DSA-1024, hybrid scheme 3, under `SCHEME_DOMAIN_RECEIPT`
/// (`FN_DSA_HYBRID.md` §6, increment 4).
///
/// Its one production sender is `serving::receipt_key::ResidentReceiptKey`,
/// the serving task's signer, and the shape is the SH-2 resident-key
/// handoff's (`SF-D13`, "injection, not custody";
/// `SH2_RESIDENT_KEY_AUDIT.md` §3 Q1): **the secret does not cross the
/// actor boundary**. The 113-byte transcript goes in, the signature comes
/// out. The domain is fixed by [`shekyl_p_host::sign_receipt_transcript`],
/// which [`HeldPersona::sign_receipt_transcript`] calls, so this handler
/// cannot sign anything else with the key even if asked.
///
/// The first message for a persona decodes its receipt key and every later
/// one signs from the held key ([`HeldReceiptKey`], `FND-4`). The first
/// therefore needs the stack a decode needs, on the actor's task; the
/// figures are on `the_first_receipt_pays_the_decode_and_later_ones_do_not`.
/// A key that does not decode is [`StakeEngineError::ReceiptKeyUndecodable`]
/// at that first message and at each one after it; the later ones are
/// refused from the remembered state and decode nothing. A decoded key whose
/// signature fails is [`StakeEngineError::ReceiptSign`], a different variant
/// (`HeldPersona::sign_receipt_transcript`).
///
/// An unheld slot is [`StakeEngineError::LookaheadExhausted`], as at every
/// other slot boundary. There is no gate on the [`HeldPersona::Bonded`]
/// tag: that tag is a reconcilable persistence hint, not a statement of
/// chain truth, and the host already cannot start without a connected bond
/// record — a second gate on a hint would add false refusals and no
/// security.
pub(crate) struct SignReceiptTranscript {
    pub p_slot: PSlot,
    pub transcript: PassTranscript,
}

impl Message<SignReceiptTranscript> for StakeEngine {
    type Reply = Result<FnDsaHybridSignature, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: SignReceiptTranscript,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let held = self
            .held
            .get_mut(&msg.p_slot)
            .ok_or(StakeEngineError::LookaheadExhausted {
                requested: msg.p_slot,
            })?;
        // Undecodable and a failed signature come back as two variants;
        // the capability's pre-flight latches on the first only.
        held.sign_receipt_transcript(&msg.transcript)
    }
}

/// Test-only: whether the persona at `p_slot` holds a decoded receipt key
/// (`None` for an unheld slot). The lazy state is otherwise invisible from
/// outside the actor, by design.
#[cfg(test)]
pub(crate) struct ReceiptKeyIsBuilt {
    pub p_slot: PSlot,
}

#[cfg(test)]
impl Message<ReceiptKeyIsBuilt> for StakeEngine {
    type Reply = Option<bool>;

    async fn handle(
        &mut self,
        msg: ReceiptKeyIsBuilt,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.held
            .get(&msg.p_slot)
            .map(|held| held.receipt_key().built().is_some())
    }
}

/// Report the public identity of the currently-active persona, or `None` when
/// idle. Inspection only — never the secret bundle.
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

/// The currently-active persona's payment destination, or `None` when idle —
/// the funding side of `Engine::stake_in`. The reply holds public keys only
/// (rule 36) and is taken **in-actor** from the live bundle. Distinct from
/// [`ActivePersona`], which reports the *identity* (`bond_id`, a signing
/// key), not where a payment to the persona goes.
pub(crate) struct ActivePersonaPaymentDestination;

impl Message<ActivePersonaPaymentDestination> for StakeEngine {
    type Reply = Result<Option<PersonaDestination>, StakeEngineError>;

    async fn handle(
        &mut self,
        _msg: ActivePersonaPaymentDestination,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.active.map(|slot| self.payment_destination_of(slot)))
    }
}

/// Plan a stake at the request (`ARCHIVAL_BOND_POST_DELAY.md` BD-Q2, BD-Q3):
/// validate the persist-before-use typestate and draw the bond-post delay,
/// once. Nothing is built or signed: the post is assembled at its due block
/// by [`AssembleBond`](super::bond::AssembleBond), which never draws.
///
/// Both `handle` and `ticket` must name the same persona slot: the handle
/// proves the slot is currently held at the generation this message was minted
/// for; the ticket proves its live-bond record was durably committed before
/// the plan. This structural pairing makes "plan before persist" and "plan
/// for an unheld persona" unexpressible (typed contracts #1 and #2).
///
/// The draw runs inside the handler (S4/S5): the OS entropy source is
/// preflighted via `try_fill_bytes` (fail-loud on source failure — no silent
/// fallback to a weaker source), then [`super::helpers::draw_entry_gap_guarded`]
/// draws a run of pairs. An equal pair is drawn again inside the guard. The
/// handler rejects only when the whole run collided, which is a stuck source.
///
/// Does **not** advance the activation generation — this path does not change
/// the active slot or wipe any persona.
///
/// # Caller workflow
///
/// ```text
/// engine.persist_bond_record(slot) → ticket (durable; Engine, not actor)
/// stake.mint_handle(slot)          → handle
/// stake.plan_bond_post(handle, ticket) → draw (sealed in the plan)
/// ```
pub(crate) struct PlanBondPost {
    /// Operation-scoped capability proving the slot is currently held (typed
    /// contract #2). Must match `ticket.p_slot()`.
    pub handle: PersonaHandle,
    /// Proof that the live-bond record was durably persisted for this slot
    /// before the plan (typed contract #1). Must match `handle.p_slot()`.
    pub ticket: crate::engine::stake_persist::PersistedBondTicket,
}

impl Message<PlanBondPost> for StakeEngine {
    type Reply = Result<BlockCount, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: PlanBondPost,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // GF-7 SCOPE (`ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md` §4): the delay
        // decorrelates the bond post from `P`'s own observable funding event
        // (BD-Q2: measured from the funding's anchor) **only** — NOT from the
        // principal's lifecycle timeline, nor from `P`'s other broadcasts.
        // That correlation (GATE6 §10.12 GF-7) remains a **genesis gate**; the
        // measurement pipeline is the `gf7-hooks` observer seam the draw
        // emits to (`ARCHIVAL_BOND_2C_GF7_HOOKS.md`).
        let handle_slot = self.validate_bond_handle(&msg.handle, msg.ticket.p_slot())?;
        self.draw_bond_delay(handle_slot)
    }
}
