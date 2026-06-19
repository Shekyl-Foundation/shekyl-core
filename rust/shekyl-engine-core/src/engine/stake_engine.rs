// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`StakeEngine`]: the `kameo` actor that owns the wallet's **pre-derived
//! archival personas** (`P`) — the derive-forward set, *not* the master seed —
//! plus [`StakeEngineHandle`], the `Clone` handle held in place of the actor.
//!
//! Per [`docs/design/ARCHIVAL_BOND_CONSTRUCTION.md`] §10/§10.1, the StakeEngine
//! actor *is* the gate-6 firewall realized as actor isolation: it is the sole
//! owner of `P`'s secret key material, structurally disjoint from the
//! `LedgerEngine` transfer pipeline. The properties below are what make that
//! isolation hold rather than merely declare it.
//!
//! # Model D — derived bundles, no session-long seed
//!
//! The seed is **not** held session-long anywhere. At `assemble()` the
//! orchestrator borrows the master seed (`&[u8; 64]`), derives the
//! **derive-forward set** — `{personas with live bonds} ∪ {p_slot ..= p_slot+k}`
//! — and hands those [`ArchivalPKeys`] bundles to this actor, then drops the
//! seed at function end (the same lifetime the `KeyActor` already imposes on the
//! seed it derives `AllKeysBlob` from). The actor therefore holds only **derived
//! material** (same `!Clone` + per-field `ZeroizeOnDrop` class as `AllKeysBlob`),
//! never the root. Rotation switches the active bundle and wipes the retired one
//! — it never re-acquires the seed. Lookahead-exhaustion and first-stake-mid-
//! session collapse onto **reopen** (re-runs `assemble()` with the transient
//! seed); there is no re-auth/KEK machinery.
//!
//! ## Why the *bonded union*, not a clean lookahead window
//!
//! The archival model rotates *while bonded*: a retired persona's bonds sit
//! on-chain as dormant balances (no simultaneous wire activity → the firewall
//! permits it), and unbonding one later needs that persona's `bond_spend` key.
//! Because the seed is gone after `assemble()`, a persona absent from the
//! pre-derived set is unreachable for the wallet's life — so a retired-but-
//! bonded persona under a bare `{p_slot ..= p_slot+k}` window would brick
//! unbonding. The held set is therefore the **bonded union plus the lookahead**,
//! and rotation-wipe wipes **only personas with no live bond** (typed contract
//! #4, [`HeldPersona`]). The live-bond slot set arrives from the persisted
//! [`StakingBlock`](shekyl_engine_state::StakingBlock) `bonded_slots` hint.
//!
//! # Secret-locality (`36-secret-locality.mdc`, `16-architectural-inheritance.mdc`)
//!
//! The actor owns the held bundles privately. The message protocol is
//! **operation-shaped, never key-shaped**: requests name an operation ("mint a
//! handle for slot N", "activate this handle", and in 2c-2b "sign this bond
//! preimage"), and replies carry **public** results ([`PersonaIdentity`] holds
//! the typed [`HybridPublicKey`] that rides the wire as `P_pubkey` — a type with
//! no secret field). Nothing in the protocol can request a bundle and nothing
//! can `Clone` one out, so the secret cannot escape the actor (§10.1 #1).
//!
//! # `PersonaHandle` — held-only, operation-scoped (typed contract #2)
//!
//! Activation (and, in 2c-2b, signing) take a [`PersonaHandle`] minted only for
//! a persona in the held set, never a raw [`PSlot`] validated per use. "Use an
//! unheld persona" then has no expressible form: the membership check collapses
//! to the single slot→handle minting boundary ([`MintPersonaHandle`]). The
//! handle is **operation-scoped** — it carries the actor's rotation
//! `generation`, and every rotation that wipes a persona advances it, so a
//! handle retained across a rotation is rejected ([`StakeEngineError::StaleHandle`])
//! rather than signing against zeroized memory. [`StakeEngineError::LookaheadExhausted`]
//! stays a *real* domain error (the budget is consumed → reopen), distinct from
//! the typed-away can't-happen state.
//!
//! # Atomic rotation (§10.1 robustness #2 / §10.9)
//!
//! Activating a held slot is a **single state transition**: a single assignment
//! installs the new active slot, then the retired slot is wiped iff it is
//! *ephemeral* (no live bond). There is never a window with two active personas
//! and never a gap with none. Bonded retired personas stay resident so
//! unbonding remains reachable. The bundles are **not** persisted; reopen
//! re-derives the derive-forward set from the seed (`assemble()`).
//!
//! # Fail-stop, not supervised
//!
//! Like [`KeyActor`](super::key_actor::KeyActor), the StakeEngine is the
//! wallet's secret owner and is **not** restart-supervised: a handler panic
//! runs [`Actor::on_panic`] returning [`ControlFlow::Break`], so the actor
//! stops rather than restarts. After a stop, every handle call collapses to the
//! terminal [`StakeEngineError::StakeActorUnavailable`]; recovery is a full
//! wallet close + re-open, which re-derives the derive-forward set.
//!
//! # Status: inert (PR 2c-2a)
//!
//! The actor is reworked to Model D here; the live spawn (`assemble()` deriving
//! the union and spawning the handle, `Engine.stake`) lands in this same PR's
//! `assemble()` wiring, and the first consumer (the JoinMarket bond request
//! that consumes a [`PersistedBondTicket`] + [`PersonaHandle`]) lands in 2c-2b.
//! Items not yet wired carry their own `#[allow(dead_code)]` so the dead-code
//! check stays effective and the allows fall away as wiring lands.
//!
//! [`docs/design/ARCHIVAL_BOND_CONSTRUCTION.md`]: ../../../../../docs/design/ARCHIVAL_BOND_CONSTRUCTION.md
//! [`ArchivalPKeys`]: shekyl_crypto_pq::archival_p::ArchivalPKeys
//! [`PersistedBondTicket`]: super::stake_persist::PersistedBondTicket

use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;

use kameo::actor::{Actor, ActorRef, Spawn, WeakActorRef};
use kameo::error::{ActorStopReason, Infallible, PanicError, SendError};
use kameo::message::{Context, Message};

use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_crypto_pq::signature::HybridPublicKey;

// ---------------------------------------------------------------------------
// Typed domain values
// ---------------------------------------------------------------------------

/// Archival persona slot index.
///
/// A newtype over `u32` so a persona slot cannot be confused at a call site
/// with any other index (an output index, a subaddress index, …). The
/// `derive_archival_p_keys` boundary takes a raw `u32`; the conversion is
/// explicit via [`PSlot::index`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)] // inert until PR 2c wiring
pub(crate) struct PSlot(pub u32);

#[allow(dead_code)] // inert until PR 2c wiring
impl PSlot {
    /// The raw slot index, for the `derive_archival_p_keys` boundary.
    #[must_use]
    pub(crate) fn index(self) -> u32 {
        self.0
    }
}

/// How many slots past the current cursor `assemble()` pre-derives into the
/// held set (`ARCHIVAL_BOND_CONSTRUCTION.md` §10.2, Model D).
///
/// # Rationale and bounds (`75-system-autonomy.mdc`)
///
/// `k` is the one tuning knob of Model D. The derive-forward set at open is
/// `{persisted bonded slots} ∪ {cursor ..= cursor + k}`: the bonded slots are
/// reachable for unbonding, and the `k`-slot window covers rotations that
/// happen *during* the session without re-acquiring the seed. Rotation is
/// sequential (`i → i+1`), so a window of `k` future slots covers `k` in-session
/// rotations before the lookahead is exhausted and the wallet must be reopened
/// (the root-free recovery path) to derive further.
///
/// - **Lower bound.** `k = 0` degenerates to "reopen to rotate" — still
///   correct and root-free, but every rotation costs a reopen.
/// - **Upper bound.** Each unit of `k` is one extra PQ keygen at open and one
///   extra resident `ArchivalPKeys` bundle; the cost is linear in `k` and paid
///   only by stakers. Large `k` widens the memory blast radius (held derived
///   personas) without benefit, since most sessions rotate at most once.
/// - **Chosen value `2`.** Most sessions use one persona and rotate at most
///   once; `k = 2` covers the common case (current + two in-session rotations)
///   with a two-bundle resident cost. Raising it is a one-line change reviewed
///   against this rationale.
pub(crate) const ARCHIVAL_PERSONA_LOOKAHEAD: u32 = 2;

/// A held persona bundle tagged by whether it carries a **live bond**.
///
/// This is **typed contract #4** ([`ARCHIVAL_BOND_CONSTRUCTION.md`] §10.2):
/// rotation-wipe must wipe only personas with *no* live bond, because a
/// retired-but-bonded persona's `bond_spend` key is needed to unbond it later
/// and — under Model D, with the seed gone after `assemble()` — a wiped persona
/// is unreachable for the wallet's life. Rather than guard that with a runtime
/// check, the wipe path ([`wipe_ephemeral`]) accepts only an [`EphemeralPersona`]
/// *by value*: a [`BondedPersona`] cannot be passed to it, so "wipe a persona
/// with a live bond" does not compile.
///
/// The bonded/ephemeral tag is assigned once at construction from the persisted
/// `bonded_slots` hint (see [`StakeEngineArgs::bonded`]); it is a reconcilable
/// hint, not consensus truth (2d reconciles it against actual bond state).
///
/// [`ARCHIVAL_BOND_CONSTRUCTION.md`]: ../../../../../docs/design/ARCHIVAL_BOND_CONSTRUCTION.md
#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
enum HeldPersona {
    /// Carries at least one live bond (`consumer_held` or posted). Never wiped
    /// while bonded — its `bond_spend` key must stay reachable to unbond.
    Bonded(BondedPersona),
    /// A pre-derived lookahead persona with no live bond. The *only* variant
    /// the rotation-wipe path accepts.
    Ephemeral(EphemeralPersona),
}

#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
impl HeldPersona {
    /// Borrow the underlying derived bundle (read-only; the secret never
    /// escapes — callers project the public [`PersonaIdentity`] out of it).
    fn keys(&self) -> &ArchivalPKeys {
        match self {
            HeldPersona::Bonded(b) => &b.0,
            HeldPersona::Ephemeral(e) => &e.0,
        }
    }
}

/// A held persona that carries a live bond. The wipe path cannot accept this
/// type (typed contract #4), so a bonded persona is never zeroized while a bond
/// depends on its `bond_spend` key.
#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
struct BondedPersona(ArchivalPKeys);

/// A held persona with no live bond — the only thing [`wipe_ephemeral`] accepts.
#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
struct EphemeralPersona(ArchivalPKeys);

/// Wipe a retired ephemeral persona.
///
/// Takes ownership of an [`EphemeralPersona`] by value — a [`BondedPersona`]
/// cannot be passed (typed contract #4), so wiping a persona with a live bond is
/// uncallable. The bundle's per-field `ZeroizeOnDrop` runs at the drop here; the
/// explicit `drop` makes the wipe a named operation rather than an implicit
/// scope-end.
#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
fn wipe_ephemeral(persona: EphemeralPersona) {
    drop(persona);
}

/// An operation-scoped capability to **activate** a held persona (typed
/// contract #2).
///
/// Minted only by [`MintPersonaHandle`] for a slot actually in the held set, so
/// "activate an unheld persona" has no expressible form — the membership check
/// lives at the single slot→handle boundary, not at every use site. The handle
/// carries the actor's rotation [`generation`](StakeEngine::generation) at mint
/// time, and [`ActivatePersona`] consumes it **by value**: a handle authorizes
/// exactly one activation.
///
/// **Operation-scoped, two ways.** A rotation (an activation that changes the
/// active slot) advances the generation, so any handle minted before it is
/// stale ([`StakeEngineError::StaleHandle`]); and the rotation removes the wiped
/// ephemeral persona from the held set, so even a same-generation handle to it
/// fails the membership check. A handle therefore cannot outlive the operation
/// that minted it, which is what makes "sign against wiped memory" unexpressible.
///
/// Signing (2c-2b) does **not** retain a handle across the rotation: it targets
/// the persona that activation made *active*, so the handle's single-activation
/// scope is sufficient. Deliberately **not** `Clone` — there is no caller that
/// needs to retain or duplicate a handle (mirrors the `AllKeysBlob` Not-Clone
/// discipline, `21-reversion-clause-discipline.mdc`); reopen this if a 2c-2b
/// caller emerges that provably needs to drive two actor operations from one
/// mint, with documented justification.
#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
pub(crate) struct PersonaHandle {
    p_slot: PSlot,
    generation: u64,
}

#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
impl PersonaHandle {
    /// The slot this handle authorizes.
    #[must_use]
    pub(crate) fn p_slot(&self) -> PSlot {
        self.p_slot
    }
}

/// The public identity of an activated persona `P`.
///
/// Carries **only public material** — the typed [`HybridPublicKey`] that rides
/// the wire as `P_pubkey`, plus the slot it was derived for. Returning the
/// typed key (rather than raw bytes, and never the secret bundle) makes "no
/// secret crosses the actor boundary" a property the type system checks:
/// `HybridPublicKey` has no secret field. `Clone + Debug` is sound for the same
/// reason.
#[derive(Clone, Debug)]
#[allow(dead_code)] // inert until PR 2c wiring
pub(crate) struct PersonaIdentity {
    /// The slot this persona was derived for.
    pub p_slot: PSlot,
    /// The persona's public bond identity key (= `hybrid_bond_id`, `P_pubkey`).
    pub bond_id: HybridPublicKey,
}

#[allow(dead_code)] // inert until PR 2c wiring
impl PersonaIdentity {
    /// Project the public identity out of a (secret) persona bundle.
    fn from_keys(keys: &ArchivalPKeys) -> Self {
        Self {
            p_slot: PSlot(keys.p_slot),
            bond_id: keys.hybrid_bond_id().clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors surfaced by the StakeEngine handle.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
pub(crate) enum StakeEngineError {
    /// The StakeEngine actor has stopped (fail-stop after a handler panic, or a
    /// clean stop). Terminal and non-retryable — the persona secrets went with
    /// the task. Recovery is a full wallet close + re-open, which re-derives the
    /// derive-forward set. The message is user-facing: it names the recovery
    /// action.
    #[error(
        "stake engine unavailable: the staking actor has stopped; \
         close and reopen the wallet to recover"
    )]
    StakeActorUnavailable,

    /// The requested slot is **not in the held derive-forward set** — the
    /// lookahead budget `{p_slot ..= p_slot+k}` is consumed (rotated past the
    /// pre-derived window). A *real* domain state, not a can't-happen: under
    /// Model D the seed is gone after `assemble()`, so reaching a fresh slot
    /// requires re-deriving the union, i.e. **reopen the wallet**. Held distinct
    /// from [`Self::StaleHandle`] precisely because the recovery differs (reopen
    /// vs. re-mint).
    #[error(
        "archival lookahead exhausted: slot {requested:?} is not in the held \
         persona set; close and reopen the wallet to extend the lookahead"
    )]
    LookaheadExhausted { requested: PSlot },

    /// A [`PersonaHandle`] was presented after a rotation advanced the actor's
    /// generation — i.e. it was retained across the rotation that is its own
    /// separate operation (typed contract #2: handles are operation-scoped). The
    /// persona it named may have been wiped; using it would risk a use-after-
    /// wipe, so it is rejected. Non-terminal: mint a fresh handle and retry.
    #[error("stale persona handle: re-mint a handle (a rotation occurred since it was issued)")]
    StaleHandle,
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// Construction arguments moved into the actor task at spawn.
///
/// Under Model D the actor receives **pre-derived** bundles (the orchestrator
/// derived them at `assemble()` while the seed was transiently borrowed, then
/// dropped the seed). The actor never sees the seed.
#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
pub(crate) struct StakeEngineArgs {
    /// The derive-forward set — pre-derived `ArchivalPKeys` keyed by slot:
    /// `{personas with live bonds} ∪ {p_slot ..= p_slot+k}`. Each is `!Clone` +
    /// per-field `ZeroizeOnDrop`. Wiped at actor stop.
    pub bundles: BTreeMap<PSlot, ArchivalPKeys>,
    /// Slots that carry a live bond (`consumer_held` or posted), from the
    /// persisted `bonded_slots` hint. Bundles in this set are tagged
    /// [`HeldPersona::Bonded`] so rotation never wipes them; the rest are
    /// [`HeldPersona::Ephemeral`]. A reconcilable hint, not consensus truth.
    pub bonded: BTreeSet<PSlot>,
    /// The initially-active slot (the scan-reconciled monotone current slot), or
    /// `None` when the wallet is staker-flagged but has not activated a persona.
    /// Must be present in `bundles` when `Some` (the orchestrator guarantees the
    /// current slot is in the derive-forward set).
    pub active: Option<PSlot>,
}

/// The `kameo` actor owning the held archival personas (the derive-forward
/// set), **not** the master seed.
///
/// The single-threaded message loop serializes access to `held`/`active`, so a
/// rotation (install-new-active, then wipe-retired-iff-ephemeral) is atomic with
/// respect to other messages.
#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
pub(crate) struct StakeEngine {
    /// The held derive-forward set, keyed by slot and tagged bonded/ephemeral.
    /// Rotation wipes only the ephemeral retired slot; bonded personas stay
    /// resident so unbonding remains reachable.
    held: BTreeMap<PSlot, HeldPersona>,
    /// The currently-active slot, or `None` when idle. Always a key of `held`
    /// when `Some`.
    active: Option<PSlot>,
    /// Rotation generation. Advances on every rotation that changes `active`,
    /// invalidating every [`PersonaHandle`] minted before it — the mechanism
    /// behind operation-scoped handles (typed contract #2).
    generation: u64,
}

#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
impl StakeEngine {
    /// Validate a presented handle: it must be from the current generation and
    /// name a still-held slot. A generation mismatch means a rotation occurred
    /// since the handle was minted (operation-scoped contract), so it is stale.
    fn validate_handle(&self, handle: &PersonaHandle) -> Result<(), StakeEngineError> {
        if handle.generation != self.generation {
            return Err(StakeEngineError::StaleHandle);
        }
        // A current-generation handle proves the slot was held at mint, and no
        // wipe has happened since (a wipe advances the generation), so this is a
        // defensive belt-and-braces check that should hold by construction.
        if !self.held.contains_key(&handle.p_slot) {
            return Err(StakeEngineError::StaleHandle);
        }
        Ok(())
    }

    /// Project the public identity of a held slot. The caller must have
    /// validated membership (e.g. via [`Self::validate_handle`]).
    fn identity_of(&self, slot: PSlot) -> PersonaIdentity {
        PersonaIdentity::from_keys(
            self.held
                .get(&slot)
                .expect("identity_of called for a held slot")
                .keys(),
        )
    }

    /// Wipe the retired slot iff it is ephemeral; a bonded persona is left
    /// resident (typed contract #4 — the wipe path accepts only the ephemeral
    /// type, so this match is the single place a slot can be removed).
    fn wipe_retired_if_ephemeral(&mut self, retired: PSlot) {
        if matches!(self.held.get(&retired), Some(HeldPersona::Ephemeral(_))) {
            // The `remove` yields the owned `EphemeralPersona`; `wipe_ephemeral`
            // accepts nothing else, so a `Bonded` variant cannot reach it.
            if let Some(HeldPersona::Ephemeral(persona)) = self.held.remove(&retired) {
                wipe_ephemeral(persona);
            }
        }
    }
}

impl Actor for StakeEngine {
    type Args = StakeEngineArgs;
    type Error = Infallible;

    /// Build the actor from the pre-derived bundles. Tag each bundle
    /// bonded/ephemeral from the `bonded` hint; no derivation happens here (the
    /// seed never reaches the actor under Model D).
    async fn on_start(
        args: StakeEngineArgs,
        _actor_ref: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        let held = args
            .bundles
            .into_iter()
            .map(|(slot, keys)| {
                let tagged = if args.bonded.contains(&slot) {
                    HeldPersona::Bonded(BondedPersona(keys))
                } else {
                    HeldPersona::Ephemeral(EphemeralPersona(keys))
                };
                (slot, tagged)
            })
            .collect::<BTreeMap<_, _>>();

        // Defensive: the orchestrator guarantees `active ∈ bundles`. Drop a
        // dangling cursor to idle rather than carry an unresolvable active slot.
        let active = args.active.filter(|slot| held.contains_key(slot));

        Ok(Self {
            held,
            active,
            generation: 0,
        })
    }

    /// Fail-stop on panic. The kameo default, locked explicitly so the
    /// secret-owner's no-restart posture is pinned at the type layer rather than
    /// inherited from a framework default that could change under a dependency
    /// bump (mirrors [`KeyActor`](super::key_actor::KeyActor)).
    async fn on_panic(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        err: PanicError,
    ) -> Result<ControlFlow<ActorStopReason>, Self::Error> {
        Ok(ControlFlow::Break(ActorStopReason::Panicked(err)))
    }

    /// Defense-in-depth wipe at stop. Each held bundle's per-field
    /// `ZeroizeOnDrop` also runs at task-end drop; clearing the map here makes
    /// the zeroization observable at fail-stop and is idempotent with the
    /// drop-glue wipe.
    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        // Dropping every held bundle runs each secret field's `ZeroizeOnDrop`.
        self.active = None;
        self.held.clear();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Mint a [`PersonaHandle`] for slot `p_slot` — the single slot→handle boundary
/// (typed contract #2). Succeeds iff the slot is in the held derive-forward set;
/// an unheld slot is [`StakeEngineError::LookaheadExhausted`] (reopen to extend
/// the lookahead). The minted handle carries the current rotation generation, so
/// it is valid only until the next rotation (operation-scoped).
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
/// slot is active this is a **rotation**: a single assignment installs the new
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
        // rotation, no generation advance.
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
        // consumed was validated above against the pre-rotation generation, so
        // the ordering is correct.
        self.generation = self.generation.saturating_add(1);

        Ok(self.identity_of(target))
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

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// `Clone` handle the orchestrator holds in place of an inline `StakeEngine`.
///
/// **Capability object.** Holding a `StakeEngineHandle` *is* the authority to
/// drive the staking actor. It is `pub(crate)` and never exported to the RPC
/// tier; that confinement is the control, made a compile-time guarantee by the
/// visibility bound (mirrors [`KeyEngineHandle`](super::key_actor::KeyEngineHandle)).
#[derive(Clone)]
#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
pub(crate) struct StakeEngineHandle {
    /// Strong reference to the stake actor's mailbox.
    actor: ActorRef<StakeEngine>,
}

#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
impl StakeEngineHandle {
    /// Spawn the StakeEngine over the pre-derived derive-forward set.
    ///
    /// The bundles were derived at `assemble()` while the master seed was
    /// transiently borrowed; the seed is dropped there and never reaches the
    /// actor (Model D). `bonded` tags which held slots carry a live bond
    /// (rotation never wipes them); `active` is the initial current slot.
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
        });
        Self { actor }
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

    /// Activate the persona named by `handle` and return its public identity.
    /// Rotation (with ephemeral-only wipe) when a different slot is active.
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
#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
fn collapse_send_error<M>(err: SendError<M, StakeEngineError>) -> StakeEngineError {
    match err {
        SendError::HandlerError(e) => e,
        SendError::ActorNotRunning(_)
        | SendError::ActorStopped
        | SendError::MailboxFull(_)
        | SendError::Timeout(_) => StakeEngineError::StakeActorUnavailable,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Lifecycle contract tests for [`StakeEngine`] / [`StakeEngineHandle`]
    //! (`ARCHIVAL_BOND_CONSTRUCTION.md` §10.2) under **Model D**: the actor holds
    //! pre-derived bundles, never the seed. Tests derive the derive-forward set
    //! with the `derive_archival_p_keys` oracle and hand it in, then exercise the
    //! actor through real messages — no mocks. The same oracle is rerun to
    //! confirm the actor projects the genesis-frozen identity bytes.

    use super::*;

    use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
    use shekyl_crypto_pq::archival_p::derive_archival_p_keys;

    /// Deterministic test seed (matches the `archival_p` module's KAT fixture).
    const TEST_SEED: [u8; MASTER_SEED_BYTES] = [0x33u8; MASTER_SEED_BYTES];

    /// Derive a persona bundle for `p_slot` on mainnet/bip39 (a permitted pair).
    /// Re-derivable on demand because `ArchivalPKeys` is `!Clone` and derivation
    /// is deterministic — each spawn gets its own freshly-derived bundle.
    fn derive_bundle(p_slot: u32) -> ArchivalPKeys {
        derive_archival_p_keys(
            &TEST_SEED,
            DerivationNetwork::Mainnet,
            SeedFormat::Bip39,
            p_slot,
        )
        .expect("oracle derivation succeeds for mainnet/bip39")
    }

    /// Spawn a handle over a pre-derived derive-forward set: `held` slots, of
    /// which `bonded` carry a live bond, with optional initial `active` slot.
    fn spawn_over(held: &[u32], bonded: &[u32], active: Option<u32>) -> StakeEngineHandle {
        let bundles: BTreeMap<PSlot, ArchivalPKeys> =
            held.iter().map(|&s| (PSlot(s), derive_bundle(s))).collect();
        let bonded: BTreeSet<PSlot> = bonded.iter().map(|&s| PSlot(s)).collect();
        StakeEngineHandle::spawn(bundles, bonded, active.map(PSlot))
    }

    /// The genesis-frozen `hybrid_bond_id` canonical bytes for a slot, computed
    /// directly via the derivation oracle.
    fn oracle_bond_id(p_slot: u32) -> Vec<u8> {
        derive_bundle(p_slot)
            .hybrid_bond_id()
            .to_canonical_bytes()
            .expect("derived bond id is canonical")
    }

    fn bond_id_bytes(identity: &PersonaIdentity) -> Vec<u8> {
        identity
            .bond_id
            .to_canonical_bytes()
            .expect("persona bond id is canonical")
    }

    /// Mint a handle for `slot` and activate it, returning the public identity.
    /// The common caller flow: a handle authorizes exactly one activation.
    async fn mint_and_activate(
        handle: &StakeEngineHandle,
        slot: u32,
    ) -> Result<PersonaIdentity, StakeEngineError> {
        let h = handle.mint_handle(PSlot(slot)).await?;
        handle.activate_persona(h).await
    }

    // §10.1 — an actor spawned with no initial active slot is idle.
    #[tokio::test]
    async fn idle_actor_has_no_active_persona() {
        let handle = spawn_over(&[0, 1], &[], None);
        let active = handle
            .active_persona()
            .await
            .expect("active query succeeds");
        assert!(active.is_none(), "no initial active slot ⇒ idle");
    }

    // §10.1 — activating a held persona projects its public identity, which
    // matches the genesis-frozen derivation oracle.
    #[tokio::test]
    async fn activate_returns_genesis_frozen_identity() {
        let handle = spawn_over(&[0], &[], None);
        let oracle0 = oracle_bond_id(0);

        let identity = mint_and_activate(&handle, 0)
            .await
            .expect("activation of a held persona");
        assert_eq!(identity.p_slot, PSlot(0));
        assert_eq!(
            bond_id_bytes(&identity),
            oracle0,
            "actor projects the genesis-frozen bond identity"
        );

        let active = handle
            .active_persona()
            .await
            .expect("active query succeeds")
            .expect("a persona is active after activation");
        assert_eq!(active.p_slot, PSlot(0));
        assert_eq!(bond_id_bytes(&active), oracle0);
    }

    // §10.1 robustness #3 — identity is deterministic across a respawn: a fresh
    // actor over a fresh derivation of the same slot projects byte-identical
    // identity. The runtime consumer of the `ARCHIVAL_P_DERIVE_V1` freeze.
    #[tokio::test]
    async fn identity_is_deterministic_across_respawn() {
        let first = {
            let handle = spawn_over(&[0], &[], None);
            bond_id_bytes(&mint_and_activate(&handle, 0).await.expect("activate 0"))
            // handle (and its actor) drop here
        };
        let second = {
            let handle = spawn_over(&[0], &[], None);
            bond_id_bytes(&mint_and_activate(&handle, 0).await.expect("activate 0"))
        };
        assert_eq!(
            first, second,
            "re-deriving the same slot from the same seed must be byte-identical"
        );
    }

    // Minting a handle for a slot outside the held derive-forward set is the
    // real domain error `LookaheadExhausted` (reopen to extend the lookahead) —
    // not a panic, not a can't-happen.
    #[tokio::test]
    async fn mint_unheld_slot_is_lookahead_exhausted() {
        let handle = spawn_over(&[0, 1], &[], None);
        let err = handle
            .mint_handle(PSlot(7))
            .await
            .expect_err("slot 7 is not held");
        assert!(
            matches!(err, StakeEngineError::LookaheadExhausted { requested } if requested == PSlot(7)),
            "expected LookaheadExhausted{{7}}, got {err:?}"
        );
    }

    // §10.1 robustness #2 — rotation replaces the active persona in a single
    // transition: after rotating to slot 1, slot 1 is the *only* active persona.
    #[tokio::test]
    async fn rotation_replaces_active_persona() {
        let handle = spawn_over(&[0, 1], &[0, 1], None);

        let id0 = mint_and_activate(&handle, 0).await.expect("activate 0");
        let id1 = mint_and_activate(&handle, 1).await.expect("rotate to 1");
        assert_ne!(
            bond_id_bytes(&id0),
            bond_id_bytes(&id1),
            "distinct slots project distinct personas"
        );
        assert_eq!(id1.p_slot, PSlot(1));

        let active = handle
            .active_persona()
            .await
            .expect("active query")
            .expect("a persona is active");
        assert_eq!(active.p_slot, PSlot(1));
        assert_eq!(bond_id_bytes(&active), bond_id_bytes(&id1));
    }

    // Typed contract #4 — rotation wipes the retired *ephemeral* persona: after
    // rotating away from an unbonded slot, that slot is no longer held, so a
    // subsequent mint is `LookaheadExhausted`.
    #[tokio::test]
    async fn rotation_wipes_ephemeral_retired() {
        let handle = spawn_over(&[0, 1], &[], None); // both ephemeral

        mint_and_activate(&handle, 0).await.expect("activate 0");
        mint_and_activate(&handle, 1)
            .await
            .expect("rotate to 1 (wipes ephemeral 0)");

        let err = handle
            .mint_handle(PSlot(0))
            .await
            .expect_err("retired ephemeral slot 0 was wiped");
        assert!(
            matches!(err, StakeEngineError::LookaheadExhausted { requested } if requested == PSlot(0)),
            "expected LookaheadExhausted{{0}} after ephemeral wipe, got {err:?}"
        );

        let active = handle
            .active_persona()
            .await
            .expect("active query")
            .expect("slot 1 active");
        assert_eq!(active.p_slot, PSlot(1));
    }

    // Typed contract #4 — rotation keeps a retired *bonded* persona resident:
    // unbonding it later stays reachable, so it can be re-activated after a
    // rotation that passed over it.
    #[tokio::test]
    async fn rotation_keeps_bonded_retired() {
        let handle = spawn_over(&[0, 1], &[0], None); // slot 0 bonded, slot 1 ephemeral

        let id0 = mint_and_activate(&handle, 0).await.expect("activate 0");
        mint_and_activate(&handle, 1)
            .await
            .expect("rotate to 1 (bonded 0 stays)");

        // Slot 0 is still held — re-mintable and re-activatable.
        let id0_again = mint_and_activate(&handle, 0)
            .await
            .expect("bonded slot 0 survived the rotation");
        assert_eq!(
            bond_id_bytes(&id0_again),
            bond_id_bytes(&id0),
            "re-activated bonded persona is the same identity"
        );
    }

    // Typed contract #2 — a handle minted before a rotation is stale afterward:
    // the rotation advanced the actor's generation, so the retained handle is
    // rejected rather than acting against a possibly-wiped persona.
    #[tokio::test]
    async fn stale_handle_after_rotation_is_rejected() {
        // Both bonded so the rotation cannot wipe — isolating the generation
        // guard from the membership guard.
        let handle = spawn_over(&[0, 1], &[0, 1], None);

        // Mint a handle for slot 0 up front, then rotate via a *different*
        // handle, leaving the slot-0 handle straddling the rotation.
        let stale = handle.mint_handle(PSlot(0)).await.expect("mint slot 0");
        mint_and_activate(&handle, 1)
            .await
            .expect("rotate to 1 (advances generation)");

        let err = handle
            .activate_persona(stale)
            .await
            .expect_err("a handle retained across a rotation is stale");
        assert!(
            matches!(err, StakeEngineError::StaleHandle),
            "expected StaleHandle, got {err:?}"
        );
    }

    // Activating the already-active slot is idempotent (same identity, no error,
    // no generation advance — the handle's generation still matches).
    #[tokio::test]
    async fn activate_same_slot_is_idempotent() {
        let handle = spawn_over(&[2], &[], Some(2));
        let a = mint_and_activate(&handle, 2).await.expect("activate 2");
        let b = mint_and_activate(&handle, 2).await.expect("re-activate 2");
        assert_eq!(bond_id_bytes(&a), bond_id_bytes(&b));
    }

    // Require-ambient spawn contract: without an ambient Tokio runtime, `spawn`
    // panics with the contract message. Plain `#[test]` precisely *because* it
    // must run with no ambient runtime.
    #[test]
    #[should_panic(expected = "requires an ambient Tokio runtime")]
    fn spawn_without_ambient_runtime_panics() {
        let _handle = StakeEngineHandle::spawn(BTreeMap::new(), BTreeSet::new(), None);
    }

    // Mailbox `Send` contract (structural): message + reply types are `Send` as
    // kameo requires.
    #[test]
    fn message_and_reply_types_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<MintPersonaHandle>();
        assert_send::<ActivatePersona>();
        assert_send::<ActivePersona>();
        assert_send::<PersonaHandle>();
        assert_send::<PersonaIdentity>();
        assert_send::<StakeEngineError>();
    }

    /// Test-only message whose handler panics, to exercise the fail-stop path.
    struct InjectPanic;

    impl Message<InjectPanic> for StakeEngine {
        type Reply = ();

        async fn handle(
            &mut self,
            _msg: InjectPanic,
            _ctx: &mut Context<Self, Self::Reply>,
        ) -> Self::Reply {
            panic!("test-injected panic: exercise fail-stop");
        }
    }

    // Panic → fail-stop → terminal, non-retryable `StakeActorUnavailable`.
    // Injects a panic; asserts the actor dies and that *repeated* calls all
    // collapse to the terminal error (a retry never recovers).
    #[tokio::test]
    async fn panic_fail_stops_and_calls_are_terminally_unavailable() {
        let handle = spawn_over(&[0], &[], None);

        // Sanity: a live mint+activate works before the panic.
        assert!(mint_and_activate(&handle, 0).await.is_ok());

        // Inject the panic; on_panic → Break (fail-stop). The panicking ask
        // resolves to a transport error as the actor dies.
        let panic_ask = handle.actor.ask(InjectPanic).await;
        assert!(
            panic_ask.is_err(),
            "a panicking handler resolves to an error"
        );
        handle.actor.wait_for_shutdown().await;
        assert!(!handle.actor.is_alive(), "panic fail-stops the actor");

        // Terminal + non-retryable across the message surface.
        for attempt in 0..3 {
            let err = handle
                .mint_handle(PSlot(0))
                .await
                .expect_err("post-death mint fails");
            assert!(
                matches!(err, StakeEngineError::StakeActorUnavailable),
                "attempt {attempt}: expected StakeActorUnavailable, got {err:?}"
            );
        }
        let err = handle
            .active_persona()
            .await
            .expect_err("post-death query fails");
        assert!(matches!(err, StakeEngineError::StakeActorUnavailable));
    }
}
