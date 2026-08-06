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
//! never the root. Activation switches the active bundle and wipes the retired one
//! — it never re-acquires the seed. Lookahead-exhaustion and first-stake-mid-
//! session collapse onto **reopen** (re-runs `assemble()` with the transient
//! seed); there is no re-auth/KEK machinery.
//!
//! ## Why the *bonded union*, not a clean lookahead window
//!
//! The archival model moves the active slot *while bonded*: a retired persona's bonds sit
//! on-chain as dormant balances (no simultaneous wire activity → the firewall
//! permits it), and unbonding one later needs that persona's `bond_spend` key.
//! Because the seed is gone after `assemble()`, a persona absent from the
//! pre-derived set is unreachable for the wallet's life — so a retired-but-
//! bonded persona under a bare `{p_slot ..= p_slot+k}` window would brick
//! unbonding. The held set is therefore the **bonded union plus the lookahead**,
//! and activation-wipe wipes **only personas with no live bond** (typed contract
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
//! handle is **operation-scoped** — it carries the actor's activation
//! `generation`, and every activation that wipes a persona advances it, so a
//! handle retained across an activation is rejected ([`StakeEngineError::StaleHandle`])
//! rather than signing against zeroized memory. [`StakeEngineError::LookaheadExhausted`]
//! stays a *real* domain error (the budget is consumed → reopen), distinct from
//! the typed-away can't-happen state.
//!
//! # Atomic activation (§10.1 robustness #2 / §10.9)
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
//! `assemble()` wiring. 2c-2b wires the block-timed placement offset into the
//! [`SignBond`] reply ([`SignedBondPost`] pairs the signed vin with its
//! bond-post offset) and the GF-7 measurement seam (`gf7-hooks`,
//! `docs/design/ARCHIVAL_BOND_2C_GF7_HOOKS.md`). The first live caller (the
//! JoinMarket bond request that consumes a [`PersistedBondTicket`] +
//! [`PersonaHandle`] and dispatches at the planned offsets) lands with the
//! 2c-2a assemble / 2d broadcast wiring. Items not yet wired carry their own
//! `#[allow(dead_code)]` so the dead-code check stays effective and the
//! allows fall away as wiring lands.
//!
//! # No behavioral delta across `gf7-hooks` (hooks-spec §6.5)
//!
//! Feature-on and feature-off builds of this actor are **behaviorally
//! identical** — the §4 layer-3 consequence, held by construction rather
//! than by test:
//!
//! - Every `#[cfg(feature = "gf7-hooks")]` site in this file (grep the
//!   attribute; the set is: the trait imports, one `StakeEngineArgs` field,
//!   one `StakeEngine` field, the `on_start` field forward, the spawn-path
//!   no-op injection, the emission block in the [`SignBond`] handler, and
//!   test code) is either **state that only the emission block reads** or
//!   **the emission block itself**.
//! - The emission block's only statements call
//!   [`BroadcastTimelineObserver::record`], whose return type is `()` — it
//!   cannot feed a value back into the handler. The draw, the degeneracy
//!   guard, the offset computation, the vin signing, and the
//!   [`SignedBondPost`] reply all sit **outside** the `cfg`, unconditioned.
//! - The production observer is the no-op even when the feature is on;
//!   recording observers exist only in `shekyl-staking-sim` (CI-asserted by
//!   the `gf7-no-emit-guard` dependency-graph check).
//!
//! Feature-off therefore removes only code whose effect was already `()`.
//! Empirically corroborated by the test suite running under both feature
//! configurations in CI.
//!
//! [`docs/design/ARCHIVAL_BOND_CONSTRUCTION.md`]: ../../../../../docs/design/ARCHIVAL_BOND_CONSTRUCTION.md
//! [`ArchivalPKeys`]: shekyl_crypto_pq::archival_p::ArchivalPKeys
//! [`PersistedBondTicket`]: super::stake_persist::PersistedBondTicket

use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;
use std::sync::Arc;

use kameo::actor::{Actor, ActorRef, Spawn, WeakActorRef};
use kameo::error::{ActorStopReason, PanicError, SendError};
use kameo::message::{Context, Message};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::Scalar;
use rand_core::RngCore as _;
use shekyl_archival_bond_builder::{build_join_market_vin, BondBuildError, JoinMarketVin};
use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
use shekyl_archival_retention::{
    bond_floor, emission_vin_verify_auth, emission_vin_verify_backing, epoch_is_claim_expired,
    ArchivalRewardEmissionVin, HoldingsDescriptor, MembershipOnlyBacking, RewardCommit,
};
use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_crypto_pq::derivation::{
    derive_output_secrets, derive_pqc_public_key, hash_pqc_public_key,
};
use shekyl_crypto_pq::kem::HybridCiphertext;
use shekyl_crypto_pq::multisig::SINGLE_SIG_CANONICAL_LEN;
use shekyl_crypto_pq::output::{construct_output, recover_combined_ss, sign_pqc_auth_for_output};
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, HybridPublicKey, SignatureScheme as _};
use shekyl_curve_generators::biased_hash_to_point;
use shekyl_engine_state::pscan_state::PFundingOutputRecord;
use shekyl_scanner::extra::Extra;
use shekyl_scanner::{GuaranteedScanner, ScannableBlock};
use shekyl_standoff::draw::{draw_entry_gap, GapRng};
#[cfg(feature = "gf7-hooks")]
use shekyl_standoff::gf7::{BroadcastTimelineObserver, NoOpObserver, TimelineEvent};
use shekyl_tx_builder::{
    phase1_payload_hashes, prove_backing_membership, sign_pqc_auths, sign_transaction_with_terms,
    tx_prefix_hash_from_parts_with_extra, InputTerm, LeafEntry, PqcAuth, SpendInput, TreeContext,
    WireEncodeInput,
};
use shekyl_types::{GlobalOutputIndex, PCanonicalId, SettlementEpoch};
use shekyl_units::AtomicUnits;
use shekyl_wire::Input;
use zeroize::Zeroizing;

use super::backing_set::ClaimOperands;
use super::bond_assembly::{
    finalize_bond_tx, wire_bond_post_input, BondAssemblyError, FundingInputContext, PBoundBytes,
};
use super::drain_assembly::{assemble_drain_tx, AssembleDrain, AssembledDrain, DrainAssemblyError};
use super::emission_claim::{
    assemble_claims, derive_claimable_epochs, self_check_claims, EmissionClaimError,
    EMISSION_CLAIMS_SIZE_BUDGET,
};
use super::error::KeyEngineError;
use super::pscan::persona_scanner::{guaranteed_scanner_for_persona, PersonaScanError};
use super::pscan::scan_step::{
    run_dual_extractor, BlockRange, DualExtractError, DualExtractOutput, FundingOutputMatch,
    KeyImageWatchSet, ScanStep, ScanStepResult, SpentFundingMatch,
};
use super::stake_timing::{OsRngGapAdapter, DEFAULT_ENTRY_GAP};
use super::traits::key::SourceSecretsBundle;
use super::{Network, ShekylAddress};

// S6 / DQ3 — the session RNG self-cert grader (`shekyl-standoff` `conformance`)
// is gated to **`x86_64` exactly** (the guard below is `target_arch = "x86_64"`,
// matching the `x86_64`-only CI conformance lane and the standoff conformance
// lane it mirrors): its goodness-of-fit is float, which is not bit-identical
// across architectures, and `x86_64` is the only target the diagnostic is built
// and run on. Rather than silently compile the self-cert out on a non-`x86_64`
// target (which would let a `--features conformance` diagnostic build report
// "conformance passed" when the grade never ran — false assurance), fail the
// build loudly: a diagnostic build that cannot run the diagnostic must say so at
// compile time, not pretend success at runtime. With this guard, `conformance`
// implies `x86_64`, so the self-cert call below needs only `cfg(feature)`.
#[cfg(all(feature = "conformance", not(target_arch = "x86_64")))]
compile_error!(
    "the StakeEngine session RNG self-cert grader (shekyl-standoff `conformance`) \
     is `x86_64`-only — its float goodness-of-fit is not bit-identical across \
     architectures. Build the `conformance` feature on `x86_64` (where the CI \
     conformance lane runs); do not enable it on other targets (including 32-bit \
     x86)."
);

// ---------------------------------------------------------------------------
// Typed domain values
// ---------------------------------------------------------------------------

/// Archival persona slot index.
///
/// Persona-slot ordinal — re-exported from [`shekyl_types::PSlot`] so the
/// stake-engine surface and the persisted pscan funding records share one
/// domain type (WI-2 domain-newtype carrier).
pub(crate) use shekyl_types::PSlot;

/// How many slots past the current cursor `assemble()` pre-derives into the
/// held set (`ARCHIVAL_BOND_CONSTRUCTION.md` §10.2, Model D).
///
/// # Rationale and bounds (`75-system-autonomy.mdc`)
///
/// `k` is the one tuning knob of Model D. The derive-forward set at open is
/// `{persisted bonded slots} ∪ {cursor ..= cursor + k}`: the bonded slots are
/// reachable for unbonding, and the `k`-slot window covers activations that
/// happen *during* the session without re-acquiring the seed. Activation is
/// sequential (`i → i+1`), so a window of `k` future slots covers `k` in-session
/// activations before the lookahead is exhausted and the wallet must be reopened
/// (the root-free recovery path) to derive further.
///
/// - **Lower bound.** `k = 0` degenerates to "reopen to activate" — still
///   correct and root-free, but every activation costs a reopen.
/// - **Upper bound.** Each unit of `k` is one extra PQ keygen at open and one
///   extra resident `ArchivalPKeys` bundle; the cost is linear in `k` and paid
///   only by stakers. Large `k` widens the memory blast radius (held derived
///   personas) without benefit, since most sessions move the active slot at most once.
/// - **Chosen value `2`.** Most sessions use one persona and move the active slot at most
///   once; `k = 2` covers the common case (current + two in-session activations)
///   with a two-bundle resident cost. Raising it is a one-line change reviewed
///   against this rationale.
pub(crate) const ARCHIVAL_PERSONA_LOOKAHEAD: u32 = 2;

/// A held persona bundle tagged by whether it carries a **live bond**.
///
/// This is **typed contract #4** ([`ARCHIVAL_BOND_CONSTRUCTION.md`] §10.2):
/// activation-wipe must wipe only personas with *no* live bond, because a
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
    /// the activation-wipe path accepts.
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

/// Wipe a **retired** (terminal) bonded persona — the DQ8 exception to typed
/// contract #4.
///
/// Takes a [`BondedPersona`] by value. It is the *only* path that wipes a bonded
/// persona, and it is reached only through the witness-gated retire handler
/// ([`RetireBondedPersona`]) — so a bonded persona is wiped **only** on
/// positively-confirmed terminal evidence (`Unbond` + `W`-lapse + finality-deep),
/// never on absence. The bundle's per-field `ZeroizeOnDrop` runs at the drop.
#[allow(dead_code)] // transient — the SP-5 retire path is the consumer.
fn wipe_bonded(persona: BondedPersona) {
    drop(persona);
}

/// Positive-confirmation evidence that a bonded persona is **terminal** and may
/// leave the scan union (2d-1 DQ8).
///
/// Constructible only when the retirement predicate holds, so a witness *existing*
/// is proof the persona is retire-eligible — and since the actor has no chain to
/// re-verify against, the witness **is** the guard. Mirrors the
/// [`PersistedBondTicket`](super::stake_persist::PersistedBondTicket) /
/// [`PersonaHandle`] evidence-typestate pattern. The discipline is the same
/// positive-confirmation, never-absence rule as SP-6's GC and SP-7's
/// `AbsentVerified`: a *wrong* retire wipes a still-live persona's `bond_spend`
/// key → can't unbond → **stuck funds**, the exact mirror of a wrongful GC, which
/// the conservative predicate guards against.
#[allow(dead_code)] // transient — the SP-5 scan task builds it; the retire handler consumes it.
pub(crate) struct RetirementWitness {
    /// The cleartext canonical id of the persona to retire (from its confirmed
    /// `Unbond` bond-post). The actor matches it against the bonded union.
    p_canonical_id: PCanonicalId,
}

#[allow(dead_code)] // transient — the SP-5 scan task is the lib consumer.
impl RetirementWitness {
    /// Build a witness **iff** the persona is retire-eligible: a *confirmed*
    /// `Unbond` whose **last creditable epoch has fallen out of the consensus
    /// claim window**. Returns `None` otherwise — never retire a persona that can
    /// still claim, which would wipe its `bond_spend` key while live reward
    /// collateral remains (stuck funds).
    ///
    /// The boundary is the consensus claim window itself, not a hand-computed
    /// `current − U ≥ W`: it calls [`epoch_is_claim_expired`], the **same**
    /// predicate the claim check uses — so an off-by-one (which would wipe a
    /// still-claimable persona) is structurally impossible, and the in-progress
    /// epoch can't be used by accident (`settled_epoch` is a *finalized* epoch).
    ///
    /// `e_last` is the persona's last creditable epoch; the scan passes the
    /// **conservative** `e_last = unbond_epoch` (a late retire only wastes a little
    /// scan work, an early one is stuck funds, so round toward later). **Finality**
    /// is guaranteed upstream — the scan surfaces bond-posts only from behind the
    /// cursor's reorg horizon, so a witnessed `Unbond` is already finality-deep.
    pub(crate) fn from_confirmed_unbond(
        p_canonical_id: PCanonicalId,
        e_last: SettlementEpoch,
        settled_epoch: SettlementEpoch,
    ) -> Option<Self> {
        epoch_is_claim_expired(e_last.to_raw(), settled_epoch.to_raw())
            .then_some(Self { p_canonical_id })
    }
}

/// What the witness-gated retire ([`RetireBondedPersona`]) did. All outcomes are
/// valid (no error): the retire is **idempotent** — re-handing the same witness
/// after the persona is gone is a no-op ([`Self::NotHeld`]).
#[allow(dead_code)] // transient — the SP-5 scan task is the lib consumer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RetireOutcome {
    /// The bonded persona was found and wiped from the union.
    Retired { slot: PSlot },
    /// No bonded persona matched the witness — already retired this session, or
    /// never held (idempotent no-op).
    NotHeld,
    /// The matching persona is the **active** slot; left in place. A terminal
    /// persona should not be active, but if it is we do not wipe it mid-use — the
    /// next activation moves `active` away and the retire re-fires.
    SkippedActive { slot: PSlot },
    /// The matching persona's slot still holds **unspent funding outputs**; left
    /// in place (the **funded-gate**). Wiping it would strand spendable `P`
    /// funds: the wipe is irreversible and the open path stops deriving a retired
    /// slot, so the funds behind the slot's keys become unrecoverable. The retire
    /// re-fires on a later sweep once the funding is drained (arm #1 prunes the
    /// last funding output on its spend).
    SkippedFunded { slot: PSlot },
}

/// The set of `P` slots that still hold **unspent** funding outputs — the
/// operand of the retire handler's funded-gate.
///
/// A persona whose slot is in this set is **not truly terminal**: spendable
/// value remains behind its keys, so the witness-gated retire must never wipe
/// it (the wipe is irreversible and the open path stops deriving a retired
/// slot). The claim-window witness guards the *reward-collateral* stuck-funds
/// dimension; this set guards the complementary *funding-output* dimension.
///
/// Redacting `Debug` and no `Serialize` (the `funding_outputs` discipline): the
/// membership — which of `P`'s slots hold live value — is persona-correlating
/// funding history and must not reach a clear log or a wire.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct FundedSlots(BTreeSet<PSlot>);

impl FundedSlots {
    /// Build the set from the slots of the accrual's unspent funding outputs.
    pub(crate) fn from_slots(slots: impl IntoIterator<Item = PSlot>) -> Self {
        Self(slots.into_iter().collect())
    }

    /// True if `slot` still holds unspent funding (retire must be deferred).
    pub(crate) fn contains(&self, slot: PSlot) -> bool {
        self.0.contains(&slot)
    }
}

impl std::fmt::Debug for FundedSlots {
    /// Redacted — the funded-slot set is `P` funding history (see the type docs).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FundedSlots(<redacted funding-history>)")
    }
}

/// An operation-scoped capability to **activate** a held persona (typed
/// contract #2).
///
/// Minted only by [`MintPersonaHandle`] for a slot actually in the held set, so
/// "activate an unheld persona" has no expressible form — the membership check
/// lives at the single slot→handle boundary, not at every use site. The handle
/// carries the actor's activation [`generation`](StakeEngine::generation) at mint
/// time, and [`ActivatePersona`] consumes it **by value**: a handle authorizes
/// exactly one activation.
///
/// **Operation-scoped, two ways.** An activation (an activation that changes the
/// active slot) advances the generation, so any handle minted before it is
/// stale ([`StakeEngineError::StaleHandle`]); and the activation removes the wiped
/// ephemeral persona from the held set, so even a same-generation handle to it
/// fails the membership check. A handle therefore cannot outlive the operation
/// that minted it, which is what makes "sign against wiped memory" unexpressible.
///
/// Signing (2c-2b) does **not** retain a handle across the activation: it targets
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

/// Always-on compile-time guard: the two operation capability tokens
/// ([`PersonaHandle`], [`PersistedBondTicket`]) must remain **single-use** —
/// neither `Clone` nor `Copy`. Their single-use-ness is what makes "use an
/// unheld persona" (typed contract #2) and "sign before persist" (typed
/// contract #1) unrepresentable: a token is consumed *by value* by `sign_bond`
/// and cannot be duplicated to bypass the consumption.
///
/// This replaces the originally-planned `trybuild` compile-fail tests for S7(c)
/// (`ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md` §4 R0-D# finding): `trybuild` compiles
/// each case as an **external** crate, which cannot name these `pub(crate)`
/// firewall types without a re-export that would itself re-expose the internals
/// the firewall exists to encapsulate. The enforcement is the type system —
/// module-private fields + `!Clone` + by-value consumption — which holds for
/// **all** code unconditionally, a stronger guarantee than any external
/// snapshot. This `const _` block is the regression guard that the `!Clone`
/// half of that guarantee is never silently weakened by a careless
/// `#[derive(Clone)]`. It is a zero-cost compile-time check (no runtime, no
/// dependency); it is the inlined equivalent of
/// `static_assertions::assert_not_impl_all!`.
///
/// If either token gains a `Clone`/`Copy` impl, the `AmbiguousIfImpl`
/// resolution below becomes ambiguous and the crate fails to compile.
const _: fn() = || {
    trait AmbiguousIfImpl<A> {
        fn token_must_stay_single_use() {}
    }
    impl<T> AmbiguousIfImpl<()> for T {}
    #[allow(dead_code)]
    struct Invalid;
    impl<T: Clone> AmbiguousIfImpl<Invalid> for T {}

    // Resolves uniquely iff the type is NOT `Clone`; ambiguous (compile error)
    // if a `Clone` impl is ever added.
    let _ = <PersonaHandle as AmbiguousIfImpl<_>>::token_must_stay_single_use;
    let _ = <super::stake_persist::PersistedBondTicket as AmbiguousIfImpl<_>>::token_must_stay_single_use;
};

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
            p_slot: PSlot::from_raw(keys.p_slot),
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
    /// lookahead budget `{p_slot ..= p_slot+k}` is consumed (moved past the
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

    /// A [`PersonaHandle`] was presented after an activation advanced the actor's
    /// generation — i.e. it was retained across the activation that is its own
    /// separate operation (typed contract #2: handles are operation-scoped). The
    /// persona it named may have been wiped; using it would risk a use-after-
    /// wipe, so it is rejected. Non-terminal: mint a fresh handle and retry.
    #[error("stale persona handle: re-mint a handle (an activation occurred since it was issued)")]
    StaleHandle,

    /// The OS entropy source failed to supply bytes for the entry-gap timing draw
    /// (`SignBond`, S5 / Round 3). A bond-timing draw requires a functional CSPRNG;
    /// a source failure is fail-loud and terminal for this request — no silent
    /// fallback to a weaker source. The cause may be **transient** (very early
    /// boot, before the entropy pool is seeded) or **persistent** (a sandbox /
    /// seccomp policy or permission restriction blocking the `getrandom` syscall);
    /// the underlying `rand_core::Error` is retained as the error `source()` so an
    /// operator can tell which — the prior message presumed a transient cause and
    /// wrongly implied a retry would always help.
    #[error(
        "entry-gap draw failed: the OS entropy source is unavailable ({0}); \
         cause may be transient (early boot) or persistent (sandbox/seccomp or \
         permission restriction) — a retry helps only in the transient case"
    )]
    RngSourceFailed(#[source] rand_core::Error),

    /// The entry-gap timing draw was statistically degenerate (`SignBond`, S5 /
    /// Round 3 — double-jitter-trap detection). Two consecutive draws from the
    /// same RNG produced identical spreads, which is the signature of a stuck
    /// or non-random source. The draw is rejected; a correct CSPRNG produces
    /// consecutive equal spreads with probability ≈ 1/601 — a single retry
    /// resolves an unlucky-but-correct draw. Multiple consecutive `RngDegeneracy`
    /// errors indicate a broken entropy source.
    #[error(
        "entry-gap draw degenerate: consecutive spreads were equal (stuck-RNG guard); \
         retry the bond request"
    )]
    RngDegeneracy,

    /// The [`PersonaHandle`] and [`PersistedBondTicket`] passed to [`SignBond`]
    /// name different persona slots. A ticket witnesses the durable persist for a
    /// *specific* slot; it cannot authorize signing for any other slot.
    /// Non-terminal: ensure both are obtained for the same `p_slot`.
    #[error(
        "sign-bond slot mismatch: handle names slot {handle_slot:?}, \
         ticket names slot {ticket_slot:?}; both must name the same persona slot"
    )]
    SlotMismatch {
        handle_slot: PSlot,
        ticket_slot: PSlot,
    },

    /// Bond construction failed after the actor validated the handle and ticket
    /// (`SignBond`, S2). The persona bundle was available but
    /// [`build_join_market_vin`] returned an error — see the wrapped
    /// [`BondBuildError`] for the specific cause (`BondFloorZero`,
    /// `IdentityEncode`, or `Sign`).
    #[error("bond construction failed: {0}")]
    BondBuild(#[from] BondBuildError),

    /// A WI-2 [`AssembleBond`] pipeline step failed — funding arithmetic,
    /// spend-bundle derivation, output construction, proving, PQC auth
    /// signing, wire encoding, or the A-1 prefix↔vin invariant. The wrapped
    /// [`BondAssemblyError`] names the §3.6 failure mode; in every arm
    /// nothing was persisted and no funding was reserved.
    #[error("bond assembly failed: {0}")]
    Assembly(#[from] BondAssemblyError),

    /// Building the bonded union's transient scanners for a [`ScanStep`] failed —
    /// a resident persona key was malformed (corrupted in-memory state). Fail
    /// closed and loud rather than scan with a silently-weakened key (DQ7). The
    /// concrete cause (scanner build vs canonical-id encode) is preserved in the
    /// wrapped [`ScanSetupError`], including its `source()` chain.
    #[error("persona scan setup failed: {0}")]
    ScanSetup(#[from] ScanSetupError),

    /// The offloaded dual extraction itself failed (oversized step, range/block
    /// mismatch, a scan error, or a funding-inflow overflow). The privacy
    /// parameter `C_min` rides on this scan, so a corrupted step fails closed,
    /// never silently.
    #[error("scan-step extraction failed: {0}")]
    ScanStep(#[from] DualExtractError),

    /// The `spawn_blocking` task running the dual extractor failed to join (it
    /// panicked — `spawn_blocking` tasks are not cancellable). The structured
    /// [`JoinError`](tokio::task::JoinError) is kept (panic payload + `source()`),
    /// not stringified, so the failure is fully diagnosable.
    #[error("scan-step task failed to join: {0}")]
    ScanJoin(#[from] tokio::task::JoinError),

    /// An [`AssembleEmissionClaim`] claim-side step refused or failed —
    /// derivation boundaries, size bounding, or the step-7 self-check. The
    /// wrapped [`EmissionClaimError`] keeps the CB-5 taxonomy (including the
    /// cause-blind `SelfCheckFailed` arm). Nothing was persisted and no
    /// funding was reserved.
    #[error("emission claim: {0}")]
    EmissionClaim(#[from] EmissionClaimError),

    /// An [`AssembleDrain`] (F-D2 DS-PR-1) pipeline step refused or failed —
    /// payment-parameter validation, funding arithmetic, output construction,
    /// proving, PQC auth signing, or wire encoding. The wrapped
    /// [`DrainAssemblyError`] names the failure; the drain path owns its own
    /// taxonomy (not the bond's) so a value-out failure never mis-reports as
    /// "bond assembly". Nothing was persisted and no funding was reserved.
    #[error("drain assembly: {0}")]
    DrainAssembly(#[from] DrainAssemblyError),
}

/// The bonded union's transient scan inputs (SP-3 dual extractor): one
/// slot-tagged [`GuaranteedScanner`] per bonded persona plus their cleartext
/// `p_canonical_id` → slot map (the id half drives the bond-post match; the
/// slot half attributes a matched `BondPost` to the recovered output's own
/// persona for GF-4b lineage classification,
/// `ARCHIVAL_GF4B_BACKING_LINEAGE.md` §3.3). Built per [`ScanStep`] and
/// dropped with it (DQ5).
pub(crate) type BondedScanInputs = (Vec<(u32, GuaranteedScanner)>, BTreeMap<PCanonicalId, u32>);

/// Why building a [`ScanStep`]'s bonded-union scan inputs failed. Both arms are a
/// **malformed resident persona key** (corrupted in-memory state) — fail closed,
/// concrete cause preserved (vs a stringified loss). Wrapped by
/// [`StakeEngineError::ScanSetup`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum ScanSetupError {
    /// Building a persona's guaranteed scanner failed (SP-1 fail-closed rejection
    /// of malformed key material).
    #[error("building a persona's guaranteed scanner failed: {0}")]
    Scanner(#[source] PersonaScanError),
    /// Deriving a persona's canonical id failed — its hybrid public key did not
    /// canonically encode.
    #[error("deriving a persona's canonical id failed: {0}")]
    CanonicalId(#[source] shekyl_crypto_pq::CryptoError),
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
    /// [`HeldPersona::Bonded`] so activation never wipes them; the rest are
    /// [`HeldPersona::Ephemeral`]. A reconcilable hint, not consensus truth.
    pub bonded: BTreeSet<PSlot>,
    /// The initially-active slot (the scan-reconciled monotone current slot), or
    /// `None` when the wallet is staker-flagged but has not activated a persona.
    /// Must be present in `bundles` when `Some` (the orchestrator guarantees the
    /// current slot is in the derive-forward set).
    pub active: Option<PSlot>,
    /// **Test + conformance only.** Selects the `on_start` session self-cert (S6)
    /// behavior. Defaults to [`TestSelfCert::Skip`] so the bulk of the stake
    /// tests — which are **not** about the self-cert — do not run a real ~15 ms
    /// statistical grade in every spawn: that is both slow and, because the
    /// uniformity chi-square has a nonzero false-positive rate at α=1e-6, an
    /// occasional-flake source (a stray false-fail kills the actor and cascades
    /// into unrelated assertions). The dedicated S6 tests opt in explicitly. The
    /// field exists only in `test + conformance` builds. In a **non-test
    /// `conformance`** build the self-cert always runs (the real `OsRng` grade,
    /// no selector); in the **default** build the self-cert is compiled out
    /// entirely and there is no grade.
    #[cfg(all(test, feature = "conformance"))]
    pub self_cert: TestSelfCert,
    /// GF-7 measurement-hook observer (`ARCHIVAL_BOND_2C_GF7_HOOKS.md` §3) —
    /// **injected**, `ScanSchedule`-discipline: no hardwired sink. Every
    /// production construction path injects [`NoOpObserver`]; only the sim
    /// (via a direct `StakeEngineArgs`, never a production spawn) constructs
    /// a recording one. Exists only under the non-default `gf7-hooks` feature
    /// (the §4 layer-3 no-emit containment); the default build carries no
    /// field, no calls, no vocabulary.
    #[cfg(feature = "gf7-hooks")]
    pub observer: Box<dyn BroadcastTimelineObserver>,
}

/// Test-only selector for the S6 session self-cert (see [`StakeEngineArgs`]).
#[cfg(all(test, feature = "conformance"))]
#[derive(Clone, Copy, Default)]
pub(crate) enum TestSelfCert {
    /// Skip the self-cert entirely (default — every stake test that is not about
    /// the self-cert, so the real grade's α=1e-6 false-positive cannot flake them).
    #[default]
    Skip,
    /// Grade the real `OsRng` adapter (the S6 pass-path test).
    RealOsRng,
    /// Grade a degenerate constant source to force fail-stop (the S6 fail test).
    Degenerate,
}

/// The `kameo` actor owning the held archival personas (the derive-forward
/// set), **not** the master seed.
///
/// The single-threaded message loop serializes access to `held`/`active`, so a
/// activation (install-new-active, then wipe-retired-iff-ephemeral) is atomic with
/// respect to other messages.
#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
pub(crate) struct StakeEngine {
    /// The held derive-forward set, keyed by slot and tagged bonded/ephemeral.
    /// Activation wipes only the ephemeral retired slot; bonded personas stay
    /// resident so unbonding remains reachable.
    held: BTreeMap<PSlot, HeldPersona>,
    /// The currently-active slot, or `None` when idle. Always a key of `held`
    /// when `Some`.
    active: Option<PSlot>,
    /// Activation generation. Advances on every activation that changes `active`,
    /// invalidating every [`PersonaHandle`] minted before it — the mechanism
    /// behind operation-scoped handles (typed contract #2).
    generation: u64,
    /// SP-R0 arm #1 (DQ-A): the key-image watch cache — key images of `P`'s
    /// held, unspent funding outputs, derived in-actor from the vault.
    /// Refreshed per scan-step from the task's authoritative held list
    /// (derive-on-add / drop-on-prune); **never persisted** — re-derived at
    /// open from the sealed records. Containment is the type's
    /// (redacting `Debug`, no `Serialize`).
    watch_cache: KeyImageWatchSet,
    /// Held records whose watch key-image derivation failed (public prune
    /// keys only). Derivation is deterministic, so re-trying every step would
    /// re-fail identically — and failing the step would wedge the whole scan
    /// pipeline on one bad record. Instead the record is skipped (loudly, see
    /// `absorb_watch_derivation`) until it leaves the held set; sound for the
    /// pruning attestation because the sweep's own derivation of the same
    /// bundle fails the same way, so a quarantined record can never be swept
    /// into a bond post. **Never persisted**; cleared per-record when the
    /// task's held list drops the record.
    watch_quarantine: BTreeSet<shekyl_types::GlobalOutputIndex>,
    /// GF-7 measurement-hook observer (injected via [`StakeEngineArgs`];
    /// see the field docs there). Feature-gated out of default builds.
    #[cfg(feature = "gf7-hooks")]
    observer: Box<dyn BroadcastTimelineObserver>,
}

#[allow(dead_code)] // inert until 2c-2a assemble wiring / 2c-2b request path
impl StakeEngine {
    /// Validate a presented handle: it must be from the current generation and
    /// name a still-held slot. A generation mismatch means an activation occurred
    /// since the handle was minted (operation-scoped contract), so it is stale.
    fn validate_handle(&self, handle: &PersonaHandle) -> Result<(), StakeEngineError> {
        if handle.generation != self.generation {
            return Err(StakeEngineError::StaleHandle);
        }
        // A current-generation handle proves the slot was held at mint, and no wipe has
        // happened since (a wipe advances the generation), so this branch is unreachable by
        // construction. If it *does* fire with a matching generation, a wipe failed to
        // advance the generation — a real invariant bug, NOT an ordinary stale handle.
        // Make it loud in dev rather than silently collapse it into `StaleHandle` (which
        // would mask the distinct failure); still fail closed in release, where
        // `StaleHandle` is the safe response either way.
        if !self.held.contains_key(&handle.p_slot) {
            debug_assert!(
                false,
                "validate_handle: a current-generation handle names an unheld slot \
                 (p_slot={:?}, handle.generation={}, engine.generation={}) — a wipe did not \
                 advance the generation (invariant violation, not a stale handle). The two \
                 generations are equal here by the check above; if they differ, that is the bug.",
                handle.p_slot, handle.generation, self.generation
            );
            return Err(StakeEngineError::StaleHandle);
        }
        Ok(())
    }

    /// Steps 1–5 shared verbatim by the [`SignBond`] and [`AssembleBond`]
    /// handlers: validate the handle, cross-check it against the ticket's slot,
    /// preflight the OS entropy source, draw the guarded entry gap, plan the
    /// entry seam, and emit the GF-7 hooks. Returns the validated handle slot and
    /// the placement plan.
    ///
    /// This is the **single definition** of a security-relevant sequence — the
    /// RNG source preflight, the double-jitter degeneracy guard, the
    /// timing-decorrelation plan, and the observer emission. Both bond handlers
    /// must run it identically; keeping it in one place means a future change to
    /// the draw/guard discipline (a stronger degeneracy check, a new observer
    /// event) lands once rather than silently diverging between two copies and
    /// weakening the timing firewall in the un-updated path with no compile error.
    fn validate_and_draw_bond_offset(
        &mut self,
        handle: &PersonaHandle,
        ticket_slot: PSlot,
    ) -> Result<(PSlot, u64), StakeEngineError> {
        // 1. Validate the handle: generation currency + slot membership.
        self.validate_handle(handle)?;

        // 2. Slot cross-check: tickets witness a specific slot; a ticket cannot
        //    authorize signing for any other slot (even a held one).
        let handle_slot = handle.p_slot;
        if handle_slot != ticket_slot {
            return Err(StakeEngineError::SlotMismatch {
                handle_slot,
                ticket_slot,
            });
        }

        // 3. Preflight the OS entropy source (Round 3 — source failure, fail-loud).
        //    `GapRng::next_u64` is infallible; a source failure therefore must be
        //    caught here via `try_fill_bytes` before calling `draw_entry_gap`.
        //    No silent fallback: source failure → `RngSourceFailed`, not a retry
        //    on a weaker source.
        {
            let mut probe = [0u8; 8];
            rand_core::OsRng
                .try_fill_bytes(&mut probe)
                .map_err(StakeEngineError::RngSourceFailed)?;
            let _ = probe; // consumed; used only to exercise the source
        }

        // 4. Entry-gap draw + per-draw degeneracy guard (S4/S5, Round 2/3).
        //    `draw_entry_gap_guarded` draws twice (spread_draw, spread_probe) and
        //    fires `RngDegeneracy` if they are equal (double-jitter-trap detection).
        //    The actual timing draw result is returned on success.
        let mut rng = OsRngGapAdapter;
        let spread = draw_entry_gap_guarded(DEFAULT_ENTRY_GAP.as_blocks(), &mut rng)
            .map_err(|DegenerateDraw| StakeEngineError::RngDegeneracy)?;
        // S6: the session-level `certify_draw` self-cert (over `OsRngGapAdapter`,
        // gated, at session start) is wired in `on_start` — see
        // `run_session_self_cert` and the `conformance` feature.

        // 5. The bond post fires `spread` blocks after the private intent `t0`.
        //    There is no second event to order and no plan to build: only the
        //    post is chain-attributable, the funding transfer is the unnamed
        //    CT-hidden FCMP++ input (`ARCHIVAL_FIREWALL_GATE6.md` pass-4 (d) +
        //    note 8), so the order coin was retired and the offset *is* the draw.
        let bond_post_offset_blocks = spread;

        // GF-7 hooks-spec §3: emit the draw-consumption and schedule events to
        // the injected observer. Sim-facing only — this block is compiled out
        // of default builds (§4 layer 3), and the production observer is the
        // no-op (§6.1). Payload discipline: opaque wallet-local slot ordinal,
        // block-relative offsets, no wall-clock, no identities.
        #[cfg(feature = "gf7-hooks")]
        {
            let persona = u64::from(handle_slot.to_raw());
            self.observer.record(TimelineEvent::EntryGapDrawConsumed {
                persona,
                window_blocks: DEFAULT_ENTRY_GAP.as_blocks(),
                spread_blocks: spread,
            });
            self.observer.record(TimelineEvent::BondPostScheduled {
                persona,
                bond_post_offset_blocks,
            });
        }

        Ok((handle_slot, bond_post_offset_blocks))
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

    /// Project the held persona at `slot` into its public
    /// [`ShekylAddress`](shekyl_address::ShekylAddress) — built **in-actor**,
    /// from the already-live bundle (never re-derived), from only the public
    /// spend/view pubs + ML-KEM-768 encap key. The reply type is structurally
    /// public-only (an address cannot carry a secret), so **no `P` secret leaves
    /// the actor** (rule 36). The orchestrator uses this only to address a
    /// funding transfer *to* `P` (`Engine::stake_in`), where `P` is a public
    /// recipient. `network` is the principal wallet's network (the actor is
    /// network-agnostic; the address's network is the sender's).
    fn receive_address_of(&self, slot: PSlot, network: Network) -> ShekylAddress {
        let keys = self
            .held
            .get(&slot)
            .expect("receive_address_of called for a held slot")
            .keys();
        ShekylAddress::new(
            network,
            *keys.spend_pk.as_canonical_bytes(),
            *keys.view_pk.as_canonical_bytes(),
            keys.ml_kem_ek.to_vec(),
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

    /// SP-R0 arm #1 (DQ-A) watch upkeep — the cheap, in-actor half of the
    /// refresh against the task's authoritative held-funding list (the
    /// records-driven framing pin). Drop-on-prune: cached (and quarantined)
    /// entries whose gindex is no longer held are dropped. Returns the
    /// derive-on-add candidates — the uncached records whose CPU-heavy
    /// derivation the caller offloads
    /// ([`derive_watch_key_images_offloaded`](Self::derive_watch_key_images_offloaded));
    /// the derivation never runs in the actor's async context (DQ5/DQ6).
    fn watch_upkeep(&mut self, held: &[FundingOutputMatch]) -> Vec<FundingOutputMatch> {
        let held_gindexes: BTreeSet<shekyl_types::GlobalOutputIndex> =
            held.iter().map(|m| m.gindex).collect();
        self.watch_cache.retain_gindexes(&held_gindexes);
        self.watch_quarantine.retain(|g| held_gindexes.contains(g));
        self.watch_derivation_candidates(held)
    }

    /// The subset of `records` whose watch key image still needs deriving:
    /// not yet watched, not quarantined, and owned by a resident-**bonded**
    /// slot. The watched-gindex set is built once, so the pass is
    /// `O(n log n)` in the held count, not the quadratic
    /// scan-per-record it replaces.
    ///
    /// A record whose owning slot is not resident-bonded is skipped, not an
    /// error: a retired persona's funding records are arm #2's retire-time
    /// atomic prune (the records leave with the persona; until then their
    /// spends are unwatchable by construction — the keys are wiped), and a
    /// bonded persona's records always have resident keys.
    fn watch_derivation_candidates(
        &self,
        records: &[FundingOutputMatch],
    ) -> Vec<FundingOutputMatch> {
        let watched = self.watch_cache.watched_gindexes();
        records
            .iter()
            .filter(|m| {
                !watched.contains(&m.gindex)
                    && !self.watch_quarantine.contains(&m.gindex)
                    && matches!(self.held.get(&m.p_slot), Some(HeldPersona::Bonded(_)))
            })
            .cloned()
            .collect()
    }

    /// Derive the watch key images of `records` on a blocking thread: the
    /// per-record hybrid-KEM decapsulation + scalar multiplication must not
    /// run on the async executor — the same DQ5/DQ6 offload discipline as the
    /// extractor, which a catch-up step over a large held set would otherwise
    /// violate for the whole derivation run. The vault is **moved** into the
    /// closure and moved back with the outcomes — never cloned (the secrets
    /// exist once, rule 35/36), and never into the *extractor* closure (the
    /// DQ-A pin: spend material and the scan closure stay separated). The
    /// handler holds `&mut self` across this `await`, so no other message can
    /// observe the actor without its vault.
    ///
    /// Per-record outcomes are values, not early returns: one record's
    /// deterministic derivation failure must not abort the others or the step
    /// (see [`absorb_watch_derivation`](Self::absorb_watch_derivation)).
    async fn derive_watch_key_images_offloaded(
        &mut self,
        records: Vec<FundingOutputMatch>,
    ) -> Vec<(shekyl_types::GlobalOutputIndex, Result<[u8; 32], String>)> {
        let held = std::mem::take(&mut self.held);
        let joined = tokio::task::spawn_blocking(move || {
            let outcomes = records
                .iter()
                .map(|m| {
                    let outcome = match held.get(&m.p_slot) {
                        Some(persona @ HeldPersona::Bonded(_)) => derive_funding_key_image(
                            persona.keys(),
                            m.ciphertext_x25519,
                            &m.ciphertext_ml_kem,
                            m.index_in_transaction,
                            m.output_key,
                        ),
                        // `watch_derivation_candidates` filtered to
                        // resident-bonded slots; a vanished slot here is a
                        // logic error — a per-record failure, never a panic
                        // (the vault must ride back out of this closure).
                        _ => Err("owning slot no longer resident-bonded".to_owned()),
                    };
                    (m.gindex, outcome)
                })
                .collect();
            (held, outcomes)
        })
        .await;
        match joined {
            Ok((held, outcomes)) => {
                self.held = held;
                outcomes
            }
            // The vault moved into the closure and the closure died: the keys
            // unwound (wiped) with it and are unrecoverable. Returning an
            // error would leave a resident actor that scans keyless — a
            // silent DQ7 weakening; fail-stop instead, the actor's documented
            // no-restart panic posture (`on_panic`).
            Err(join_err) => panic!("watch-derivation offload lost the vault: {join_err}"),
        }
    }

    /// Fold one offloaded derivation outcome into the watch (derive-on-add)
    /// or the quarantine, returning the key image on success.
    ///
    /// Quarantine, **not** a step error: the derivation is deterministic
    /// (same record, same vault ⇒ same failure), so failing the step would
    /// permanently wedge the scan pipeline on one bad record — frontier
    /// frozen, balances, bond-post matches, and unbond processing all
    /// stalled. Skipping only this record keeps the wallet syncing, and is
    /// sound for the [`SpentRecordsDurablyPruned`] attestation: assemble
    /// re-derives the same bundle (`derive_spend_parts`) and fails the same
    /// way, so a record the watch cannot derive can never be swept into a
    /// bond post — the duplicate-key-image poison the witness precludes
    /// cannot arise from a quarantined record. Loud (error level, once per
    /// record per residency): a failed derivation is still corrupted-state
    /// evidence.
    fn absorb_watch_derivation(
        &mut self,
        gindex: shekyl_types::GlobalOutputIndex,
        outcome: Result<[u8; 32], String>,
    ) -> Option<[u8; 32]> {
        match outcome {
            Ok(key_image) => {
                self.watch_cache.insert(key_image, gindex);
                Some(key_image)
            }
            Err(reason) => {
                if self.watch_quarantine.insert(gindex) {
                    tracing::error!(
                        gindex = gindex.to_raw(),
                        %reason,
                        "watch key-image derivation failed; record quarantined from the \
                         spent-watch until it leaves the held set (its on-chain spend \
                         will not be observed; assemble of this record fails identically, \
                         so it cannot be swept into a bond post either)"
                    );
                }
                None
            }
        }
    }

    /// Build the bonded union's transient scan inputs for a [`ScanStep`]: a
    /// [`GuaranteedScanner`] per bonded persona (SP-1, burning-bug-immune) plus
    /// their cleartext `p_canonical_id` set (the public half of the SP-3 dual
    /// extractor).
    ///
    /// These are built from the resident bundles and handed straight into the
    /// offload closure: the scanners are transient secret copies dropped at the
    /// end of the scan-step (DQ5), adding no resident secret surface beyond the
    /// keys the actor already vaults. Ephemeral (lookahead, no-bond) personas are
    /// **not** scanned — archival funding accrues only to a persona with a live
    /// bond (the bonded tag is the available signal; SP-6 reconciles it).
    ///
    /// Fails closed if a resident key is malformed: a silently-weakened scanner
    /// would mis-size the privacy parameter `C_min` (DQ7).
    ///
    /// `known_personas` is recomputed here **on purpose**, not cached: it rides
    /// the same loop that rebuilds the transient secret scanners, which *must*
    /// be rebuilt every batch (DQ5). Caching only the public id map would save
    /// one `persona_canonical_id` per bonded persona per batch (marginal, since
    /// bonded personas are few) at the cost of a stale-cache invalidation surface
    /// on a firewall-critical set — a missed invalidation would silently drop a
    /// newly-bonded persona's bond-post matches. Recompute is the safe trade.
    fn bonded_scan_inputs(&self) -> Result<BondedScanInputs, ScanSetupError> {
        let mut scanners = Vec::new();
        let mut known_personas = BTreeMap::new();
        for (slot, held) in &self.held {
            if let HeldPersona::Bonded(_) = held {
                let keys = held.keys();
                // Slot-tagged so the extractor can attribute each recovered
                // output to its owning persona (WI-2 D-A1 funding records).
                scanners.push((
                    slot.to_raw(),
                    guaranteed_scanner_for_persona(keys).map_err(ScanSetupError::Scanner)?,
                ));
                let id = persona_canonical_id(keys).map_err(ScanSetupError::CanonicalId)?;
                known_personas.insert(id, slot.to_raw());
            }
        }
        Ok((scanners, known_personas))
    }

    /// Retire a now-terminal bonded persona (2d-1 DQ8): wipe its key and drop it
    /// from the scan union, identified by the witness's `p_canonical_id`.
    ///
    /// The witness already proves eligibility; this only *applies* it. **Idempotent
    /// and conservative:** a persona already gone is a [`RetireOutcome::NotHeld`]
    /// no-op; the **active** persona is left in place ([`RetireOutcome::
    /// SkippedActive`]) — a terminal persona should not be active, but we never wipe
    /// the active slot mid-use; and a slot that still holds unspent funding is left
    /// in place ([`RetireOutcome::SkippedFunded`], the **funded-gate**) so the
    /// irreversible wipe never strands spendable `P` funds. Only
    /// [`HeldPersona::Bonded`] is matched (an ephemeral persona has no bond to be
    /// terminal).
    fn retire_bonded(
        &mut self,
        witness: &RetirementWitness,
        funded_slots: &FundedSlots,
    ) -> RetireOutcome {
        // Find the bonded persona whose canonical id matches the witness. A key
        // that fails to encode is skipped (it cannot be the match); the scan that
        // produced the witness already encoded it.
        let slot = self.held.iter().find_map(|(slot, held)| match held {
            HeldPersona::Bonded(_) => {
                let id = persona_canonical_id(held.keys()).ok()?;
                (id == witness.p_canonical_id).then_some(*slot)
            }
            HeldPersona::Ephemeral(_) => None,
        });
        let Some(slot) = slot else {
            return RetireOutcome::NotHeld;
        };
        if self.active == Some(slot) {
            return RetireOutcome::SkippedActive { slot };
        }
        // Funded-gate: never wipe a slot that still holds unspent funding. The
        // wipe is irreversible and the open path stops deriving a retired slot,
        // so wiping a funded slot would strand spendable `P` funds. Defer until
        // the funding is drained; the durable pending trigger re-fires the retire.
        if funded_slots.contains(slot) {
            return RetireOutcome::SkippedFunded { slot };
        }
        // Remove + wipe the now-terminal bonded persona. The match re-confirms the
        // `Bonded` variant, so `wipe_bonded` (typed contract #4's DQ8 exception) is
        // reached only here.
        if let Some(HeldPersona::Bonded(persona)) = self.held.remove(&slot) {
            wipe_bonded(persona);
        }
        RetireOutcome::Retired { slot }
    }
}

/// `P`'s cleartext canonical id from its keys — `cSHAKE256` over the canonical
/// `hybrid_bond_id` bytes, the same value an on-chain bond-post carries. `Err` if
/// the hybrid key does not canonically encode (a corrupted resident key).
pub(crate) fn persona_canonical_id(
    keys: &ArchivalPKeys,
) -> Result<PCanonicalId, shekyl_crypto_pq::CryptoError> {
    let hybrid = keys.hybrid_bond_id().to_canonical_bytes()?;
    Ok(p_canonical_id_from_hybrid_pubkey(&hybrid))
}

/// Failure surface of [`StakeEngine`]'s spawn ([`Actor::on_start`]).
///
/// The variant set is **designed for the failures known to be incoming, not just
/// today's** (S6 plan §2.1 / F3): 2d-1's `P`-scan init (scan-store open, cursor
/// recovery) will add **always-on** variants here, so it *adds a variant* rather
/// than reshaping the type. Today the **only** variant is the conformance RNG
/// self-cert, `#[cfg]`-compiled out by default — so in the default build this is
/// an **empty enum**, `on_start` cannot construct an `Err`, and the failure
/// branch is zero-cost.
///
/// `Debug` satisfies kameo's `ReplyError` bound (blanket `Debug + Send + 'static`);
/// `Clone` is required by `ActorRef::wait_for_startup_result`, the eager
/// observation path the spawn site uses (S6 plan §2.1).
#[derive(Debug, Clone)]
pub(crate) enum StakeEngineStartError {
    /// The session RNG self-cert (S6, conformance build only) graded the
    /// production `OsRng` adapter as **non-conformant**. A degenerate timing RNG
    /// defeats the gate-6 decorrelation firewall, so the actor refuses to start
    /// (fail-stop → wallet-open fails loudly with the grade in the report).
    #[cfg(feature = "conformance")]
    RngSelfCertFailed(shekyl_standoff::conformance::CertifyReport),
}

/// S6 — grade `rng` with the session self-cert and decide whether the actor may
/// start: pass → `Ok(())`, non-conformant → `Err(RngSelfCertFailed(report))`.
///
/// Extracted from [`Actor::on_start`] so the **decision** is unit-testable with
/// an injected degenerate RNG without spawning the actor (the *full* spawn →
/// fail-stop → `OpenError` path with a degenerate source is the Round-2/`R0-D#`
/// test). Conformance build only.
#[cfg(feature = "conformance")]
fn run_session_self_cert<R: GapRng>(rng: &mut R) -> Result<(), StakeEngineStartError> {
    let report = shekyl_standoff::conformance::certify_draw(
        rng,
        DEFAULT_ENTRY_GAP.as_blocks(),
        super::stake_timing::CERTIFY_SAMPLE_N,
    );
    if report.passed() {
        Ok(())
    } else {
        Err(StakeEngineStartError::RngSelfCertFailed(report))
    }
}

impl Actor for StakeEngine {
    type Args = StakeEngineArgs;
    type Error = StakeEngineStartError;

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

        // S6 — session RNG self-cert. Compiled in **only** under the `conformance`
        // feature (`x86_64` enforced by the module-level `compile_error!`); the
        // default build has no grade at all. Grade the real `OsRng` adapter before the
        // actor accepts any work; a non-conformant CSPRNG fail-stops the spawn (and
        // so wallet-open), so a degenerate timing RNG never reaches the gate-6
        // decorrelation draw. This certifies the real adapter at the real
        // session-start — stronger than the reference-RNG KAT (S6 §0). A
        // **non-test `conformance`** build always grades; the **`test +
        // conformance`** build selects via `args.self_cert` (default `Skip`, so
        // unrelated tests are neither slowed nor flaked by the grade's α=1e-6
        // false-positive).
        #[cfg(all(feature = "conformance", not(test)))]
        run_session_self_cert(&mut OsRngGapAdapter)?;
        #[cfg(all(feature = "conformance", test))]
        match args.self_cert {
            TestSelfCert::Skip => {}
            TestSelfCert::RealOsRng => run_session_self_cert(&mut OsRngGapAdapter)?,
            TestSelfCert::Degenerate => {
                struct ConstZeroRng;
                impl GapRng for ConstZeroRng {
                    fn next_u64(&mut self) -> u64 {
                        0
                    }
                }
                run_session_self_cert(&mut ConstZeroRng)?;
            }
        }

        Ok(Self {
            held,
            active,
            generation: 0,
            watch_cache: KeyImageWatchSet::new(),
            watch_quarantine: BTreeSet::new(),
            #[cfg(feature = "gf7-hooks")]
            observer: args.observer,
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
/// projection, like [`ActivePersona`]: no activation, no activation, no
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

/// Request the StakeEngine to build and sign a JoinMarket archival bond post,
/// consuming the persist-before-use typestate (Bond-PR 2c-2b, S1/S2).
///
/// Both `handle` and `ticket` must name the same persona slot: the handle
/// proves the slot is currently held at the generation this message was minted
/// for; the ticket proves its live-bond record was durably committed before
/// signing. This structural pairing makes "sign before persist" and "sign for
/// an unheld persona" unexpressible (typed contracts #1 and #2).
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
/// called here; the reply is a [`SignedBondPost`] carrying the signed
/// `JoinMarketVin` **and** the bond-post placement offset derived from this
/// request's entry-gap draw — the caller receives the placement offset with the
/// bytes it places, so the draw cannot be lost between signing and scheduling.
///
/// Does **not** advance the activation generation — signing does not change
/// the active slot or wipe any persona.
///
/// # Caller workflow
///
/// ```text
/// stake.mint_handle(slot)      → handle1
/// stake.activate_persona(handle1)           (sets active slot; handle1 consumed)
/// engine.persist_bond_record(slot) → ticket (durable; Engine, not actor)
/// stake.mint_handle(slot)      → handle2
/// stake.sign_bond(handle2, ticket, holdings, tx_prefix_hash) → SignedBondPost
/// ```
#[allow(dead_code)] // inert until 2c-2b request path is wired end-to-end
pub(crate) struct SignBond {
    /// Operation-scoped capability proving the slot is currently held (typed
    /// contract #2). Must match `ticket.p_slot()`.
    pub handle: PersonaHandle,
    /// Proof that the live-bond record was durably persisted for this slot
    /// before signing (typed contract #1). Must match `handle.p_slot()`.
    pub ticket: super::stake_persist::PersistedBondTicket,
    /// Holdings to compute `bond_floor` from. Passed to
    /// [`build_join_market_vin`] inside the actor.
    pub holdings: HoldingsDescriptor,
    /// 32-byte prefix hash of the transaction the bond post rides in.
    /// Binds the signature to this specific transaction.
    pub tx_prefix_hash: [u8; 32],
}

/// Reply of [`SignBond`]: the signed bond vin **and** the block-timed
/// placement offset derived from the same request's entry-gap draw.
///
/// Pairing them in one reply is the seam discipline: the caller that receives
/// the bytes to place also receives *where to place them* (blocks from its
/// private intent anchor `t0`), so the placement offset cannot be lost between
/// signing and scheduling. The offset is relative; the anchor itself never
/// leaves the caller.
#[allow(dead_code)] // inert until the 2c-2a assemble / 2d dispatch consumer lands
#[derive(Debug)]
pub(crate) struct SignedBondPost {
    /// The signed JoinMarket bond vin, ready for transaction assembly.
    pub vin: JoinMarketVin,
    /// Blocks from the private-intent anchor `t0` to the bond-post broadcast —
    /// the drawn entry-gap spread. (No entry offset: only the bond post is
    /// chain-attributable, so there is no second event to place.)
    pub bond_post_offset_blocks: u64,
}

impl Message<SignBond> for StakeEngine {
    type Reply = Result<SignedBondPost, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: SignBond,
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
        // (see `AssembleBond`); this handler plans + signs the vin, it does not
        // broadcast.
        let (handle_slot, bond_post_offset_blocks) =
            self.validate_and_draw_bond_offset(&msg.handle, msg.ticket.p_slot())?;

        // 6. Borrow the held bundle — slot membership confirmed by step 1.
        let keys = self
            .held
            .get(&handle_slot)
            .expect("validate_handle confirmed slot is held")
            .keys();

        // 7. Build and sign the JoinMarket vin inside the actor.
        //    `ArchivalPKeys` is borrowed here and never returned to the caller
        //    (rule 36-secret-locality): only the signed `JoinMarketVin` (paired
        //    with its placement offset) crosses the actor boundary.
        let vin = build_join_market_vin(keys, msg.holdings, &msg.tx_prefix_hash)
            .map_err(StakeEngineError::BondBuild)?;
        Ok(SignedBondPost {
            vin,
            bond_post_offset_blocks,
        })
    }
}

// ---------------------------------------------------------------------------
// WI-2 D-A3 — AssembleBond: the production bond-assembly message
// ---------------------------------------------------------------------------

/// Assemble the **full, broadcast-ready** JoinMarket bond transaction inside
/// the actor (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.3) — the production superset
/// of [`SignBond`] (which signs the vin only and remains for the composition
/// KAT).
///
/// Carries the same handle + ticket typed contracts as [`SignBond`], plus the
/// **public** funding contexts the Engine-side orchestrator selected (§3.2)
/// and path-assembled: records, membership paths, and the tree context. The
/// spend secrets are **not** in the message — they are re-derived from each
/// record's `(ciphertext, index)` inside the handler
/// ([`derive_p_source_secrets_bundle`], rule 36).
///
/// The reply pairs the minted [`PBoundBytes`] with the bond-post placement
/// offset from this request's entry-gap draw — the same seam discipline as
/// [`SignedBondPost`]: the caller that receives the bytes to place receives
/// where to place them.
///
/// Dead_code allow: the Engine orchestrator is wired; go-live still needs
/// SP-R0/2d-1 pruning **and** the RPC stake entry (rule-21 — neither alone;
/// half (a) landed 2026-07-18 with SP-R0 arm #1, logic-discharged — half (b)
/// is the remaining retirement, the staker-activation round).
pub(crate) struct AssembleBond {
    /// Operation-scoped capability proving the slot is currently held (typed
    /// contract #2). Must match `ticket.p_slot()`.
    pub handle: PersonaHandle,
    /// Proof that the live-bond record was durably persisted for this slot
    /// before assembly (typed contract #1). Must match `handle.p_slot()`.
    pub ticket: super::stake_persist::PersistedBondTicket,
    /// Holdings to bond; `bond_floor(holdings)` is recomputed inside.
    pub holdings: HoldingsDescriptor,
    /// The selected funding inputs (§3.2) with their assembled membership
    /// paths — public identity + public tree data only.
    pub funding: Vec<FundingInputContext>,
    /// The curve-tree reference context the paths were assembled against.
    pub tree_ctx: TreeContext,
    /// The fee the Engine-side selection was run against.
    pub fee: u64,
}

/// Reply of [`AssembleBond`]: the persona-bound wire bytes (minted at the
/// single P-1 site, [`finalize_bond_tx`]), the placement offset, and the
/// funding gindexes for the caller's reservation record (§3.5). Secrets never
/// cross the boundary.
///
/// Dead_code allow: reply type of the wired orchestrator; same dual gate as
/// [`AssembleBond`].
#[allow(dead_code)]
// rule-21: (a) SP-R0 arm #1 pruning DONE 2026-07-18 (logic-discharged); retires with (b) the RPC stake entry (#332). The placement carrier is the bare `bond_post_offset_blocks` (the entry-seam plan/order-coin was retired in the GF-7 coin retirement).
#[derive(Debug)]
pub(crate) struct AssembledBondPost {
    /// The fully-signed, wire-encoded bond transaction, persona-bound.
    pub bound_tx: PBoundBytes,
    /// Blocks from the private-intent anchor `t0` to the bond-post broadcast —
    /// the drawn entry-gap spread.
    pub bond_post_offset_blocks: u64,
    /// The spent funding records' gindexes — the §3.5 reservation set.
    pub funding_gindexes: Vec<shekyl_types::GlobalOutputIndex>,
}

impl Message<AssembleBond> for StakeEngine {
    type Reply = Result<AssembledBondPost, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: AssembleBond,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // ── Steps 1–5: the shared bond-handler prologue (identical typed
        // contracts + guarded draw as `SignBond`); see
        // `validate_and_draw_bond_offset`. ──────────────────────────────────
        let (handle_slot, bond_post_offset_blocks) =
            self.validate_and_draw_bond_offset(&msg.handle, msg.ticket.p_slot())?;

        // ── Step 6: borrow the held bundle (never crosses the boundary) ──
        let keys = self
            .held
            .get(&handle_slot)
            .expect("validate_handle confirmed slot is held")
            .keys();

        // ── Step 7: funding arithmetic (§3.2 balance rule, checked) ──────
        // `funding == change + fee + credit` exactly; change splits across
        // TWO outputs (daemon prunable-tx floor: `vout.size() < 2` rejects).
        let floor = bond_floor(&msg.holdings);
        let required = floor
            .checked_add(msg.fee)
            .ok_or(BondAssemblyError::AmountOverflow)?;
        let mut available: u64 = 0;
        for ctx in &msg.funding {
            available = available
                .checked_add(ctx.record.amount.to_raw())
                .ok_or(BondAssemblyError::AmountOverflow)?;
        }
        if available < required {
            return Err(BondAssemblyError::InsufficientFunding {
                available,
                required,
            }
            .into());
        }
        let change = available - required;
        let change_lo = change / 2;
        let change_hi = change - change_lo;

        // ── Step 8: change outputs to P's own base address ────────────────
        // Both return to `P`'s base spend key (the pscan `GuaranteedScanner`
        // claims against `spend_pk` directly), so the change re-enters the
        // funding set on the next sweep.
        let mut tx_key_secret = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(tx_key_secret.as_mut());
        let tx_pubkey = &Scalar::from_bytes_mod_order(*tx_key_secret) * ED25519_BASEPOINT_TABLE;

        let ConstructedVouts {
            output_infos,
            output_keys,
            view_tags,
            kem_blobs,
            leaf_hash_blob,
        } = construct_vouts_to_base(
            keys,
            &tx_key_secret,
            &[change_lo, change_hi],
            "change-output construction",
            |_, _| {},
        )?;

        // ── Step 9: tx_extra — tx pubkey + per-output KEM blobs + the 0x07
        // PQC leaf hashes (without which the change outputs ingest with a
        // zero `h_pqc` leaf and are unspendable).
        let mut extra = Extra::for_hybrid_transfer(tx_pubkey, kem_blobs);
        extra.push_pqc_leaf_hashes(leaf_hash_blob);
        let tx_extra = extra.serialize();

        // ── Step 10 (§3.3 actor step 1): re-derive spend bundles, compute
        // key images, build the tx-builder SpendInputs — the shared
        // [`prepare_funding_inputs`] leg (also the emission handler's fee
        // side). Secrets stay inside this frame until they move into the
        // proving closure.
        let prepared = prepare_funding_inputs(keys, msg.funding)?;

        let key_images: Vec<[u8; 32]> = prepared.iter().map(|p| p.key_image).collect();
        let funding_gindexes: Vec<shekyl_types::GlobalOutputIndex> =
            prepared.iter().map(|p| p.gindex).collect();

        // ── Steps 11–12 (§3.3 actor step 2): the wire BondPost prefix input
        // from PUBLIC parts, then the prefix hash. No circularity: the wire
        // input carries no signature, so the prefix is fully determined
        // before the vin is signed.
        let hybrid_pk_bytes = keys
            .hybrid_sign_pk
            .to_canonical_bytes()
            .map_err(|e| BondAssemblyError::build("identity encoding", e))?;
        let bond_spend_pk_bytes = keys
            .bond_spend_pk
            .to_canonical_bytes()
            .map_err(|e| BondAssemblyError::build("identity encoding", e))?;
        let persona = p_canonical_id_from_hybrid_pubkey(&hybrid_pk_bytes);
        let expected_vin = shekyl_archival_retention::ArchivalBondPostVin {
            hybrid_public_key: hybrid_pk_bytes.clone(),
            p_canonical_id: *persona.as_bytes(),
            post_kind: shekyl_archival_retention::BondPostKind::JoinMarket,
            bond_spend_pk: bond_spend_pk_bytes,
            holdings: msg.holdings.clone(),
            bonded_total_atomic: floor,
            bond_credit: floor,
            bond_debit: 0,
        };
        let prefix_bond_input: Input = wire_bond_post_input(&expected_vin)?;
        let extra_inputs = vec![prefix_bond_input];

        let prefix_hash = tx_prefix_hash_from_parts_with_extra(
            &key_images,
            &extra_inputs,
            &output_keys,
            // Every change output is confidential (wire amount 0) — derived
            // from the count, same as the wire encode below, so the two
            // sites cannot disagree on arity.
            &vec![0; output_keys.len()],
            &view_tags,
            &tx_extra,
        )
        .map_err(|e| BondAssemblyError::build("prefix hash", e))?;

        // ── Step 13 (§3.3 actor step 3): build + sign the vin over the now-
        // fixed prefix hash.
        let built = build_join_market_vin(keys, msg.holdings.clone(), &prefix_hash)
            .map_err(StakeEngineError::BondBuild)?;

        // ── Step 14 — invariant A-1 (fail closed): the signed vin's post
        // fields must equal the prefix's BondPost input. Typed equality on
        // `ArchivalBondPostVin` implies byte-identity (its wire write is a
        // deterministic function of the value). A mismatch means the
        // signature binds a different post than the hash covered — a build
        // defect, never recoverable.
        if built.vin() != &expected_vin {
            // Loud in debug (a build defect, never a recoverable state), fail
            // closed in release. `debug_assert!(false, …)` — not
            // `debug_assert_eq!(built.vin(), &expected_vin, …)`, which would be
            // an always-false assert inside a branch that already established
            // inequality (it reads as a conditional check but can only panic).
            debug_assert!(
                false,
                "A-1: signed vin diverged from the prefix BondPost input"
            );
            return Err(BondAssemblyError::BondPostMismatch.into());
        }
        let credit_term = built.credit_term();

        // ── Step 15 (§3.3 actor step 5): offload the CPU-bound proving
        // (Bp+ + FCMP membership) to `spawn_blocking` — the SP-5 pattern.
        // The SpendInputs (owned secrets) MOVE into the closure and come
        // back for the fast inline PQC signing; `&mut self` is held across
        // the await, so the mailbox cannot interleave another message.
        let mut spend_inputs = Vec::with_capacity(prepared.len());
        let mut pqc_pubkeys = Vec::with_capacity(prepared.len());
        for p in prepared {
            spend_inputs.push(p.spend);
            pqc_pubkeys.push(p.pqc_pubkey);
        }
        let outputs_for_prove = output_infos.clone();
        let tree = msg.tree_ctx.clone();
        let fee = msg.fee;
        let (signed, spend_inputs) = tokio::task::spawn_blocking(move || {
            sign_transaction_with_terms(
                prefix_hash,
                &spend_inputs,
                &outputs_for_prove,
                AtomicUnits::from_raw(fee),
                &[],
                &[credit_term],
                &tree,
            )
            .map(|signed| (signed, spend_inputs))
        })
        .await
        .map_err(|e| BondAssemblyError::build("proving offload join", e))?
        .map_err(|e| BondAssemblyError::build("proving", e))?;

        let bulletproof = Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice())
            .map_err(|e| BondAssemblyError::build("bulletproof parse", e))?;

        // ── Step 16: assemble the wire input; pqc_auths carries one slot per
        // prefix input — the spend slots (output-derived keys) then the bond
        // slot (P's identity key), matching prefix input order.
        //
        // `signed` is a locally-owned value dropped at the end of this handler
        // and never read whole again (the only prior use, the bulletproof parse
        // above, borrowed `bulletproof_plus`). So the multi-KB owned proof
        // fields MOVE into the wire input rather than clone — the two `Copy`
        // reads below (`reference_block`, `tree_depth`) still work after a
        // partial move.
        let mut wire = WireEncodeInput {
            key_images,
            extra_inputs,
            output_amounts: vec![0; output_keys.len()],
            output_keys,
            view_tags,
            tx_extra,
            fee,
            enc_amounts: signed.enc_amounts,
            enc_labels: signed.enc_labels,
            out_commitments: signed.commitments,
            pseudo_outs: signed.pseudo_outs,
            bulletproof,
            reference_block: signed.reference_block,
            fcmp_proof: signed.fcmp_proof,
            // Placeholder auths at real pubkeys (the phase-1 payload hash
            // reads them); the fee-slot pubkeys MOVE in — nothing reads
            // `pqc_pubkeys` again (`sign_pqc_auths` re-derives per input).
            pqc_auths: pqc_pubkeys
                .into_iter()
                .map(|pk| PqcAuth {
                    auth_version: 1,
                    signature: Vec::new(),
                    public_key: pk,
                })
                .chain(std::iter::once(PqcAuth {
                    auth_version: 1,
                    signature: Vec::new(),
                    public_key: hybrid_pk_bytes.clone(),
                }))
                .collect(),
            fcmp_layers: signed.tree_depth,
        };

        // ── Step 17: PQC auth completion (fast; stays inline). One payload
        // hash per pqc_auths slot; the spend slots sign with output-derived
        // keys, the bond slot signs with P's `hybrid_sign_sk`.
        let payload_hashes = phase1_payload_hashes(&wire)
            .map_err(|e| BondAssemblyError::build("phase1 payload hash", e))?;
        if payload_hashes.len() != spend_inputs.len() + 1 {
            return Err(BondAssemblyError::build(
                "phase1 payload hash",
                format!(
                    "expected {} payload hashes, got {}",
                    spend_inputs.len() + 1,
                    payload_hashes.len()
                ),
            )
            .into());
        }
        let mut pqc_auths = sign_pqc_auths(&payload_hashes[..spend_inputs.len()], &spend_inputs)
            .map_err(|e| BondAssemblyError::build("pqc auth signing", e))?;
        let bond_payload_hash = payload_hashes[spend_inputs.len()];
        let bond_sig = HybridEd25519MlDsa
            .sign(&keys.hybrid_sign_sk, &bond_payload_hash)
            .map_err(|e| BondAssemblyError::build("bond pqc auth signing", e))?;
        pqc_auths.push(PqcAuth {
            auth_version: 1,
            signature: bond_sig
                .to_canonical_bytes()
                .map_err(|e| BondAssemblyError::build("bond pqc auth encoding", e))?,
            public_key: hybrid_pk_bytes,
        });
        wire.pqc_auths = pqc_auths;
        drop(spend_inputs); // secrets end here; nothing below needs them

        // ── Step 18 (§3.3 actor step 6): encode + mint at the P-1 site ────
        let bound_tx = finalize_bond_tx(persona, &wire)?;

        Ok(AssembledBondPost {
            bound_tx,
            bond_post_offset_blocks,
            funding_gindexes,
        })
    }
}

// ---------------------------------------------------------------------------
// F-D2 DS-PR-1 — AssembleDrain: the P→principal value-out message
// ---------------------------------------------------------------------------

impl Message<AssembleDrain> for StakeEngine {
    type Reply = Result<AssembledDrain, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: AssembleDrain,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Thin validate-and-delegate shell (composition discipline): the same
        // handle-validation preamble as `AssembleEmissionClaim` (no ticket, no
        // entry-seam draw), then the held bundle is borrowed and the crypto
        // assembly runs in `drain_assembly::assemble_drain_tx`. `keys` never
        // crosses the actor boundary (rule 36); `&mut self` is held across the
        // proving await so the mailbox cannot interleave.
        self.validate_handle(&msg.handle)?;
        let handle_slot = msg.handle.p_slot();
        let keys = self
            .held
            .get(&handle_slot)
            .expect("validate_handle confirmed slot is held")
            .keys();
        assemble_drain_tx(
            keys,
            &msg.dest,
            msg.funding,
            msg.tree_ctx,
            msg.payment_amount,
            msg.fee,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// Shared funding-input preparation (AssembleBond + AssembleEmissionClaim)
// ---------------------------------------------------------------------------

/// One prepared spend input: the tx-builder [`SpendInput`] (owned secrets)
/// plus the public companions the wire needs (key image, PQC slot pubkey,
/// reservation gindex).
pub(super) struct PreparedInput {
    pub(super) spend: SpendInput,
    pub(super) key_image: [u8; 32],
    pub(super) pqc_pubkey: Vec<u8>,
    pub(super) gindex: GlobalOutputIndex,
}

/// One constructed vout batch to `P`'s base address — the shared
/// output-construction loop of [`AssembleBond`] (two confidential change
/// vouts) and [`AssembleEmissionClaim`] (loud reward + two change vouts):
/// per output, `construct_output` → KEM blob layout → leaf-hash blob →
/// `[u8; 9]` enc-amount/enc-label packing → tx-builder `OutputInfo`. Both
/// change vouts return to `P`'s base spend key (the pscan
/// `GuaranteedScanner` claims against `spend_pk` directly), so change
/// re-enters the funding set on the next sweep.
struct ConstructedVouts {
    output_infos: Vec<shekyl_tx_builder::OutputInfo>,
    output_keys: Vec<[u8; 32]>,
    view_tags: Vec<Option<u8>>,
    kem_blobs: Vec<Vec<u8>>,
    leaf_hash_blob: Vec<u8>,
}

/// Construct `amounts` as vouts to `P`'s base address. `capture` sees each
/// constructed output `(index, &OutputData)` before its fields are packed,
/// so the emission path lifts its reward commit without a second loop or a
/// parallel construction site.
fn construct_vouts_to_base(
    keys: &ArchivalPKeys,
    tx_key_secret: &Zeroizing<[u8; 32]>,
    amounts: &[u64],
    error_site: &'static str,
    mut capture: impl FnMut(usize, &shekyl_crypto_pq::output::OutputData),
) -> Result<ConstructedVouts, BondAssemblyError> {
    let mut vouts = ConstructedVouts {
        output_infos: Vec::with_capacity(amounts.len()),
        output_keys: Vec::with_capacity(amounts.len()),
        view_tags: Vec::with_capacity(amounts.len()),
        kem_blobs: Vec::with_capacity(amounts.len()),
        leaf_hash_blob: Vec::with_capacity(32 * amounts.len()),
    };
    for (idx, &amount) in amounts.iter().enumerate() {
        let constructed = construct_output(
            tx_key_secret,
            &keys.x25519_pk,
            &keys.ml_kem_ek,
            keys.spend_pk.as_canonical_bytes(),
            amount,
            idx as u64,
        )
        .map_err(|e| BondAssemblyError::build(error_site, e))?;
        capture(idx, &constructed);
        let mut kem_blob = Vec::with_capacity(32 + constructed.kem_ciphertext_ml_kem.len());
        kem_blob.extend_from_slice(&constructed.kem_ciphertext_x25519);
        kem_blob.extend_from_slice(&constructed.kem_ciphertext_ml_kem);
        vouts.kem_blobs.push(kem_blob);
        vouts.leaf_hash_blob.extend_from_slice(&constructed.h_pqc);
        vouts.output_keys.push(constructed.output_key);
        vouts.view_tags.push(Some(constructed.view_tag_prefilter));
        vouts.output_infos.push(shekyl_tx_builder::OutputInfo {
            dest_key: constructed.output_key,
            amount: AtomicUnits::from_raw(amount),
            commitment_mask: constructed.z,
            enc_amount: {
                let mut enc = [0u8; 9];
                enc[..8].copy_from_slice(&constructed.enc_amount);
                enc[8] = constructed.amount_tag;
                enc
            },
            enc_label: {
                let mut enc = [0u8; 9];
                enc[..8].copy_from_slice(&constructed.enc_label);
                enc[8] = constructed.label_tag;
                enc
            },
        });
    }
    Ok(vouts)
}

/// One record's re-derived spend-side parts — the shared per-record body of
/// [`prepare_funding_inputs`] (bond + emission fee spends) and the emission
/// handler's **backing** leg, which is the same derivation minus the key
/// image (membership-only). One definition: a correction to the bundle
/// derivation, the leaf-chunk `h_pqc` lookup, or the `combined_ss` handling
/// lands once, or the backing proof's secrets silently diverge from the fee
/// path's and every claim fails its own leaf gate.
struct DerivedSpendParts {
    bundle: SourceSecretsBundle,
    /// The first 64 bytes of the bundle's combined secret — the
    /// per-output-PQC derivation operand (the backing leg retains it for
    /// Auth-B signing).
    combined64: Zeroizing<[u8; 64]>,
    /// The record's leaf hash, read back from its own leaf chunk (`h_pqc`
    /// is not persisted on the record — public identity only).
    h_pqc: [u8; 32],
    /// The per-output PQC public key derived from `combined64`.
    pqc_pubkey: Vec<u8>,
}

/// Re-derive one funding record's spend-side parts (rule 36: secrets are
/// re-derived from the record's `(ciphertext, index)` inside the actor,
/// never carried in the message).
fn derive_spend_parts(
    keys: &ArchivalPKeys,
    rec: &PFundingOutputRecord,
    leaf_chunk: &[LeafEntry],
) -> Result<DerivedSpendParts, BondAssemblyError> {
    let ciphertext = HybridCiphertext {
        x25519: rec.ciphertext_x25519,
        ml_kem: rec.ciphertext_ml_kem.clone(),
    };
    let bundle = derive_p_source_secrets_bundle(keys, &ciphertext, rec.index_in_transaction)
        .map_err(|e| BondAssemblyError::build("spend-bundle derivation", e))?;

    let h_pqc = leaf_chunk
        .iter()
        .find(|leaf| leaf.output_key == rec.output_key)
        .map(|leaf| leaf.h_pqc)
        .ok_or_else(|| {
            BondAssemblyError::build(
                "leaf-chunk lookup",
                "funding output missing from its own leaf chunk",
            )
        })?;

    let combined64: Zeroizing<[u8; 64]> =
        Zeroizing::new(bundle.combined_ss[..64].try_into().map_err(|_| {
            BondAssemblyError::build("spend-bundle derivation", "combined_ss wrong length")
        })?);
    let pqc_pubkey = derive_pqc_public_key(&combined64, rec.index_in_transaction)
        .map_err(|e| BondAssemblyError::build("pqc public-key derivation", e))?;

    Ok(DerivedSpendParts {
        bundle,
        combined64,
        h_pqc,
        pqc_pubkey,
    })
}

impl DerivedSpendParts {
    /// The tx-builder [`SpendInput`] over these parts, moving the
    /// membership vecs in (never deep-copying them).
    fn into_spend_input(
        self,
        rec: &PFundingOutputRecord,
        leaf_chunk: Vec<LeafEntry>,
        c1_layers: Vec<Vec<[u8; 32]>>,
        c2_layers: Vec<Vec<[u8; 32]>>,
    ) -> SpendInput {
        SpendInput {
            output_key: rec.output_key,
            commitment: rec.commitment,
            amount: rec.amount,
            spend_key_x: *self.bundle.spend_key_x,
            spend_key_y: *self.bundle.spend_key_y,
            commitment_mask: *self.bundle.commitment_mask,
            h_pqc: self.h_pqc,
            combined_ss: self.bundle.combined_ss.to_vec(),
            output_index: rec.index_in_transaction,
            leaf_chunk,
            c1_layers,
            c2_layers,
        }
    }
}

/// Re-derive spend bundles for the selected funding inputs, compute key
/// images, and build the tx-builder [`SpendInput`]s — the shared spend-side
/// leg of [`AssembleBond`] and [`AssembleEmissionClaim`] (rule 36: secrets are
/// re-derived from each record's `(ciphertext, index)` inside the actor,
/// never carried in the message).
///
/// Consumes `funding` by value: the curve-tree membership vecs (`leaf_chunk`,
/// `c1_layers`, `c2_layers` — many 32-byte node vecs per tree layer) MOVE into
/// each `SpendInput` rather than deep-copy. The returned set is sorted
/// strictly DESCENDING by key image — the consensus order shared by the
/// proof, the wire key-image list, and the pqc_auths slots (same rule as the
/// transfer path).
// `pub(super)`: the F-D2 drain assembly (`drain_assembly.rs`) reuses this exact
// persona-keyed spend-side leg — the drain spends `P`-funding inputs identically
// to a bond/claim fee sweep (same key-image derivation, same descending order),
// so there is one definition of "turn selected P-funding records into signed
// spend inputs," never a drain-specific fork (rule 36 + composition discipline).
pub(super) fn prepare_funding_inputs(
    keys: &ArchivalPKeys,
    funding: Vec<FundingInputContext>,
) -> Result<Vec<PreparedInput>, BondAssemblyError> {
    let mut prepared = Vec::with_capacity(funding.len());
    for ctx in funding {
        let rec = &ctx.record;
        let mut parts = derive_spend_parts(keys, rec, &ctx.leaf_chunk)?;

        // KI = x·Hp(O) — the single shared definition (see
        // `key_image_from_spend_key_x`; the watch path derives through the
        // same leg, so watch and sweep cannot diverge). The full-path-only
        // leg (the backing's membership-only leg has none).
        let key_image = key_image_from_spend_key_x(&parts.bundle.spend_key_x, rec.output_key)
            .map_err(|e| BondAssemblyError::build("key-image derivation", e))?;

        let pqc_pubkey = std::mem::take(&mut parts.pqc_pubkey);
        let gindex = rec.gindex;
        prepared.push(PreparedInput {
            spend: parts.into_spend_input(rec, ctx.leaf_chunk, ctx.c1_layers, ctx.c2_layers),
            key_image,
            pqc_pubkey,
            gindex,
        });
    }
    prepared.sort_by(|a, b| b.key_image.cmp(&a.key_image));
    Ok(prepared)
}

// ---------------------------------------------------------------------------
// PR-3 commit 4 — AssembleEmissionClaim: the emission-claim assembly message
// ---------------------------------------------------------------------------

/// Assemble the **full, broadcast-ready** emission-claim transaction inside
/// the actor (`REWARD_EMISSION_VIN_PLAN.md` §8.0.2/§8.0.3, PR-3 commit 4) —
/// the emission sibling of [`AssembleBond`].
///
/// No [`PersistedBondTicket`](super::stake_persist::PersistedBondTicket) and
/// no entry-seam plan: the claim consumes no funding-entry seam (the bond is
/// already on-chain), and claim-broadcast timing is the GF-4 dispatch seam,
/// deliberately outside this builder (same return-bytes-only posture as the
/// bond path).
///
/// Assembly order is forced by the F-C1c hash structure (verified at
/// `blockchain.cpp:3857-3868`): fee inputs + vouts + extra → **signable
/// hash** over the vin-less prefix → membership proof + dual auths complete
/// the vin → **full prefix hash** → fee-side proof → tx PQC auths. The
/// emission vin cannot be covered by the hash its own proof and auths sign
/// over.
pub(crate) struct AssembleEmissionClaim {
    /// Operation-scoped capability proving the slot is currently held.
    pub handle: PersonaHandle,
    /// The sealed operand set — claim source, designated backing, swept fee
    /// inputs, membership paths — mintable only through
    /// [`DesignatedBacking::fee_sweep`](super::backing_set::DesignatedBacking::fee_sweep)
    /// → [`SweptFeeInputs::with_paths`](super::backing_set::SweptFeeInputs::with_paths),
    /// so possession is proof of same-tip (item 6) and Q11 backing/fee
    /// disjointness. The handler re-checks nothing (`backing_set.rs` module
    /// docs: the old step-2 runtime refusals are deleted, not relocated).
    pub operands: ClaimOperands,
    /// The curve-tree reference context all paths were assembled against.
    pub tree_ctx: TreeContext,
}

/// Reply of [`AssembleEmissionClaim`]: the persona-bound wire bytes (minted
/// at the single P-1 site, [`finalize_bond_tx`]), plus the public facts the
/// caller's reservation and dedup records need. Secrets never cross the
/// boundary.
// Staging (not tolerated dead code, `15-deletion-and-debt.mdc`): the receipt
// (`claim_dispatch::EmissionClaimReceipt`) embeds this reply whole, so the
// lib-target field readers arrive with the RPC stake entry (rule-21, the same
// retirement condition as the seam's allow); the orchestrator e2e KAT reads
// every field today.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct AssembledEmissionClaim {
    /// The fully-signed, wire-encoded emission-claim transaction.
    pub bound_tx: PBoundBytes,
    /// The spent **fee** funding records' gindexes — the reservation set.
    /// The backing's gindex is deliberately absent: the backing is proven
    /// (membership-only, no key image), not spent.
    pub fee_gindexes: Vec<GlobalOutputIndex>,
    /// The epochs this tx claims (the vin's `settlement_epochs`) — the
    /// caller's pending-dedup set.
    pub claimed_epochs: Vec<u64>,
    /// Epochs dropped by the size bound, deferred to the next claim tx.
    pub size_deferred: Vec<u64>,
    /// The loud mint this tx pays out (`Σ reward_amount_plain`).
    pub total_reward: u64,
}

impl Message<AssembleEmissionClaim> for StakeEngine {
    type Reply = Result<AssembledEmissionClaim, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: AssembleEmissionClaim,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // ── Step 1: handle validation (no ticket, no entry-seam draw —
        // see the message doc). ─────────────────────────────────────────
        self.validate_handle(&msg.handle)?;
        let handle_slot = msg.handle.p_slot();

        // ── Step 2: unseal the operands. Consistency is the TYPE's, not
        // this handler's: `ClaimOperands` is mintable only through
        // `DesignatedBacking::fee_sweep` → `SweptFeeInputs::with_paths`
        // (backing_set.rs), so same-tip (item 6), Q11 backing/fee
        // disjointness, a non-empty fee set, and `fee_total >= fee` hold
        // by possession — the refusal arms that used to live here were
        // deleted with the seal, not relocated.
        let ops = msg.operands.into_parts();

        // ── Step 3: borrow the held bundle (never crosses the boundary).
        // CB-2: everything below signs with material derived from this
        // pre-derived bundle; the seed is not re-acquired anywhere.
        let keys = self
            .held
            .get(&handle_slot)
            .expect("validate_handle confirmed slot is held")
            .keys();

        // ── Step 4: derive + assemble the claims leg (single-evaluator:
        // rows and rewards ride the derivation; assembly never re-runs the
        // recompute it was admitted on).
        let claims = {
            let derived = derive_claimable_epochs(&ops.source)?;
            if !derived.skipped.is_empty() {
                // Local diagnostics only (CB-5: cause-blind toward the
                // daemon; nothing derived from these verdicts shapes
                // daemon-visible behavior).
                tracing::debug!(
                    skipped = ?derived.skipped,
                    "emission claim derivation: window epochs not selected"
                );
            }
            assemble_claims(&derived, EMISSION_CLAIMS_SIZE_BUDGET)?
        };
        let total_reward = claims.total_reward;

        // ── Step 5: fee arithmetic. The reward is fully consumed by the
        // loud vout (`vout_reward_sum == total_reward`, enforced by the
        // daemon's balance `Σ pseudoOuts + total_reward·H = Σ out_masks +
        // fee·H`), so the fee is funded by the sealed fee spends. The
        // structural refusals (empty selection, shortfall, sum overflow)
        // fired at the mint (`fee_sweep`); `fee_total` is the sweep's
        // exact checked sum and `fee_total >= fee` by its shortfall
        // refusal, so the change split is plain subtraction.
        let fee = ops.fee.to_raw();
        let change = ops.fee_total.to_raw() - fee;
        let change_lo = change / 2;
        let change_hi = change - change_lo;

        // ── Step 6: outputs. One LOUD reward vout (plaintext amount on the
        // wire, §5.5) paying the full mint to P's base address, plus two
        // confidential change vouts (daemon prunable-tx floor). The daemon's
        // ordered reward-commit set is "non-zero wire amounts, in vout
        // order" — exactly the reward vout here, so the auth digest binds
        // one commit.
        let mut tx_key_secret = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(tx_key_secret.as_mut());
        let tx_pubkey = &Scalar::from_bytes_mod_order(*tx_key_secret) * ED25519_BASEPOINT_TABLE;

        let mut reward_commit: Option<RewardCommit> = None;
        let ConstructedVouts {
            output_infos,
            output_keys,
            view_tags,
            kem_blobs,
            leaf_hash_blob,
        } = construct_vouts_to_base(
            keys,
            &tx_key_secret,
            &[total_reward, change_lo, change_hi],
            "claim-output construction",
            |idx, constructed| {
                if idx == 0 {
                    // The auth digest must bind the commitment the daemon
                    // reads from the tx's outPk. `construct_output`'s C =
                    // z·G + amount·H is the same formula (and mask) the
                    // signer emits; the post-sign cross-check below fails
                    // loudly if they ever diverge.
                    reward_commit = Some(RewardCommit {
                        commitment: constructed.commitment,
                        amount_plain: total_reward,
                        one_time_key: constructed.output_key,
                    });
                }
            },
        )?;
        let reward_commits =
            vec![reward_commit.expect("vout_amounts is non-empty; index 0 always constructs")];
        // The reward vout is loud (plaintext amount on the wire); the change
        // vouts stay confidential (wire amount 0).
        let output_amounts: Vec<u64> = vec![total_reward, 0, 0];

        // ── Step 7: tx_extra — tx pubkey + per-output KEM blobs + 0x07 PQC
        // leaf hashes (same shape as the bond path).
        let mut extra = Extra::for_hybrid_transfer(tx_pubkey, kem_blobs);
        extra.push_pqc_leaf_hashes(leaf_hash_blob);
        let tx_extra = extra.serialize();

        // ── Step 8: fee spend inputs — shared spend-side leg with the bond
        // path (descending key-image order).
        let prepared = prepare_funding_inputs(keys, ops.fee_funding)?;
        let key_images: Vec<[u8; 32]> = prepared.iter().map(|p| p.key_image).collect();
        let fee_gindexes: Vec<GlobalOutputIndex> = prepared.iter().map(|p| p.gindex).collect();

        // ── Step 9: the SIGNABLE hash (F-C1c) — the prefix with the
        // emission vin erased WHOLESALE. The wire encoder places ToKey key
        // images first and extra inputs after, so the emission vin sits at
        // `archival_emission_index == key_images.len()`; the daemon's
        // `classify_archival_tx` finds it there and `blockchain.cpp:3866`
        // erases exactly that entry — leaving these key images, these
        // outputs (loud amount included), and this extra: byte-identical to
        // the vin-less prefix hashed here.
        let signable_tx_hash = tx_prefix_hash_from_parts_with_extra(
            &key_images,
            &[],
            &output_keys,
            &output_amounts,
            &view_tags,
            &tx_extra,
        )
        .map_err(|e| BondAssemblyError::build("signable hash", e))?;

        // ── Step 10: backing spend input (membership-only; no key image).
        // The parts are re-derived from the designation's own record — the
        // single record owner (the `MembershipPath` doc in `backing_set.rs`:
        // paths carry no record copy) — through the SAME
        // [`derive_spend_parts`] the fee spends use (one derivation
        // definition; a divergence would fail every claim at the leaf gate
        // below).
        let rec = ops.backing.record();
        let backing_index = rec.index_in_transaction;
        let mut parts = derive_spend_parts(keys, rec, &ops.backing_path.leaf_chunk)?;
        let backing_h_pqc = parts.h_pqc;
        let backing_pubkey = std::mem::take(&mut parts.pqc_pubkey);
        // Retained for Auth-B signing after the bundle moves into the
        // proving closure.
        let backing_combined = std::mem::replace(&mut parts.combined64, Zeroizing::new([0u8; 64]));
        // Pre-flight leaf gate: the daemon's C-1 gate demands
        // hash(backing_pubkey) == leaf.h_pqc. A mismatch here means stale or
        // defective tree data (or a record that is not this persona's) —
        // fail before proving, not at the daemon.
        if hash_pqc_public_key(&backing_pubkey) != backing_h_pqc {
            return Err(BondAssemblyError::build(
                "backing leaf gate",
                "derived backing pubkey does not hash to the leaf's pqc_pk_hash \
                 (stale/defective tree data, or a record not owned by this persona)",
            )
            .into());
        }
        let backing_spend = parts.into_spend_input(
            rec,
            ops.backing_path.leaf_chunk,
            ops.backing_path.c1_layers,
            ops.backing_path.c2_layers,
        );

        // ── Step 11: membership-only proof over the signable hash (CPU-
        // bound → spawn_blocking, SP-5 pattern). The backing secrets end in
        // this closure; Auth-B below uses only the retained combined-secret
        // copy.
        let tree = msg.tree_ctx.clone();
        let membership = tokio::task::spawn_blocking(move || {
            prove_backing_membership(&backing_spend, &tree, signable_tx_hash)
        })
        .await
        .map_err(|e| BondAssemblyError::build("membership proving offload join", e))?
        .map_err(|e| BondAssemblyError::build("membership proving", e))?;

        // ── Step 12: the vin, with placeholder auths at canonical length
        // (the auth digest spans fields 1–6 + tx context, never the auth
        // legs themselves, so the placeholders don't poison it).
        let hybrid_pk_bytes = keys
            .hybrid_sign_pk
            .to_canonical_bytes()
            .map_err(|e| BondAssemblyError::build("identity encoding", e))?;
        let persona = p_canonical_id_from_hybrid_pubkey(&hybrid_pk_bytes);
        let mut vin = ArchivalRewardEmissionVin {
            p_pubkey: hybrid_pk_bytes.clone(),
            holdings: claims.holdings.clone(),
            settlement_epochs: claims.settlement_epochs.clone(),
            work_claim: claims.work_claim,
            backing: MembershipOnlyBacking {
                proof: membership.proof,
                pseudo_out: membership.pseudo_out,
                pqc_pk_hash: backing_h_pqc,
                backing_pubkey: backing_pubkey.clone(),
                tree_depth: membership.tree_depth,
            },
            reward_amount_plain: claims.reward_amount_plain,
            auth_backing: vec![0u8; SINGLE_SIG_CANONICAL_LEN],
            auth_claim: vec![0u8; SINGLE_SIG_CANONICAL_LEN],
        };

        // ── Step 13: dual auth over the role-separated binding messages
        // (Q1). Auth-B signs with the backing's OUTPUT-DERIVED hybrid key
        // (the daemon's C-1 gate checks hash(backing_pubkey) == leaf.h_pqc,
        // verified at emission_verify.rs — NOT P's identity key); Auth-P
        // signs with P's identity hybrid key (the daemon derives the vin's
        // p_canonical_id from it, blockchain.cpp:3783 id-equality).
        let auth_msgs = vin
            .auth_msgs(&reward_commits, &signable_tx_hash)
            .map_err(|e| BondAssemblyError::build("auth binding message", e))?;
        let auth_b = sign_pqc_auth_for_output(&backing_combined, backing_index, &auth_msgs.backing)
            .map_err(|e| BondAssemblyError::build("backing auth signing", e))?;
        if auth_b.hybrid_public_key != backing_pubkey {
            // Same derivation, same inputs — divergence is a build defect.
            debug_assert!(
                false,
                "Auth-B pubkey diverged from the vin's backing_pubkey"
            );
            return Err(BondAssemblyError::build(
                "backing auth signing",
                "Auth-B signer pubkey diverged from the vin's backing_pubkey",
            )
            .into());
        }
        vin.auth_backing = auth_b.signature;
        let claim_sig = HybridEd25519MlDsa
            .sign(&keys.hybrid_sign_sk, &auth_msgs.claim)
            .map_err(|e| BondAssemblyError::build("claim auth signing", e))?;
        vin.auth_claim = claim_sig
            .to_canonical_bytes()
            .map_err(|e| BondAssemblyError::build("claim auth encoding", e))?;

        // ── Step 14: the completed vin joins the prefix; FULL prefix hash.
        let emission_input = Input::ArchivalRewardEmission {
            canonical_bytes: vin
                .serialize()
                .map_err(|e| BondAssemblyError::build("emission vin encoding", e))?,
        };
        let extra_inputs = vec![emission_input];
        let prefix_hash = tx_prefix_hash_from_parts_with_extra(
            &key_images,
            &extra_inputs,
            &output_keys,
            &output_amounts,
            &view_tags,
            &tx_extra,
        )
        .map_err(|e| BondAssemblyError::build("prefix hash", e))?;

        // ── Step 15: fee-side proving (Bp+ over all three vouts, loud one
        // included, + FCMP over the fee spends) with `total_reward` as the
        // INPUT-side cleartext term — the daemon's balance is
        // `Σ pseudoOuts + total_reward·H = Σ out_masks + fee·H`
        // (`verCtSemanticsEmission`, rctSigs.cpp:364). The build-time
        // backing self-check (CPU-bound verify) rides the same closure.
        let mut spend_inputs = Vec::with_capacity(prepared.len());
        let mut pqc_pubkeys = Vec::with_capacity(prepared.len());
        for p in prepared {
            spend_inputs.push(p.spend);
            pqc_pubkeys.push(p.pqc_pubkey);
        }
        // `output_infos` and `vin` MOVE into the proving closure (no clones:
        // neither is read again until the closure returns them).
        let outputs_for_prove = output_infos;
        let tree = msg.tree_ctx.clone();
        let reward_term = InputTerm::new(AtomicUnits::from_raw(total_reward));
        let (signed, spend_inputs, vin) = tokio::task::spawn_blocking(move || {
            let signed = sign_transaction_with_terms(
                prefix_hash,
                &spend_inputs,
                &outputs_for_prove,
                AtomicUnits::from_raw(fee),
                &[reward_term],
                &[],
                &tree,
            )
            .map_err(|e| StakeEngineError::from(BondAssemblyError::build("proving", e)))?;
            // Step-7 self-check, backing leg: the landed consensus verifier
            // over the assembled vin (cause-blind on refusal, CB-5).
            if let Err(e) = emission_vin_verify_backing(
                &vin,
                &tree.tree_root,
                tree.tree_depth,
                signable_tx_hash,
            ) {
                tracing::error!(error = %e, "emission self-check: backing verification failed");
                return Err(StakeEngineError::EmissionClaim(
                    EmissionClaimError::SelfCheckFailed,
                ));
            }
            Ok((signed, spend_inputs, vin))
        })
        .await
        .map_err(|e| BondAssemblyError::build("proving offload join", e))??;

        // The auth digest bound the pre-computed reward commit; the daemon
        // verifies against the tx's outPk (the signer's commitment). Both
        // are z·G + amount·H over the same mask — divergence is a build
        // defect, failed loudly before any bytes leave the builder.
        if signed.commitments.first() != Some(&reward_commits[0].commitment) {
            debug_assert!(
                false,
                "signer reward commitment diverged from the auth-bound commit"
            );
            return Err(BondAssemblyError::build(
                "reward-commit cross-check",
                "signer commitment diverged from the auth-bound reward commit",
            )
            .into());
        }

        let bulletproof = Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice())
            .map_err(|e| BondAssemblyError::build("bulletproof parse", e))?;

        // ── Step 16: assemble the wire input; pqc_auths carries one slot
        // per prefix input — the fee spend slots (output-derived keys) then
        // the emission slot (P's identity key: the daemon derives the vin's
        // p_canonical_id from this slot's pubkey, id-equality at
        // blockchain.cpp:3783).
        let mut wire = WireEncodeInput {
            key_images,
            extra_inputs,
            output_amounts,
            output_keys,
            view_tags,
            tx_extra,
            fee,
            enc_amounts: signed.enc_amounts,
            enc_labels: signed.enc_labels,
            out_commitments: signed.commitments,
            pseudo_outs: signed.pseudo_outs,
            bulletproof,
            reference_block: signed.reference_block,
            fcmp_proof: signed.fcmp_proof,
            // Placeholder auths at real pubkeys (the phase-1 payload hash
            // reads them); the fee-slot pubkeys MOVE in — nothing reads
            // `pqc_pubkeys` again (`sign_pqc_auths` re-derives per input).
            pqc_auths: pqc_pubkeys
                .into_iter()
                .map(|pk| PqcAuth {
                    auth_version: 1,
                    signature: Vec::new(),
                    public_key: pk,
                })
                .chain(std::iter::once(PqcAuth {
                    auth_version: 1,
                    signature: Vec::new(),
                    public_key: hybrid_pk_bytes.clone(),
                }))
                .collect(),
            fcmp_layers: signed.tree_depth,
        };

        // ── Step 17: PQC auth completion (fast; inline). Fee slots sign
        // with output-derived keys; the emission slot signs with P's
        // `hybrid_sign_sk` (CB-2: derived bundle, no seed re-borrow).
        let payload_hashes = phase1_payload_hashes(&wire)
            .map_err(|e| BondAssemblyError::build("phase1 payload hash", e))?;
        if payload_hashes.len() != spend_inputs.len() + 1 {
            return Err(BondAssemblyError::build(
                "phase1 payload hash",
                format!(
                    "expected {} payload hashes, got {}",
                    spend_inputs.len() + 1,
                    payload_hashes.len()
                ),
            )
            .into());
        }
        let mut pqc_auths = sign_pqc_auths(&payload_hashes[..spend_inputs.len()], &spend_inputs)
            .map_err(|e| BondAssemblyError::build("pqc auth signing", e))?;
        let emission_payload_hash = payload_hashes[spend_inputs.len()];
        let emission_sig = HybridEd25519MlDsa
            .sign(&keys.hybrid_sign_sk, &emission_payload_hash)
            .map_err(|e| BondAssemblyError::build("emission pqc auth signing", e))?;
        pqc_auths.push(PqcAuth {
            auth_version: 1,
            signature: emission_sig
                .to_canonical_bytes()
                .map_err(|e| BondAssemblyError::build("emission pqc auth encoding", e))?,
            public_key: hybrid_pk_bytes,
        });
        wire.pqc_auths = pqc_auths;
        drop(spend_inputs); // secrets end here; nothing below needs them

        // ── Step 18: remaining self-check legs (fast; inline). Claims leg:
        // the landed verifier's economics recompute against the paired
        // source. Auth leg: both role signatures over the recomputed
        // binding messages (cause-blind on refusal, CB-5).
        self_check_claims(&ops.source, &vin, total_reward)?;
        if let Err(e) = emission_vin_verify_auth(&vin, &reward_commits, &signable_tx_hash) {
            tracing::error!(error = %e, "emission self-check: auth verification failed");
            return Err(EmissionClaimError::SelfCheckFailed.into());
        }

        // ── Step 19: encode + mint at the P-1 site. ──────────────────────
        let bound_tx = finalize_bond_tx(persona, &wire)?;

        Ok(AssembledEmissionClaim {
            bound_tx,
            fee_gindexes,
            claimed_epochs: claims.settlement_epochs,
            size_deferred: claims.size_deferred,
            total_reward,
        })
    }
}

// ---------------------------------------------------------------------------
// WI-2 D-A3 step 1 — P-side per-output spend-bundle derivation
// ---------------------------------------------------------------------------

/// Re-derive the per-output spend-secrets bundle for a **P-owned** funding
/// output — the persona analog of
/// [`LocalKeys::derive_primary_source_secrets_bundle`]
/// (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.3 actor step 1), over the same
/// pipeline with `P`'s keys substituted for the principal's:
///
/// 1. `combined_ss` ← [`recover_combined_ss`]`(P.view_sk, P.ml_kem_dk,
///    ciphertext)` — hybrid X25519 + ML-KEM-768 re-decap and HKDF-SHA-512
///    combination.
/// 2. Per-output secrets ← [`derive_output_secrets`]`(combined_ss,
///    output_index)`.
/// 3. Spend scalar `x = ho + b` with `b` = `P.spend_sk`. **No claim offset**,
///    for the same reason as the principal path: `P`'s funding outputs are
///    paid to the *base* spend key `b·G` (the scan's `GuaranteedScanner`
///    claims against `spend_pk` directly), so `O = x·G + y·T` and
///    `KI = x·Hp(O)` both bind to `b`.
///
/// This is exactly the WI-2 D-A1 re-derivation contract: the persisted
/// `PFundingOutputRecord` carries only `(ciphertext, index_in_transaction)`
/// public identity; the secrets drop in the scan's offload closure (rule 16,
/// the M3d discipline) and are recomputed here, inside the actor, at
/// assemble time. Every intermediate is `Zeroizing`; only the bundle's own
/// wiped-on-drop fields leave the frame — and the bundle itself never leaves
/// the actor (rule 36).
///
/// A free function rather than a `StakeEngine` method: it needs only the
/// borrowed [`ArchivalPKeys`], and the `AssembleBond` handler calls it per
/// selected funding record before entering the proving offload.
///
/// [`LocalKeys::derive_primary_source_secrets_bundle`]: super::local_keys::LocalKeys
/// [`recover_combined_ss`]: shekyl_crypto_pq::output::recover_combined_ss
/// [`derive_output_secrets`]: shekyl_crypto_pq::derivation::derive_output_secrets
#[allow(dead_code)] // transient — consumed by the WI-2 `AssembleBond` handler as it lands.
pub(crate) fn derive_p_source_secrets_bundle(
    keys: &ArchivalPKeys,
    source_ciphertext: &HybridCiphertext,
    output_index: u64,
) -> Result<SourceSecretsBundle, KeyEngineError> {
    let combined_ss = recover_combined_ss(
        keys.view_sk.as_canonical_bytes(),
        keys.ml_kem_dk.as_canonical_bytes(),
        &source_ciphertext.x25519,
        &source_ciphertext.ml_kem,
    )?;

    let secrets = derive_output_secrets(&combined_ss.0, output_index);

    // `x = ho + b` — see the principal-path comment in `local_keys.rs` for
    // why there is no claim-offset term. Each intermediate `Scalar` is
    // `Zeroizing` so the canonical-byte materializations wipe on drop.
    let ho_scalar: Zeroizing<Scalar> = Zeroizing::new(
        Option::from(Scalar::from_canonical_bytes(secrets.ho))
            .expect("ho from wide_reduce is always canonical (per derive_output_secrets)"),
    );
    let b_scalar: Zeroizing<Scalar> = Zeroizing::new(Scalar::from_bytes_mod_order(
        *keys.spend_sk.as_canonical_bytes(),
    ));
    let x_scalar: Zeroizing<Scalar> = Zeroizing::new(*ho_scalar + *b_scalar);
    let spend_key_x = Zeroizing::new(x_scalar.to_bytes());

    Ok(SourceSecretsBundle {
        spend_key_x,
        spend_key_y: Zeroizing::new(secrets.y),
        commitment_mask: Zeroizing::new(secrets.z),
        combined_ss: Zeroizing::new(combined_ss.0.to_vec()),
        output_index,
    })
}

/// `KI = x·Hp(O)` for one funding record, from its public
/// `(ciphertext, index, output_key)` identity and the owning persona's
/// vaulted keys — **the** single definition of the funding key image
/// (SP-R0 arm #1). Every consumer — the actor's watch derive-on-add, the
/// assemble path ([`prepare_funding_inputs`] via
/// [`key_image_from_spend_key_x`], sharing the leg after its own bundle
/// derivation), and the DQ-F fire harness — derives through here, so the
/// construction cannot diverge between the watch and the sweep. A divergence
/// would mean derived watch key images stop matching on-chain spends, prunes
/// never fire, and the stale-record poison [`SpentRecordsDurablyPruned`]
/// precludes returns — which is why this is one function, not three copies.
///
/// The derived intermediates are `Zeroizing`; only the key image leaves.
/// Errors are public reason text, never key material.
pub(crate) fn derive_funding_key_image(
    keys: &ArchivalPKeys,
    ciphertext_x25519: [u8; 32],
    ciphertext_ml_kem: &[u8],
    index_in_transaction: u64,
    output_key: [u8; 32],
) -> Result<[u8; 32], String> {
    let ciphertext = HybridCiphertext {
        x25519: ciphertext_x25519,
        ml_kem: ciphertext_ml_kem.to_vec(),
    };
    let bundle = derive_p_source_secrets_bundle(keys, &ciphertext, index_in_transaction)
        .map_err(|e| format!("spend-bundle derivation: {e}"))?;
    key_image_from_spend_key_x(&bundle.spend_key_x, output_key)
}

/// The key-image leg of [`derive_funding_key_image`] alone — for the
/// assemble path, which already holds the derived bundle (it needs the
/// bundle's other secrets too) and must compute the same `KI = x·Hp(O)` the
/// FCMP++ verifier checks.
pub(crate) fn key_image_from_spend_key_x(
    spend_key_x: &[u8; 32],
    output_key: [u8; 32],
) -> Result<[u8; 32], String> {
    let x_scalar: Zeroizing<Scalar> = Zeroizing::new(
        Option::from(Scalar::from_canonical_bytes(*spend_key_x))
            .ok_or_else(|| "non-canonical x".to_owned())?,
    );
    Ok((biased_hash_to_point(output_key) * *x_scalar)
        .compress()
        .to_bytes())
}

// SP-5 — the actor performs the per-batch scan-step; `view_sk` never crosses the
// boundary. The handler builds the bonded union's transient scanners from the
// resident bundles and **offloads** the CPU+secret dual extraction to
// `spawn_blocking`, so the secret lives only inside the closure and drops at its
// end (DQ5). The handler holds `&mut self` across the offload `await`, so the
// (unbounded) mailbox cannot process another message until it returns — which is
// exactly why the task sends **bounded** `ScanStep`s, interleaving
// activation/sign/activate between batches (DQ6: bounded AND offloaded). Only the
// public `ScanStepResult` comes back.
impl Message<ScanStep> for StakeEngine {
    type Reply = Result<ScanStepResult, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: ScanStep,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let ScanStep {
            range,
            blocks,
            held_funding,
        } = msg;
        // SP-R0 arm #1 (DQ-A): watch upkeep against the task's held list —
        // cheap set work in-actor; any uncached record's derivation offloads
        // to its own blocking closure (DQ5/DQ6 — the vault moves in and back;
        // spend material never enters the *extractor* closure below). The
        // common warm-cache step derives nothing and skips the offload.
        let to_derive = self.watch_upkeep(&held_funding);
        if !to_derive.is_empty() {
            let outcomes = self.derive_watch_key_images_offloaded(to_derive).await;
            for (gindex, outcome) in outcomes {
                self.absorb_watch_derivation(gindex, outcome);
            }
        }
        let (scanners, known_personas) = self.bonded_scan_inputs()?;
        // Hand the extractor closure a transient watch snapshot (documented
        // rule-35 `Clone` exception on the type; both copies wipe on drop).
        let watch = self.watch_cache.clone();
        // The secret `scanners` are MOVED into the closure; they never reach the
        // actor task again and are dropped at the closure's end. The two `?`
        // surface the join failure (`ScanJoin`) and the extraction failure
        // (`ScanStep`) via their `#[from]` conversions — structured, not
        // stringified.
        let DualExtractOutput {
            mut result,
            trailing_key_images,
        } = tokio::task::spawn_blocking(move || {
            run_dual_extractor(scanners, &known_personas, range, &blocks, &watch)
        })
        .await??;
        // Close arm (c)'s in-step blind spot: derive this step's discoveries
        // (derive-on-add, offloaded exactly like the refresh) and match them
        // against the trailing spend key images the closure collected — an
        // output discovered at height `h` can be spent at `h' > h` within
        // the same step, and only the actor can derive its key image. Merged
        // hits prune exactly like watch hits; the derived entries also warm
        // the cache for the next step. Discoveries are rare (the common case
        // is an empty candidate list — zero cost, no offload).
        let to_derive = self.watch_derivation_candidates(&result.funding_outputs);
        if !to_derive.is_empty() {
            let outcomes = self.derive_watch_key_images_offloaded(to_derive).await;
            for (gindex, outcome) in outcomes {
                if let Some(key_image) = self.absorb_watch_derivation(gindex, outcome) {
                    if trailing_key_images.contains(&key_image) {
                        result.spent_funding.push(SpentFundingMatch { gindex });
                    }
                }
            }
        }
        // Drop-on-prune: spent outputs leave the watch with their records.
        for spent in &result.spent_funding {
            self.watch_cache.remove_gindex(spent.gindex);
        }
        Ok(result)
    }
}

/// Project the **public** canonical id of a held persona (SA-DQ-3 / first-stake
/// W2-resume: the engine needs to ask "does a confirmed bond post exist for
/// slot S?" against the pscan evidence, which is keyed by canonical id). Same
/// public projection `bonded_scan_inputs` computes per scan; no secret
/// crosses the boundary.
pub(crate) struct ProjectPersonaCanonicalId {
    pub p_slot: PSlot,
}

impl Message<ProjectPersonaCanonicalId> for StakeEngine {
    type Reply = Result<PCanonicalId, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: ProjectPersonaCanonicalId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let held = self
            .held
            .get(&msg.p_slot)
            .ok_or(StakeEngineError::LookaheadExhausted {
                requested: msg.p_slot,
            })?;
        persona_canonical_id(held.keys())
            .map_err(|e| StakeEngineError::ScanSetup(ScanSetupError::CanonicalId(e)))
    }
}

/// Retire a now-terminal bonded persona from the scan union (2d-1 DQ8), wiping its
/// key. Carries the [`RetirementWitness`] — the positive-confirmation evidence
/// that gates the wipe (the actor cannot re-verify). Sent by the SP-5 scan task
/// when it confirms an `Unbond` + `W`-lapse + finality-deep.
#[allow(dead_code)] // transient — the SP-5 scan task is the lib sender.
pub(crate) struct RetireBondedPersona {
    pub witness: RetirementWitness,
    /// Slots the caller knows still hold unspent funding — the funded-gate
    /// operand. The handler resolves the witness to a slot and refuses the
    /// irreversible wipe if the slot is in this set (returns `SkippedFunded`).
    /// `Arc` so a sweep with many retire candidates clones a pointer per
    /// message, not the set (the containment properties — redacting `Debug`,
    /// no `Serialize` — ride through the `Arc` unchanged).
    pub funded_slots: std::sync::Arc<FundedSlots>,
}

// The retire is infallible at the actor — all outcomes are valid and idempotent,
// so the handler always returns `Ok`. The `Result` reply matches the other
// handlers (and lets the handle's `ask` surface a stopped actor as
// `StakeActorUnavailable`); the `Err` arm is only ever the actor being gone.
impl Message<RetireBondedPersona> for StakeEngine {
    type Reply = Result<RetireOutcome, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: RetireBondedPersona,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.retire_bonded(&msg.witness, &msg.funded_slots))
    }
}

/// The entry-gap degeneracy guard fired: two consecutive draws produced equal
/// spreads (the double-jitter-trap signature).
///
/// A named zero-sized type rather than `()` so the failure reads at the
/// signature and the single call site maps it explicitly. It is deliberately
/// **not** an enum: there is exactly one way this guard fails, and a multi-variant
/// "in case we add more later" error would be pre-provisioned flexibility
/// (`21-reversion-clause-discipline.mdc`) — add a variant (or a new error type)
/// when a second failure mode actually exists.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DegenerateDraw;

/// Draw an entry gap and check for the double-jitter-trap degeneracy pattern
/// (S5, Round 3 — per-draw guard, float-free, integer-only).
///
/// Draws twice from `rng`. If the two `spread` values are equal, the guard
/// fires and [`DegenerateDraw`] is returned — the caller maps this to
/// [`StakeEngineError::RngDegeneracy`]. On success, the first draw's `spread`
/// is returned; the probe draw is consumed and discarded.
///
/// **Why two draws?** The double-jitter trap produces a triangular spread
/// distribution (peaked at 0) by computing `|a - b|`; consecutive draws from
/// such a source are statistically likely to cluster. Two consecutive equal
/// spreads from a correct CSPRNG occur with probability ≈ 1/(window+1) ≈
/// 0.17 % — rare enough to fire on a stuck RNG without triggering excessive
/// retries on a correct one.
///
/// **False-positive handling:** the caller (the `SignBond` handler) surfaces
/// `RngDegeneracy` and the user retries. A single false positive in 601 bond
/// requests is acceptable; multiple consecutive false positives signal a
/// broken entropy source.
///
/// **Extracted for testability** (S7(b)): tests feed degenerate `GapRng`
/// implementations directly into this function without going through the actor
/// or `OsRng`.
///
/// # Precondition: `window > 0`
///
/// A zero-width window draws `spread == 0` deterministically on every call, so
/// the two probe draws are *trivially* equal and the guard would fire — but that
/// is a **window misconfiguration**, not RNG degeneracy: a zero-width standoff
/// provides no funding↔bond-post decorrelation, defeating the gate-6 firewall
/// the draw exists to serve. The operational caller always passes
/// [`DEFAULT_ENTRY_GAP`] (600), so a zero window is unreachable in
/// production; the `debug_assert` catches any future misuse loudly in test/debug
/// builds rather than silently mislabelling it as `RngDegeneracy`. (More
/// generally the guard is only well-behaved for windows large enough that
/// `1/(window+1)` is an acceptable false-positive rate — 600 gives ≈ 0.17 %.)
///
/// The draw yields a single `spread` — there is no order coin (retired: only the
/// bond post is chain-attributable, so there is no second event to order,
/// `ARCHIVAL_FIREWALL_GATE6.md` method note 8).
pub(crate) fn draw_entry_gap_guarded<R: GapRng>(
    window: u64,
    rng: &mut R,
) -> Result<u64, DegenerateDraw> {
    debug_assert!(
        window > 0,
        "entry-gap window must be > 0: a zero-width standoff provides no \
         decorrelation and makes the degeneracy guard fire unconditionally; \
         pass the operational DEFAULT_ENTRY_GAP window"
    );
    let spread_draw = draw_entry_gap(window, rng);
    let spread_probe = draw_entry_gap(window, rng);
    if spread_draw == spread_probe {
        return Err(DegenerateDraw);
    }
    Ok(spread_draw)
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
    /// projection: no activation, no activation, no generation advance (see
    /// [`PersonaIdentityOf`]).
    pub(crate) async fn persona_identity(
        &self,
        p_slot: PSlot,
    ) -> Result<PersonaIdentity, StakeEngineError> {
        self.actor
            .ask(PersonaIdentityOf { p_slot })
            .await
            .map_err(collapse_send_error)
    }

    /// Build and sign a JoinMarket archival bond post for the persona named by
    /// `handle` (Bond-PR 2c-2b, S1/S2), returning the signed vin **paired
    /// with** its block-timed placement plan ([`SignedBondPost`]).
    ///
    /// Consumes both `handle` (operation-scoped capability, typed contract #2)
    /// and `ticket` (persist-before-use witness, typed contract #1) by value,
    /// so "sign before persist" and "sign for an unheld persona" are uncallable.
    ///
    /// See [`SignBond`] for the full caller workflow.
    ///
    /// # Errors
    ///
    /// - [`StakeEngineError::StakeActorUnavailable`] — actor stopped (terminal).
    /// - [`StakeEngineError::StaleHandle`] — the handle is from a prior
    ///   generation *or* its slot is no longer in the held set. Both collapse to
    ///   `StaleHandle` in `validate_handle` (a wipe advances the generation, so a
    ///   stale-generation handle and a no-longer-held slot are the same failure).
    ///   `LookaheadExhausted` is *not* reachable here — it is a `mint_handle`
    ///   error; signing only validates an already-minted handle.
    /// - [`StakeEngineError::SlotMismatch`] — `handle.p_slot != ticket.p_slot`.
    /// - [`StakeEngineError::RngSourceFailed`] — OS entropy source unavailable.
    /// - [`StakeEngineError::RngDegeneracy`] — timing draw degenerate; retry.
    /// - [`StakeEngineError::BondBuild`] — bond construction failed (see inner).
    #[allow(dead_code)] // inert until 2c-2b request path is wired end-to-end
    pub(crate) async fn sign_bond(
        &self,
        handle: PersonaHandle,
        ticket: super::stake_persist::PersistedBondTicket,
        holdings: HoldingsDescriptor,
        tx_prefix_hash: [u8; 32],
    ) -> Result<SignedBondPost, StakeEngineError> {
        self.actor
            .ask(SignBond {
                handle,
                ticket,
                holdings,
                tx_prefix_hash,
            })
            .await
            .map_err(collapse_send_error)
    }

    /// Ask the actor to assemble the full, broadcast-ready JoinMarket bond
    /// (`AssembleBond`). Engine-side caller is [`Engine::assemble_bond_post`]
    /// (WI-2 §3.3). Dead_code allow retires only when **both** SP-R0 / 2d-1
    /// pruning **and** the RPC stake entry land — neither alone (half (a)
    /// landed 2026-07-18 with SP-R0 arm #1; half (b) remains).
    pub(crate) async fn assemble_bond(
        &self,
        handle: PersonaHandle,
        ticket: super::stake_persist::PersistedBondTicket,
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
    /// Dead_code allow: the assembly is wired; the Engine orchestrator entry
    /// (DS-PR-2) and the RPC drain entry are the remaining consumers (rule-21).
    #[allow(dead_code)]
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
    #[allow(dead_code)] // transient — the driving task (PR-B / SP-5) is the non-test consumer.
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
    #[allow(dead_code)] // transient — the driving task (PR-B / SP-5) is the non-test consumer.
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

/// Shared C-4 fixtures — one fixture family across the actor's own KATs and
/// the `claim_orchestrator` end-to-end KAT (the `emission_claim::test_fixtures`
/// precedent: promote rather than grow a second source shape that can drift).
#[cfg(test)]
pub(crate) mod test_fixtures {
    use std::collections::{BTreeMap, BTreeSet};

    use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
    use shekyl_crypto_pq::archival_p::{derive_archival_p_keys, ArchivalPKeys};
    use shekyl_crypto_pq::output::construct_output;
    use shekyl_curve_generators::biased_hash_to_point;
    use shekyl_engine_state::pscan_state::{MintLineageOutput, PFundingOutputRecord};
    use shekyl_tx_builder::LeafEntry;

    use super::{PSlot, StakeEngineHandle};
    use crate::engine::test_support::funding_record;

    /// Deterministic test seed (matches the `archival_p` module's KAT fixture).
    const TEST_SEED: [u8; MASTER_SEED_BYTES] = [0x33u8; MASTER_SEED_BYTES];

    /// One tx-key for every fixture output (outputs differ by index).
    pub(crate) const FIXTURE_TX_KEY: [u8; 32] = [0x5Au8; 32];

    /// Derive a persona bundle for `p_slot` on mainnet/bip39 (a permitted pair).
    /// Re-derivable on demand because `ArchivalPKeys` is `!Clone` and derivation
    /// is deterministic — each spawn gets its own freshly-derived bundle.
    pub(crate) fn derive_bundle(p_slot: u32) -> ArchivalPKeys {
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
    pub(crate) fn spawn_over(
        held: &[u32],
        bonded: &[u32],
        active: Option<u32>,
    ) -> StakeEngineHandle {
        let bundles: BTreeMap<PSlot, ArchivalPKeys> = held
            .iter()
            .map(|&s| (PSlot::from_raw(s), derive_bundle(s)))
            .collect();
        let bonded: BTreeSet<PSlot> = bonded.iter().map(|&s| PSlot::from_raw(s)).collect();
        StakeEngineHandle::spawn(bundles, bonded, active.map(PSlot::from_raw))
    }

    /// A REAL P-paid output for `keys`: a funding record carrying the
    /// exact public identity `construct_output` emitted (so the actor's
    /// re-derivation chain — combined-ss recovery, spend/mask scalars,
    /// per-output PQC keypair — reproduces the construction) plus the
    /// matching curve-tree leaf with the REAL `h_pqc`. The real hash is
    /// load-bearing: the handler's pre-flight leaf gate and the
    /// verify-side C-1 gate both demand `hash(backing_pubkey) ==
    /// leaf.h_pqc`, so a synthetic value refuses assembly.
    pub(crate) fn constructed_record(
        keys: &ArchivalPKeys,
        gindex: u64,
        height: u64,
        amount: u64,
        index_in_transaction: u64,
        lineage: MintLineageOutput,
    ) -> (PFundingOutputRecord, LeafEntry) {
        let constructed = construct_output(
            &FIXTURE_TX_KEY,
            &keys.x25519_pk,
            &keys.ml_kem_ek,
            keys.spend_pk.as_canonical_bytes(),
            amount,
            index_in_transaction,
        )
        .expect("fixture output constructs");
        let mut record = funding_record(0, gindex, height, amount, lineage);
        record.index_in_transaction = index_in_transaction;
        record.output_key = constructed.output_key;
        record.commitment = constructed.commitment;
        record.ciphertext_x25519 = constructed.kem_ciphertext_x25519;
        record.ciphertext_ml_kem = constructed.kem_ciphertext_ml_kem.clone();
        let leaf = LeafEntry {
            output_key: constructed.output_key,
            key_image_gen: biased_hash_to_point(constructed.output_key)
                .compress()
                .to_bytes(),
            commitment: constructed.commitment,
            h_pqc: constructed.h_pqc,
        };
        (record, leaf)
    }
}

#[cfg(test)]
#[path = "stake_engine_tests.rs"]
mod tests;
