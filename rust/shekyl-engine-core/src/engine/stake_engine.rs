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
mod tests {
    //! Lifecycle contract tests for [`StakeEngine`] / [`StakeEngineHandle`]
    //! (`ARCHIVAL_BOND_CONSTRUCTION.md` §10.2) under **Model D**: the actor holds
    //! pre-derived bundles, never the seed. Tests derive the derive-forward set
    //! with the `derive_archival_p_keys` oracle (via the shared `test_fixtures`)
    //! and hand it in, then exercise the actor through real messages — no mocks.
    //! The same oracle is rerun to confirm the actor projects the genesis-frozen
    //! identity bytes.

    use super::test_fixtures::{constructed_record, derive_bundle, spawn_over};
    use super::*;

    use shekyl_archival_retention::{ShardSet, MAX_CLAIM_AGE_W};

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
        let h = handle.mint_handle(PSlot::from_raw(slot)).await?;
        handle.activate_persona(h).await
    }

    /// GF-2 boundary (the firewall-critical half of `Engine::stake_in`): the
    /// address the actor projects for the active persona — public-only, built
    /// in-actor, no re-derivation — is one `P`'s own dual-scan recovers.
    /// Construct an output to the *projected* address, then recover it with `P`'s
    /// secret bundle (the `derive_bundle` oracle — test-side only; production
    /// never re-derives). A wrong projection (wrong keys / wrong persona) fails
    /// recovery.
    #[tokio::test]
    async fn active_persona_receive_address_is_recovered_by_p_dual_scan() {
        use shekyl_crypto_pq::montgomery::ed25519_pk_to_x25519_pk;
        use shekyl_crypto_pq::output::{construct_output, scan_output_recover};

        let slot = 3u32;
        // Address network is the sender's; it does not affect the derived keys
        // (which the `DerivationNetwork` fixes), only the address encoding.
        let network = Network::Mainnet;

        let stake = spawn_over(&[slot], &[], Some(slot));
        let address = stake
            .active_persona_receive_address(network)
            .await
            .expect("accessor")
            .expect("an active persona projects an address")
            .encode()
            .expect("encode P's projected address");

        // The address `stake_in` would target, decoded back to key material.
        let decoded = ShekylAddress::decode_for_network(&address, network).expect("decode");
        let x25519_pk = ed25519_pk_to_x25519_pk(&decoded.view_key).expect("montgomery");

        let amount = 50_000u64;
        let output_index = 7u64;
        let constructed = construct_output(
            &[0x5Au8; 32],
            &x25519_pk,
            &decoded.ml_kem_encap_key,
            &decoded.spend_key,
            amount,
            output_index,
        )
        .expect("construct an output to P's projected address");

        // P's dual-scan (secret bundle via the test oracle) recovers it.
        let keys = derive_bundle(slot);
        let recovered = scan_output_recover(
            keys.view_sk.as_canonical_bytes(),
            keys.ml_kem_dk.as_canonical_bytes(),
            &constructed.kem_ciphertext_x25519,
            &constructed.kem_ciphertext_ml_kem,
            &constructed.output_key,
            &constructed.commitment,
            &constructed.enc_amount,
            constructed.amount_tag,
            &constructed.enc_label,
            constructed.label_tag,
            constructed.view_tag_prefilter,
            output_index,
        )
        .expect("P recovers the output addressed via the actor's projection");

        assert_eq!(
            recovered.amount, amount,
            "recovered amount matches the funded amount"
        );
        assert_eq!(
            &recovered.recovered_spend_key,
            keys.spend_pk.as_canonical_bytes(),
            "the output is owned by P (projected address == P's receive key)"
        );

        // Idle actor projects no address (the `NoActivePersona` path).
        let idle = spawn_over(&[slot], &[], None);
        assert!(
            idle.active_persona_receive_address(network)
                .await
                .expect("accessor")
                .is_none(),
            "an idle actor projects no receive address"
        );
    }

    /// WI-2 D-A1/D-A3 — the P-side spend-bundle re-derivation is
    /// byte-identical to the scanner-side derivation chain for the same
    /// output (the M3b byte-identical-derivation property, P edition,
    /// `ARCHIVAL_BOND_WI2_ASSEMBLY.md` §4).
    ///
    /// The persisted `PFundingOutputRecord` carries only public identity
    /// (`ciphertext`, `index_in_transaction`); assemble-time spending is
    /// sound only if [`derive_p_source_secrets_bundle`] recomputes exactly
    /// the secrets the scan derived (and dropped) at discovery time. The
    /// oracle here is `scan_output_recover` — the same chain the persona
    /// `GuaranteedScanner` drives — hand-composed into a bundle, plus the
    /// SAL open `x·G + y·T == O` as the real-correctness guard.
    #[test]
    fn p_source_secrets_bundle_byte_identical_against_scan_chain() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use shekyl_crypto_pq::output::{construct_output, scan_output_recover};

        let keys = derive_bundle(0);
        let tx_key_secret = [0x5Au8; 32];

        for output_index in [0u64, 1, 7, 255, 1_000_000] {
            let constructed = construct_output(
                &tx_key_secret,
                &keys.x25519_pk,
                &keys.ml_kem_ek,
                keys.spend_pk.as_canonical_bytes(),
                50_000u64.wrapping_add(output_index),
                output_index,
            )
            .expect("construct_output succeeds for a P-paid synthetic output");
            let ciphertext = HybridCiphertext {
                x25519: constructed.kem_ciphertext_x25519,
                ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
            };

            // Oracle: the scanner-side chain, hand-composed (x = ho + b,
            // no claim offset — P outputs are paid to the base spend key).
            let recovered = scan_output_recover(
                keys.view_sk.as_canonical_bytes(),
                keys.ml_kem_dk.as_canonical_bytes(),
                &constructed.kem_ciphertext_x25519,
                &constructed.kem_ciphertext_ml_kem,
                &constructed.output_key,
                &constructed.commitment,
                &constructed.enc_amount,
                constructed.amount_tag,
                &constructed.enc_label,
                constructed.label_tag,
                constructed.view_tag_prefilter,
                output_index,
            )
            .expect("scan_output_recover claims the P-paid output");
            let ho: Scalar =
                Option::from(Scalar::from_canonical_bytes(recovered.ho)).expect("ho canonical");
            let b: Scalar = Scalar::from_bytes_mod_order(*keys.spend_sk.as_canonical_bytes());
            let oracle_x = (ho + b).to_bytes();

            // Assemble-time chain under test.
            let bundle = derive_p_source_secrets_bundle(&keys, &ciphertext, output_index)
                .expect("derive_p_source_secrets_bundle succeeds against own ciphertext");

            assert_eq!(
                *bundle.spend_key_x, oracle_x,
                "spend_key_x byte-identity violated (output_index={output_index})"
            );
            assert_eq!(*bundle.spend_key_y, recovered.y);
            assert_eq!(*bundle.commitment_mask, recovered.z);
            assert_eq!(bundle.combined_ss.as_slice(), &recovered.combined_ss[..]);
            assert_eq!(bundle.output_index, output_index);

            // Real-correctness guard: the derived witness opens the output
            // key under the SAL relation the daemon enforces.
            let x: Scalar = Option::from(Scalar::from_canonical_bytes(*bundle.spend_key_x))
                .expect("x canonical");
            let y: Scalar = Option::from(Scalar::from_canonical_bytes(*bundle.spend_key_y))
                .expect("y canonical");
            let o = CompressedEdwardsY(constructed.output_key)
                .decompress()
                .expect("O decompresses");
            assert_eq!(
                (&x * ED25519_BASEPOINT_TABLE) + (*shekyl_curve_generators::T * y),
                o,
                "SAL relation x·G + y·T == O violated (output_index={output_index})"
            );
        }
    }

    /// A corrupted funding-record ciphertext fails closed at re-derivation
    /// (the D-A5 "spend-bundle derivation failure" row): a low-order X25519
    /// component is rejected by `recover_combined_ss`, never silently spent.
    #[test]
    fn p_source_secrets_bundle_rejects_tampered_ciphertext() {
        let keys = derive_bundle(0);
        let tampered = HybridCiphertext {
            x25519: [0u8; 32], // low-order Montgomery point u=0
            ml_kem: vec![0u8; shekyl_crypto_pq::kem::ML_KEM_768_CT_LEN],
        };
        let err = derive_p_source_secrets_bundle(&keys, &tampered, 0)
            .expect_err("a low-order X25519 component must be rejected");
        assert!(matches!(
            err,
            KeyEngineError::SourceCiphertextDecapsulationFailed(_)
        ));
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
        assert_eq!(identity.p_slot, PSlot::from_raw(0));
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
        assert_eq!(active.p_slot, PSlot::from_raw(0));
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
            .mint_handle(PSlot::from_raw(7))
            .await
            .expect_err("slot 7 is not held");
        assert!(
            matches!(err, StakeEngineError::LookaheadExhausted { requested } if requested == PSlot::from_raw(7)),
            "expected LookaheadExhausted{{7}}, got {err:?}"
        );
    }

    // §10.1 robustness #2 — activation replaces the active persona in a single
    // transition: after activating to slot 1, slot 1 is the *only* active persona.
    #[tokio::test]
    async fn activation_replaces_active_persona() {
        let handle = spawn_over(&[0, 1], &[0, 1], None);

        let id0 = mint_and_activate(&handle, 0).await.expect("activate 0");
        let id1 = mint_and_activate(&handle, 1)
            .await
            .expect("activate slot 1");
        assert_ne!(
            bond_id_bytes(&id0),
            bond_id_bytes(&id1),
            "distinct slots project distinct personas"
        );
        assert_eq!(id1.p_slot, PSlot::from_raw(1));

        let active = handle
            .active_persona()
            .await
            .expect("active query")
            .expect("a persona is active");
        assert_eq!(active.p_slot, PSlot::from_raw(1));
        assert_eq!(bond_id_bytes(&active), bond_id_bytes(&id1));
    }

    // Typed contract #4 — activation wipes the retired *ephemeral* persona: after
    // moving away from an unbonded slot, that slot is no longer held, so a
    // subsequent mint is `LookaheadExhausted`.
    #[tokio::test]
    async fn activation_wipes_ephemeral_retired() {
        let handle = spawn_over(&[0, 1], &[], None); // both ephemeral

        mint_and_activate(&handle, 0).await.expect("activate 0");
        mint_and_activate(&handle, 1)
            .await
            .expect("activate slot 1 (wipes ephemeral 0)");

        let err = handle
            .mint_handle(PSlot::from_raw(0))
            .await
            .expect_err("retired ephemeral slot 0 was wiped");
        assert!(
            matches!(err, StakeEngineError::LookaheadExhausted { requested } if requested == PSlot::from_raw(0)),
            "expected LookaheadExhausted{{0}} after ephemeral wipe, got {err:?}"
        );

        let active = handle
            .active_persona()
            .await
            .expect("active query")
            .expect("slot 1 active");
        assert_eq!(active.p_slot, PSlot::from_raw(1));
    }

    // Typed contract #4 — activation keeps a retired *bonded* persona resident:
    // unbonding it later stays reachable, so it can be re-activated after a
    // activation that passed over it.
    #[tokio::test]
    async fn activation_keeps_bonded_retired() {
        let handle = spawn_over(&[0, 1], &[0], None); // slot 0 bonded, slot 1 ephemeral

        let id0 = mint_and_activate(&handle, 0).await.expect("activate 0");
        mint_and_activate(&handle, 1)
            .await
            .expect("activate slot 1 (bonded 0 stays)");

        // Slot 0 is still held — re-mintable and re-activatable.
        let id0_again = mint_and_activate(&handle, 0)
            .await
            .expect("bonded slot 0 survived the activation");
        assert_eq!(
            bond_id_bytes(&id0_again),
            bond_id_bytes(&id0),
            "re-activated bonded persona is the same identity"
        );
    }

    // Typed contract #2 — a handle minted before an activation is stale afterward:
    // the activation advanced the actor's generation, so the retained handle is
    // rejected rather than acting against a possibly-wiped persona.
    #[tokio::test]
    async fn stale_handle_after_activation_is_rejected() {
        // Both bonded so the activation cannot wipe — isolating the generation
        // guard from the membership guard.
        let handle = spawn_over(&[0, 1], &[0, 1], None);

        // Mint a handle for slot 0 up front, then rotate via a *different*
        // handle, leaving the slot-0 handle straddling the activation.
        let stale = handle
            .mint_handle(PSlot::from_raw(0))
            .await
            .expect("mint slot 0");
        mint_and_activate(&handle, 1)
            .await
            .expect("activate slot 1 (advances generation)");

        let err = handle
            .activate_persona(stale)
            .await
            .expect_err("a handle retained across an activation is stale");
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
                .mint_handle(PSlot::from_raw(0))
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

    // -----------------------------------------------------------------------
    // Bond-PR 2c-2b S7 — request-path composition KAT + own-surface negatives
    // -----------------------------------------------------------------------
    //
    // S7(a): `verify_credit_funding` reject on wrong funding.
    // S7(b): degeneracy guard fires on degenerate draw (double-jitter-trap RNG).
    //
    // The `draw_entry_gap_guarded` helper is extracted and tested directly so the
    // degeneracy logic is exercised with injectable RNGs without going through the
    // actor (which uses `OsRngGapAdapter` in production).
    //
    // S7(c) unrepresentability ("sign without ticket", "unheld-handle sign") is
    // NOT covered by trybuild: that path was retired (plan §4.1 R0-D1) because the
    // capability tokens are `pub(crate)` with module-private fields, so an external
    // trybuild crate cannot name them without re-exposing firewall internals. It is
    // instead enforced unconditionally by the type system (module-private fields +
    // by-value consumption), with the `!Clone` half pinned by the always-on
    // `AmbiguousIfImpl` `const _` guard above (near `PersonaHandle`).

    /// S7(b) — degeneracy guard fires on a stuck-RNG (double-jitter-trap pattern).
    ///
    /// A `ConstRng` that always returns the same `u64` produces identical spread
    /// values on every call to `draw_entry_gap`, so `draw_entry_gap_guarded`
    /// must fire the degeneracy guard for any window > 0.
    #[test]
    fn degeneracy_guard_fires_on_stuck_rng() {
        struct ConstRng(u64);
        impl GapRng for ConstRng {
            fn next_u64(&mut self) -> u64 {
                self.0
            }
        }

        // Any constant value produces the same spread twice → guard fires.
        // Use the canonical operational window (single-sourced) so the test
        // tracks the wallet's real draw window rather than a stray literal.
        for seed in [0u64, 1, 42, u64::MAX / 2] {
            let mut rng = ConstRng(seed);
            let result =
                draw_entry_gap_guarded(shekyl_standoff::DEFAULT_ENTRY_GAP_WINDOW, &mut rng);
            assert!(
                result.is_err(),
                "stuck-RNG seed {seed}: expected degeneracy guard to fire, got ok"
            );
        }
    }

    /// S7(b) — degeneracy guard passes a correct RNG.
    ///
    /// A deterministic counter RNG produces distinct consecutive spreads (except
    /// in pathological cases the guard's false-positive rate handles via retry),
    /// so the guard should pass for the common case.
    #[test]
    fn degeneracy_guard_passes_correct_rng() {
        struct CounterRng(u64);
        impl GapRng for CounterRng {
            fn next_u64(&mut self) -> u64 {
                let v = self.0;
                self.0 = self.0.wrapping_add(1_000_000_007); // large coprime step
                v
            }
        }

        let mut rng = CounterRng(0xDEAD_BEEF_0000_0000);
        let result = draw_entry_gap_guarded(shekyl_standoff::DEFAULT_ENTRY_GAP_WINDOW, &mut rng);
        assert!(
            result.is_ok(),
            "counter RNG should not trigger the degeneracy guard: {result:?}"
        );
    }

    /// S7(a) — `verify_credit_funding` rejects incorrect funding totals.
    ///
    /// Tests the builder-level funding invariant directly (the actor path would
    /// call `verify_credit_funding` after the `sign_bond` handler produces the
    /// `JoinMarketVin`). Exercises both underflow and overflow cases.
    #[test]
    fn verify_credit_funding_rejects_wrong_total() {
        use shekyl_archival_bond_builder::{verify_credit_funding, BondBuildError};
        use shekyl_archival_retention::{HoldingsDescriptor, HoldingsKind};
        use shekyl_units::AtomicUnits;

        let bundle = derive_bundle(0);
        let holdings = HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
        };
        let tx_prefix_hash = [0u8; 32];
        let vin = build_join_market_vin(&bundle, holdings, &tx_prefix_hash)
            .expect("build_join_market_vin succeeds for valid inputs");

        let fee = AtomicUnits::from_raw(100);
        let outputs = AtomicUnits::from_raw(500);
        let bond_credit = AtomicUnits::from_raw(vin.vin().bond_credit);
        let correct_total = outputs
            .checked_add(fee)
            .and_then(|s| s.checked_add(bond_credit))
            .expect("test amounts fit in u64");

        assert!(
            verify_credit_funding(correct_total, outputs, fee, &vin).is_ok(),
            "correct total must pass"
        );

        let short = AtomicUnits::from_raw(correct_total.to_raw() - 1);
        let err = verify_credit_funding(short, outputs, fee, &vin)
            .expect_err("underflow funding must fail");
        assert!(
            matches!(err, BondBuildError::CreditImbalance { .. }),
            "wrong error: {err:?}"
        );

        let over = AtomicUnits::from_raw(correct_total.to_raw() + 1);
        let err = verify_credit_funding(over, outputs, fee, &vin)
            .expect_err("overflow funding must fail");
        assert!(
            matches!(err, BondBuildError::CreditImbalance { .. }),
            "wrong error: {err:?}"
        );
    }

    /// S7 slot-mismatch negative — a ticket for slot A with a handle for slot B
    /// produces [`StakeEngineError::SlotMismatch`], not a signing attempt.
    #[tokio::test]
    async fn sign_bond_slot_mismatch_is_rejected() {
        use crate::engine::stake_persist::PersistedBondTicket;
        use shekyl_archival_retention::{HoldingsDescriptor, HoldingsKind};

        let handle = spawn_over(&[0, 1], &[], None);
        mint_and_activate(&handle, 0)
            .await
            .expect("activate slot 0");
        let h0 = handle
            .mint_handle(PSlot::from_raw(0))
            .await
            .expect("mint handle for slot 0");

        // Forge a ticket for slot 1 (bypassing Engine::persist_bond_record
        // via the test-only constructor on PersistedBondTicket).
        let ticket_for_slot_1 = PersistedBondTicket::__test_only_forge(PSlot::from_raw(1));

        let holdings = HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
        };
        let err = handle
            .sign_bond(h0, ticket_for_slot_1, holdings, [0u8; 32])
            .await
            .expect_err("slot mismatch must fail");

        assert!(
            matches!(
                err,
                StakeEngineError::SlotMismatch {
                    handle_slot,
                    ticket_slot,
                } if handle_slot == PSlot::from_raw(0) && ticket_slot == PSlot::from_raw(1)
            ),
            "expected SlotMismatch(0, 1), got {err:?}"
        );
    }

    /// GF-7 hooks-spec §6.2 (emission-complete for the 2c-2b surface) — a
    /// successful `sign_bond` emits exactly the draw-consumption and schedule
    /// events to the **injected** observer, and the emitted payloads are
    /// internally consistent: the scheduled offset equals the drawn spread
    /// (causal — the post fires `spread` blocks after the private intent), and
    /// it matches the offset riding the reply. Also pins the §3 payload
    /// discipline the sim depends on: opaque slot ordinal and the sweepable
    /// window parameter on the draw event.
    #[cfg(feature = "gf7-hooks")]
    #[tokio::test]
    async fn sign_bond_emits_gf7_draw_and_schedule_events() {
        use std::sync::{Arc, Mutex};

        use crate::engine::stake_persist::PersistedBondTicket;
        use shekyl_archival_retention::{HoldingsDescriptor, HoldingsKind};

        struct Recorder(Arc<Mutex<Vec<TimelineEvent>>>);
        impl BroadcastTimelineObserver for Recorder {
            fn record(&mut self, event: TimelineEvent) {
                self.0.lock().expect("recorder lock").push(event);
            }
        }

        let recorded = Arc::new(Mutex::new(Vec::new()));
        let bundles: BTreeMap<PSlot, ArchivalPKeys> = [(PSlot::from_raw(0), derive_bundle(0))]
            .into_iter()
            .collect();
        let handle = StakeEngineHandle {
            actor: StakeEngine::spawn(StakeEngineArgs {
                bundles,
                bonded: BTreeSet::new(),
                active: None,
                #[cfg(feature = "conformance")]
                self_cert: TestSelfCert::Skip,
                observer: Box::new(Recorder(Arc::clone(&recorded))),
            }),
        };

        let h0 = handle
            .mint_handle(PSlot::from_raw(0))
            .await
            .expect("mint handle for slot 0");
        let ticket = PersistedBondTicket::__test_only_forge(PSlot::from_raw(0));
        let holdings = HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
        };
        let post = handle
            .sign_bond(h0, ticket, holdings, [0u8; 32])
            .await
            .expect("sign_bond succeeds for a held, matching slot");

        let events = recorded.lock().expect("recorder lock");
        assert_eq!(
            events.len(),
            2,
            "exactly the two 2c-2b emission points fire: {events:?}"
        );

        let spread = match events[0] {
            TimelineEvent::EntryGapDrawConsumed {
                persona,
                window_blocks,
                spread_blocks,
            } => {
                assert_eq!(persona, 0, "opaque wallet-local slot ordinal");
                assert_eq!(
                    window_blocks,
                    DEFAULT_ENTRY_GAP.as_blocks(),
                    "sweepable window parameter rides the event"
                );
                spread_blocks
            }
            ref other => panic!("first event must be the draw consumption, got {other:?}"),
        };

        match events[1] {
            TimelineEvent::BondPostScheduled {
                persona,
                bond_post_offset_blocks,
            } => {
                assert_eq!(persona, 0, "same persona ordinal as the draw event");
                // Causal by construction: the post fires `spread` blocks after
                // the private intent; there is no second event and no coin.
                assert_eq!(
                    bond_post_offset_blocks, spread,
                    "scheduled offset must be the drawn spread"
                );
                assert_eq!(
                    bond_post_offset_blocks, post.bond_post_offset_blocks,
                    "schedule event must match the offset riding the reply"
                );
            }
            ref other => panic!("second event must be the schedule, got {other:?}"),
        }
    }

    // ---- SP-3/SP-5: the offloaded dual-extractor scan-step ----

    use shekyl_crypto_pq::kem::HybridKemPublicKey;
    use shekyl_scanner::bench_fixtures::scannable_block_for_recipient;
    use shekyl_types::{BlockHeight, SettlementEpoch};
    use shekyl_units::AtomicUnits;
    use shekyl_wire::transaction::{BondPost, BondPostKind, Input};
    use shekyl_wire::Holdings;

    /// The cleartext canonical id an on-chain bond-post carries for `slot`.
    fn canonical_id(slot: u32) -> PCanonicalId {
        p_canonical_id_from_hybrid_pubkey(&oracle_bond_id(slot))
    }

    /// A block with one output addressed to persona `slot`.
    fn block_funding(slot: u32) -> ScannableBlock {
        let p = derive_bundle(slot);
        let kem = HybridKemPublicKey {
            x25519: p.x25519_pk,
            ml_kem: p.ml_kem_ek.to_vec(),
        };
        scannable_block_for_recipient(1, &kem, p.spend_pk.as_canonical_bytes())
    }

    /// Append a JoinMarket bond-post for persona `slot` to a block's first tx.
    fn with_bond_post(mut block: ScannableBlock, slot: u32) -> ScannableBlock {
        let post = BondPost {
            hybrid_public_key: oracle_bond_id(slot),
            p_canonical_id: canonical_id(slot).to_bytes(),
            kind: BondPostKind::JoinMarket {
                bond_spend_pk: Vec::new(),
            },
            holdings: Holdings::CompleteTree,
            bonded_total_atomic: 1_000,
            bond_credit: 1_000,
            bond_debit: 0,
        };
        block.transactions[0]
            .prefix
            .inputs
            .push(Input::BondPost(Box::new(post)));
        block
    }

    fn one_block_range(h: u64) -> BlockRange {
        BlockRange::new(BlockHeight::from_raw(h), BlockHeight::from_raw(h + 1)).expect("range")
    }

    // SP-3/SP-5 — a bonded persona's funding *and* its bond-post both come back
    // (public) through the actor's offloaded scan-step; `view_sk` never crosses.
    #[tokio::test]
    async fn scan_step_extracts_funding_and_bond_post_for_a_bonded_persona() {
        let handle = spawn_over(&[0], &[0], None); // persona 0 held AND bonded
        let block = with_bond_post(block_funding(0), 0);

        let res = handle
            .scan_step(one_block_range(20_001), vec![block], Vec::new().into())
            .await
            .expect("scan-step succeeds");

        assert_eq!(
            res.funding.len(),
            1,
            "the bonded persona's output is summed"
        );
        assert_eq!(res.funding[0].epoch, SettlementEpoch::from_raw(2)); // 20_001 / 10_000
        assert!(res.funding[0].amount > AtomicUnits::ZERO);
        assert_eq!(res.bond_post_matches.len(), 1, "its bond-post matched");
        assert_eq!(res.bond_post_matches[0].p_canonical_id, canonical_id(0));
    }

    // A persona that is HELD but not BONDED is not scanned, and a foreign bond-post
    // does not match — the bonded tag gates the scan set (DQ8; SP-6 reconciles).
    #[tokio::test]
    async fn scan_step_skips_non_bonded_personas_and_foreign_posts() {
        // Persona 0 bonded; the block is addressed to persona 1 (held, not bonded)
        // and carries persona 1's bond-post.
        let handle = spawn_over(&[0, 1], &[0], None);
        let block = with_bond_post(block_funding(1), 1);

        let res = handle
            .scan_step(one_block_range(20_001), vec![block], Vec::new().into())
            .await
            .expect("scan-step succeeds");

        assert!(
            res.funding.is_empty(),
            "persona 1's output is not ours to recover"
        );
        assert!(
            res.bond_post_matches.is_empty(),
            "persona 1's canonical id is not in the bonded union"
        );
    }

    // Bounded + offloaded (DQ6): the handler returns and frees the mailbox, so the
    // actor answers the next message rather than freezing on the scan.
    #[tokio::test]
    async fn actor_is_responsive_after_a_scan_step() {
        let handle = spawn_over(&[0], &[0], None);
        let _ = handle
            .scan_step(
                one_block_range(1),
                vec![block_funding(0)],
                Vec::new().into(),
            )
            .await
            .expect("scan-step succeeds");
        let active = handle.active_persona().await.expect("still responsive");
        assert!(active.is_none(), "actor processed the follow-up message");
    }

    // ---- DQ8: witness-gated retirement of a terminal bonded persona ----

    /// A witness exists iff the persona's last creditable epoch `e_last = U` has
    /// fallen *below* the claim window floor `settled − W`. The boundary edge —
    /// `settled = U + W`, where `U` is still the oldest claimable epoch — must
    /// **not** retire (it's the off-by-one that would wipe a still-claimable
    /// persona). Eligibility begins at `settled = U + W + 1`.
    #[test]
    fn retirement_witness_fires_one_epoch_after_the_claim_window_closes() {
        let id = canonical_id(0);
        let unbond = SettlementEpoch::from_raw(10);
        // settled = U + W: U is exactly the oldest claimable epoch → still claimable
        // → must NOT retire.
        assert!(
            RetirementWitness::from_confirmed_unbond(
                id,
                unbond,
                SettlementEpoch::from_raw(10 + MAX_CLAIM_AGE_W),
            )
            .is_none(),
            "U is still claimable at settled = U + W; retiring here is stuck funds"
        );
        // settled = U + W + 1: U has dropped below the window floor → retire.
        assert!(
            RetirementWitness::from_confirmed_unbond(
                id,
                unbond,
                SettlementEpoch::from_raw(10 + MAX_CLAIM_AGE_W + 1),
            )
            .is_some(),
            "retire once U falls out of the claim window"
        );
    }

    /// The witness retires (wipes) a terminal bonded persona, and the retire is
    /// idempotent: re-handing it after the persona is gone is a `NotHeld` no-op.
    #[tokio::test]
    async fn retire_wipes_a_terminal_persona_and_is_idempotent() {
        let handle = spawn_over(&[0], &[0], None); // persona 0 bonded, not active
        let witness = RetirementWitness::from_confirmed_unbond(
            canonical_id(0),
            SettlementEpoch::from_raw(0),
            SettlementEpoch::from_raw(MAX_CLAIM_AGE_W + 1),
        )
        .expect("eligible");

        assert_eq!(
            handle
                .retire_bonded_persona(witness, std::sync::Arc::new(FundedSlots::default()))
                .await
                .expect("retire"),
            RetireOutcome::Retired {
                slot: PSlot::from_raw(0)
            }
        );

        // Gone now → a fresh witness for the same persona is a no-op.
        let again = RetirementWitness::from_confirmed_unbond(
            canonical_id(0),
            SettlementEpoch::from_raw(0),
            SettlementEpoch::from_raw(MAX_CLAIM_AGE_W + 1),
        )
        .expect("eligible");
        assert_eq!(
            handle
                .retire_bonded_persona(again, std::sync::Arc::new(FundedSlots::default()))
                .await
                .expect("retire"),
            RetireOutcome::NotHeld,
            "retiring an already-gone persona is an idempotent no-op"
        );
    }

    /// The funded-gate: a terminal persona whose slot still holds unspent
    /// funding is left in place ([`RetireOutcome::SkippedFunded`]) — wiping it
    /// would strand the funds. Once drained (the slot leaves the funded set) the
    /// same witness retires it.
    #[tokio::test]
    async fn retire_defers_a_funded_persona_then_wipes_once_drained() {
        let handle = spawn_over(&[0], &[0], None); // persona 0 bonded, not active
        let witness = || {
            RetirementWitness::from_confirmed_unbond(
                canonical_id(0),
                SettlementEpoch::from_raw(0),
                SettlementEpoch::from_raw(MAX_CLAIM_AGE_W + 1),
            )
            .expect("eligible")
        };

        // Slot 0 still holds unspent funding → the wipe is refused.
        let funded = FundedSlots::from_slots([PSlot::from_raw(0)]);
        assert_eq!(
            handle
                .retire_bonded_persona(witness(), std::sync::Arc::new(funded))
                .await
                .expect("retire"),
            RetireOutcome::SkippedFunded {
                slot: PSlot::from_raw(0)
            },
            "a funded slot is never wiped (stuck-funds guard)"
        );

        // Drained now (empty funded set) → the same witness retires it.
        assert_eq!(
            handle
                .retire_bonded_persona(witness(), std::sync::Arc::new(FundedSlots::default()))
                .await
                .expect("retire"),
            RetireOutcome::Retired {
                slot: PSlot::from_raw(0)
            },
            "once drained the deferred retire fires"
        );
    }

    /// The active persona is never wiped mid-use — retire skips it (the next
    /// activation moves `active` away, then the retire re-fires).
    #[tokio::test]
    async fn retire_skips_the_active_persona() {
        let handle = spawn_over(&[0], &[0], Some(0)); // persona 0 bonded AND active
        let witness = RetirementWitness::from_confirmed_unbond(
            canonical_id(0),
            SettlementEpoch::from_raw(0),
            SettlementEpoch::from_raw(MAX_CLAIM_AGE_W + 1),
        )
        .expect("eligible");
        assert_eq!(
            handle
                .retire_bonded_persona(witness, std::sync::Arc::new(FundedSlots::default()))
                .await
                .expect("retire"),
            RetireOutcome::SkippedActive {
                slot: PSlot::from_raw(0)
            }
        );
    }

    /// A witness for a persona we do not hold (never bonded, or another wallet's)
    /// is a `NotHeld` no-op — the actor matches only its own bonded union.
    #[tokio::test]
    async fn retire_an_unheld_persona_is_notheld() {
        let handle = spawn_over(&[0], &[0], None); // we hold persona 0
                                                   // A witness for persona 1 (not held).
        let witness = RetirementWitness::from_confirmed_unbond(
            canonical_id(1),
            SettlementEpoch::from_raw(0),
            SettlementEpoch::from_raw(MAX_CLAIM_AGE_W + 1),
        )
        .expect("eligible");
        assert_eq!(
            handle
                .retire_bonded_persona(witness, std::sync::Arc::new(FundedSlots::default()))
                .await
                .expect("retire"),
            RetireOutcome::NotHeld
        );
    }

    /// S6 — session RNG self-cert wiring (conformance build only).
    #[cfg(feature = "conformance")]
    mod s6_self_cert {
        use super::*;

        /// The **decision**: a stuck RNG (constant output) grades non-conformant,
        /// so the extracted self-cert returns the typed start error. Proves
        /// fail-stop *decides* correctly without spawning; the full
        /// spawn→`OpenError` path with a degenerate source is the Round-2 test.
        #[test]
        fn run_session_self_cert_rejects_stuck_rng() {
            struct ConstRng(u64);
            impl GapRng for ConstRng {
                fn next_u64(&mut self) -> u64 {
                    self.0
                }
            }
            let mut rng = ConstRng(0x42);
            let result = run_session_self_cert(&mut rng);
            assert!(
                matches!(result, Err(StakeEngineStartError::RngSelfCertFailed(_))),
                "a stuck RNG must fail the session self-cert, got {result:?}"
            );
        }

        /// Build a handle with an explicit self-cert mode (the bulk-test
        /// `spawn_over` uses `Skip`; the S6 tests need `RealOsRng`/`Degenerate`).
        fn spawn_with_self_cert(held: &[u32], mode: TestSelfCert) -> StakeEngineHandle {
            let bundles: BTreeMap<PSlot, ArchivalPKeys> = held
                .iter()
                .map(|&s| (PSlot::from_raw(s), derive_bundle(s)))
                .collect();
            let args = StakeEngineArgs {
                bundles,
                bonded: BTreeSet::new(),
                active: None,
                self_cert: mode,
                #[cfg(feature = "gf7-hooks")]
                observer: Box::new(shekyl_standoff::gf7::NoOpObserver),
            };
            StakeEngineHandle {
                actor: StakeEngine::spawn(args),
            }
        }

        /// The **wiring**: the production `OsRng` adapter grades conformant, so a
        /// freshly spawned StakeEngine starts cleanly and the eager observation
        /// path (`wait_for_self_cert`) returns `Ok`. Multi-thread so the actor
        /// task keeps running while the test awaits its startup. (A single real
        /// grade per run keeps the α=1e-6 false-positive negligible — the flake
        /// risk only became real when every spawn graded; see `StakeEngineArgs`.)
        #[tokio::test(flavor = "multi_thread")]
        async fn session_self_cert_passes_over_os_rng_at_spawn() {
            let handle = spawn_with_self_cert(&[0], TestSelfCert::RealOsRng);
            let cert = handle.wait_for_self_cert().await;
            assert!(
                cert.is_ok(),
                "the production OsRng adapter must pass the session self-cert, got {cert:?}"
            );
            // The actor is alive and serving after a passing self-cert.
            assert!(handle.active_persona().await.is_ok());
        }

        /// The full **fail-stop path** (R0-D# / Round 2): a degenerate self-cert
        /// source makes `on_start` return `Err`, kameo turns that into a startup
        /// failure (the actor never enters its message loop), the eager
        /// observation (`wait_for_self_cert`) surfaces it as `Err`, and the actor
        /// is dead — any later op collapses to the terminal `StakeActorUnavailable`.
        /// (At the wallet-open path this same `Err` becomes
        /// `OpenError::StakeRngSelfCertFailed`.)
        #[tokio::test(flavor = "multi_thread")]
        async fn degenerate_self_cert_fail_stops_spawn() {
            // Force a degenerate source so `on_start` returns Err and the actor
            // fail-stops (the spawn helper builds args directly with the mode).
            let handle = spawn_with_self_cert(&[0], TestSelfCert::Degenerate);

            let cert = handle.wait_for_self_cert().await;
            assert!(
                cert.is_err(),
                "a degenerate self-cert source must fail-stop the spawn, got {cert:?}"
            );
            // The actor fail-stopped: subsequent ops are terminally unavailable.
            assert!(matches!(
                handle.active_persona().await,
                Err(StakeEngineError::StakeActorUnavailable)
            ));
        }
    }

    /// PR-3 commit 4 — [`AssembleEmissionClaim`]'s end-to-end **daemon-side
    /// differential**: parse the produced bytes, re-derive every consensus
    /// operand (`archival_emission_index`, the erase-rule signable hash, the
    /// ordered reward-commit set, the id-equality key) from the wire alone,
    /// and drive the landed verifiers over the PARSED vin — nothing below
    /// reuses the builder's in-memory intermediates, so builder/daemon drift
    /// on any of those rules fails here rather than at a real daemon.
    ///
    /// The old handler-side refusal KATs (stale anchor, backing-in-fee-set,
    /// mandatory fee funding) moved to `backing_set.rs` with the checks
    /// themselves: `ClaimOperands` is mintable only through the sweep seal,
    /// so those states have no expressible form at this message boundary.
    mod emission_claim_assembly {
        use super::*;

        use shekyl_engine_state::pscan_state::MintLineageOutput;
        use shekyl_types::BlockHeight;
        use shekyl_wire::{Ct, Transaction};

        use crate::engine::backing_set::{BackingSet, MembershipPath};
        use crate::engine::bond_assembly::SpentRecordsDurablyPruned;
        use crate::engine::emission_claim::test_fixtures::{snapshot, source_with};
        use crate::engine::emission_source::EmissionClaimSource;
        use crate::engine::synthetic_tree::consistent_synthetic_path;

        /// The known-claimable source shape shared with the `emission_claim`
        /// step-7 differential (settled = 10, epochs 4 and 5 claimable) — one
        /// fixture family across both differential halves, per the
        /// `test_fixtures` module doc.
        fn claimable_source() -> EmissionClaimSource {
            source_with(10, vec![], vec![snapshot(4), snapshot(5)])
        }

        /// The end-to-end daemon-side differential. Assembly runs over a
        /// depth-consistent synthetic tree with two REAL P-paid outputs
        /// (backing + fee spend); every check below then re-derives the
        /// daemon's operands from the produced BYTES:
        ///
        /// 1. **Index pin** — `classify_archival_tx` finds the emission vin
        ///    after the ToKey key images, so `archival_emission_index ==
        ///    count(key images)`.
        /// 2. **Erase rule** (`blockchain.cpp:3866`) — remove the vin
        ///    WHOLESALE from the *parsed* prefix and hash what remains via
        ///    `shekyl_wire`'s independent prefix-hash implementation; the
        ///    landed verifiers accept the vin's membership proof and both
        ///    auths against THAT hash, or the builder's from-parts signable
        ///    hash diverged from the daemon's.
        /// 3. **Id-equality** (`blockchain.cpp:3783`) — the vin's `p_pubkey`
        ///    derives the claimant id, and the emission `pqc_auths` slot
        ///    carries the same key.
        /// 4. **Reward-commit rule** — non-zero WIRE amounts in vout order,
        ///    commitments from the tx's outPk (never the builder's copy),
        ///    exactly one loud vout carrying `total_reward`.
        /// 5. **Claims leg** — `self_check_claims` (the landed economics
        ///    verifier) over the parsed vin and the paired source.
        #[tokio::test(flavor = "multi_thread")]
        async fn assembled_claim_survives_the_daemon_side_differential() {
            let handle = spawn_over(&[0], &[], None);
            let h = handle
                .mint_handle(PSlot::from_raw(0))
                .await
                .expect("slot 0 held");
            let keys = derive_bundle(0);
            let source = claimable_source();
            let tip = source.chain_height.to_raw() - 1;

            // Two real P-paid outputs in ONE leaf chunk — the backing
            // (rung-2 lineage) and the fee spend (rung 3) — under one
            // depth-consistent single-path tree shared by both proofs.
            let (backing_record, backing_leaf) =
                constructed_record(&keys, 11, 5, 750_000, 0, MintLineageOutput::BondPostChange);
            let (fee_record, fee_leaf) =
                constructed_record(&keys, 22, 6, 90_000, 1, MintLineageOutput::ExternalTransfer);
            let backing_gindex = backing_record.gindex;
            let leaf_chunk = vec![backing_leaf, fee_leaf];
            // Depth 2 — the wire encoder's spendable minimum (`fcmp_layers >=
            // 2`); the synthetic single-path tree is depth-consistent at any
            // depth.
            let depth = 2u8;
            let (c1_layers, c2_layers, tree_root) = consistent_synthetic_path(&leaf_chunk, depth);
            let tree_ctx = TreeContext {
                reference_block: [7u8; 32],
                tree_root,
                tree_depth: depth,
            };

            // Mint the sealed operands through the ONLY route there is:
            // designate the backing at the source's tip, sweep the fee
            // inputs against it (the Q11 exclusion and the item-6 same-tip
            // check fire in the mint, exercised by the `backing_set.rs`
            // KATs), then zip the assembled paths in. Both leaves share the
            // single synthetic path, so every witness record gets the same
            // path data — exactly the old hand-built shape, now sealed.
            let fee = 10_000u64;
            let records = [backing_record.clone(), fee_record];
            let swept = BackingSet::from_spendable(
                &[backing_record],
                PSlot::from_raw(0),
                BlockHeight::from_raw(tip),
                BlockHeight::from_raw(0),
            )
            .designate_backing()
            .expect("the rung-2 record designates")
            .fee_sweep(
                source.clone(),
                &SpentRecordsDurablyPruned::for_test(),
                &records,
                PSlot::from_raw(0),
                &Default::default(),
                AtomicUnits::from_raw(fee),
            )
            .expect("the fee sweep mints the sealed witness");
            let paths: Vec<MembershipPath> = swept
                .path_records()
                .map(|_| MembershipPath {
                    leaf_chunk: leaf_chunk.clone(),
                    c1_layers: c1_layers.clone(),
                    c2_layers: c2_layers.clone(),
                })
                .collect();
            let operands = swept
                .with_paths(paths)
                .expect("one path per witness record");

            let reply = handle
                .assemble_emission_claim(AssembleEmissionClaim {
                    handle: h,
                    operands,
                    tree_ctx,
                })
                .await
                .expect("emission-claim assembly completes end-to-end");

            assert!(reply.total_reward > 0, "fixture epochs carry a real reward");
            assert_eq!(reply.claimed_epochs, vec![4, 5]);
            assert!(reply.size_deferred.is_empty());
            // Q11 surface: only the fee spend is reserved — the backing is
            // consumed as backing, never as a fee input.
            assert_eq!(reply.fee_gindexes, vec![GlobalOutputIndex::from_raw(22)]);
            assert!(!reply.fee_gindexes.contains(&backing_gindex));

            // ── Everything below recomputes from the wire BYTES. ──────────
            let mut cursor: &[u8] = reply.bound_tx.bytes();
            let mut tx = Transaction::read(&mut cursor).expect("assembled bytes parse whole");
            assert!(cursor.is_empty(), "no trailing bytes after the tx");

            // (1) Index pin.
            let to_key_count = tx
                .prefix
                .inputs
                .iter()
                .filter(|i| matches!(i, Input::ToKey { .. }))
                .count();
            assert_eq!(to_key_count, 1, "one fee spend");
            let emission_index = tx
                .prefix
                .inputs
                .iter()
                .position(|i| matches!(i, Input::ArchivalRewardEmission { .. }))
                .expect("emission vin present");
            assert_eq!(
                emission_index, to_key_count,
                "emission vin sits after the key images — the daemon's erase index"
            );
            assert_eq!(tx.prefix.inputs.len(), to_key_count + 1);

            // Exact-parse the vin blob (the daemon's canonical-encoding
            // demand; `read` consumes the 0x04 tag the blob carries).
            let Input::ArchivalRewardEmission { canonical_bytes } =
                &tx.prefix.inputs[emission_index]
            else {
                unreachable!("position() matched this variant");
            };
            let vin = ArchivalRewardEmissionVin::read(&mut canonical_bytes.as_slice())
                .expect("vin blob parses");

            // (3) Id-equality: vin p_pubkey derives the claimant id...
            let expected_id = p_canonical_id_from_hybrid_pubkey(
                &keys
                    .hybrid_sign_pk
                    .to_canonical_bytes()
                    .expect("identity encodes"),
            );
            assert_eq!(
                p_canonical_id_from_hybrid_pubkey(&vin.p_pubkey),
                expected_id
            );
            // ...and the emission pqc_auths slot carries the SAME key (the
            // daemon derives the slot's id and demands equality — the
            // resolved symmetry item, NOT the bond's slot-key rule assumed).
            let Ct::Fcmp {
                base,
                pqc_auths,
                fee: wire_fee,
                ..
            } = &tx.ct
            else {
                panic!("emission claim is an Fcmp ct");
            };
            assert_eq!(*wire_fee, fee);
            assert_eq!(pqc_auths.len(), tx.prefix.inputs.len());
            assert_eq!(
                pqc_auths[emission_index].hybrid_public_key, vin.p_pubkey,
                "emission slot key == vin p_pubkey (id-equality's operand)"
            );

            // (4) The daemon's reward-commit rule.
            let reward_commits: Vec<RewardCommit> = tx
                .prefix
                .outputs
                .iter()
                .enumerate()
                .filter(|(_, o)| o.amount != 0)
                .map(|(i, o)| RewardCommit {
                    commitment: base.commitments[i],
                    amount_plain: o.amount,
                    one_time_key: o.key,
                })
                .collect();
            assert_eq!(reward_commits.len(), 1, "exactly one loud vout");
            assert_eq!(reward_commits[0].amount_plain, reply.total_reward);
            let vout_reward_sum: u64 = reward_commits.iter().map(|c| c.amount_plain).sum();

            // (2) The erase rule: remove the emission vin WHOLESALE from the
            // parsed prefix; hash what remains through the wire crate's own
            // prefix-hash path (independent of the builder's from-parts
            // hasher).
            let full_prefix_hash = tx.prefix_hash();
            tx.prefix.inputs.remove(emission_index);
            let signable = tx.prefix_hash();

            // Premise arm: the erase is load-bearing — the vin-less hash
            // differs from the full prefix hash, and the auths REFUSE the
            // wrong (un-erased) operand. Without this, the accepts below
            // could go vacuously green if the two hashes ever coincided.
            assert_ne!(signable, full_prefix_hash, "the erase must change the hash");
            emission_vin_verify_auth(&vin, &reward_commits, &full_prefix_hash)
                .expect_err("auths must refuse a signable hash that was not erase-derived");

            // The three landed-verifier legs over the PARSED vin and the
            // recomputed operands: membership proof + leaf gate, both role
            // auths, and the economics recompute. A builder/daemon drift in
            // the signable hash, index derivation, commit set, or either
            // auth key refuses here.
            emission_vin_verify_backing(&vin, &tree_root, depth, signable)
                .expect("backing leg verifies against the erase-rule hash");
            emission_vin_verify_auth(&vin, &reward_commits, &signable)
                .expect("both auth legs verify against the erase-rule hash");
            self_check_claims(&source, &vin, vout_reward_sum)
                .expect("claims leg verifies against the paired source");
        }
    }

    /// F-D2 DS-PR-1 — the drain's **composite wire-shape arm** (T-DS-6 ∧
    /// T-DS-7), checked from the produced BYTES: a `P`→principal drain
    /// serializes as a modal 2-out confidential transfer. Every property below
    /// that a bond/claim carries and a transfer does not — an archival prefix
    /// input, a loud (plaintext-amount) vout, an identity auth slot — is
    /// asserted ABSENT, and every property a modal transfer has — exactly two
    /// confidential outputs, spend-only `pqc_auths` — asserted present.
    ///
    /// The full byte-diff against a live principal-keyed transfer and the
    /// scan-claim confirmation of the change output (T-DS-3) land with the
    /// DS-PR-2 regtest e2e (mirroring the emission daemon-side differential's
    /// own e2e placement); these in-crate arms fix the structural shape the
    /// e2e then confirms empirically.
    mod drain_assembly_shape {
        use super::*;

        use shekyl_engine_state::pscan_state::MintLineageOutput;
        use shekyl_wire::{Ct, Transaction};

        use crate::engine::drain_assembly::{AssembleDrain, DrainAssemblyError, DrainDestination};
        use crate::engine::synthetic_tree::consistent_synthetic_path;

        /// Two REAL P-paid funding inputs (`600_000 + 400_000`) in one
        /// depth-consistent synthetic leaf chunk, plus a valid principal
        /// destination (a distinct persona's public triple — the drain does not
        /// care whose principal it is, only that the keys are well-formed).
        fn drain_fixture() -> (Vec<FundingInputContext>, TreeContext, DrainDestination, u64) {
            let keys = derive_bundle(0);
            let (rec0, leaf0) = constructed_record(
                &keys,
                11,
                5,
                600_000,
                0,
                MintLineageOutput::ExternalTransfer,
            );
            let (rec1, leaf1) = constructed_record(
                &keys,
                22,
                6,
                400_000,
                1,
                MintLineageOutput::ExternalTransfer,
            );
            let leaf_chunk = vec![leaf0, leaf1];
            let depth = 2u8;
            let (c1_layers, c2_layers, tree_root) = consistent_synthetic_path(&leaf_chunk, depth);
            let tree_ctx = TreeContext {
                reference_block: [7u8; 32],
                tree_root,
                tree_depth: depth,
            };
            let funding = vec![
                FundingInputContext {
                    record: rec0,
                    leaf_chunk: leaf_chunk.clone(),
                    c1_layers: c1_layers.clone(),
                    c2_layers: c2_layers.clone(),
                },
                FundingInputContext {
                    record: rec1,
                    leaf_chunk,
                    c1_layers,
                    c2_layers,
                },
            ];
            // Principal = a different persona's public keys (valid points/encap
            // key), so the payment vout is genuinely NOT a P-space output.
            let principal = derive_bundle(9);
            let dest = DrainDestination {
                spend_pk: *principal.spend_pk.as_canonical_bytes(),
                x25519_pk: principal.x25519_pk,
                ml_kem_ek: principal.ml_kem_ek.to_vec(),
            };
            (funding, tree_ctx, dest, 1_000_000)
        }

        /// A partial drain (`payment < available - fee`, change > 0) is a modal
        /// 2-out confidential transfer on the wire.
        #[tokio::test(flavor = "multi_thread")]
        async fn drain_is_transfer_shaped() {
            let handle = spawn_over(&[0], &[], None);
            let h = handle
                .mint_handle(PSlot::from_raw(0))
                .await
                .expect("slot 0 held");
            let (funding, tree_ctx, dest, _available) = drain_fixture();

            let fee = 10_000u64;
            let reply = handle
                .assemble_drain(AssembleDrain {
                    handle: h,
                    funding,
                    tree_ctx,
                    dest,
                    payment_amount: 600_000, // change = 1_000_000 - 600_000 - 10_000 > 0
                    fee,
                })
                .await
                .expect("drain assembly completes end-to-end");

            assert_eq!(
                reply.funding_gindexes.len(),
                2,
                "both funding inputs reserved"
            );

            // ── Everything below recomputes from the wire BYTES. ──────────
            let mut cursor: &[u8] = reply.bound_tx.bytes();
            let tx = Transaction::read(&mut cursor).expect("assembled bytes parse whole");
            assert!(cursor.is_empty(), "no trailing bytes after the tx");

            // Transfer-shaped prefix inputs: every input is a plain ToKey
            // key-image spend — NO `ArchivalRewardEmission`, NO `BondPost`.
            assert_eq!(tx.prefix.inputs.len(), 2, "two funding spends");
            assert!(
                tx.prefix
                    .inputs
                    .iter()
                    .all(|i| matches!(i, Input::ToKey { .. })),
                "a drain carries only key-image spends — no archival prefix input"
            );

            // Modal 2-out (T-DS-6): exactly two outputs, both CONFIDENTIAL
            // (wire amount 0) — no loud reward vout, unlike an emission claim.
            assert_eq!(tx.prefix.outputs.len(), 2, "principal payment + P change");
            assert!(
                tx.prefix.outputs.iter().all(|o| o.amount == 0),
                "both vouts are confidential (no plaintext amount on the wire)"
            );

            let Ct::Fcmp {
                pqc_auths,
                fee: wire_fee,
                ..
            } = &tx.ct
            else {
                panic!("a drain is an Fcmp ct");
            };
            assert_eq!(*wire_fee, fee, "wire fee matches the assembled fee");

            // Spend-only `pqc_auths`: one slot per input, NO identity auth slot
            // (the byte-shape difference between a drain and a bond is exactly
            // the absence of the P-identity auth the bond appends).
            assert_eq!(
                pqc_auths.len(),
                tx.prefix.inputs.len(),
                "one auth per spend — no extra identity slot"
            );
            let p_identity = derive_bundle(0)
                .hybrid_sign_pk
                .to_canonical_bytes()
                .expect("identity encodes");
            assert!(
                pqc_auths.iter().all(|a| a.hybrid_public_key != p_identity),
                "no auth slot carries P's identity key — a drain does not sign as a persona"
            );
        }

        /// A drain-**all** (`payment == available - fee`, change == 0) STILL
        /// emits two nonzero outputs: with no residual `P` value to return, the
        /// principal payment is SPLIT into two nonzero principal outputs (a sweep
        /// to self), so the vout count is the modal `2` (T-DS-6) and the daemon
        /// prunable-tx floor holds — a 1-out drain (the distinguishable shape) is
        /// never produced.
        #[tokio::test(flavor = "multi_thread")]
        async fn drain_all_still_emits_two_outputs() {
            let handle = spawn_over(&[0], &[], None);
            let h = handle
                .mint_handle(PSlot::from_raw(0))
                .await
                .expect("slot 0 held");
            let (funding, tree_ctx, dest, available) = drain_fixture();

            let fee = 10_000u64;
            let reply = handle
                .assemble_drain(AssembleDrain {
                    handle: h,
                    funding,
                    tree_ctx,
                    dest,
                    payment_amount: available - fee, // change == 0
                    fee,
                })
                .await
                .expect("drain-all assembly completes end-to-end");

            let mut cursor: &[u8] = reply.bound_tx.bytes();
            let tx = Transaction::read(&mut cursor).expect("assembled bytes parse whole");
            assert!(cursor.is_empty());
            assert_eq!(
                tx.prefix.outputs.len(),
                2,
                "drain-all splits the payment into two principal outputs — modal 2-out, never 1-out"
            );
            assert!(
                tx.prefix.outputs.iter().all(|o| o.amount == 0),
                "both vouts confidential (no plaintext amount on the wire)"
            );
        }

        /// A drain-all whose net payment (`available - fee`) is a single atomic
        /// unit cannot form two nonzero outputs, so it is refused **loudly** with
        /// [`DrainAssemblyError::PaymentUnsplittable`] rather than shaped into
        /// the distinguishable 1-out (T-DS-6). Pathological — the fee dwarfs one
        /// atomic unit — but the refusal is structural, not best-effort.
        #[tokio::test(flavor = "multi_thread")]
        async fn drain_all_net_below_two_is_refused() {
            let handle = spawn_over(&[0], &[], None);
            let h = handle
                .mint_handle(PSlot::from_raw(0))
                .await
                .expect("slot 0 held");
            let (funding, tree_ctx, dest, available) = drain_fixture();

            // fee = available - 1 ⇒ net payment == 1, change == 0 ⇒ unsplittable.
            let fee = available - 1;
            let err = handle
                .assemble_drain(AssembleDrain {
                    handle: h,
                    funding,
                    tree_ctx,
                    dest,
                    payment_amount: 1,
                    fee,
                })
                .await
                .expect_err("a 1-atomic net drain-all cannot be a modal 2-out");
            assert!(
                matches!(
                    err,
                    StakeEngineError::DrainAssembly(DrainAssemblyError::PaymentUnsplittable {
                        net: 1
                    })
                ),
                "expected DrainAssembly(PaymentUnsplittable {{ net: 1 }}), got {err:?}"
            );
        }

        /// A drain that pays **zero** to the principal is not a drain: it is
        /// refused up front with [`DrainAssemblyError::PaymentZero`] before any
        /// output construction, rather than surfacing later as the shared
        /// prover's opaque `ZeroOutputAmount` on a zero-value vout 0 — a
        /// caller-input error, diagnosed at its source.
        #[tokio::test(flavor = "multi_thread")]
        async fn drain_zero_payment_is_refused() {
            let handle = spawn_over(&[0], &[], None);
            let h = handle
                .mint_handle(PSlot::from_raw(0))
                .await
                .expect("slot 0 held");
            let (funding, tree_ctx, dest, available) = drain_fixture();

            // Ample funding, small fee ⇒ change > 0; the zero payment (not the
            // funding) is what is rejected, before any output is built.
            let fee = 10_000u64;
            assert!(available > fee, "fixture funds exceed the fee (change > 0)");
            let err = handle
                .assemble_drain(AssembleDrain {
                    handle: h,
                    funding,
                    tree_ctx,
                    dest,
                    payment_amount: 0,
                    fee,
                })
                .await
                .expect_err("a zero-payment drain pays nothing to principal");
            assert!(
                matches!(
                    err,
                    StakeEngineError::DrainAssembly(DrainAssemblyError::PaymentZero)
                ),
                "expected DrainAssembly(PaymentZero), got {err:?}"
            );
        }

        /// The composite wire-shape arm (T-DS-6 ∧ T-DS-7): the two drain regimes
        /// an observer could try to tell apart — a **partial** drain (change > 0)
        /// and a **drain-all** (change == 0, principal payment split) — must be
        /// byte-identical modulo the hidden/committed leaves. Transfer-parity
        /// itself is by construction (both regimes and an ordinary `sign_tx`
        /// transfer share the single [`assemble_transfer_wire`] constructor), so
        /// this diff guards the one remaining degree of freedom: that
        /// split-on-drain-all reshaped the amounts WITHOUT perturbing the wire
        /// skeleton. A whole-tx normalized byte-diff, not a sub-surface check.
        #[tokio::test(flavor = "multi_thread")]
        async fn drain_partial_and_drain_all_are_wire_identical() {
            let fee = 10_000u64;

            let partial = {
                let handle = spawn_over(&[0], &[], None);
                let h = handle
                    .mint_handle(PSlot::from_raw(0))
                    .await
                    .expect("slot 0 held");
                let (funding, tree_ctx, dest, available) = drain_fixture();
                let reply = handle
                    .assemble_drain(AssembleDrain {
                        handle: h,
                        funding,
                        tree_ctx,
                        dest,
                        payment_amount: 600_000, // change = available - 600_000 - fee > 0
                        fee,
                    })
                    .await
                    .expect("partial drain assembles");
                assert!(
                    available - 600_000 - fee > 0,
                    "fixture keeps change positive"
                );
                let mut cursor: &[u8] = reply.bound_tx.bytes();
                let tx = Transaction::read(&mut cursor).expect("partial parses whole");
                assert!(cursor.is_empty());
                tx
            };

            let drain_all = {
                let handle = spawn_over(&[0], &[], None);
                let h = handle
                    .mint_handle(PSlot::from_raw(0))
                    .await
                    .expect("slot 0 held");
                let (funding, tree_ctx, dest, available) = drain_fixture();
                let reply = handle
                    .assemble_drain(AssembleDrain {
                        handle: h,
                        funding,
                        tree_ctx,
                        dest,
                        payment_amount: available - fee, // change == 0 ⇒ split
                        fee,
                    })
                    .await
                    .expect("drain-all assembles");
                let mut cursor: &[u8] = reply.bound_tx.bytes();
                let tx = Transaction::read(&mut cursor).expect("drain-all parses whole");
                assert!(cursor.is_empty());
                tx
            };

            // Sanity: the raw bytes DIFFER (hidden values are genuinely distinct)
            // — otherwise the normalized equality below would be vacuous.
            assert_ne!(
                crate::engine::test_support::whole_tx_wire_bytes(&partial),
                crate::engine::test_support::whole_tx_wire_bytes(&drain_all),
                "raw drain bytes must differ (distinct hidden amounts)"
            );

            let mut partial_norm = partial;
            let mut drain_all_norm = drain_all;
            crate::engine::test_support::normalize_fcmp_wire_shape(&mut partial_norm);
            crate::engine::test_support::normalize_fcmp_wire_shape(&mut drain_all_norm);

            assert_eq!(
                crate::engine::test_support::whole_tx_wire_bytes(&partial_norm),
                crate::engine::test_support::whole_tx_wire_bytes(&drain_all_norm),
                "partial drain and drain-all are wire-identical modulo hidden \
                 leaves — the split-on-drain-all path did not perturb the skeleton"
            );
        }
    }
}
