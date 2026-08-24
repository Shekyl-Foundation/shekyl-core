// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Domain types, errors, and spawn args for the stake actor.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_archival_bond_builder::BondBuildError;
use shekyl_archival_retention::epoch_is_claim_expired;
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_crypto_pq::signature::HybridPublicKey;
use shekyl_scanner::GuaranteedScanner;
#[cfg(feature = "gf7-hooks")]
use shekyl_standoff::gf7::BroadcastTimelineObserver;
use shekyl_types::{PCanonicalId, SettlementEpoch};

use crate::engine::bond_assembly::BondAssemblyError;
use crate::engine::drain_assembly::DrainAssemblyError;
use crate::engine::emission_claim::EmissionClaimError;
use crate::engine::pscan::persona_scanner::PersonaScanError;
use crate::engine::pscan::scan_step::DualExtractError;

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

/// The bond watch's **probe window** (SA-R-6 from-seed reconstruction): how
/// many slots past the monotone cursor get a persona canonical id derived
/// into `StakingBlock::persona_id_cache` at open, so the principal
/// refresh/rescan can sight on-chain bond posts for slots the wallet's
/// record has lost.
///
/// Distinct knob from [`ARCHIVAL_PERSONA_LOOKAHEAD`], different cost model:
/// a lookahead slot is a **resident key bundle** (memory + a full keygen per
/// open for stakers); a probe slot is a **32-byte cached public id** derived
/// once per slot for the wallet's life (the cache never invalidates), so the
/// steady-state cost of the window is a map load. The one-time derivation
/// (~W PQ keygens) is paid at wallet create / first open after upgrade — a
/// moment that already runs full PQ account keygen, sized to stay small at
/// the rule-76 device floor.
///
/// - **Width.** A restore-from-seed recovers at most `W` slots of staking
///   history per open+rescan cycle (`ceil(depth / W)` cycles for deeper
///   histories — each cycle's merge raises the cursor, and the next open
///   derives the window above it). Bonds are epoch-scale and sequential, so
///   realistic depths are far below `32`; one cycle is the expected case.
/// - Must exceed the lookahead: the watch must at minimum cover every slot
///   the wallet could bind in-session (compile-checked below).
pub(crate) const ARCHIVAL_PERSONA_PROBE_WINDOW: u32 = 32;

const _: () = assert!(
    ARCHIVAL_PERSONA_PROBE_WINDOW > ARCHIVAL_PERSONA_LOOKAHEAD,
    "the bond watch must cover at least every slot bindable in-session"
);

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
pub(crate) enum HeldPersona {
    /// Carries at least one live bond (`consumer_held` or posted). Never wiped
    /// while bonded — its `bond_spend` key must stay reachable to unbond.
    Bonded(BondedPersona),
    /// A pre-derived lookahead persona with no live bond. The *only* variant
    /// the activation-wipe path accepts.
    Ephemeral(EphemeralPersona),
}

impl HeldPersona {
    /// Borrow the underlying derived bundle (read-only; the secret never
    /// escapes — callers project the public [`PersonaIdentity`] out of it).
    pub(crate) fn keys(&self) -> &ArchivalPKeys {
        match self {
            HeldPersona::Bonded(b) => &b.0,
            HeldPersona::Ephemeral(e) => &e.0,
        }
    }
}

/// A held persona that carries a live bond. The wipe path cannot accept this
/// type (typed contract #4), so a bonded persona is never zeroized while a bond
/// depends on its `bond_spend` key.
pub(crate) struct BondedPersona(pub(crate) ArchivalPKeys);

/// A held persona with no live bond — the only thing [`wipe_ephemeral`] accepts.
pub(crate) struct EphemeralPersona(pub(crate) ArchivalPKeys);

/// Wipe a retired ephemeral persona.
///
/// Takes ownership of an [`EphemeralPersona`] by value — a [`BondedPersona`]
/// cannot be passed (typed contract #4), so wiping a persona with a live bond is
/// uncallable. The bundle's per-field `ZeroizeOnDrop` runs at the drop here; the
/// explicit `drop` makes the wipe a named operation rather than an implicit
/// scope-end.
pub(crate) fn wipe_ephemeral(persona: EphemeralPersona) {
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
pub(crate) fn wipe_bonded(persona: BondedPersona) {
    drop(persona);
}

/// Positive-confirmation evidence that a bonded persona is **terminal** and may
/// leave the scan union (2d-1 DQ8).
///
/// Constructible only when the retirement predicate holds, so a witness *existing*
/// is proof the persona is retire-eligible — and since the actor has no chain to
/// re-verify against, the witness **is** the guard. Mirrors the
/// [`PersistedBondTicket`](crate::engine::stake_persist::PersistedBondTicket) /
/// [`PersonaHandle`] evidence-typestate pattern. The discipline is the same
/// positive-confirmation, never-absence rule as SP-6's GC and SP-7's
/// `AbsentVerified`: a *wrong* retire wipes a still-live persona's `bond_spend`
/// key → can't unbond → **stuck funds**, the exact mirror of a wrongful GC, which
/// the conservative predicate guards against.
pub(crate) struct RetirementWitness {
    /// The cleartext canonical id of the persona to retire (from its confirmed
    /// `Unbond` bond-post). The actor matches it against the bonded union.
    pub(crate) p_canonical_id: PCanonicalId,
}

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
pub(crate) struct PersonaHandle {
    pub(crate) p_slot: PSlot,
    pub(crate) generation: u64,
}

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
/// unheld persona" (typed contract #2) and "construct before persist" (typed
/// contract #1) unrepresentable: a token is consumed *by value* by
/// `plan_bond_post` and cannot be duplicated to bypass the consumption.
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
    struct Invalid;
    impl<T: Clone> AmbiguousIfImpl<Invalid> for T {}

    // Resolves uniquely iff the type is NOT `Clone`; ambiguous (compile error)
    // if a `Clone` impl is ever added.
    let _ = <PersonaHandle as AmbiguousIfImpl<_>>::token_must_stay_single_use;
    let _ = <crate::engine::stake_persist::PersistedBondTicket as AmbiguousIfImpl<_>>::token_must_stay_single_use;
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
pub(crate) struct PersonaIdentity {
    /// The slot this persona was derived for.
    pub p_slot: PSlot,
    /// The persona's public bond identity key (= `hybrid_bond_id`, `P_pubkey`).
    pub bond_id: HybridPublicKey,
}

impl PersonaIdentity {
    /// Project the public identity out of a (secret) persona bundle.
    pub(crate) fn from_keys(keys: &ArchivalPKeys) -> Self {
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
    /// (`PlanBondPost`, S5 / Round 3). A bond-timing draw requires a functional CSPRNG;
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

    /// The entry-gap timing draw was statistically degenerate (`PlanBondPost`, S5 /
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

    /// The [`PersonaHandle`] and [`PersistedBondTicket`] passed to [`PlanBondPost`]
    /// name different persona slots. A ticket witnesses the durable persist for a
    /// *specific* slot; it cannot authorize a bond operation for any other slot.
    /// Non-terminal: ensure both are obtained for the same `p_slot`.
    #[error(
        "bond-post slot mismatch: handle names slot {handle_slot:?}, \
         ticket names slot {ticket_slot:?}; both must name the same persona slot"
    )]
    SlotMismatch {
        handle_slot: PSlot,
        ticket_slot: PSlot,
    },

    /// Bond construction failed after the actor validated the handle and ticket
    /// (`PlanBondPost`, S2). The persona bundle was available but
    /// [`build_join_market_vin`] returned an error — see the wrapped
    /// [`BondBuildError`] for the specific cause (`BondFloorZero`,
    /// `IdentityEncode`, or `BondSpendEncode`).
    #[error("bond construction failed: {0}")]
    BondBuild(#[from] BondBuildError),

    /// A WI-2 [`AssembleBond`] pipeline step failed — funding arithmetic,
    /// spend-bundle derivation, output construction, proving, PQC auth
    /// signing, or wire encoding. The wrapped [`BondAssemblyError`] names the
    /// §3.6 failure mode; in every arm nothing was persisted and no funding
    /// was reserved.
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
    /// production construction path injects [`shekyl_standoff::gf7::NoOpObserver`]; only the sim
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
