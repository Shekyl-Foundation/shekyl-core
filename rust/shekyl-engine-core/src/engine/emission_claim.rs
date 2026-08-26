// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Emission claim assembly — the pure module of the wallet-side claim
//! builder (`EMISSION_CLAIM_BUILDER.md` §2, PR 2 of the §8 chain).
//!
//! This module is deterministic given a decoded [`EmissionClaimSource`]:
//! no daemon, no actor harness, no clock — KAT-able end-to-end with a
//! fixture source (§8 PR-2 validation surface). The RPC fetch/decode is
//! [`emission_source`](super::emission_source) (PR 1); backing selection,
//! membership proof, dual auth, and tx assembly are the PR-3 `StakeEngine`
//! handler's, which consumes this module's outputs.
//!
//! ## Step-1 claimable-epoch derivation (the M1 forward pin, discharged)
//!
//! `docs/FOLLOWUPS.md` M1 round-1 record: claimable epochs derive from
//! **the same positive-share recompute the verifier runs** — literally:
//! [`claimant_reward_share`], the shared steps-4/5 evaluation head the
//! verify body calls, never a mirrored copy — and never from close-only
//! operands (the close's outcome reaches the wallet only through the
//! persisted `Σwork(E)` denominator, same as verify; the retired M1 gate
//! was the original such operand — `ARCHIVAL_REWARD_GATE_M1.md` §13) and
//! never from row-absence proxies. Claimable ⇔ the recomputed
//! share is strictly positive, which is exactly the §2.3 wire positivity
//! predicate (`reward_amount_plain[i] > 0` — a zero row is unencodable, so
//! the builder omits the epoch rather than encode it).
//!
//! ## Boundary verdicts (read-only predicates)
//!
//! Every window verdict resolves through a landed read-only predicate —
//! **top** ([`epoch_is_not_settled`] ⇒ `NotSettled`), **bottom**
//! ([`epoch_is_claim_expired`] ⇒ `WindowExpired`), **dedup**
//! ([`claimed_epochs_contains`] ⇒ `AlreadyClaimed`), **join**
//! ([`epoch_is_before_join`] ⇒ `BeforeJoin`, verify step 2's
//! `E ≥ E_join + 1` against the **record's** join epoch). These are the
//! same functions the connect path's `claimed_epochs_check_and_set` and
//! the verify body resolve through (one definition each, enforced by their
//! call sites and the connect-mutator differential KAT), so builder and
//! consensus cannot drift — no inline boundary arithmetic exists here.
//!
//! The **finalization** boundary — verify's strict
//! `current_block_height > h_close(E)` — is the verify body's step-1
//! predicate, consumed via [`epoch_close_height`] (the literal function
//! verify calls). The connect window and the verify window differ by
//! exactly one count — see the Step 7 section for the close-boundary
//! trace.
//!
//! ## Cause-blindness (CB-5)
//!
//! A zero-share epoch is skipped as [`EpochSkip::ZeroShare`] — one
//! verdict for every zero cause (no serve credit, floored-to-zero share).
//! The distinction is not merely withheld; it is **not derivable here**:
//! the claim path consults no close-only operand, so the wallet cannot
//! tell the causes apart and neither can an observer of the refusal. Do
//! not add a branch that could.
//!
//! ## Steps 2 + 5 — work-claim rows, rewards, sizing
//!
//! The derivation builds each admitted epoch's canonical row from the
//! admitting evaluation in the same scope (single-evaluator discipline);
//! [`assemble_claims`] turns the derived batch into the vin's claims-side
//! content, integer-exact against verify (tolerance zero):
//!
//! - **Canonical row form.** Per epoch, one [`ShardWorkEntry`] per shard
//!   the claimant is credited on — `serve_credit_bit = true`, sorted by
//!   `shard_id` ascending, no other entries. Verify accepts padding
//!   entries (`bit = false, scarcity = 0` rows pass its per-entry
//!   equalities), but the builder never emits them: the minimal form is
//!   the one whose entry sum equals `work_P(E)` by the same accumulation
//!   the close ran, and padding is bytes that buy nothing. The per-entry
//!   scarcity resolves the shard row **by first position of `shard_id`**
//!   — byte-exactly the lookup verify's `ScarcityMismatch` recompute
//!   performs — and the entry sum must equal the derivation's `work_P`
//!   ([`EmissionClaimError::SourceInvalid`] otherwise: a gather whose
//!   pair-indexed accumulation disagrees with its id-resolved recompute
//!   is internally inconsistent, e.g. duplicate `shard_id` rows).
//!
//! - **The u64→u32 conversion guard.** The recompute chain is `u64`; the
//!   wire's `scarcity_micro` is `u32`. The builder refuses at its own
//!   conversion site ([`EmissionClaimError::ScarcityConversion`]) rather
//!   than relying on the encoder's `ScarcityOverflow` — the encoder
//!   catching it would mean the builder emitted an invalid value and got
//!   saved downstream, in the wrong component. Under the compiled
//!   constants pipeline the guard is structurally unreachable
//!   (`verify_view` pins `age_weight_milli`; `age_milli ≤ 1000`; so
//!   scarcity `≤ WORK_MILLI_SCALE + ARCHIVAL_REWARD_AGE_WEIGHT_MILLI` —
//!   const-asserted below, so a constant bump that could cross the wire
//!   field's width fails the build and reopens this analysis rather than
//!   silently arming the path). The KAT drives the refusal with a
//!   hostile-constants view built directly, because no daemon input can
//!   reach it through the decode path.
//!
//! - **Rewards.** `reward_amount_plain[i]` is the derivation's recomputed
//!   share, verbatim — the builder never invents an amount (§2 step 5).
//!   Strictly positive by the claimability predicate, so the rows are
//!   wire-encodable by construction. The batch total is `checked_add`
//!   (overflow ⇒ [`EmissionClaimError::SourceInvalid`]: budgets are
//!   daemon-supplied).
//!
//! - **Sizing (bound-or-split, GF-4b item 5).** The claims-leg projection
//!   is measured with the **production encoder** on **the** vin the
//!   assembly's content is returned from — built once with the
//!   cryptographic legs at their structural maxima (canonical-length
//!   pubkeys/sigs, [`MAX_BACKING_PROOF_BYTES`] proof, saturated depth) —
//!   a worst-case upper bound on the real vin's bytes, from the same
//!   write path, so no shadow size model can drift **and** the measured
//!   content is byte-identical to the emitted content (one construction
//!   site, [`claims_vin`]). Over budget ⇒ pop the youngest epoch
//!   (oldest-first retention mirrors the batch cap's
//!   never-strand-a-savable-epoch order) and re-measure; a single epoch
//!   alone over budget refuses
//!   [`EmissionClaimError::SizeBoundExceeded`]. The budget is a
//!   parameter; [`EMISSION_CLAIMS_SIZE_BUDGET`] is the documented
//!   default, derived from the **binding** relay bound — the per-tx
//!   weight limit ([`TX_WEIGHT_LIMIT`], 149 400 B) — never
//!   `MAX_TX_SIZE` (the 1 MB parse cap): a batch bounded against the
//!   parse cap could pass assembly and the step-7 self-check (which
//!   checks no size) yet be permanently unsubmittable at the mempool,
//!   re-assembled identically on every retry until the window's rewards
//!   expire.
//!
//! ## Step 7 — the build-time self-check
//!
//! [`self_check_claims`] runs the **landed consensus verifier**
//! ([`emission_vin_verify_claims`] — the literal function, never a
//! mirror) over the assembled vin and the same decoded source the
//! assembly consumed (§7.3 decode-locus pin: a self-check over a copy
//! tests the copy). A builder/verifier disagreement is a bug surfaced
//! loudly at build time, never a mempool rejection to diagnose post-hoc
//! — the differential test made a production invariant (M1's
//! walk-vs-counter idiom applied to assembly).
//!
//! The verify-context height is the source's gather tip
//! (`chain_height`, a block count — i.e. the next block's height, the
//! earliest the assembled tx could be included at), so the self-check
//! proves the batch verifies **for next-block inclusion**. The settled
//! operand the window verdicts consume is decode-enforced equal to
//! `settlement_epoch_at_height(chain_height)` (PR 1), so the derivation's
//! boundaries and the self-check's recomputed boundaries provably share
//! one basis.
//!
//! **The close-boundary count (verified at daemon source).** The close
//! of `E` runs while connecting `E`'s **last** block — the hook operand
//! is the next height (`blockchain_db.cpp` `add_block`:
//! `process_archival_epoch_close_at_height(prev_height + 1)`, fired
//! connecting height `(E+1)·SEB − 1`). So at the one count
//! `chain_height == h_close(E)` the budget row for `E` **already
//! exists** and the connect window admits `E` (`settled = E + 1` from
//! the same `db.height()` read, `archival_claim_source.cpp`), while
//! verify's strict `current_block_height > h_close(E)` still rejects a
//! claim of `E` in the very next block. The connect and verify windows
//! genuinely differ by one count; a `NoCloseRow` skip does **not**
//! foreclose the edge (an earlier revision claimed it did — wrongly).
//! The derivation therefore applies verify's own step-1 predicate, via
//! the same [`epoch_close_height`] verify calls, and defers the epoch
//! one block ([`EpochSkip::NotFinalized`]) — the assembled batch
//! verifies at the gather tip by construction, and the boundary KAT's
//! premise arm proves the deferral is load-bearing (an `E`-bearing vin
//! at that count drives the real verifier to `EpochNotFinalized`).
//!
//! **Cause-blindness (CB-5 builder pin).** [`EmissionClaimError::SelfCheckFailed`]
//! carries **no operand**: "self-check failed on operand X" would leak
//! which operand the daemon mis-sourced — an observable a lying daemon
//! could farm. The verifier's [`EmissionVerifyError`] is logged locally
//! only; the surfaced refusal is one blind verdict for every cause.
//!
//! **Coverage boundary (PR 2).** This self-check is the **claims leg**
//! (verify steps 1–5). The claims verifier reads the vin's backing/auth
//! fields only through `validate()`'s shape pins (canonical lengths,
//! proof-size bounds) — verified at source: `emission_vin_verify_claims`
//! never reads their content — so the step-7 KAT's dummy canonical-length
//! legs exercise the claims leg fully. The backing and auth legs
//! (`emission_vin_verify_backing` / `_auth`) become checkable only when
//! PR 3 constructs a real proof and real signatures; their self-check
//! composition lands there, with the whole-vin differential.
//!
//! [`EmissionVerifyError`]: shekyl_archival_retention::EmissionVerifyError

use shekyl_archival_retention::{
    claimant_reward_share, claimed_epochs_contains, emission_vin_verify_claims, epoch_close_height,
    epoch_is_before_join, epoch_is_claim_expired, epoch_is_not_settled, shard_contribution_micro,
    ArchivalRewardEmissionVin, EmissionEpochSource, EmissionVerifyContext, EmissionWireError,
    EpochCloseBond, HoldingsDescriptor, MembershipOnlyBacking, ServedWork, ShardWorkEntry,
    WorkEpochClaim, ARCHIVAL_REWARD_AGE_WEIGHT_MILLI, MAX_BACKING_PROOF_BYTES,
    MAX_SETTLEMENT_EPOCHS_PER_EMISSION, WORK_MICRO_PER_MILLI, WORK_MILLI_SCALE,
};
use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};
use shekyl_wire::transaction::TX_WEIGHT_LIMIT;
use tracing::error;

use super::emission_source::{BondContext, EmissionClaimSource, EpochSnapshot};

// The compiled-constants bound behind the conversion guard's structural-
// unreachability claim (module doc): an honest recompute through
// `verify_view` satisfies `scarcity_micro ≤ WORK_MICRO_PER_MILLI ·
// (WORK_MILLI_SCALE + weight)` (age is depth-fraction-bounded to
// `WORK_MILLI_SCALE`, so `g ≤ WORK_MILLI_SCALE + weight`, and `r_market ≥ 1`
// for a nonzero term makes `scarcity_micro = floor(WORK_MICRO_PER_MILLI · g /
// r) ≤ WORK_MICRO_PER_MILLI · g`). A weight bump that could cross the wire
// field's width must fail this build, not silently arm the runtime refusal.
//
// Evaluated in `u128`: every operand is a **config-generated** `u64`, so the
// drift this guard exists to catch is precisely the drift that could overflow a
// `u64` product first — and a const-eval overflow reports "attempt to compute …
// which would overflow" instead of the message below, i.e. the guard would fail
// to explain itself exactly when it fires. `u128` cannot overflow from `u64`
// operands, so the diagnostic is preserved for any value the config can produce.
const _: () = assert!(
    (WORK_MICRO_PER_MILLI as u128)
        * ((WORK_MILLI_SCALE as u128) + (ARCHIVAL_REWARD_AGE_WEIGHT_MILLI as u128))
        <= u32::MAX as u128,
    "compiled constants must keep scarcity_micro within the u32 wire field"
);

/// Bytes of the [`TX_WEIGHT_LIMIT`] envelope reserved for everything
/// outside the emission vin, sized by worst-case arithmetic over the wire
/// layout (`tx_fee_model`'s field constants; rule 75: rationale + bounds):
///
/// - tx prefix + 16 vouts + their `tx_extra` KEM ciphertexts (the dominant
///   vout-side term: 16 × ~1.1 KiB) ≈ 19.4 KiB,
/// - two fee-side FCMP++ spend inputs at max tree depth (measured proof
///   table: 12 032 B for `n_in = 2`) + their hybrid PQC auths
///   (2 × 5 389 B) + pseudo-outs ≈ 22.9 KiB,
/// - the Bp+ proof (834 B) and its verification **clawback** for 16 padded
///   outputs (3 430 B — tx *weight* counts the clawback; the vin
///   measurement is serialized bytes, so the clawback belongs to this
///   reserve) ≈ 4.2 KiB,
///
/// summing to ≈ 45.6 KiB; 48 KiB adds headroom. *Reversion (rule 21):*
/// PR-3's tx assembly owns fee-input selection and replaces this static
/// reserve with its measured fee-side envelope; reopen sooner if a claim
/// tx needs more than two fee inputs.
pub const EMISSION_NON_CLAIMS_RESERVE_BYTES: usize = 49_152;

/// Default claims-leg size budget for [`assemble_claims`]:
/// [`TX_WEIGHT_LIMIT`] — the **binding** per-tx relay/consensus bound
/// (`MAX_TX_SIZE` is only the parse cap; a vin bounded against it would be
/// permanently unsubmittable) — minus [`EMISSION_NON_CLAIMS_RESERVE_BYTES`].
pub const EMISSION_CLAIMS_SIZE_BUDGET: usize = TX_WEIGHT_LIMIT - EMISSION_NON_CLAIMS_RESERVE_BYTES;

// The budget must leave real room for claims content beyond the vin's
// fixed-size cryptographic legs (max backing proof + two canonical hybrid
// pubkeys + two canonical hybrid sigs): a reserve bump that starves the
// claims leg must fail this build, not surface at runtime as universal
// `SizeBoundExceeded` refusals.
const _: () = assert!(
    EMISSION_CLAIMS_SIZE_BUDGET
        > MAX_BACKING_PROOF_BYTES
            + 2 * (SINGLE_KEY_CANONICAL_LEN + SINGLE_SIG_CANONICAL_LEN)
            + 8_192,
    "claims budget must exceed the vin's fixed cryptographic legs plus row room"
);

/// Builder refusals (CB-5 taxonomy, the arms this module constructs).
///
/// Staged completeness (§8 / rule 15 — no dead variants):
/// `InsufficientBacking` landed with its constructor site — the
/// designated-backing selector (`backing_set::InsufficientBacking`,
/// refused by `BackingSet::designate_backing` on an empty set) — as its
/// own refusal type rather than a variant here: it is a selection-time
/// refusal, upstream of claim gathering.
#[derive(Debug, thiserror::Error)]
pub enum EmissionClaimError {
    /// Nothing claimable — an **idle state, not an error** (rule 82 /
    /// CB-5): every window epoch was skipped (zero share, expired,
    /// already claimed, not settled, pre-join, no close row) or the daemon
    /// has no bond record for `P`. Cause-blind by construction: the
    /// refusal carries no per-epoch reasons (the [`EpochSkip`] diagnostics
    /// ride the `Ok` path only, and `ZeroShare` is itself one verdict for
    /// all zero causes).
    #[error("no claimable epochs")]
    NoClaimableEpochs,
    /// The daemon's gather rows are internally inconsistent (a credit
    /// pair or the claimant index references outside the bond/shard
    /// arrays; duplicate credited shards; an id-resolved recompute that
    /// disagrees with the pair-indexed accumulation; a reward sum
    /// overflowing `u64`; a window epoch whose close height does not
    /// exist) — malformed input from an untrusted daemon, refused loudly
    /// (`20-rust-vs-cpp-policy.mdc` §3), never skipped-and-continued: a
    /// daemon that mis-serializes one epoch cannot be trusted for the
    /// window.
    #[error("epoch {epoch}: claim-source rows are internally inconsistent")]
    SourceInvalid { epoch: u64 },
    /// The recomputed per-shard scarcity does not fit the wire's `u32`
    /// field. The builder refuses at its own conversion site — never
    /// relying on the encoder's `ScarcityOverflow` to be saved
    /// downstream (module doc; structurally unreachable under the
    /// compiled constants, const-asserted above).
    #[error("epoch {epoch} shard {shard_id}: recomputed scarcity exceeds the u32 wire field")]
    ScarcityConversion { epoch: u64, shard_id: u64 },
    /// A single epoch's claim alone exceeds the claims-leg size budget —
    /// nothing further to split (§2 step 5 bound-or-split's terminal
    /// refusal).
    #[error("epoch {epoch}: single-epoch claim ({projected} B) exceeds budget ({budget} B)")]
    SizeBoundExceeded {
        epoch: u64,
        projected: usize,
        budget: usize,
    },
    /// The builder-constructed claims rows violate a wire structural
    /// invariant (e.g. more credited shards than
    /// [`shekyl_archival_retention::bond_wire::MAX_HOLDINGS_SHARDS`]) —
    /// surfaced by the production encoder during the sizing measurement,
    /// refused before any vin leaves the builder.
    #[error("claims rows unencodable: {0}")]
    RowsUnencodable(#[source] EmissionWireError),
    /// The assembled vin failed the landed consensus verifier (§2 step 7)
    /// — a builder/verifier disagreement, i.e. a bug, surfaced loudly at
    /// build time rather than as a mempool rejection to diagnose post-hoc.
    ///
    /// **Cause-blind by construction (CB-5 builder pin):** a unit variant,
    /// no operand — "self-check failed on operand X" would leak which
    /// operand the daemon mis-sourced, an observable a lying daemon could
    /// farm. The verifier's rejection is logged locally only (module doc
    /// "Step 7").
    #[error("assembled claim failed the build-time self-check")]
    SelfCheckFailed,
}

/// Why a window epoch was not selected by the derivation — **local
/// diagnostics**, never a transport operand or an observable refusal
/// payload (CB-5: the claim query is cause-blind; nothing derived from
/// these verdicts may shape daemon-visible behavior).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochSkip {
    /// `E ≥ current_settled_epoch` ([`epoch_is_not_settled`] — the connect
    /// predicate's `NotSettled`).
    NotSettled,
    /// `E` fell below the claim window floor ([`epoch_is_claim_expired`] —
    /// the connect predicate's `Expired`).
    WindowExpired,
    /// `E` is already in the bond record's claimed set
    /// ([`claimed_epochs_contains`] — the connect predicate's dedup
    /// verdict).
    AlreadyClaimed,
    /// `E ≤ E_join`: the epoch predates (or equals) the **record's**
    /// market entry — verify step 2's `E ≥ E_join + 1` bound
    /// ([`epoch_is_before_join`]; verify: `EpochBeforeJoin`). Reachable
    /// when the record's join epoch is newer than a frozen row's
    /// (retire-then-rejoin: the rejoin re-derives `E_join` from the
    /// rejoin height, while `E`'s frozen close rows still credit the old
    /// bond row).
    BeforeJoin,
    /// Settled by the connect window but not yet finalized for
    /// next-block inclusion: `chain_height ≤ h_close(E)` — verify's
    /// step-1 strict predicate, which admits `E` exactly one count
    /// after the connect window does (module doc "Step 7"). Fires only
    /// at `chain_height == h_close(E)` (the equality count); the epoch
    /// is claimable one block later. Named after verify's
    /// `EpochNotFinalized` rejection, whose predicate this consumes.
    NotFinalized,
    /// No frozen close row for `E` (`has_budget_row == false`) — mirrors
    /// the verify shim's reject; there is no denominator to claim against.
    NoCloseRow,
    /// The recomputed share is zero. **One verdict for every zero cause**
    /// (gated, no serve credit, floored) — see the module doc's
    /// cause-blindness section.
    ZeroShare,
    /// Claimable, but the batch already holds
    /// [`MAX_SETTLEMENT_EPOCHS_PER_EMISSION`] older epochs — deferred to
    /// the next claim tx (§6.6 F4 drain-vs-batch: `W = 26`, batch 15, so
    /// a full backlog drains in two txs before anything expires).
    BatchDeferred,
}

/// One claimable epoch: every boundary verdict passed and the recomputed
/// share is strictly positive.
///
/// Carries the admitting evaluation's outputs — the canonical work-claim
/// row and the recomputed share — built in the same scope that admitted
/// the epoch (single-evaluator discipline: the row can never pair with a
/// different evaluation, and no later step re-indexes the source it came
/// from).
#[derive(Debug, Clone)]
pub struct ClaimableEpoch {
    /// The claimed `E`.
    pub settlement_epoch: u64,
    /// The canonical work-claim row (module doc "Canonical row form"),
    /// built from the admitting evaluation's per-shard terms.
    pub claim: WorkEpochClaim,
    /// `P`'s recomputed reward share — strictly positive (the §2.3 wire
    /// positivity predicate is the claimability predicate), byte-exactly
    /// what verify's step 5 recomputes ([`claimant_reward_share`]'s
    /// `reward` — the literal shared function).
    pub reward: u64,
}

/// Step-1 output: the selected batch plus per-epoch skip diagnostics.
///
/// Borrows the source's bond context (`'src`), so a stale batch cannot be
/// paired with a refetched source: PR-3's staleness/retry path must
/// re-derive after every refetch — the type makes the stale pairing
/// unrepresentable (a refusal at compile time, not a panic or a
/// mis-assembly at run time).
#[derive(Debug)]
pub struct ClaimableEpochs<'src> {
    /// The claim context the batch was derived against — the assembly
    /// copies the holdings descriptor by value from here (§5.3/§6.4.1:
    /// verify demands record equality; the builder never recomputes a
    /// descriptor).
    pub bond: &'src BondContext,
    /// Strictly increasing (window order), `1..=15` entries.
    pub claimable: Vec<ClaimableEpoch>,
    /// Local diagnostics for every window epoch **not** selected, in
    /// window order. See [`EpochSkip`]'s observability caveat.
    pub skipped: Vec<(u64, EpochSkip)>,
}

/// §2 step 1 — derive the claimable-epoch batch from a decoded claim
/// source.
///
/// Per window epoch, in ascending (window) order:
///
/// 1. **Boundaries** — the read-only predicates (module doc): top
///    ([`epoch_is_not_settled`]), bottom ([`epoch_is_claim_expired`]),
///    dedup ([`claimed_epochs_contains`]), join
///    ([`epoch_is_before_join`], verify step 2 against the record's
///    `E_join`). The decoded record is never mutated.
/// 2. **Strict finalization** — verify's step-1 predicate at the
///    earliest inclusion height (`chain_height > h_close(E)`, via
///    [`epoch_close_height`]); the connect window admits `E` one count
///    before verify accepts it, so the equality count defers
///    ([`EpochSkip::NotFinalized`] — module doc "Step 7"). An epoch with
///    no close height at all (u64 overflow) is malformed input, refused
///    loudly.
/// 3. **Close row** — no frozen close row (`has_budget_row == false`)
///    skips ([`EpochSkip::NoCloseRow`]).
/// 4. **Share recompute** — [`claimant_reward_share`], the shared
///    steps-4/5 evaluation head the verify body runs (absent claimant
///    index ⇒ zero work, exactly as verify treats it), against the
///    **persisted** `Σwork(E)` and frozen `budget(E)`. Claimable ⇔ share
///    `> 0`; the canonical row is built from the same evaluation in the
///    same scope.
///
/// Selection is oldest-first (window order) up to
/// [`MAX_SETTLEMENT_EPOCHS_PER_EMISSION`]; younger claimable epochs
/// beyond the cap defer to the next claim tx ([`EpochSkip::BatchDeferred`]).
/// Oldest-first is load-bearing: the oldest epochs are nearest the
/// expiry floor, so deferral never pushes an epoch out of the window
/// that a different order could have saved.
///
/// Refuses [`EmissionClaimError::NoClaimableEpochs`] when the batch is
/// empty (including the no-bond-record case — an idle state, not an
/// error) and [`EmissionClaimError::SourceInvalid`] on internally
/// inconsistent gather rows.
pub fn derive_claimable_epochs(
    source: &EmissionClaimSource,
) -> Result<ClaimableEpochs<'_>, EmissionClaimError> {
    let Some(bond) = source.bond.as_ref() else {
        return Err(EmissionClaimError::NoClaimableEpochs);
    };

    let mut claimable: Vec<ClaimableEpoch> = Vec::new();
    let mut skipped: Vec<(u64, EpochSkip)> = Vec::new();

    for snap in &source.epochs {
        let epoch = snap.settlement_epoch;

        // Boundary verdicts — the read-only predicates (module doc), in
        // the connect mutator's check order; no inline boundary
        // arithmetic.
        if epoch_is_not_settled(epoch, source.current_settled_epoch) {
            skipped.push((epoch, EpochSkip::NotSettled));
            continue;
        }
        if epoch_is_claim_expired(epoch, source.current_settled_epoch) {
            skipped.push((epoch, EpochSkip::WindowExpired));
            continue;
        }
        if claimed_epochs_contains(&bond.claimed_settlement_epochs, epoch) {
            skipped.push((epoch, EpochSkip::AlreadyClaimed));
            continue;
        }
        // Verify step 2's join bound, against the *record's* join epoch —
        // the same predicate the verify body calls. The frozen rows'
        // membership masks are not enough: a retire-then-rejoin record
        // carries a newer `E_join` than the rows that credited `E`, and
        // without this skip the builder would assemble a vin its own
        // self-check — and the chain — refuses (`EpochBeforeJoin`).
        if epoch_is_before_join(epoch, bond.join_settlement_epoch) {
            skipped.push((epoch, EpochSkip::BeforeJoin));
            continue;
        }

        // Verify's step-1 strict finalization at the earliest inclusion
        // height — consumed via the same `epoch_close_height` the verify
        // body calls (never inline arithmetic). The connect window admits
        // `E` one count before verify accepts it (module doc "Step 7"), so
        // the equality count defers one block. A window epoch with no
        // close height at all (`(E+1)·SEB` overflows u64) cannot come from
        // an honest daemon — the decode invariant pins `E < settled =
        // settlement_epoch_at_height(chain_height)`, which bounds
        // `h_close(E) ≤ chain_height` — so refuse loudly rather than defer
        // as transiently not-finalized (fail-closed on untrusted input).
        let Some(h_close) = epoch_close_height(epoch) else {
            return Err(EmissionClaimError::SourceInvalid { epoch });
        };
        // Verify's operand is the block carrying the tx; assembled now,
        // that is the chain count's next height (`ChainCount::next_height`
        // — the typed form of "the count IS the earliest inclusion height").
        if source.chain_height.next_height().to_raw() <= h_close {
            skipped.push((epoch, EpochSkip::NotFinalized));
            continue;
        }

        if !snap.has_budget_row {
            skipped.push((epoch, EpochSkip::NoCloseRow));
            continue;
        }

        // Share recompute — the shared steps-4/5 evaluation head
        // ([`claimant_reward_share`]: literally the function the verify
        // body runs) over the same decoded views the self-check consumes
        // (§7.3 decode-locus pin). Malformed gather indices refuse loudly
        // (untrusted daemon), mirroring verify's GatherMalformed /
        // ClaimantIndexOutOfRange rejections.
        let bonds = snap.bonds_view();
        let view = snap.source(&bonds);
        let share = claimant_reward_share(&view)
            .map_err(|_| EmissionClaimError::SourceInvalid { epoch })?;
        if share.reward == 0 {
            skipped.push((epoch, EpochSkip::ZeroShare));
            continue;
        }

        // Batch cap — deliberately *after* the share recompute: every
        // window epoch gets the full loud validation of the untrusted
        // gather (a malformed over-cap epoch is `SourceInvalid` now, not
        // on the next claim tx), and `BatchDeferred` keeps its documented
        // meaning — "claimable, deferred" — which a hoisted check would
        // dilute to "unevaluated". The discarded recomputes are bounded
        // (≤ `W − 15` epochs per derivation).
        if claimable.len() == MAX_SETTLEMENT_EPOCHS_PER_EMISSION {
            skipped.push((epoch, EpochSkip::BatchDeferred));
            continue;
        }

        // Step-2 row assembly from the admitting evaluation, in the same
        // scope (single-evaluator discipline).
        let Some(claimant) = view.claimant_bond_idx else {
            // reward > 0 ⇒ positive credited work ⇒ a serve-credit row
            // exists, so a `None` claimant here is an internal
            // contradiction in the gather — refused typed, never panicked.
            return Err(EmissionClaimError::SourceInvalid { epoch });
        };
        let claim = work_epoch_claim(&view, &share.served, claimant)?;
        claimable.push(ClaimableEpoch {
            settlement_epoch: epoch,
            claim,
            reward: share.reward,
        });
    }

    if claimable.is_empty() {
        return Err(EmissionClaimError::NoClaimableEpochs);
    }
    Ok(ClaimableEpochs {
        bond,
        claimable,
        skipped,
    })
}

/// Steps 2 + 5 output: the vin's claims-side content, aligned per epoch,
/// plus the by-value holdings copy and the size-deferral diagnostics.
///
/// The PR-3 `StakeEngine` handler completes the vin around this (backing
/// selection, dual auth) and runs the step-7 self-check on the whole.
#[derive(Debug)]
pub struct AssembledClaims {
    /// Strictly increasing (window order) — the vin's `settlement_epochs`.
    pub settlement_epochs: Vec<u64>,
    /// Per-epoch canonical work-claim rows, aligned with
    /// `settlement_epochs` (module doc: credited shards only, sorted by
    /// `shard_id`, `serve_credit_bit = true`).
    pub work_claim: Vec<WorkEpochClaim>,
    /// Per-epoch recomputed shares, aligned — verbatim the derivation's
    /// rewards (the builder never invents an amount), strictly positive.
    pub reward_amount_plain: Vec<u64>,
    /// The bond record's holdings descriptor, copied **by value**
    /// (§5.3/§6.4.1: verify demands record equality; the builder never
    /// recomputes a descriptor).
    pub holdings: HoldingsDescriptor,
    /// `checked_add` sum of `reward_amount_plain` — the mint the PR-3
    /// reward-vout construction distributes.
    pub total_reward: u64,
    /// Epochs dropped by the size bound, in window order (the verdict is
    /// definitionally "size-deferred", so only the epoch rides here) —
    /// deferred to the next claim tx; same observability caveat as
    /// [`ClaimableEpochs::skipped`].
    pub size_deferred: Vec<u64>,
}

/// §2 steps 2 + 5 — assemble the claims-side vin content from the derived
/// batch (module doc: canonical row form, rewards, and the bound-or-split
/// size discipline).
///
/// Consumes the derivation's own evaluation (rows and rewards ride
/// [`ClaimableEpoch`]) — single-evaluator discipline: assembly never
/// re-runs the recompute it was admitted on. The `'src` borrow on
/// `derived` ties the batch to the source it was derived from, so a
/// refetched source cannot be paired with a stale batch.
///
/// `claims_size_budget` is the claims-leg byte bound
/// ([`EMISSION_CLAIMS_SIZE_BUDGET`] is the documented default; the
/// parameter exists so the bound is testable at exact boundaries).
pub fn assemble_claims(
    derived: &ClaimableEpochs<'_>,
    claims_size_budget: usize,
) -> Result<AssembledClaims, EmissionClaimError> {
    debug_assert!(
        !derived.claimable.is_empty(),
        "derive_claimable_epochs never returns an empty batch"
    );

    // Step 5 sizing — bound or split (GF-4b item 5) over **one** vin
    // ([`claims_vin`], the single construction site), built once with the
    // cryptographic legs at their structural maxima and measured by the
    // production encoder (module doc "Sizing"). While over budget, pop the
    // youngest epoch off the same vin and re-measure; refuse when one
    // epoch alone cannot fit.
    let mut vin = claims_vin(
        derived.bond.holdings.clone(),
        derived
            .claimable
            .iter()
            .map(|c| c.settlement_epoch)
            .collect(),
        derived.claimable.iter().map(|c| c.claim.clone()).collect(),
        derived.claimable.iter().map(|c| c.reward).collect(),
        MAX_BACKING_PROOF_BYTES,
        u8::MAX,
    );
    let mut size_deferred: Vec<u64> = Vec::new();
    loop {
        let projected = vin
            .serialize()
            .map_err(EmissionClaimError::RowsUnencodable)?
            .len();
        if projected <= claims_size_budget {
            break;
        }
        if vin.settlement_epochs.len() == 1 {
            return Err(EmissionClaimError::SizeBoundExceeded {
                epoch: vin.settlement_epochs[0],
                projected,
                budget: claims_size_budget,
            });
        }
        let epoch = vin.settlement_epochs.pop().expect("len > 1 checked above");
        vin.work_claim.pop();
        vin.reward_amount_plain.pop();
        size_deferred.push(epoch);
    }
    // Popped youngest-first; report in window order.
    size_deferred.reverse();

    // Step 5 rewards — verbatim derivation shares; the batch total is
    // checked (budgets are daemon-supplied; an overflowing sum is
    // malformed source, not arithmetic to saturate through).
    let mut total_reward: u64 = 0;
    for (&epoch, &reward) in vin
        .settlement_epochs
        .iter()
        .zip(vin.reward_amount_plain.iter())
    {
        total_reward = total_reward
            .checked_add(reward)
            .ok_or(EmissionClaimError::SourceInvalid { epoch })?;
    }

    // The emitted content is moved out of the measured vin itself: the
    // bytes bounded above are byte-identical to the content PR-3 completes
    // and submits.
    Ok(AssembledClaims {
        settlement_epochs: vin.settlement_epochs,
        work_claim: vin.work_claim,
        reward_amount_plain: vin.reward_amount_plain,
        holdings: vin.holdings,
        total_reward,
        size_deferred,
    })
}

/// One epoch's canonical [`WorkEpochClaim`] from the admitting evaluation
/// (module doc "Canonical row form"): one entry per credited shard, sorted
/// by `shard_id`, `serve_credit_bit = true`, scarcity resolved by first
/// position of `shard_id` — byte-exactly verify's `ScarcityMismatch`
/// lookup. This is **the** builder conversion site for the wire's
/// `u32 scarcity_micro` (checked, refusing — module doc).
///
/// `claimant` is the derivation's admitted claimant index (bounds-checked
/// by [`claimant_reward_share`] before admission).
fn work_epoch_claim(
    view: &EmissionEpochSource<'_>,
    served: &ServedWork,
    claimant: usize,
) -> Result<WorkEpochClaim, EmissionClaimError> {
    let epoch = view.inputs.settlement_epoch;
    debug_assert!(
        served.member[claimant],
        "claimable ⇒ positive credited work ⇒ market member"
    );

    let mut shard_ids: Vec<u64> = view
        .inputs
        .credit_pairs
        .iter()
        .filter(|pair| pair.bond_idx == claimant)
        .map(|pair| view.inputs.shards[pair.shard_idx].shard_id)
        .collect();
    shard_ids.sort_unstable();
    if shard_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        // Duplicate credited shards: the ledger key `P‖shard‖E` is unique,
        // so a gather carrying two credits for one (claimant, shard) is
        // malformed — and would double-count `work_P` besides.
        return Err(EmissionClaimError::SourceInvalid { epoch });
    }

    let mut entry_sum: u64 = 0;
    let mut shard_entries = Vec::with_capacity(shard_ids.len());
    for shard_id in shard_ids {
        // The linear first-position scan is deliberate parity, not an
        // oversight: it is byte-exactly the lookup verify's
        // `ScarcityMismatch` recompute performs (and the step-7 self-check
        // runs that verifier over the same rows, so a builder-side index
        // map would not change the end-to-end cost — only add a second
        // lookup semantic that could drift from verify's).
        let shard_idx = view
            .inputs
            .shards
            .iter()
            .position(|s| s.shard_id == shard_id)
            .expect("credited pair implies the shard row exists");
        let scarcity = shard_contribution_micro(&view.inputs, &served.r_market_by_shard, shard_idx);
        let scarcity_micro = u32::try_from(scarcity)
            .map_err(|_| EmissionClaimError::ScarcityConversion { epoch, shard_id })?;
        entry_sum = entry_sum.saturating_add(scarcity);
        shard_entries.push(ShardWorkEntry {
            shard_id,
            serve_credit_bit: true,
            scarcity_micro,
        });
    }

    // The id-resolved recompute must equal the pair-indexed accumulation
    // the derivation selected on (verify's `WorkTotalMismatch` compare,
    // run here so a doomed vin refuses at derivation, not on-chain). Both are
    // **micro** — the compare runs in micro-space before the single floor,
    // mirroring the verify body (D1 fix). They diverge only on an internally
    // inconsistent gather — e.g. duplicate `shard_id` rows shadowing the
    // credited row's index.
    if entry_sum != served.work_micro_by_bond[claimant] {
        return Err(EmissionClaimError::SourceInvalid { epoch });
    }
    Ok(WorkEpochClaim {
        epoch,
        shard_entries,
    })
}

/// **The** builder vin construction site: the assembled claims content
/// inside a vin whose cryptographic legs are zeroed at caller-chosen
/// sizes. The sizing measurement uses the structural maxima
/// ([`MAX_BACKING_PROOF_BYTES`], saturated depth) for a worst-case bound;
/// the KATs' self-check vins use minimal legs (`validate()` pins the real
/// legs to the same canonical key/sig lengths used here, proof excepted,
/// which is `≤` the maximum). One constructor means the measured content,
/// the emitted content, and the KAT-verified content cannot drift.
fn claims_vin(
    holdings: HoldingsDescriptor,
    settlement_epochs: Vec<u64>,
    work_claim: Vec<WorkEpochClaim>,
    reward_amount_plain: Vec<u64>,
    proof_len: usize,
    tree_depth: u8,
) -> ArchivalRewardEmissionVin {
    ArchivalRewardEmissionVin {
        p_pubkey: vec![0; SINGLE_KEY_CANONICAL_LEN],
        holdings,
        settlement_epochs,
        work_claim,
        backing: MembershipOnlyBacking {
            proof: vec![0; proof_len],
            pseudo_out: [0; 32],
            pqc_pk_hash: [0; 32],
            backing_pubkey: vec![0; SINGLE_KEY_CANONICAL_LEN],
            tree_depth,
        },
        reward_amount_plain,
        auth_backing: vec![0; SINGLE_SIG_CANONICAL_LEN],
        auth_claim: vec![0; SINGLE_SIG_CANONICAL_LEN],
    }
}

/// §2 step 7 — the build-time self-check: run the **landed consensus
/// verifier** ([`emission_vin_verify_claims`], never a mirror) over the
/// assembled vin and the same decoded source the assembly consumed
/// (module doc "Step 7"; §7.3 decode-locus pin).
///
/// PR-3's handler calls this on the **completed** vin (real backing and
/// auth legs). The claims verifier reads those fields only through
/// `validate()`'s shape pins — never their content — so this module's
/// KATs drive it with canonical-length dummies (coverage boundary,
/// module doc).
///
/// `vout_reward_sum` is Σ of the tx's reward-vout `amount_plain`s — the
/// caller passes the sum of the vouts it **actually constructed**, so
/// verify's loud inflation compare bites on the real tx rather than on
/// the vin's own amounts echoed back.
///
/// Refuses [`EmissionClaimError::SelfCheckFailed`], cause-blind: the
/// verifier's rejection (and a caller-side pairing bug — a vin epoch or
/// bond record missing from the source, which forecloses even marshaling
/// the verify call) is logged locally only.
pub fn self_check_claims(
    source: &EmissionClaimSource,
    vin: &ArchivalRewardEmissionVin,
    vout_reward_sum: u64,
) -> Result<(), EmissionClaimError> {
    let Some(bond) = source.bond.as_ref() else {
        // An assembled vin implies its own source carried a bond record, so
        // a missing record here is a caller pairing bug (e.g. a refetched
        // source whose record vanished) — refused blind, never panicked.
        error!("step-7 self-check: no bond record in the paired source");
        return Err(EmissionClaimError::SelfCheckFailed);
    };

    // Marshal one frozen snapshot per claimed epoch, in vin order — the
    // same 1:1 alignment the consensus dispatch hands the verifier.
    let mut snaps: Vec<&EpochSnapshot> = Vec::with_capacity(vin.settlement_epochs.len());
    for &epoch in &vin.settlement_epochs {
        match source.epochs.iter().find(|s| s.settlement_epoch == epoch) {
            Some(snap) => snaps.push(snap),
            None => {
                error!(
                    epoch,
                    "step-7 self-check: claimed epoch missing from the decoded source"
                );
                return Err(EmissionClaimError::SelfCheckFailed);
            }
        }
    }
    let bonds_per_snap: Vec<Vec<EpochCloseBond<'_>>> =
        snaps.iter().map(|snap| snap.bonds_view()).collect();
    let epoch_sources: Vec<EmissionEpochSource<'_>> = snaps
        .iter()
        .zip(&bonds_per_snap)
        .map(|(snap, bonds)| snap.source(bonds))
        .collect();

    // The gather tip is the verify-context height (module doc "Step 7":
    // `chain_height.next_height()` is the earliest inclusion height, and
    // the exact operand the daemon derived `current_settled_epoch` from).
    let ctx = EmissionVerifyContext {
        current_block_height: source.chain_height.next_height().to_raw(),
        bond: Some(bond.record()),
        vout_reward_sum,
    };
    match emission_vin_verify_claims(vin, &ctx, &epoch_sources) {
        Ok(_claims_verified) => Ok(()),
        Err(verify_err) => {
            // Log-local, refuse-blind (CB-5): the rejection detail never
            // rides the surfaced error.
            error!(%verify_err, "step-7 self-check: the landed verifier refused the assembled vin");
            Err(EmissionClaimError::SelfCheckFailed)
        }
    }
}

/// Shared emission-source KAT fixtures, built from [`EMISSION_KAT_SHAPE`] —
/// the same shape the consensus verify KATs
/// (`shekyl-archival-retention/tests/emission_verify_kat.rs`) pin, so every
/// differential half (this module's derivation/assembly KATs and the C-4
/// `AssembleEmissionClaim` handler KATs in `stake_engine.rs`) exercises one
/// fixture rather than growing a second source shape that can drift.
#[cfg(test)]
pub(crate) mod test_fixtures;

#[cfg(test)]
mod tests {
    use super::test_fixtures::{
        resigma, snapshot, source_at_count, source_with, zero_share_snapshot, BUDGET, SHARD_A,
        SHARD_B,
    };
    use super::*;
    use crate::engine::emission_source::EpochSnapshot;
    use shekyl_archival_retention::ShardSet;
    use shekyl_types::ChainCount;

    use shekyl_archival_retention::{
        as_of_e_served_work, bond_wire::MAX_HOLDINGS_SHARDS, claimed_epochs_check_and_set,
        credited_work_milli, reward_share_floor, settlement_epoch_at_height, ClaimedEpochsError,
        CreditPair, EpochCloseInputs, EpochCloseShard, EMISSION_KAT_SHAPE, MAX_CLAIM_AGE_W,
        SETTLEMENT_EPOCH_BLOCKS,
    };

    /// The derivation's structural checks in one grid: boundary verdicts
    /// come from the read-only predicates (each skip reason at its exact
    /// boundary), share positivity is the claimability predicate, and the
    /// selected epochs are the survivors in window order.
    ///
    /// Coverage boundary (50-testing.mdc): the share equalities below
    /// bite against **recompute-chain determinism and
    /// builder-consumes-verify-functions** — builder and test call the
    /// same chain, so they do NOT cover that the assembled claim
    /// verifies. That is the step-7 differential's job
    /// ([`self_check_accepts_assembled_and_refuses_every_mutation`]),
    /// which drives the landed verifier over the assembled vin.
    #[test]
    fn boundary_verdicts_and_share_positivity_select_the_batch() {
        // settled = W + 10 puts the expiry floor at 10 (a real bottom
        // boundary, not saturated-to-zero).
        let settled = MAX_CLAIM_AGE_W + 10;
        let floor = settled - MAX_CLAIM_AGE_W;
        let source = source_with(
            settled,
            vec![20],
            vec![
                snapshot(floor - 1),            // expired (one below the floor)
                snapshot(floor),                // claimable (the floor itself)
                snapshot(20),                   // already claimed
                zero_share_snapshot(25, true),  // zero share (gated cause)
                zero_share_snapshot(26, false), // zero share (no-credit cause)
                snapshot(settled - 1),          // claimable (youngest settled)
                snapshot(settled),              // not settled (== settled)
            ],
        );
        let derived = derive_claimable_epochs(&source).expect("two epochs claimable");

        let selected: Vec<u64> = derived
            .claimable
            .iter()
            .map(|c| c.settlement_epoch)
            .collect();
        assert_eq!(selected, vec![floor, settled - 1]);
        assert_eq!(
            derived.skipped,
            vec![
                (floor - 1, EpochSkip::WindowExpired),
                (20, EpochSkip::AlreadyClaimed),
                (25, EpochSkip::ZeroShare),
                (26, EpochSkip::ZeroShare),
                (settled, EpochSkip::NotSettled),
            ],
            "each boundary must map to its read-only-predicate verdict; the \
             two zero causes must be indistinguishable (cause-blind)"
        );

        // Share positivity is the wire-positivity predicate: every
        // selected reward is strictly positive (encodable) and byte-exact
        // against verify's step-4/5 recompute — composed here from the
        // literal chain (`as_of_e_served_work` → `credited_work_milli` →
        // `reward_share_floor`) so the shared evaluation head the
        // derivation consumes is pinned against the chain, not against
        // itself. The carried row is the admitting evaluation's.
        for c in &derived.claimable {
            assert!(c.reward > 0, "claimable ⇒ wire-encodable (> 0)");
            let snap = source
                .epochs
                .iter()
                .find(|s| s.settlement_epoch == c.settlement_epoch)
                .unwrap();
            let bonds = snap.bonds_view();
            let view = snap.source(&bonds);
            let served = as_of_e_served_work(&view.inputs).unwrap();
            let idx = view.claimant_bond_idx.unwrap();
            let credited = credited_work_milli(served.work_by_bond[idx], served.member[idx]);
            assert_eq!(
                c.reward,
                reward_share_floor(view.budget, credited, view.persisted_sigma_work_milli),
                "derivation reward must equal verify's recompute"
            );
            let entry_sum: u64 = c
                .claim
                .shard_entries
                .iter()
                .map(|e| u64::from(e.scarcity_micro))
                .sum();
            assert_eq!(
                entry_sum, served.work_micro_by_bond[idx],
                "the carried row must be the admitting evaluation's (micro-space)"
            );
        }
    }

    /// Drift tripwire for the read-only boundary predicates: the connect
    /// mutator's classification must agree with the predicates the
    /// derivation consumes ([`epoch_is_not_settled`] /
    /// [`epoch_is_claim_expired`] / [`claimed_epochs_contains`]) at every
    /// epoch across the window. If the connect predicate's boundaries
    /// ever move, this differential fails before any consensus KAT does.
    #[test]
    fn read_only_predicates_agree_with_connect_mutator() {
        let settled = MAX_CLAIM_AGE_W + 10;
        let claimed = vec![15, 20, 30];
        for epoch in 0..=settled + 2 {
            let mut scratch = claimed.clone();
            let verdict = claimed_epochs_check_and_set(&mut scratch, epoch, settled);
            let expected = if epoch_is_not_settled(epoch, settled) {
                Err(ClaimedEpochsError::NotSettled)
            } else if epoch_is_claim_expired(epoch, settled) {
                Err(ClaimedEpochsError::Expired)
            } else if claimed_epochs_contains(&claimed, epoch) {
                Ok(false)
            } else {
                Ok(true)
            };
            assert_eq!(verdict, expected, "predicates diverged at epoch {epoch}");
        }
    }

    /// Verify step 2's join bound, applied at derivation: a record whose
    /// join epoch is newer than the frozen rows' (retire-then-rejoin)
    /// defers pre-join epochs ([`EpochSkip::BeforeJoin`]) instead of
    /// assembling a batch the self-check — and the chain — would refuse
    /// whole (`EpochBeforeJoin` ⇒ cause-blind `SelfCheckFailed`), blocking
    /// the valid epochs behind it until the offender aged out.
    #[test]
    fn join_bound_defers_pre_join_epochs() {
        let epochs = || vec![snapshot(4), snapshot(5), snapshot(6)];

        // Rejoined at epoch 5: E ∈ {4, 5} predate/equal the record's join
        // (the frozen rows still carry the shape's original join).
        let mut rejoined = source_with(10, vec![], epochs());
        rejoined.bond.as_mut().unwrap().join_settlement_epoch = 5;
        let derived = derive_claimable_epochs(&rejoined).expect("epoch 6 claimable");
        let selected: Vec<u64> = derived
            .claimable
            .iter()
            .map(|c| c.settlement_epoch)
            .collect();
        assert_eq!(selected, vec![6]);
        assert_eq!(
            derived.skipped,
            vec![(4, EpochSkip::BeforeJoin), (5, EpochSkip::BeforeJoin)]
        );

        // Premise arm (the skip is load-bearing): the vin the builder
        // would have assembled without the join bound — built against the
        // pre-rejoin record, where all three epochs clear it — drives the
        // landed verifier to `EpochBeforeJoin` when self-checked against
        // the rejoined record, surfaced as the blind `SelfCheckFailed`.
        let pre_rejoin = source_with(10, vec![], epochs());
        let derived_pre = derive_claimable_epochs(&pre_rejoin).expect("all claimable");
        let assembled = assemble_claims(&derived_pre, EMISSION_CLAIMS_SIZE_BUDGET).expect("fits");
        let vin = dummy_leg_vin(&assembled);
        self_check_claims(&pre_rejoin, &vin, assembled.total_reward)
            .expect("sanity: verifies against the pre-rejoin record");
        assert!(matches!(
            self_check_claims(&rejoined, &vin, assembled.total_reward),
            Err(EmissionClaimError::SelfCheckFailed)
        ));
    }

    /// Oldest-first 15-cap: with more claimable epochs than the batch
    /// bound, exactly the oldest 15 are selected (nearest expiry — the
    /// order that never strands a savable epoch) and the rest defer.
    /// Epochs start at the shape's first post-join epoch (`E_join + 1`,
    /// verify step 2's bound — the dedicated join KAT covers the skip).
    #[test]
    fn batch_caps_at_fifteen_oldest_first() {
        let settled = 20;
        let first = EMISSION_KAT_SHAPE.join_settlement_epoch + 1;
        let epochs: Vec<EpochSnapshot> = (first..=18).map(snapshot).collect();
        let source = source_with(settled, vec![], epochs);
        let derived = derive_claimable_epochs(&source).expect("claimable");

        let selected: Vec<u64> = derived
            .claimable
            .iter()
            .map(|c| c.settlement_epoch)
            .collect();
        let expected: Vec<u64> =
            (first..first + MAX_SETTLEMENT_EPOCHS_PER_EMISSION as u64).collect();
        assert_eq!(selected, expected, "oldest 15, window order");
        assert!(
            selected.windows(2).all(|w| w[0] < w[1]),
            "wire invariant: strictly increasing"
        );
        assert_eq!(
            derived.skipped,
            vec![
                (17, EpochSkip::BatchDeferred),
                (18, EpochSkip::BatchDeferred),
            ]
        );
    }

    /// Idle refusals: no bond record, an empty window, and an
    /// all-skipped window each refuse `NoClaimableEpochs` — an idle
    /// state, not an error, and cause-blind (no per-epoch payload).
    #[test]
    fn refuses_idle_when_nothing_claimable() {
        // No bond record.
        let mut source = source_with(10, vec![], vec![snapshot(5)]);
        source.bond = None;
        assert!(matches!(
            derive_claimable_epochs(&source),
            Err(EmissionClaimError::NoClaimableEpochs)
        ));

        // Empty window.
        let source = source_with(10, vec![], vec![]);
        assert!(matches!(
            derive_claimable_epochs(&source),
            Err(EmissionClaimError::NoClaimableEpochs)
        ));

        // Every epoch skipped (zero share both causes + already claimed).
        let source = source_with(
            10,
            vec![5],
            vec![
                zero_share_snapshot(4, true),
                snapshot(5),
                zero_share_snapshot(6, false),
            ],
        );
        assert!(matches!(
            derive_claimable_epochs(&source),
            Err(EmissionClaimError::NoClaimableEpochs)
        ));
    }

    /// The close-boundary count (module doc "Step 7"): at the one count
    /// `chain_height == h_close(E)` the connect window admits `E` and
    /// the budget row exists (the close ran while connecting `E`'s last
    /// block — `blockchain_db.cpp` `add_block`), but verify's strict
    /// step-1 predicate rejects a claim of `E` in the very next block.
    /// The derivation defers `E` ([`EpochSkip::NotFinalized`]) so the
    /// assembled batch verifies at the gather tip; one count later `E`
    /// is claimable.
    #[test]
    fn close_boundary_count_defers_the_youngest_epoch_one_block() {
        let epoch = 5;
        let h_close = epoch_close_height(epoch).expect("fixture epoch closes");
        // Fixture-coherence premise: at the boundary count the connect
        // window already admits the epoch — the deferral below is doing
        // real work, not restating the top boundary's `NotSettled`.
        assert_eq!(settlement_epoch_at_height(h_close), epoch + 1);

        // At the boundary count: epoch 4 selected, epoch 5 defers.
        let at_boundary = source_at_count(h_close, vec![], vec![snapshot(4), snapshot(5)]);
        let derived = derive_claimable_epochs(&at_boundary).expect("epoch 4 claimable");
        let selected: Vec<u64> = derived
            .claimable
            .iter()
            .map(|c| c.settlement_epoch)
            .collect();
        assert_eq!(selected, vec![4]);
        assert_eq!(derived.skipped, vec![(5, EpochSkip::NotFinalized)]);

        // The deferred batch passes the self-check at the boundary count.
        let assembled = assemble_claims(&derived, EMISSION_CLAIMS_SIZE_BUDGET).expect("fits");
        self_check_claims(
            &at_boundary,
            &dummy_leg_vin(&assembled),
            assembled.total_reward,
        )
        .expect("the deferred batch must verify at the gather tip");

        // Premise arm (the deferral is load-bearing): an `E`-bearing vin
        // — assembled one count past the boundary, where `E` is
        // claimable — is exactly the vin the builder would have built at
        // the boundary count without the strict-finalization skip. The
        // real verifier refuses it there (`EpochNotFinalized`, surfaced
        // blind), so the skip is what stands between the builder and a
        // spurious whole-batch `SelfCheckFailed`.
        let past_boundary = source_at_count(h_close + 1, vec![], vec![snapshot(4), snapshot(5)]);
        let derived_past = derive_claimable_epochs(&past_boundary).expect("both claimable");
        let selected_past: Vec<u64> = derived_past
            .claimable
            .iter()
            .map(|c| c.settlement_epoch)
            .collect();
        assert_eq!(
            selected_past,
            vec![4, 5],
            "one count past the boundary the epoch is claimable"
        );
        let assembled_past =
            assemble_claims(&derived_past, EMISSION_CLAIMS_SIZE_BUDGET).expect("fits");
        let e_bearing = dummy_leg_vin(&assembled_past);
        self_check_claims(&past_boundary, &e_bearing, assembled_past.total_reward)
            .expect("sanity: the E-bearing vin verifies one count past the boundary");
        assert!(
            matches!(
                self_check_claims(&at_boundary, &e_bearing, assembled_past.total_reward),
                Err(EmissionClaimError::SelfCheckFailed)
            ),
            "at the boundary count the same vin must refuse (verify: EpochNotFinalized)"
        );
    }

    /// A window epoch without a frozen close row skips (`NoCloseRow`,
    /// mirroring the verify shim's reject) without poisoning the batch.
    #[test]
    fn missing_close_row_skips_the_epoch_only() {
        let mut no_row = snapshot(5);
        no_row.has_budget_row = false;
        let source = source_with(10, vec![], vec![no_row, snapshot(6)]);
        let derived = derive_claimable_epochs(&source).expect("epoch 6 claimable");
        assert_eq!(derived.claimable.len(), 1);
        assert_eq!(derived.claimable[0].settlement_epoch, 6);
        assert_eq!(derived.skipped, vec![(5, EpochSkip::NoCloseRow)]);
    }

    /// A window epoch with no close height at all (`(E+1)·SEB` overflows
    /// u64) cannot come from an honest daemon — PR 1's decode invariant
    /// pins `E < settlement_epoch_at_height(chain_height)` — so the
    /// derivation refuses it loudly (`SourceInvalid`) instead of deferring
    /// it as transiently `NotFinalized` (it can never finalize). Built
    /// directly: a hostile source, unreachable through the decode path
    /// (the module-doc conversion-guard idiom).
    #[test]
    fn overflowing_close_height_is_source_invalid() {
        let epoch = u64::MAX - 1;
        assert!(
            epoch_close_height(epoch).is_none(),
            "premise: the close height must not exist"
        );
        let snap = EpochSnapshot {
            settlement_epoch: epoch,
            close_block_height: 0,
            sigma_work_milli: 0,
            budget_atomic: BUDGET,
            has_budget_row: true,
            bonds: vec![],
            shards: vec![],
            credit_pairs: vec![],
            claimant_bond_idx: None,
        };
        let mut source = source_with(10, vec![], vec![snap]);
        // Hostile boundary operands that admit the epoch through the
        // window predicates (decode refuses this pair; the derivation
        // must still fail closed on it).
        source.current_settled_epoch = u64::MAX;
        source.chain_height = ChainCount::from_raw(u64::MAX);
        assert!(matches!(
            derive_claimable_epochs(&source),
            Err(EmissionClaimError::SourceInvalid { epoch: e }) if e == epoch
        ));
    }

    /// Internally inconsistent gather rows refuse loudly (untrusted
    /// daemon), never skip-and-continue: a credit pair indexing outside
    /// the arrays, and a claimant index outside the bond rows.
    #[test]
    fn malformed_gather_is_loud() {
        let mut bad_pair = snapshot(5);
        bad_pair.credit_pairs.push(CreditPair {
            bond_idx: 9,
            shard_idx: 0,
        });
        let source = source_with(10, vec![], vec![bad_pair]);
        assert!(matches!(
            derive_claimable_epochs(&source),
            Err(EmissionClaimError::SourceInvalid { epoch: 5 })
        ));

        let mut bad_claimant = snapshot(5);
        bad_claimant.claimant_bond_idx = Some(9);
        let source = source_with(10, vec![], vec![bad_claimant]);
        assert!(matches!(
            derive_claimable_epochs(&source),
            Err(EmissionClaimError::SourceInvalid { epoch: 5 })
        ));
    }

    // ── Steps 2 + 5: assembly ───────────────────────────────────────────

    /// Canonical row form, integer-exact against verify's compares:
    /// credited shards only (ascending `shard_id`, bit set), per-entry
    /// scarcity equal to verify's `ScarcityMismatch` recompute (first-
    /// position id resolution), entry sum equal to verify's
    /// `WorkTotalMismatch` operand, rewards verbatim from the derivation,
    /// and the holdings copied by value from the record.
    #[test]
    fn assembles_canonical_rows_rewards_and_holdings() {
        let mut snap = snapshot(5);
        let close = epoch_close_height(5).expect("fixture epoch closes");
        // Shard rows deliberately in descending id order (canonicality is
        // the builder's, not the daemon's); the claimant is credited on A
        // and B, the other bond alone on shard 11 (must not appear).
        snap.shards = vec![
            EpochCloseShard {
                shard_id: SHARD_B,
                has_segment: true,
                freeze_height: close - 8_000,
            },
            EpochCloseShard {
                shard_id: SHARD_A,
                has_segment: true,
                freeze_height: close - 5_000,
            },
            EpochCloseShard {
                shard_id: 11,
                has_segment: true,
                freeze_height: close - 2_000,
            },
        ];
        snap.credit_pairs = vec![
            CreditPair {
                bond_idx: 0,
                shard_idx: 1,
            },
            CreditPair {
                bond_idx: 0,
                shard_idx: 0,
            },
            CreditPair {
                bond_idx: 1,
                shard_idx: 2,
            },
        ];
        resigma(&mut snap);
        let source = source_with(10, vec![], vec![snap]);
        let derived = derive_claimable_epochs(&source).expect("claimable");
        let assembled = assemble_claims(&derived, EMISSION_CLAIMS_SIZE_BUDGET).expect("fits");

        assert_eq!(assembled.settlement_epochs, vec![5]);
        assert_eq!(
            assembled.reward_amount_plain,
            vec![derived.claimable[0].reward],
            "the builder never invents an amount — verbatim the derivation share"
        );
        assert_eq!(assembled.total_reward, derived.claimable[0].reward);
        assert!(assembled.size_deferred.is_empty());
        assert_eq!(
            assembled.holdings,
            source.bond.as_ref().unwrap().holdings,
            "by-value record copy (§5.3/§6.4.1), never recomputed"
        );

        let claim = &assembled.work_claim[0];
        assert_eq!(claim.epoch, 5);
        let ids: Vec<u64> = claim.shard_entries.iter().map(|e| e.shard_id).collect();
        assert_eq!(
            ids,
            vec![SHARD_A, SHARD_B],
            "credited shards only, ascending shard_id"
        );
        assert!(claim.shard_entries.iter().all(|e| e.serve_credit_bit));

        // Verify's step-4 compares, run over the same view.
        let snap = &source.epochs[0];
        let bonds = snap.bonds_view();
        let view = snap.source(&bonds);
        let served = as_of_e_served_work(&view.inputs).unwrap();
        let mut entry_sum = 0u64;
        for entry in &claim.shard_entries {
            let idx = view
                .inputs
                .shards
                .iter()
                .position(|s| s.shard_id == entry.shard_id)
                .unwrap();
            let expected = shard_contribution_micro(&view.inputs, &served.r_market_by_shard, idx);
            assert_eq!(
                u64::from(entry.scarcity_micro),
                expected,
                "verify's ScarcityMismatch compare (tolerance zero, micro)"
            );
            entry_sum += expected;
        }
        assert_eq!(
            entry_sum, served.work_micro_by_bond[0],
            "verify's WorkTotalMismatch compare (tolerance zero, micro-space)"
        );
    }

    /// The u64→u32 conversion guard bites **at the builder's conversion
    /// site**, not the encoder's `ScarcityOverflow`. The production
    /// decode path cannot reach it — `verify_view` pins
    /// `age_weight_milli` to the compiled constant, bounding an honest
    /// recompute to `WORK_MICRO_PER_MILLI · (WORK_MILLI_SCALE + weight)`
    /// (const-asserted at module scope) — so the KAT builds the hostile view
    /// directly and drives the same per-epoch row builder the derivation runs.
    #[test]
    fn scarcity_conversion_refuses_at_the_builder() {
        let bonds = [EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &[],
        }];
        let shards = [EpochCloseShard {
            shard_id: SHARD_A,
            has_segment: true,
            freeze_height: 0,
        }];
        let pairs = [CreditPair {
            bond_idx: 0,
            shard_idx: 0,
        }];
        let view = EmissionEpochSource {
            inputs: EpochCloseInputs {
                settlement_epoch: 4,
                close_block_height: epoch_close_height(4).unwrap(),
                settlement_epoch_blocks: SETTLEMENT_EPOCH_BLOCKS,
                // Hostile: unreachable through `verify_view` (which pins the
                // weight to the compiled ~2000). Drives the micro recompute over
                // u32::MAX without overflowing the u128 quotient into
                // `mul_div_floor`'s 0-fallback: `g = 1000 + weight`, `r = 1`, so
                // `scarcity_micro = 1000·g ≈ 1.0×10¹⁰ ∈ (u32::MAX, u64::MAX]`.
                // (`u64::MAX` would overflow to 0 — no longer a hostile value.)
                age_weight_milli: 10_000_000,
                bonds: &bonds,
                shards: &shards,
                credit_pairs: &pairs,
            },
            persisted_sigma_work_milli: 1,
            claimant_bond_idx: Some(0),
            budget: BUDGET,
        };
        let served = as_of_e_served_work(&view.inputs).unwrap();
        // Premise armed: the recompute really exceeds the wire field.
        assert!(
            shard_contribution_micro(&view.inputs, &served.r_market_by_shard, 0)
                > u64::from(u32::MAX),
            "fixture must drive the recompute over u32::MAX"
        );
        assert!(matches!(
            work_epoch_claim(&view, &served, 0),
            Err(EmissionClaimError::ScarcityConversion {
                epoch: 4,
                shard_id: SHARD_A
            })
        ));
    }

    /// Bound-or-split at exact byte boundaries: at the projection the
    /// batch fits; one byte under, the youngest epoch defers
    /// (`size_deferred`) and the older two keep their claim; one byte
    /// under a single epoch's floor, the terminal refusal fires with the
    /// measured projection. The boundary lengths are measured through the
    /// same construction site the assembly uses ([`claims_vin`] at the
    /// structural maxima).
    #[test]
    fn size_bound_defers_youngest_then_refuses() {
        let source = source_with(10, vec![], vec![snapshot(3), snapshot(4), snapshot(5)]);
        let derived = derive_claimable_epochs(&source).expect("three claimable");

        let full = assemble_claims(&derived, EMISSION_CLAIMS_SIZE_BUDGET).expect("fits default");
        assert_eq!(full.settlement_epochs, vec![3, 4, 5]);
        let max_len = |n: usize| {
            claims_vin(
                full.holdings.clone(),
                full.settlement_epochs[..n].to_vec(),
                full.work_claim[..n].to_vec(),
                full.reward_amount_plain[..n].to_vec(),
                MAX_BACKING_PROOF_BYTES,
                u8::MAX,
            )
            .serialize()
            .unwrap()
            .len()
        };
        let len3 = max_len(3);
        let len1 = max_len(1);

        let at = assemble_claims(&derived, len3).expect("exactly at the bound");
        assert_eq!(at.settlement_epochs, vec![3, 4, 5]);
        assert!(at.size_deferred.is_empty());

        let under = assemble_claims(&derived, len3 - 1).expect("splits");
        assert_eq!(under.settlement_epochs, vec![3, 4], "oldest retained");
        assert_eq!(under.size_deferred, vec![5]);
        assert_eq!(
            under.total_reward,
            under.reward_amount_plain.iter().sum::<u64>()
        );

        assert!(matches!(
            assemble_claims(&derived, len1 - 1),
            Err(EmissionClaimError::SizeBoundExceeded {
                epoch: 3,
                projected,
                budget,
            }) if projected == len1 && budget == len1 - 1
        ));
    }

    /// A gather carrying two credits for one (claimant, shard) is
    /// malformed (the ledger key `P‖shard‖E` is unique) — refused at
    /// derivation (where the row is now built), before the double-counted
    /// claim can enter a batch.
    #[test]
    fn duplicate_credited_shard_is_source_invalid() {
        let mut snap = snapshot(5);
        snap.credit_pairs.push(CreditPair {
            bond_idx: 0,
            shard_idx: 0,
        });
        resigma(&mut snap);
        let source = source_with(10, vec![], vec![snap]);
        assert!(matches!(
            derive_claimable_epochs(&source),
            Err(EmissionClaimError::SourceInvalid { epoch: 5 })
        ));
    }

    /// Duplicate `shard_id` rows where the credited row is shadowed by an
    /// earlier one: the id-resolved recompute (verify's lookup) diverges
    /// from the pair-indexed accumulation, so the entry-sum compare
    /// refuses at derivation — the vin would be doomed to
    /// `WorkTotalMismatch` on-chain.
    #[test]
    fn shadowed_shard_row_is_source_invalid() {
        let mut snap = snapshot(5);
        let close = epoch_close_height(5).expect("fixture epoch closes");
        snap.shards = vec![
            EpochCloseShard {
                shard_id: SHARD_A,
                has_segment: true,
                freeze_height: close - 1_000,
            },
            EpochCloseShard {
                shard_id: SHARD_A,
                has_segment: true,
                freeze_height: close - 9_000,
            },
        ];
        snap.credit_pairs = vec![CreditPair {
            bond_idx: 0,
            shard_idx: 1,
        }];
        resigma(&mut snap);
        let source = source_with(10, vec![], vec![snap]);
        assert!(matches!(
            derive_claimable_epochs(&source),
            Err(EmissionClaimError::SourceInvalid { epoch: 5 })
        ));
    }

    // ── Step 7: the build-time self-check ───────────────────────────────

    /// The assembled claims inside a vin whose cryptographic legs are
    /// canonical-length dummies — sufficient for the claims leg, whose
    /// verifier never reads their content (module doc coverage boundary;
    /// the backing/auth legs' self-check composition is PR 3's, with real
    /// legs). Built through the production construction site
    /// ([`claims_vin`]) with minimal proof/depth.
    fn dummy_leg_vin(assembled: &AssembledClaims) -> ArchivalRewardEmissionVin {
        claims_vin(
            assembled.holdings.clone(),
            assembled.settlement_epochs.clone(),
            assembled.work_claim.clone(),
            assembled.reward_amount_plain.clone(),
            1,
            0,
        )
    }

    /// The step-7 differential: the assembled vin passes the **landed**
    /// `emission_vin_verify_claims` (the premise — assembly is
    /// verifier-accepted, which is what makes the derivation and assembly
    /// KATs' determinism halves sufficient in aggregate), and every
    /// mutation flips accept → refuse through the same verifier. Each arm
    /// names the verify compare it arms; a mutation that did not move the
    /// verdict would fail its assert (no dead differential arms).
    ///
    /// The surfaced refusal is `SelfCheckFailed` in every arm — a unit
    /// variant, so cause-blindness is structural (CB-5: the operand the
    /// verifier rejected on is unrepresentable in the surfaced error).
    #[test]
    fn self_check_accepts_assembled_and_refuses_every_mutation() {
        // Epoch 6 is present in the source but gated (persisted Σwork = 0)
        // — skipped by the derivation, available to the swap arm below.
        let source = source_with(
            10,
            vec![],
            vec![snapshot(4), snapshot(5), zero_share_snapshot(6, true)],
        );
        let derived = derive_claimable_epochs(&source).expect("epochs 4, 5 claimable");
        let assembled = assemble_claims(&derived, EMISSION_CLAIMS_SIZE_BUDGET).expect("fits");
        let base = dummy_leg_vin(&assembled);

        // Premise: the unmutated assembly is verifier-accepted.
        self_check_claims(&source, &base, assembled.total_reward)
            .expect("assembled vin must pass the landed verifier");

        type Mutation = fn(&mut ArchivalRewardEmissionVin);
        let mutations: [(&str, Mutation); 6] = [
            ("scarcity +1 (verify: ScarcityMismatch)", |vin| {
                vin.work_claim[0].shard_entries[0].scarcity_micro += 1;
            }),
            (
                "credit bit cleared (verify: ServeCreditBitMismatch)",
                |vin| {
                    vin.work_claim[0].shard_entries[0].serve_credit_bit = false;
                },
            ),
            ("reward +1 (verify: RewardMismatch)", |vin| {
                vin.reward_amount_plain[0] += 1;
            }),
            (
                "credited entries dropped (verify: WorkTotalMismatch)",
                |vin| {
                    vin.work_claim[0].shard_entries.clear();
                },
            ),
            (
                "epoch swapped to the gated epoch (verify: RewardMismatch \
                 — its recomputed share is zero)",
                |vin| {
                    vin.settlement_epochs[1] = 6;
                    vin.work_claim[1].epoch = 6;
                },
            ),
            ("holdings swapped (verify: HoldingsMismatch)", |vin| {
                vin.holdings.shard_ids = ShardSet::new(vec![SHARD_B]).unwrap();
            }),
        ];
        for (name, mutate) in mutations {
            let mut vin = base.clone();
            mutate(&mut vin);
            assert!(
                matches!(
                    self_check_claims(&source, &vin, assembled.total_reward),
                    Err(EmissionClaimError::SelfCheckFailed)
                ),
                "mutation must flip accept → refuse: {name}"
            );
        }

        // Context arms: the vout sum the caller constructed (verify:
        // VoutSumMismatch — the loud inflation check bites on the real
        // vouts, not the vin's own amounts echoed back) …
        assert!(matches!(
            self_check_claims(&source, &base, assembled.total_reward + 1),
            Err(EmissionClaimError::SelfCheckFailed)
        ));
        // … and the bond record's claimed set (verify: EpochAlreadyClaimed
        // — proves the `record()` marshaling reaches the dedup compare).
        let claimed_source = source_with(
            10,
            vec![4],
            vec![snapshot(4), snapshot(5), zero_share_snapshot(6, true)],
        );
        assert!(matches!(
            self_check_claims(&claimed_source, &base, assembled.total_reward),
            Err(EmissionClaimError::SelfCheckFailed)
        ));

        // A claimed epoch missing from the source forecloses marshaling
        // the verify call at all — same blind refusal, logged locally.
        let mut vin = base.clone();
        vin.settlement_epochs[1] = 99;
        vin.work_claim[1].epoch = 99;
        assert!(matches!(
            self_check_claims(&source, &vin, assembled.total_reward),
            Err(EmissionClaimError::SelfCheckFailed)
        ));

        // A source whose bond record vanished (a caller pairing bug — the
        // refetch path) is the same blind refusal, never a panic.
        let mut bondless = source_with(
            10,
            vec![],
            vec![snapshot(4), snapshot(5), zero_share_snapshot(6, true)],
        );
        bondless.bond = None;
        assert!(matches!(
            self_check_claims(&bondless, &base, assembled.total_reward),
            Err(EmissionClaimError::SelfCheckFailed)
        ));
    }

    /// More credited shards than the wire admits: the production encoder
    /// refuses during the sizing measurement (`ShardEntriesExceeded` →
    /// `RowsUnencodable`) — the structural bound is armed, not assumed
    /// from the daemon's cardinality.
    #[test]
    fn oversized_shard_entries_refuse_rows_unencodable() {
        let mut snap = snapshot(5);
        snap.shards = (0..=MAX_HOLDINGS_SHARDS as u64)
            .map(|shard_id| EpochCloseShard {
                shard_id,
                has_segment: false,
                freeze_height: 0,
            })
            .collect();
        snap.credit_pairs = (0..=MAX_HOLDINGS_SHARDS)
            .map(|shard_idx| CreditPair {
                bond_idx: 0,
                shard_idx,
            })
            .collect();
        resigma(&mut snap);
        let source = source_with(10, vec![], vec![snap]);
        let derived = derive_claimable_epochs(&source).expect("admitted");
        assert!(matches!(
            assemble_claims(&derived, EMISSION_CLAIMS_SIZE_BUDGET),
            Err(EmissionClaimError::RowsUnencodable(
                EmissionWireError::ShardEntriesExceeded { got }
            )) if got == MAX_HOLDINGS_SHARDS + 1
        ));
    }
}
