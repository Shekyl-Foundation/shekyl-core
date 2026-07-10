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
//! **the same positive-share recompute the verifier runs** — never from
//! `K_COVER` (this module contains no `K_COVER` read; the gate's outcome
//! reaches the wallet only through the persisted `Σwork(E)` denominator,
//! same as verify) and never from row-absence proxies. Claimable ⇔ the
//! recomputed share is strictly positive, which is exactly the §2.3 wire
//! positivity predicate (`reward_amount_plain[i] > 0` — a zero row is
//! unencodable, so the builder omits the epoch rather than encode it).
//!
//! ## The scratch-oracle purity pin (boundary verdicts)
//!
//! All three boundary verdicts — **top** (`E ≥ settled` ⇒ `NotSettled`),
//! **bottom** (`E < floor` ⇒ `Expired`), **dedup** (`Ok(false)` ⇒ already
//! claimed) — come from [`claimed_epochs_check_and_set`] run on a
//! **scratch clone** of the bond record's claimed set: the literal
//! function the connect path runs, used as a read-only classifier. This
//! satisfies §2 step 1's single-source intent for the top boundary —
//! `E < settled` lives only inside that function (expiry and dedup have
//! read-only siblings, `epoch_is_claim_expired` / `claimed_epochs_contains`;
//! the top boundary does not), and an inline `E < settled` guard here
//! would be a second copy that silently diverges the moment the connect
//! path's check changes.
//!
//! **Purity pin:** the scratch-oracle pattern is sound only while
//! `claimed_epochs_check_and_set` is pure w.r.t. all state but the passed
//! set — verified at `claimed_epochs.rs:118-146` on 2026-07-09 (reads
//! `epoch` / `current_settled_epoch` by value and one const; mutates only
//! the passed `Vec`; no log, metric, global, or I/O; the `debug_assert!`
//! is a release no-op touching nothing external). A future side-effect
//! addition to that function **reopens this disposition** — the scratch
//! clone isolates the set, not the side effect, and the builder fires the
//! oracle once per window epoch (≤ `MAX_CLAIM_AGE_W + 1` calls per
//! derivation). The read-only sibling extraction
//! (`epoch_is_not_settled`) that would retire the oracle entirely is
//! filed in `docs/FOLLOWUPS.md` (V3.1, trigger-gated).
//!
//! ## Cause-blindness (CB-5)
//!
//! A zero-share epoch is skipped as [`EpochSkip::ZeroShare`] — one
//! verdict for every zero cause (pre-`K_COVER`-gated epoch, no serve
//! credit, floored-to-zero share). The distinction is not merely withheld;
//! it is **not derivable here**: `K_COVER` is compared at exactly one
//! site (`epoch_close_compute`), the claim path never consults it, so the
//! wallet cannot tell the causes apart and neither can an observer of the
//! refusal. Do not add a branch that could.
//!
//! ## Steps 2 + 5 — work-claim rows, rewards, sizing
//!
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
//!   wire's `scarcity_milli` is `u32`. The builder refuses at its own
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
//!   is measured with the **production encoder** on a vin whose
//!   cryptographic legs are at their structural maxima (canonical-length
//!   pubkeys/sigs, [`MAX_BACKING_PROOF_BYTES`] proof) — a worst-case
//!   upper bound on the real vin's bytes, from the same write path, so no
//!   shadow size model can drift. Over budget ⇒ drop the youngest epoch
//!   ([`EpochSkip::SizeDeferred`]; oldest-first retention mirrors the
//!   batch cap's never-strand-a-savable-epoch order) and re-measure; a
//!   single epoch alone over budget refuses
//!   [`EmissionClaimError::SizeBoundExceeded`]. The budget is a
//!   parameter; [`EMISSION_CLAIMS_SIZE_BUDGET`] is the documented default.

// PR-2 lands the assembly core ahead of its consumer: PR-3's `StakeEngine`
// claim handler is the call site. This allow is deleted by PR-3
// (`EMISSION_CLAIM_BUILDER.md` §8) — staging, not tolerated dead code per
// `15-deletion-and-debt.mdc` (the emission_source PR-1 allow this PR deletes
// followed the same protocol).
#![allow(dead_code)]

use shekyl_archival_retention::{
    as_of_e_served_work, capped_work_milli, claimed_epochs_check_and_set, reward_share_floor,
    shard_contribution_milli, ArchivalRewardEmissionVin, ClaimedEpochsError, EmissionEpochSource,
    EmissionWireError, HoldingsDescriptor, MembershipOnlyBacking, ServedWork, ShardWorkEntry,
    WorkEpochClaim, ARCHIVAL_REWARD_AGE_WEIGHT_MILLI, MAX_BACKING_PROOF_BYTES,
    MAX_SETTLEMENT_EPOCHS_PER_EMISSION, WORK_MILLI_SCALE,
};
use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};
use shekyl_wire::transaction::MAX_TX_SIZE;

use super::emission_source::EmissionClaimSource;

// The compiled-constants bound behind the conversion guard's structural-
// unreachability claim (module doc): an honest recompute through
// `verify_view` satisfies `scarcity ≤ WORK_MILLI_SCALE + weight` (age is
// depth-fraction-bounded to `WORK_MILLI_SCALE`, `r_market ≥ 1` for a
// nonzero term). A weight bump that could cross the wire field's width
// must fail this build, not silently arm the runtime refusal.
const _: () = assert!(
    WORK_MILLI_SCALE + ARCHIVAL_REWARD_AGE_WEIGHT_MILLI <= u32::MAX as u64,
    "compiled constants must keep scarcity_milli within the u32 wire field"
);

/// Bytes of the [`MAX_TX_SIZE`] envelope reserved for everything outside
/// the emission vin: tx prefix/extra, the reward + change vouts (≤ 16
/// commits, low single-digit kB), and — the dominant term — the fee-side
/// FCMP++ spend legs, each the same order as the 64 KiB
/// [`MAX_BACKING_PROOF_BYTES`] membership bound. 128 KiB reserves
/// headroom for the expected one-to-two fee inputs (rule 75: rationale +
/// bounds). *Reversion (rule 21):* PR-3's tx assembly owns fee-input
/// selection and replaces this static reserve with its measured fee-side
/// envelope; reopen sooner if a claim tx needs more than two fee inputs.
pub const EMISSION_NON_CLAIMS_RESERVE_BYTES: usize = 131_072;

/// Default claims-leg size budget for [`assemble_claims`]:
/// [`MAX_TX_SIZE`] minus [`EMISSION_NON_CLAIMS_RESERVE_BYTES`].
pub const EMISSION_CLAIMS_SIZE_BUDGET: usize = MAX_TX_SIZE - EMISSION_NON_CLAIMS_RESERVE_BYTES;

/// Builder refusals (CB-5 taxonomy, the arms this module constructs).
///
/// Staged completeness (§8 / rule 15 — no dead variants): `SelfCheckFailed`
/// lands with its constructor site (the §2 step-7 self-check, this PR's
/// next commit); `InsufficientBacking` lands with `BackingSet` selection
/// (PR 3).
#[derive(Debug, thiserror::Error)]
pub enum EmissionClaimError {
    /// Nothing claimable — an **idle state, not an error** (rule 82 /
    /// CB-5): every window epoch was skipped (zero share, expired,
    /// already claimed, not settled, no close row) or the daemon has no
    /// bond record for `P`. Cause-blind by construction: the refusal
    /// carries no per-epoch reasons (the [`EpochSkip`] diagnostics ride
    /// the `Ok` path only, and `ZeroShare` is itself one verdict for all
    /// zero causes).
    #[error("no claimable epochs")]
    NoClaimableEpochs,
    /// The daemon's gather rows are internally inconsistent (a credit
    /// pair or the claimant index references outside the bond/shard
    /// arrays; duplicate credited shards; an id-resolved recompute that
    /// disagrees with the pair-indexed accumulation; a reward sum
    /// overflowing `u64`) — malformed input from an untrusted daemon,
    /// refused loudly (`20-rust-vs-cpp-policy.mdc` §3), never
    /// skipped-and-continued: a daemon that mis-serializes one epoch
    /// cannot be trusted for the window.
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
}

/// Why a window epoch was not selected — **local diagnostics**, never a
/// transport operand or an observable refusal payload (CB-5: the claim
/// query is cause-blind; nothing derived from these verdicts may shape
/// daemon-visible behavior).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochSkip {
    /// `E ≥ current_settled_epoch` (the connect predicate's `NotSettled`).
    NotSettled,
    /// `E` fell below the claim window floor (the connect predicate's
    /// `Expired`).
    WindowExpired,
    /// `E` is already in the bond record's claimed set (the connect
    /// predicate's dedup verdict).
    AlreadyClaimed,
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
    /// Claimable and within the batch cap, but the claims-leg size
    /// projection exceeded the budget with this epoch included —
    /// deferred to the next claim tx (§2 step 5 bound-or-split;
    /// youngest-first deferral mirrors the batch cap's
    /// never-strand-a-savable-epoch order).
    SizeDeferred,
}

/// One claimable epoch: the boundary verdicts passed and the recomputed
/// share is strictly positive.
///
/// Carries the recompute's outputs so the work-claim assembly consumes
/// **the same evaluation** the derivation selected on (single-evaluator
/// discipline — assembly must not re-run the recompute and risk pairing
/// rows with a different evaluation than the one that admitted the epoch).
#[derive(Debug, Clone)]
pub struct ClaimableEpoch {
    /// The claimed `E`.
    pub settlement_epoch: u64,
    /// Index of this epoch's snapshot in the source's `epochs` (the
    /// assembly re-reads shard rows and `claimant_bond_idx` from it).
    pub snapshot_idx: usize,
    /// The `as_of_e_served_work` outputs for this epoch's frozen rows.
    pub served: ServedWork,
    /// `P`'s recomputed reward share — strictly positive (the §2.3 wire
    /// positivity predicate is the claimability predicate), byte-exactly
    /// what verify's step 5 recomputes: `reward_share_floor(budget,
    /// capped_work_milli(work_P, member, curve), persisted Σwork)`.
    pub reward: u64,
}

/// Step-1 output: the selected batch plus per-epoch skip diagnostics.
#[derive(Debug)]
pub struct ClaimableEpochs {
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
/// 1. **Boundary** — the scratch-oracle call (module doc): clone the bond
///    record's claimed set, run [`claimed_epochs_check_and_set`] against
///    the daemon's `current_settled_epoch`, map the verdict
///    (`NotSettled` / `Expired` / dedup) to a skip or proceed. The clone
///    is discarded; the builder never mutates the decoded record.
/// 2. **Close row** — no frozen close row (`has_budget_row == false`)
///    skips ([`EpochSkip::NoCloseRow`]).
/// 3. **Share recompute** — the verify-exact chain over the frozen rows:
///    [`as_of_e_served_work`] → `work_P` at `claimant_bond_idx` (absent
///    index ⇒ zero work, exactly as verify treats it) →
///    [`capped_work_milli`] → [`reward_share_floor`] against the
///    **persisted** `Σwork(E)` and frozen `budget(E)`. Claimable ⇔ share
///    `> 0`.
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
) -> Result<ClaimableEpochs, EmissionClaimError> {
    let Some(bond) = source.bond.as_ref() else {
        return Err(EmissionClaimError::NoClaimableEpochs);
    };

    let mut claimable: Vec<ClaimableEpoch> = Vec::new();
    let mut skipped: Vec<(u64, EpochSkip)> = Vec::new();

    for (snapshot_idx, snap) in source.epochs.iter().enumerate() {
        let epoch = snap.settlement_epoch;

        // Boundary — the scratch-oracle call (purity pin in the module
        // doc). All three verdicts from the one connect-path function;
        // no inline boundary arithmetic.
        let mut scratch = bond.claimed_settlement_epochs.clone();
        match claimed_epochs_check_and_set(&mut scratch, epoch, source.current_settled_epoch) {
            Err(ClaimedEpochsError::NotSettled) => {
                skipped.push((epoch, EpochSkip::NotSettled));
                continue;
            }
            Err(ClaimedEpochsError::Expired) => {
                skipped.push((epoch, EpochSkip::WindowExpired));
                continue;
            }
            Ok(false) => {
                skipped.push((epoch, EpochSkip::AlreadyClaimed));
                continue;
            }
            Ok(true) => {}
        }

        if !snap.has_budget_row {
            skipped.push((epoch, EpochSkip::NoCloseRow));
            continue;
        }

        // Share recompute — the verify-exact chain over the same decoded
        // views the assembly and self-check consume (§7.3 decode-locus
        // pin). Malformed gather indices refuse loudly (untrusted
        // daemon), mirroring verify's GatherMalformed /
        // ClaimantIndexOutOfRange rejections.
        let bonds = snap.bonds_view();
        let view = snap.source(&bonds);
        let served = as_of_e_served_work(&view.inputs)
            .map_err(|_| EmissionClaimError::SourceInvalid { epoch })?;
        let (work_p, is_member) = match view.claimant_bond_idx {
            Some(idx) if idx >= served.work_by_bond.len() => {
                return Err(EmissionClaimError::SourceInvalid { epoch });
            }
            Some(idx) => (served.work_by_bond[idx], served.member[idx]),
            None => (0, false),
        };
        let capped = capped_work_milli(work_p, is_member, &view.inputs.curve);
        let reward = reward_share_floor(view.budget, capped, view.persisted_sigma_work_milli);
        if reward == 0 {
            skipped.push((epoch, EpochSkip::ZeroShare));
            continue;
        }

        if claimable.len() == MAX_SETTLEMENT_EPOCHS_PER_EMISSION {
            skipped.push((epoch, EpochSkip::BatchDeferred));
            continue;
        }
        claimable.push(ClaimableEpoch {
            settlement_epoch: epoch,
            snapshot_idx,
            served,
            reward,
        });
    }

    if claimable.is_empty() {
        return Err(EmissionClaimError::NoClaimableEpochs);
    }
    Ok(ClaimableEpochs { claimable, skipped })
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
    /// Epochs dropped by the size bound ([`EpochSkip::SizeDeferred`]), in
    /// window order — same observability caveat as
    /// [`ClaimableEpochs::skipped`].
    pub size_deferred: Vec<(u64, EpochSkip)>,
}

/// §2 steps 2 + 5 — assemble the claims-side vin content from the derived
/// batch (module doc: canonical row form, the u64→u32 conversion guard,
/// rewards, and the bound-or-split size discipline).
///
/// Consumes the derivation's own evaluation ([`ClaimableEpoch::served`] /
/// [`ClaimableEpoch::reward`]) — single-evaluator discipline: assembly
/// never re-runs the recompute it was admitted on.
///
/// `claims_size_budget` is the claims-leg byte bound
/// ([`EMISSION_CLAIMS_SIZE_BUDGET`] is the documented default; the
/// parameter exists so the bound is testable at exact boundaries).
pub fn assemble_claims(
    source: &EmissionClaimSource,
    derived: &ClaimableEpochs,
    claims_size_budget: usize,
) -> Result<AssembledClaims, EmissionClaimError> {
    let bond = source
        .bond
        .as_ref()
        .expect("derive_claimable_epochs admitted a batch, so the bond record exists");
    debug_assert!(
        !derived.claimable.is_empty(),
        "derive_claimable_epochs never returns an empty batch"
    );

    // Step 2 — per-epoch canonical rows from the derivation's evaluation.
    let mut rows: Vec<(u64, WorkEpochClaim, u64)> = Vec::with_capacity(derived.claimable.len());
    for c in &derived.claimable {
        let snap = &source.epochs[c.snapshot_idx];
        let bonds = snap.bonds_view();
        let view = snap.source(&bonds);
        let claim = work_epoch_claim(&view, &c.served)?;
        rows.push((c.settlement_epoch, claim, c.reward));
    }

    // Step 5 sizing — bound or split (GF-4b item 5): measure the
    // worst-case claims leg with the production encoder; drop the
    // youngest epoch while over budget; refuse when one epoch alone
    // cannot fit.
    let mut size_deferred: Vec<(u64, EpochSkip)> = Vec::new();
    loop {
        let projected = worst_case_claims_len(&bond.holdings, &rows)?;
        if projected <= claims_size_budget {
            break;
        }
        if rows.len() == 1 {
            return Err(EmissionClaimError::SizeBoundExceeded {
                epoch: rows[0].0,
                projected,
                budget: claims_size_budget,
            });
        }
        let (epoch, _, _) = rows.pop().expect("len > 1 checked above");
        size_deferred.push((epoch, EpochSkip::SizeDeferred));
    }
    // Popped youngest-first; report in window order.
    size_deferred.reverse();

    // Step 5 rewards — verbatim derivation shares; the batch total is
    // checked (budgets are daemon-supplied; an overflowing sum is
    // malformed source, not arithmetic to saturate through).
    let mut total_reward: u64 = 0;
    for (epoch, _, reward) in &rows {
        total_reward = total_reward
            .checked_add(*reward)
            .ok_or(EmissionClaimError::SourceInvalid { epoch: *epoch })?;
    }

    let mut settlement_epochs = Vec::with_capacity(rows.len());
    let mut work_claim = Vec::with_capacity(rows.len());
    let mut reward_amount_plain = Vec::with_capacity(rows.len());
    for (epoch, claim, reward) in rows {
        settlement_epochs.push(epoch);
        work_claim.push(claim);
        reward_amount_plain.push(reward);
    }
    Ok(AssembledClaims {
        settlement_epochs,
        work_claim,
        reward_amount_plain,
        holdings: bond.holdings.clone(),
        total_reward,
        size_deferred,
    })
}

/// One epoch's canonical [`WorkEpochClaim`] from the derivation's
/// evaluation (module doc "Canonical row form"): one entry per credited
/// shard, sorted by `shard_id`, `serve_credit_bit = true`, scarcity
/// resolved by first position of `shard_id` — byte-exactly verify's
/// `ScarcityMismatch` lookup. This is **the** builder conversion site for
/// the wire's `u32 scarcity_milli` (checked, refusing — module doc).
fn work_epoch_claim(
    view: &EmissionEpochSource<'_>,
    served: &ServedWork,
) -> Result<WorkEpochClaim, EmissionClaimError> {
    let epoch = view.inputs.settlement_epoch;
    let claimant = view
        .claimant_bond_idx
        .expect("claimable ⇒ positive share ⇒ a serve-credit row exists");
    debug_assert!(
        served.member[claimant],
        "claimable ⇒ positive capped work ⇒ market member"
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
        let shard_idx = view
            .inputs
            .shards
            .iter()
            .position(|s| s.shard_id == shard_id)
            .expect("credited pair implies the shard row exists");
        let scarcity = shard_contribution_milli(&view.inputs, &served.r_market_by_shard, shard_idx);
        let scarcity_milli = u32::try_from(scarcity)
            .map_err(|_| EmissionClaimError::ScarcityConversion { epoch, shard_id })?;
        entry_sum = entry_sum.saturating_add(scarcity);
        shard_entries.push(ShardWorkEntry {
            shard_id,
            serve_credit_bit: true,
            scarcity_milli,
        });
    }

    // The id-resolved recompute must equal the pair-indexed accumulation
    // the derivation selected on (verify's `WorkTotalMismatch` compare,
    // run here so a doomed vin refuses at assembly, not on-chain). They
    // diverge only on an internally inconsistent gather — e.g. duplicate
    // `shard_id` rows shadowing the credited row's index.
    if entry_sum != served.work_by_bond[claimant] {
        return Err(EmissionClaimError::SourceInvalid { epoch });
    }
    Ok(WorkEpochClaim {
        epoch,
        shard_entries,
    })
}

/// Worst-case claims-leg projection: the actual claims content inside a
/// vin whose cryptographic legs sit at their structural maxima
/// (canonical-length pubkeys/sigs, [`MAX_BACKING_PROOF_BYTES`] proof),
/// serialized by the **production encoder** — an upper bound on the real
/// vin's bytes from the same write path, so no shadow size model can
/// drift (validate() pins the real legs to these exact lengths, proof
/// excepted, which is `≤` the maximum used here).
fn worst_case_claims_len(
    holdings: &HoldingsDescriptor,
    rows: &[(u64, WorkEpochClaim, u64)],
) -> Result<usize, EmissionClaimError> {
    let vin = ArchivalRewardEmissionVin {
        p_pubkey: vec![0; SINGLE_KEY_CANONICAL_LEN],
        holdings: holdings.clone(),
        settlement_epochs: rows.iter().map(|(epoch, ..)| *epoch).collect(),
        work_claim: rows.iter().map(|(_, claim, _)| claim.clone()).collect(),
        backing: MembershipOnlyBacking {
            proof: vec![0; MAX_BACKING_PROOF_BYTES],
            pseudo_out: [0; 32],
            pqc_pk_hash: [0; 32],
            backing_pubkey: vec![0; SINGLE_KEY_CANONICAL_LEN],
            tree_depth: u8::MAX,
        },
        reward_amount_plain: rows.iter().map(|(.., reward)| *reward).collect(),
        auth_backing: vec![0; SINGLE_SIG_CANONICAL_LEN],
        auth_claim: vec![0; SINGLE_SIG_CANONICAL_LEN],
    };
    Ok(vin
        .serialize()
        .map_err(EmissionClaimError::RowsUnencodable)?
        .len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::emission_source::{BondContext, BondRow, EpochSnapshot};
    use shekyl_archival_retention::{
        bond_wire::MAX_HOLDINGS_SHARDS, claimed_epochs_contains, epoch_close_height,
        epoch_is_claim_expired, sigma_work_milli, BandedCurveParams, CreditPair, EpochCloseBond,
        EpochCloseInputs, EpochCloseShard, HoldingsDescriptor, HoldingsKind, KCover,
        ARCHIVAL_REWARD_PLATEAU_VALUE_MILLI, ARCHIVAL_REWARD_PLATEAU_WORK_MILLI, MAX_CLAIM_AGE_W,
        SETTLEMENT_EPOCH_BLOCKS,
    };

    const BUDGET: u64 = 1_000_000;
    const SHARD_A: u64 = 7;
    const SHARD_B: u64 = 9;

    /// The emission_verify_kat fixture shape, owned: two bonds (idx 0 =
    /// claimant, idx 1 = other), two shards, credits {claimant→A,
    /// other→A, other→B}. `sigma_work_milli` is derived through the same
    /// sourcing functions the close persists with, so the fixture's
    /// denominator is exactly what a real close would have stored.
    fn snapshot(epoch: u64) -> EpochSnapshot {
        let close = epoch_close_height(epoch).expect("fixture epoch closes");
        let mut snap = EpochSnapshot {
            settlement_epoch: epoch,
            close_block_height: close,
            sigma_work_milli: 0,
            budget_atomic: BUDGET,
            has_budget_row: true,
            bonds: vec![
                BondRow {
                    join_settlement_epoch: 0,
                    is_foundation_complete_tree: false,
                    bad_intervals: vec![],
                },
                BondRow {
                    join_settlement_epoch: 0,
                    is_foundation_complete_tree: false,
                    bad_intervals: vec![],
                },
            ],
            shards: vec![
                EpochCloseShard {
                    shard_id: SHARD_A,
                    has_segment: true,
                    freeze_height: close - 5_000,
                },
                EpochCloseShard {
                    shard_id: SHARD_B,
                    has_segment: true,
                    freeze_height: close - 8_000,
                },
            ],
            credit_pairs: vec![
                CreditPair {
                    bond_idx: 0,
                    shard_idx: 0,
                },
                CreditPair {
                    bond_idx: 1,
                    shard_idx: 0,
                },
                CreditPair {
                    bond_idx: 1,
                    shard_idx: 1,
                },
            ],
            claimant_bond_idx: Some(0),
        };
        resigma(&mut snap);
        assert!(
            snap.sigma_work_milli > 0,
            "fixture must have a live denominator"
        );
        snap
    }

    /// Recompute a (possibly mutated) fixture's denominator through the
    /// same sourcing functions the close persists with.
    fn resigma(snap: &mut EpochSnapshot) {
        let sigma = {
            let bonds = snap.bonds_view();
            let view = snap.source(&bonds);
            let served = as_of_e_served_work(&view.inputs).expect("well-formed fixture");
            sigma_work_milli(&served.work_by_bond, &view.inputs.curve, &served.member)
        };
        snap.sigma_work_milli = sigma;
    }

    /// A zero-share snapshot in its two indistinguishable causes: gated
    /// (`sigma == 0`, the M1 zero-at-top outcome as persisted) or
    /// no-serve-credit (`claimant_bond_idx == None`). Both must classify
    /// identically ([`EpochSkip::ZeroShare`]) — the cause-blindness KAT
    /// drives both through this one constructor.
    fn zero_share_snapshot(epoch: u64, gated: bool) -> EpochSnapshot {
        let mut snap = snapshot(epoch);
        if gated {
            snap.sigma_work_milli = 0;
        } else {
            snap.claimant_bond_idx = None;
        }
        snap
    }

    fn source_with(
        current_settled_epoch: u64,
        claimed: Vec<u64>,
        epochs: Vec<EpochSnapshot>,
    ) -> EmissionClaimSource {
        EmissionClaimSource {
            chain_height: current_settled_epoch * SETTLEMENT_EPOCH_BLOCKS + 1,
            current_settled_epoch,
            bond: Some(BondContext {
                join_settlement_epoch: 0,
                holdings: HoldingsDescriptor {
                    kind: HoldingsKind::ShardSetCompact,
                    shard_ids: vec![SHARD_A],
                },
                claimed_settlement_epochs: claimed,
            }),
            epochs,
        }
    }

    /// The derivation's three structural checks in one grid: boundary
    /// verdicts come from the connect predicate (each skip reason at its
    /// exact boundary), share positivity is the claimability predicate,
    /// and the selected epochs are the survivors in window order.
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
            "each boundary must map to its connect-predicate verdict; the \
             two zero causes must be indistinguishable (cause-blind)"
        );

        // Share positivity is the wire-positivity predicate: every
        // selected reward is strictly positive (encodable) and byte-exact
        // against verify's step-4/5 recompute over the same view.
        for c in &derived.claimable {
            assert!(c.reward > 0, "claimable ⇒ wire-encodable (> 0)");
            let snap = &source.epochs[c.snapshot_idx];
            let bonds = snap.bonds_view();
            let view = snap.source(&bonds);
            let served = as_of_e_served_work(&view.inputs).unwrap();
            assert_eq!(c.served, served, "assembly must consume this evaluation");
            let idx = view.claimant_bond_idx.unwrap();
            let capped = capped_work_milli(
                served.work_by_bond[idx],
                served.member[idx],
                &view.inputs.curve,
            );
            assert_eq!(
                c.reward,
                reward_share_floor(view.budget, capped, view.persisted_sigma_work_milli),
                "derivation reward must equal verify's recompute"
            );
        }
    }

    /// Drift tripwire for the scratch-oracle disposition: the oracle's
    /// classification must agree with the read-only predicates where
    /// siblings exist (`epoch_is_claim_expired`, `claimed_epochs_contains`)
    /// and with the documented top boundary (`E < settled`). If the
    /// connect predicate's boundaries ever move, this differential fails
    /// before any consensus KAT does.
    #[test]
    fn scratch_oracle_agrees_with_read_only_predicates() {
        let settled = MAX_CLAIM_AGE_W + 10;
        let claimed = vec![15, 20, 30];
        for epoch in 0..=settled + 2 {
            let mut scratch = claimed.clone();
            let verdict = claimed_epochs_check_and_set(&mut scratch, epoch, settled);
            let expected = if epoch >= settled {
                Err(ClaimedEpochsError::NotSettled)
            } else if epoch_is_claim_expired(epoch, settled) {
                Err(ClaimedEpochsError::Expired)
            } else if claimed_epochs_contains(&claimed, epoch) {
                Ok(false)
            } else {
                Ok(true)
            };
            assert_eq!(verdict, expected, "oracle diverged at epoch {epoch}");
        }
    }

    /// Oldest-first 15-cap: with more claimable epochs than the batch
    /// bound, exactly the oldest 15 are selected (nearest expiry — the
    /// order that never strands a savable epoch) and the rest defer.
    #[test]
    fn batch_caps_at_fifteen_oldest_first() {
        let settled = 20;
        let epochs: Vec<EpochSnapshot> = (1..=18).map(snapshot).collect();
        let source = source_with(settled, vec![], epochs);
        let derived = derive_claimable_epochs(&source).expect("claimable");

        let selected: Vec<u64> = derived
            .claimable
            .iter()
            .map(|c| c.settlement_epoch)
            .collect();
        let expected: Vec<u64> = (1..=MAX_SETTLEMENT_EPOCHS_PER_EMISSION as u64).collect();
        assert_eq!(selected, expected, "oldest 15, window order");
        assert!(
            selected.windows(2).all(|w| w[0] < w[1]),
            "wire invariant: strictly increasing"
        );
        assert_eq!(
            derived.skipped,
            vec![
                (16, EpochSkip::BatchDeferred),
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
        let assembled =
            assemble_claims(&source, &derived, EMISSION_CLAIMS_SIZE_BUDGET).expect("fits");

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
            let expected = shard_contribution_milli(&view.inputs, &served.r_market_by_shard, idx);
            assert_eq!(
                u64::from(entry.scarcity_milli),
                expected,
                "verify's ScarcityMismatch compare (tolerance zero)"
            );
            entry_sum += expected;
        }
        assert_eq!(
            entry_sum, served.work_by_bond[0],
            "verify's WorkTotalMismatch compare (tolerance zero)"
        );
    }

    /// The u64→u32 conversion guard bites **at the builder's conversion
    /// site**, not the encoder's `ScarcityOverflow`. The production
    /// decode path cannot reach it — `verify_view` pins
    /// `age_weight_milli` to the compiled constant, bounding an honest
    /// recompute to `WORK_MILLI_SCALE + weight` (const-asserted at module
    /// scope) — so the KAT builds the hostile view directly and drives
    /// the same per-epoch row builder `assemble_claims` runs.
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
                // Hostile: unreachable through `verify_view`.
                age_weight_milli: u64::MAX,
                curve: BandedCurveParams {
                    plateau_work_milli: ARCHIVAL_REWARD_PLATEAU_WORK_MILLI,
                    plateau_value_milli: ARCHIVAL_REWARD_PLATEAU_VALUE_MILLI,
                },
                bonds: &bonds,
                shards: &shards,
                credit_pairs: &pairs,
                frozen_shard_count: 0,
                k_cover: KCover::consensus(),
            },
            persisted_sigma_work_milli: 1,
            claimant_bond_idx: Some(0),
            budget: BUDGET,
        };
        let served = as_of_e_served_work(&view.inputs).unwrap();
        // Premise armed: the recompute really exceeds the wire field.
        assert!(
            shard_contribution_milli(&view.inputs, &served.r_market_by_shard, 0)
                > u64::from(u32::MAX),
            "fixture must drive the recompute over u32::MAX"
        );
        assert!(matches!(
            work_epoch_claim(&view, &served),
            Err(EmissionClaimError::ScarcityConversion {
                epoch: 4,
                shard_id: SHARD_A
            })
        ));
    }

    /// Bound-or-split at exact byte boundaries: at the projection the
    /// batch fits; one byte under, the youngest epoch defers
    /// (`SizeDeferred`) and the older two keep their claim; one byte
    /// under a single epoch's floor, the terminal refusal fires with the
    /// measured projection.
    #[test]
    fn size_bound_defers_youngest_then_refuses() {
        let source = source_with(10, vec![], vec![snapshot(3), snapshot(4), snapshot(5)]);
        let derived = derive_claimable_epochs(&source).expect("three claimable");
        let holdings = &source.bond.as_ref().unwrap().holdings;

        let full =
            assemble_claims(&source, &derived, EMISSION_CLAIMS_SIZE_BUDGET).expect("fits default");
        assert_eq!(full.settlement_epochs, vec![3, 4, 5]);
        let rows: Vec<(u64, WorkEpochClaim, u64)> = full
            .settlement_epochs
            .iter()
            .zip(&full.work_claim)
            .zip(&full.reward_amount_plain)
            .map(|((&epoch, claim), &reward)| (epoch, claim.clone(), reward))
            .collect();
        let len3 = worst_case_claims_len(holdings, &rows).unwrap();
        let len1 = worst_case_claims_len(holdings, &rows[..1]).unwrap();

        let at = assemble_claims(&source, &derived, len3).expect("exactly at the bound");
        assert_eq!(at.settlement_epochs, vec![3, 4, 5]);
        assert!(at.size_deferred.is_empty());

        let under = assemble_claims(&source, &derived, len3 - 1).expect("splits");
        assert_eq!(under.settlement_epochs, vec![3, 4], "oldest retained");
        assert_eq!(under.size_deferred, vec![(5, EpochSkip::SizeDeferred)]);
        assert_eq!(
            under.total_reward,
            under.reward_amount_plain.iter().sum::<u64>()
        );

        assert!(matches!(
            assemble_claims(&source, &derived, len1 - 1),
            Err(EmissionClaimError::SizeBoundExceeded {
                epoch: 3,
                projected,
                budget,
            }) if projected == len1 && budget == len1 - 1
        ));
    }

    /// A gather carrying two credits for one (claimant, shard) is
    /// malformed (the ledger key `P‖shard‖E` is unique) — refused at
    /// assembly, before the double-counted claim can reach a vin.
    #[test]
    fn duplicate_credited_shard_is_source_invalid() {
        let mut snap = snapshot(5);
        snap.credit_pairs.push(CreditPair {
            bond_idx: 0,
            shard_idx: 0,
        });
        resigma(&mut snap);
        let source = source_with(10, vec![], vec![snap]);
        let derived = derive_claimable_epochs(&source).expect("admitted (double-counted share)");
        assert!(matches!(
            assemble_claims(&source, &derived, EMISSION_CLAIMS_SIZE_BUDGET),
            Err(EmissionClaimError::SourceInvalid { epoch: 5 })
        ));
    }

    /// Duplicate `shard_id` rows where the credited row is shadowed by an
    /// earlier one: the id-resolved recompute (verify's lookup) diverges
    /// from the pair-indexed accumulation, so the entry-sum compare
    /// refuses at assembly — the vin would be doomed to
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
        let derived = derive_claimable_epochs(&source).expect("admitted (positive share)");
        assert!(matches!(
            assemble_claims(&source, &derived, EMISSION_CLAIMS_SIZE_BUDGET),
            Err(EmissionClaimError::SourceInvalid { epoch: 5 })
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
            assemble_claims(&source, &derived, EMISSION_CLAIMS_SIZE_BUDGET),
            Err(EmissionClaimError::RowsUnencodable(
                EmissionWireError::ShardEntriesExceeded { got }
            )) if got == MAX_HOLDINGS_SHARDS + 1
        ));
    }
}
