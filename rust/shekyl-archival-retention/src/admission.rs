// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **D3/R3 — admission-time viability predicate.**
//!
//! Admit a bond only if its holdings score **non-zero credited work**, evaluated
//! through the *same* chain that pays: [`shard_work_micro`] →
//! [`work_milli_from_micro`]. The admission predicate **is** the payment
//! predicate, so the two cannot drift.
//!
//! ## Why a predicate and not a minimum holding size
//!
//! The D3 round first sized a frozen `min_holding`, and the sizing is what proved
//! the numeric wrong: `min_holding(r) = ceil(r/1000)` is a **forecast about `r`**,
//! and `r` is dynamic (`archivers × holdings / n`), so any fixed number is wrong
//! somewhere on the trajectory. The viability *condition*, unlike the number,
//! needs no forecast — it is computable from chain state at admission time, and it
//! **self-sizes**: the quantization cliff moves with `r`, and the floor moves with
//! it, by construction, forever (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`
//! §12.9 OQ-2).
//!
//! ## What it buys
//!
//! Today a bond can lock real capital into a **guaranteed-zero** position: the
//! quantization boundary is invisible at bonding time and discovered at claim
//! time. This makes the unviable bond **unrepresentable** rather than merely
//! unprofitable — *do not admit positions the frozen `WORK_MILLI_SCALE` cannot
//! pay*. It **protects reach** rather than taxing it: the positions it refuses
//! were already zeros.
//!
//! ## `k = 1`, and why headroom belongs in the wallet
//!
//! The threshold is **one milli** — the smallest representable credit. The gate
//! therefore sits exactly at the zero-work cliff, so the only positions whose
//! admission is contested are worth ~one milli per epoch: **the gaming prize is
//! pinned at ≈ 0**. A consensus `k` meaningfully above 1 would lift the gate onto
//! positions with real value and grow that prize from nil to small, so **headroom
//! margins belong in the wallet as warnings, never in consensus**.
//!
//! ## Manipulation analysis (§12.9, decided-unless-contested)
//!
//! The design target is *cheap computation, worthless prize* — **not** an
//! expensive predicate. The validator pays this cost at every bond-connect, so
//! expense would be a consensus **DoS surface**, not a tax on a manipulator.
//!
//! 1. **No new oracle.** `r_market` is already consensus state the payment path
//!    consumes every epoch through this same code. Admission is a second,
//!    strictly smaller-stakes consumer of an already-priced quantity.
//! 2. **Per-epoch re-scoring voids admission gaming.** Depress `r`, admit, restore
//!    `r`: the position then scores zero at every subsequent close. All value
//!    flows through per-epoch scoring, which admission timing cannot touch — the
//!    attacker pays unbond/exit costs and bond churn to acquire *a registered
//!    zero*.
//! 3. **Denial is capacity-priced and routable-around.** Inflating `r` to block
//!    applicants is untargeted: the applicant picks other shards, or simply holds
//!    *more* of the same ones (the predicate is over the holding's **sum**), and
//!    every copy the griefer bonds lowers their own scarcity income.
//! 4. **Timing is killed by the read-point** — see [`ParentStateHoldings`].
//! 5. **Validator cost is bounded, and here is the actual number:** the caller
//!    does **two** LMDB point lookups per held shard (the `r_market` row and the
//!    segment freeze height), so at `MAX_HOLDINGS_SHARDS = 4096` one bond post
//!    costs at most ~8k point reads. Real, but not a cheap DoS: every shard in
//!    the holding is priced at a full `ARCHIVAL_BOND_FLOOR_ATOMIC` of locked
//!    collateral, and the tx carries a PQC signature and pays weight fees. The
//!    arithmetic itself is a single pass. The whole-corpus case walks **none**,
//!    because it short-circuits ([`check_admission`]) — without that
//!    short-circuit a `CompleteTree` admission would have to gather every shard
//!    on the chain, the one genuinely unbounded path here.
//!
//! ## Scope: `JoinMarket` only
//!
//! Rebond pins its post-holdings as a **superset** of the record
//! ([`crate::bond_post::verify_rebond_bond_post`] Pin 1) and HoldingsUpdate-add
//! only adds, so both are **monotone in credited work** and cannot turn a viable
//! position into a zero — there is no bypass through them. HoldingsUpdate-**drop**
//! can reduce work and is left ungated *on purpose*: refusing an **entry** into a
//! zero costs the applicant nothing (they never entered, and are free to pick a
//! different holding), whereas refusing an **exit-ward** move would trap capital
//! in a larger position than the holder wants and force a full `Unbond` where
//! they asked for a partial one. The gate protects reach; it must not tax it.

use crate::bond_floor::ARCHIVAL_REWARD_AGE_WEIGHT_MILLI;
use crate::bond_wire::{HoldingsDescriptor, HoldingsKind};
use crate::consensus_state::{shard_age_milli, shard_work_micro};
use crate::constants::effective_settlement_epoch_blocks;
use crate::reward_arithmetic::work_milli_from_micro;

/// Consensus admission threshold, **milli**. One milli is the smallest
/// representable credit, which pins the contested band — and therefore the gaming
/// prize — at ≈ 0. Raising this in consensus is the one edit that grows the prize
/// from nil to small; put headroom in the wallet instead (module docs).
pub const ADMISSION_MIN_WORK_MILLI: u64 = 1;

/// Wire / FFI codes for [`AdmissionError`] and marshal failures the C ABI maps
/// separately. Kept in one place so the header, the Rust FFI, and the daemon
/// log string cannot drift.
pub mod codes {
    /// Holding credits at least [`super::ADMISSION_MIN_WORK_MILLI`].
    pub const OK: u8 = 0;
    /// A gather array pointer was null with a non-zero length (marshal only).
    pub const ERR_NULL_PTR: u8 = 1;
    /// `holdings_kind` is not a valid discriminant (marshal only).
    pub const ERR_HOLDINGS_KIND: u8 = 2;
    /// Gather length disagrees with itself or with the vin shard count.
    pub const ERR_GATHER_MISMATCH: u8 = 3;
    /// Holding would score zero at every epoch close.
    pub const ERR_BELOW_FLOOR: u8 = 4;
}

/// One held shard as seen at the admission read-point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionShard {
    /// `R_market(shard)` at the read-point — **before** the applicant joins.
    /// [`credited_work_at_admission`] adds the applicant itself; do not
    /// pre-increment this.
    pub r_market: u64,
    /// Shard age in milli (the depth-fraction normalization,
    /// [`crate::consensus_state::shard_age_milli`]).
    pub age_milli: u64,
}

/// A holdings gather taken **as of the parent block (`H − 1`)**.
///
/// **The read-point is a ruling, and this type is how it is carried.** Evaluating
/// against tip state would let intra-block ordering move the verdict: a bond post
/// and an unbond in the *same* block could be sequenced to catch a transient `r`.
/// Reading parent state makes ordering irrelevant and makes every validator
/// compute an identical verdict — the same discipline as the
/// `frozen_segment_count` frontier-read and the M3-1 cached-counter drift ruling.
///
/// The read-point lives in the **type name** rather than a comment so a tip-state
/// gather is a visible lie at the call site instead of a silent default. Note the
/// limit of what Rust can enforce: this type makes the requirement legible and
/// [`check_admission`] is pure in it, but *that the gather was actually taken at
/// `H − 1`* is a property of the C++ dispatch, not of this module.
///
/// ## The two fields have different read-points, and the weaker one governs
///
/// - `r_market` is **settled-epoch** state: the `archival_r_market` rows are
///   written when an epoch closes and are keyed by settlement epoch, so the value
///   readable during block `H` belongs to the last *settled* epoch and is fixed
///   for that whole epoch. It is ordering-immune **by construction** — no
///   discipline at the call site is needed to make it so.
/// - `age_milli` is **height-derived** ([`crate::consensus_state::shard_age_milli`]
///   takes a `close_block_height`, and a shard's freeze height can be written by
///   the very block under validation).
///
/// So the parent-height discipline is required *because of `age_milli`*, which is
/// why this type is named for the parent block rather than the settled epoch.
/// Naming it for the epoch would be precise about `r_market` and wrong about
/// `age_milli` — and would tell the dispatch author to pass the wrong height.
/// **Pass the parent height (`H − 1`), never the tip.**
///
/// (Bonding right after a *genuine* mass unbond is not manipulation — that is
/// reading true state, and the admitted position really is viable at that state.)
#[derive(Debug, Clone, Copy)]
pub struct ParentStateHoldings<'a> {
    /// Per-shard chain state, **parallel to the vin's `shard_ids`**, as of `H − 1`.
    /// Empty for a `CompleteTree` holding, which is decided without a gather.
    pub shards: &'a [AdmissionShard],
    /// `g`'s age weight — the compiled consensus parameter
    /// ([`crate::bond_floor::ARCHIVAL_REWARD_AGE_WEIGHT_MILLI`]).
    pub age_weight_milli: u64,
}

/// Why a bond post is refused admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    /// The holding scores below [`ADMISSION_MIN_WORK_MILLI`] — a **known-zero**
    /// position, refused at admission rather than admitted and discovered
    /// unpayable at claim time.
    #[error(
        "holdings credit {credited_milli} milli, below the admission floor: \
         this bond would score zero at every epoch close"
    )]
    BelowViabilityFloor {
        /// What the holding actually credits through the production chain.
        credited_milli: u64,
    },
    /// The marshaled gather does not line up with the vin's shard list.
    ///
    /// This is a **real** invariant, not a restatement of the codec bound: the
    /// gather is built by the C++ caller out of LMDB, *independently* of the vin's
    /// wire decode, so the two can disagree. A mismatch means the caller scored a
    /// different holding than the one being admitted, and the verdict would be
    /// meaningless — fail closed rather than score whatever arrived.
    #[error("admission gather covers {gathered} shards but the vin holds {vin_shards}")]
    GatherLengthMismatch {
        /// Shards named by the vin's holdings descriptor.
        vin_shards: usize,
        /// Entries supplied in the parent-state gather.
        gathered: usize,
    },
    /// The marshaled gather's **columns disagree with each other**.
    ///
    /// Distinct from [`Self::GatherLengthMismatch`], which compares the gather to
    /// the *vin*. Here the caller's own parallel arrays are ragged, so there is no
    /// single "gathered" length to report — collapsing them to a max/min would
    /// discard exactly the fact a debugger needs, namely *which column is short*.
    /// Every length is carried instead.
    #[error(
        "admission gather columns disagree: r_market={r_market}, \
         freeze_heights={freeze_heights}, has_segment={has_segment}"
    )]
    GatherColumnLengthMismatch {
        /// Length of the `r_market` column.
        r_market: usize,
        /// Length of the `freeze_heights` column.
        freeze_heights: usize,
        /// Length of the `has_segment` column.
        has_segment: usize,
    },
}

impl AdmissionError {
    /// Stable C-ABI / log code for this verdict ([`codes`]).
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::BelowViabilityFloor { .. } => codes::ERR_BELOW_FLOOR,
            Self::GatherLengthMismatch { .. } | Self::GatherColumnLengthMismatch { .. } => {
                codes::ERR_GATHER_MISMATCH
            }
        }
    }

    /// Short static reason for daemon logs (no allocation across the FFI).
    #[must_use]
    pub const fn as_static_str(self) -> &'static str {
        match self {
            Self::BelowViabilityFloor { .. } => {
                "holdings credit no work at the parent-block read-point \
                 — this bond would score zero at every epoch close"
            }
            Self::GatherLengthMismatch { .. } => {
                "admission gather length does not match the vin's shard list"
            }
            Self::GatherColumnLengthMismatch { .. } => {
                "admission gather columns disagree with each other \
                 (r_market / freeze_heights / has_segment)"
            }
        }
    }
}

/// Stable reason strings for the full C-ABI code space (including marshal-only
/// codes that never become an [`AdmissionError`]).
#[must_use]
pub const fn admission_code_static_str(code: u8) -> &'static str {
    match code {
        codes::OK => "ok",
        codes::ERR_NULL_PTR => "null gather pointer with non-zero length",
        codes::ERR_HOLDINGS_KIND => "invalid holdings_kind",
        codes::ERR_GATHER_MISMATCH => "admission gather length does not match the vin's shard list",
        codes::ERR_BELOW_FLOOR => {
            "holdings credit no work at the parent-block read-point \
             — this bond would score zero at every epoch close"
        }
        _ => "unknown admission error",
    }
}

impl ParentStateHoldings<'_> {
    /// Production constructor: age weight is the compiled consensus constant.
    #[must_use]
    pub fn with_consensus_age_weight(shards: &[AdmissionShard]) -> ParentStateHoldings<'_> {
        ParentStateHoldings {
            shards,
            age_weight_milli: ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
        }
    }
}

/// Build the per-shard parent-state gather from raw LMDB columns.
///
/// C++ owns the I/O; this owns the **age derivation** (parent height + freeze
/// height + SEB schedule) so the daemon cannot re-implement `shard_age_milli`
/// or pass a tip-dated age by accident at this layer.
///
/// ## `has_segment` is a column, not a sentinel
///
/// A shard with **no frozen segment** scores `age_milli = 0` — exactly as the
/// reward path does ([`crate::consensus_state::shard_contribution_micro`], whose
/// age term is `if shard.has_segment { shard_age_milli(..) } else { 0 }`). That
/// fact **cannot be recovered from `freeze_height` alone**: `0` is a legitimate
/// genesis-band freeze height (the "oldest" sentinel → longest horizon), so a
/// missing row and a genesis-frozen shard are indistinguishable by value. Worse,
/// defaulting a missing row to `0` yields `age_epochs == chain_epochs` and so the
/// **maximum** age — the reward path's zero becomes admission's maximum, which
/// over-scores the holding and admits bonds the pay path would score lower.
///
/// Passing the presence bit explicitly is what keeps admission and payment the
/// same computation. Encoding it as a magic freeze height (e.g. defaulting to
/// `parent_height` so the `close <= freeze` branch fires) would produce the right
/// number today by writing a false fact into the data, and would rot the moment
/// anything else reads that column.
pub fn parent_state_shards_from_gather(
    r_market: &[u64],
    freeze_heights: &[u64],
    has_segment: &[bool],
    parent_height: u64,
) -> Result<Vec<AdmissionShard>, AdmissionError> {
    if r_market.len() != freeze_heights.len() || r_market.len() != has_segment.len() {
        return Err(AdmissionError::GatherColumnLengthMismatch {
            r_market: r_market.len(),
            freeze_heights: freeze_heights.len(),
            has_segment: has_segment.len(),
        });
    }
    let seb = effective_settlement_epoch_blocks();
    Ok(r_market
        .iter()
        .zip(freeze_heights.iter())
        .zip(has_segment.iter())
        .map(
            |((&r_market, &freeze_height), &has_segment)| AdmissionShard {
                r_market,
                age_milli: if has_segment {
                    shard_age_milli(parent_height, freeze_height, seb)
                } else {
                    0
                },
            },
        )
        .collect())
}

/// Credited work (milli) a holding would score at the read-point.
///
/// Runs the **same** per-shard function as the reward path ([`shard_work_micro`])
/// with `serve_credit = true`, which makes the hypothesis explicit and
/// single-sourced: admission asks *"if this bond serves, does it credit
/// anything?"*, so the serve flag is assumed deliberately, never silently
/// dropped. Sums in micro and floors **once** at the aggregate — the D1
/// single-floor-site discipline. Flooring per shard here would re-introduce the
/// exact truncation Stage 1 removed, and would refuse viable bonds.
///
/// ## The applicant counts itself: `r_market + 1`
///
/// Replication is scored at `r_market + 1` because **the applicant joins the
/// market it is being measured against**. At close, `r_market` counts every `P`
/// with a serve-credit row for the shard — which includes this bond once it
/// serves — so scoring against the pre-join `r_market` would measure a market the
/// applicant is not yet in and answer the wrong question.
///
/// This is not a bootstrap patch; it is the model, and two failures fall out of
/// getting it wrong:
///
/// 1. **The sole-holder inversion.** `shard_work_micro` returns `0` for
///    `r_market == 0` (correct on the paying path: a bond with no serve credit is
///    not in the market). Without `+1`, the first archiver to take a rare shard —
///    the *maximal-scarcity, most valuable* participant — scores zero and is
///    refused. That is the exact inverse of the gate's purpose.
/// 2. **Genesis deadlock.** No epoch has closed at genesis, so every `r_market`
///    reads `0`; without `+1` no bond is ever admissible, and serve credit cannot
///    be earned without bonding. The chain could never start an archival market.
#[must_use]
pub fn credited_work_at_admission(holdings: &ParentStateHoldings<'_>) -> u64 {
    let micro = holdings
        .shards
        .iter()
        .map(|s| {
            shard_work_micro(
                s.r_market.saturating_add(1),
                s.age_milli,
                holdings.age_weight_milli,
                true,
            )
        })
        .fold(0u64, u64::saturating_add);
    work_milli_from_micro(micro)
}

/// The admission gate: `Ok(())` iff the holding credits at least
/// [`ADMISSION_MIN_WORK_MILLI`] at the parent-state read-point.
///
/// Pure in its inputs — identical gathers give identical verdicts, which is what
/// lets the parent-state read-point defeat intra-block ordering.
///
/// ## `CompleteTree` is admitted without a gather
///
/// A whole-corpus holding names no shards, so scoring it would mean gathering
/// every shard on the chain — the one unbounded path here (module docs, note 5).
/// It is admitted unconditionally instead, and the justification is **dominance,
/// not triviality**: `CompleteTree` holds a superset of every `ShardSetCompact`
/// holding, so it credits at least as much as any admissible alternative.
///
/// The honest limitation, named rather than hidden: this position *can* score
/// zero, in the degenerate regime where the corpus is smaller than its
/// replication (`n < r` — e.g. a single-shard corpus held by thousands of
/// archivers, where `1e6/r` falls under one milli). But in that regime **every**
/// position scores zero, so refusing the whole-corpus holder would refuse the
/// entire market. That is a corpus-scale pathology, not the per-bond mistake this
/// gate exists to catch, and refusing the maximal-reach participant is the exact
/// opposite of protecting reach.
pub fn check_admission(
    holdings: &HoldingsDescriptor,
    parent_state: &ParentStateHoldings<'_>,
) -> Result<(), AdmissionError> {
    check_admission_of(holdings.kind, holdings.shard_ids.len(), parent_state)
}

/// [`check_admission`] from the holdings' `(kind, shard count)` alone.
///
/// The gate never reads shard-id *values* — only how many there are, to check the
/// gather lines up — so a caller that holds just the count (the FFI, whose C++
/// side already marshals the count and would have to rebuild a validated
/// `ShardSet` for no gain) shares the one implementation. Same split, and the
/// same reason, as [`crate::bond_floor::bond_floor_of`].
pub fn check_admission_of(
    kind: HoldingsKind,
    vin_shards: usize,
    parent_state: &ParentStateHoldings<'_>,
) -> Result<(), AdmissionError> {
    if kind == HoldingsKind::CompleteTree {
        return Ok(());
    }

    if parent_state.shards.len() != vin_shards {
        return Err(AdmissionError::GatherLengthMismatch {
            vin_shards,
            gathered: parent_state.shards.len(),
        });
    }

    let credited_milli = credited_work_at_admission(parent_state);
    if credited_milli < ADMISSION_MIN_WORK_MILLI {
        return Err(AdmissionError::BelowViabilityFloor { credited_milli });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bond_wire::ShardSet;

    const AGE_WEIGHT: u64 = 2_000;

    fn gather(n: usize, r: u64) -> Vec<AdmissionShard> {
        vec![
            AdmissionShard {
                r_market: r,
                age_milli: 0,
            };
            n
        ]
    }

    fn compact(n: u64) -> HoldingsDescriptor {
        HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new((1..=n).collect()).expect("valid shard set"),
        }
    }

    fn parent(shards: &[AdmissionShard]) -> ParentStateHoldings<'_> {
        ParentStateHoldings {
            shards,
            age_weight_milli: AGE_WEIGHT,
        }
    }

    /// **The `k = 1` boundary, both sides.** A holding crediting exactly one milli
    /// is admitted; one crediting zero is refused. Sitting the gate *at* the
    /// smallest representable credit is what pins the contested band — and so the
    /// gaming prize — at ≈ 0, which is why the boundary is the property to pin.
    ///
    /// At age 0, `g = WORK_MILLI_SCALE`, so a shard scores `floor(1e6 / r_eff)`
    /// micro where `r_eff = r_market + 1` (the applicant counts itself). A
    /// pre-join `r_market = 999` lands exactly on one milli; `1_000` one notch
    /// under.
    #[test]
    fn admits_exactly_one_milli_and_refuses_zero() {
        let at_floor = gather(1, 999);
        assert_eq!(
            credited_work_at_admission(&parent(&at_floor)),
            ADMISSION_MIN_WORK_MILLI,
            "fixture must sit exactly ON the floor for the boundary to be tested"
        );
        assert!(
            check_admission(&compact(1), &parent(&at_floor)).is_ok(),
            "exactly k must ADMIT"
        );

        let below = gather(1, 1_000);
        assert_eq!(credited_work_at_admission(&parent(&below)), 0);
        assert!(
            matches!(
                check_admission(&compact(1), &parent(&below)),
                Err(AdmissionError::BelowViabilityFloor { credited_milli: 0 })
            ),
            "below k must REFUSE, naming what it actually credited"
        );
    }

    /// **The predicate is over the holding's SUM**, so the documented remedy for a
    /// refused applicant — hold *more* of the same shards — actually works. This
    /// is what makes denial-by-`r`-inflation routable-around rather than a block.
    #[test]
    fn more_shards_of_the_same_depth_clears_the_floor() {
        // r_eff = 5_000 ⇒ 200 micro/shard: one shard is a zero, five make a milli.
        let one = gather(1, 4_999);
        assert!(
            check_admission(&compact(1), &parent(&one)).is_err(),
            "one deep shard is a zero"
        );
        let five = gather(5, 4_999);
        assert!(
            check_admission(&compact(5), &parent(&five)).is_ok(),
            "the sum over holdings must clear the floor"
        );
    }

    /// The floor sums in **micro** and floors once, so a holding of many
    /// individually-sub-milli shards is admitted on its aggregate — the D1
    /// discipline. Flooring per shard would refuse this viable bond.
    #[test]
    fn aggregates_in_micro_not_per_shard() {
        // r_eff = 4_000 ⇒ 250 micro/shard.
        assert_eq!(
            work_milli_from_micro(shard_work_micro(4_000, 0, AGE_WEIGHT, true)),
            0,
            "premise: a single shard at this depth is sub-milli"
        );
        let shards = gather(4, 3_999);
        assert!(
            check_admission(&compact(4), &parent(&shards)).is_ok(),
            "the aggregate must clear even when every shard alone is sub-milli"
        );
    }

    /// The verdict is a pure function of the gather, so permuting it decides
    /// identically. This is the half of the read-point ruling Rust can execute;
    /// that the gather is taken at `H − 1` is the C++ dispatch's obligation.
    #[test]
    fn verdict_is_order_invariant() {
        let mut shards = gather(3, 2_000);
        shards.extend(gather(2, 400));
        let mut reversed = shards.clone();
        reversed.reverse();
        assert_eq!(
            credited_work_at_admission(&parent(&shards)),
            credited_work_at_admission(&parent(&reversed)),
            "intra-block ordering must not move the verdict"
        );
    }

    /// **The applicant counts itself.** Both failures that `r_market + 1` exists
    /// to prevent, pinned so the term cannot be quietly dropped:
    ///
    /// 1. the **sole-holder inversion** — the first archiver on a rare shard sees
    ///    `r_market == 0` and, unincremented, would score zero and be refused,
    ///    which is the inverse of the gate's purpose; and
    /// 2. the **genesis deadlock** — before any epoch closes every `r_market`
    ///    reads `0`, so an unincremented gate would admit nobody, ever, and serve
    ///    credit cannot be earned without first bonding.
    #[test]
    fn a_sole_holder_at_r_zero_is_admitted_not_refused() {
        let sole = gather(1, 0);
        assert_eq!(
            credited_work_at_admission(&parent(&sole)),
            1_000,
            "r_eff = 1 is maximal scarcity: the whole per-shard scale"
        );
        assert!(
            check_admission(&compact(1), &parent(&sole)).is_ok(),
            "the maximal-scarcity archiver must be admitted"
        );

        // The genesis shape: a whole holding of never-yet-served shards.
        let genesis = gather(32, 0);
        assert!(
            check_admission(&compact(32), &parent(&genesis)).is_ok(),
            "a pre-first-close chain must be able to open its archival market"
        );
    }

    /// **The age term must match the reward path on BOTH branches.** A shard with
    /// no frozen segment scores `age_milli = 0` at payment
    /// ([`crate::consensus_state::shard_contribution_micro`]), so it must score 0
    /// here too.
    ///
    /// This is the single-source property at its sharpest, because the failure is
    /// silent and inverted: `freeze_height = 0` is a *legitimate* genesis-band
    /// value, so a missing row cannot be detected from the height alone — and
    /// defaulting it to `0` gives `age_epochs == chain_epochs`, i.e. the
    /// **maximum** age where payment gives zero. Admission would then over-score
    /// and admit bonds the pay path scores lower.
    #[test]
    fn an_unfrozen_shard_scores_zero_age_exactly_as_the_reward_path_does() {
        const SEB: u64 = crate::constants::SETTLEMENT_EPOCH_BLOCKS;
        let parent_height = SEB * 40;

        // Same freeze height, differing only in whether a segment exists.
        let unfrozen =
            parent_state_shards_from_gather(&[7], &[0], &[false], parent_height).expect("gather");
        let frozen =
            parent_state_shards_from_gather(&[7], &[0], &[true], parent_height).expect("gather");

        assert_eq!(
            unfrozen[0].age_milli, 0,
            "no segment must score zero age, as shard_contribution_micro does"
        );
        assert_eq!(
            frozen[0].age_milli,
            shard_age_milli(parent_height, 0, SEB),
            "a frozen shard must score the production age term unchanged"
        );
        assert!(
            frozen[0].age_milli > 0,
            "fixture must actually separate the branches, or it proves nothing"
        );
    }

    /// Ragged gather columns name every length, so a debugger can see *which*
    /// column is short rather than a max/min that discards it.
    #[test]
    fn ragged_gather_columns_report_all_three_lengths() {
        let err = parent_state_shards_from_gather(&[1, 2, 3], &[0, 0], &[true], 0)
            .expect_err("ragged columns must fail closed");
        assert_eq!(
            err,
            AdmissionError::GatherColumnLengthMismatch {
                r_market: 3,
                freeze_heights: 2,
                has_segment: 1,
            }
        );
        assert_eq!(err.code(), codes::ERR_GATHER_MISMATCH);
    }

    /// A whole-corpus holding is admitted without a gather — dominance, and the
    /// only way to keep the predicate's cost bounded.
    #[test]
    fn complete_tree_is_admitted_without_a_gather() {
        let whole = HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: ShardSet::new(vec![]).expect("empty set is the CompleteTree shape"),
        };
        assert!(check_admission(&whole, &parent(&[])).is_ok());
    }

    /// The gather is built from LMDB independently of the vin's wire decode, so a
    /// disagreement is reachable — and means the caller scored a *different*
    /// holding than the one being admitted. Fail closed.
    #[test]
    fn refuses_a_gather_that_does_not_match_the_vin() {
        let shards = gather(2, 6);
        assert!(matches!(
            check_admission(&compact(3), &parent(&shards)),
            Err(AdmissionError::GatherLengthMismatch {
                vin_shards: 3,
                gathered: 2
            })
        ));
    }

    /// Age derivation lives in the gather builder so C++ cannot re-implement
    /// `shard_age_milli` or tip-date the age at this layer.
    #[test]
    fn parent_state_shards_from_gather_derives_age_and_rejects_parallel_mismatch() {
        let r = [0u64, 1];
        let freeze = [0u64, 0];
        let seg = [true, true];
        let shards = parent_state_shards_from_gather(&r, &freeze, &seg, 0).expect("parallel");
        assert_eq!(shards.len(), 2);
        assert_eq!(shards[0].age_milli, 0);
        assert!(matches!(
            parent_state_shards_from_gather(&[1], &[0, 0], &[true], 0),
            Err(AdmissionError::GatherColumnLengthMismatch { .. })
        ));
        assert_eq!(
            AdmissionError::BelowViabilityFloor { credited_milli: 0 }.code(),
            codes::ERR_BELOW_FLOOR
        );
    }
}
