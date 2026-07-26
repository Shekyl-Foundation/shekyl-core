//! Pure consensus-state computation for emission reads (ARCHIVAL_CONSENSUS_STATE.md §3–§5).
//!
//! No LMDB. This module is the **single implementation** of the epoch-close
//! consensus semantics: the C++ daemon gathers raw rows from LMDB, calls
//! [`epoch_close_compute`] through `shekyl-ffi`, and stores the returned
//! `R_market` / `Σwork` values. C++ performs no consensus arithmetic of its
//! own (`20-rust-vs-cpp-policy.mdc` §4; `40-ffi-discipline.mdc` coarse-call rule).

use crate::bond_floor::ARCHIVAL_REWARD_AGE_WEIGHT_MILLI;
use crate::constants::{effective_settlement_epoch_blocks, SETTLEMENT_EPOCH_BLOCKS};
use crate::reward_arithmetic::{
    mul_div_floor, scarcity_micro, work_milli_from_micro, WORK_MILLI_SCALE,
};

const _: () = assert!(
    SETTLEMENT_EPOCH_BLOCKS > 0,
    "settlement epoch must be nonzero"
);

/// Settlement epoch containing `block_height` (`floor(height / SEB)`), where
/// `SEB` is [`effective_settlement_epoch_blocks`] — the genesis pin, or the
/// clamped fakechain-only regtest override.
///
/// Used for bond-connect `join_settlement_epoch` derivation and prune-horizon
/// arithmetic; the daemon performs no epoch arithmetic of its own.
#[must_use]
pub fn settlement_epoch_at_height(block_height: u64) -> u64 {
    block_height / effective_settlement_epoch_blocks()
}

/// Settlement epoch that closes at `block_height`, when one does.
///
/// Epoch `E` covers heights `[E·SEB, (E+1)·SEB)`; its close is processed at
/// the first height of the next epoch (`(E+1)·SEB`). Returns `None` at
/// height 0 and at non-boundary heights.
#[must_use]
pub fn epoch_close_due_at_height(block_height: u64) -> Option<u64> {
    let seb = effective_settlement_epoch_blocks();
    if block_height == 0 || !block_height.is_multiple_of(seb) {
        return None;
    }
    Some(block_height / seb - 1)
}

/// The block height at which settlement epoch `epoch` closes — the inverse of
/// [`epoch_close_due_at_height`]. Epoch `E` covers `[E·SEB, (E+1)·SEB)`, so it closes at
/// `(E+1)·SEB` (the first height of the next epoch). Returns `None` if `(E+1)·SEB` would
/// overflow `u64` (an impossible epoch). Single-sources the close-boundary formula so
/// callers needing "is epoch `E` finalized at height `H`?" (`epoch_close_height(E) <= H`)
/// do not re-derive `(E+1)·SEB` by hand and risk drift from this genesis-frozen mapping.
#[must_use]
pub fn epoch_close_height(epoch: u64) -> Option<u64> {
    epoch
        .checked_add(1)
        .and_then(|next| next.checked_mul(effective_settlement_epoch_blocks()))
}

/// Prune horizon at `block_height`: epochs strictly below the returned value
/// are unclaimable (`E < tip − MAX_CLAIM_AGE_W`, ARCHIVAL_CONSENSUS_STATE.md §5)
/// and may be deleted. `None` while the chain is younger than the window.
#[must_use]
pub fn prune_below_epoch_at_height(block_height: u64, max_claim_age_w: u64) -> Option<u64> {
    let tip_epoch = settlement_epoch_at_height(block_height);
    if tip_epoch > max_claim_age_w {
        Some(tip_epoch - max_claim_age_w)
    } else {
        None
    }
}

/// Interval-log entry (gate-4 F3): half-open `[start_epoch, end_exclusive)`.
///
/// The log carries **two entry kinds** — do not assume every entry is a slash:
/// a *bad-standing interval* has `start < end` (a slash opens with
/// `end_exclusive = u64::MAX`; `Rebond` closes it in place), while the `Unbond`
/// **clean interval-close** is **zero-length** (`start == end`) — a pure exit
/// marker recording the unbond settlement epoch
/// ([`clean_interval_close`](crate::bond_connect::clean_interval_close)). Its
/// empty range excludes no epoch from [`good_through`] by construction, and
/// every codec/marshal path deliberately carries `start == end`; never add a
/// "valid interval is non-empty" assertion on this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadInterval {
    pub start_epoch: u64,
    pub end_exclusive: u64,
}

/// Spec-correct `good_through` (interval semantics at E-close).
#[must_use]
pub fn good_through(
    join_settlement_epoch: u64,
    settlement_epoch: u64,
    bad_intervals: &[BadInterval],
) -> bool {
    if settlement_epoch < join_settlement_epoch.saturating_add(1) {
        return false;
    }
    for iv in bad_intervals {
        if settlement_epoch < iv.start_epoch {
            continue;
        }
        if iv.end_exclusive == u64::MAX || settlement_epoch < iv.end_exclusive {
            return false;
        }
    }
    true
}

/// Market membership at epoch close (ARCHIVAL_BOND_GATE4.md §2.2).
#[must_use]
pub fn market_member_at_epoch(
    join_settlement_epoch: u64,
    settlement_epoch: u64,
    bad_intervals: &[BadInterval],
    is_foundation_complete_tree: bool,
) -> bool {
    if is_foundation_complete_tree {
        return false;
    }
    good_through(join_settlement_epoch, settlement_epoch, bad_intervals)
}

/// One archiver's serve-credit row for `R_market` materialization KATs.
#[derive(Debug, Clone)]
pub struct ServeCreditRow {
    pub p_id: [u8; 32],
    pub shard_id: u64,
    pub serve_credit: bool,
    pub join_settlement_epoch: u64,
    pub bad_intervals: Vec<BadInterval>,
    pub is_foundation: bool,
}

/// `R_market(shard, E)` — serve-credit-weighted count (Gap 2 pin).
#[must_use]
pub fn r_market_count(rows: &[ServeCreditRow], shard_id: u64, settlement_epoch: u64) -> u64 {
    let mut n = 0u64;
    for row in rows {
        if row.shard_id != shard_id || !row.serve_credit {
            continue;
        }
        if !market_member_at_epoch(
            row.join_settlement_epoch,
            settlement_epoch,
            &row.bad_intervals,
            row.is_foundation,
        ) {
            continue;
        }
        n = n.saturating_add(1);
    }
    n
}

/// Per-shard work in **micro-units** for one held shard with serve credit —
/// summed per bond and floored to milli once at the aggregate
/// ([`as_of_e_served_work`]). Zero without serve credit or a market co-holder.
#[must_use]
pub fn shard_work_micro(
    r_market: u64,
    age_milli: u64,
    age_weight_milli: u64,
    serve_credit: bool,
) -> u64 {
    if !serve_credit || r_market == 0 {
        return 0;
    }
    scarcity_micro(r_market, age_milli, age_weight_milli)
}

/// `Σwork(E)` milli — sum of `Curve(work_P)` over market archivers.
///
/// # Panics
///
/// Panics when `per_p_work_milli` and `market_mask` lengths differ — the two
/// slices are parallel per-`P` views and a mismatch is a caller programming
/// error, not a recoverable input state. [`epoch_close_compute`] builds both
/// from the same bond list, so the contract holds by construction there.
#[must_use]
pub fn sigma_work_milli(per_p_work_milli: &[u64], market_mask: &[bool]) -> u64 {
    assert_eq!(
        per_p_work_milli.len(),
        market_mask.len(),
        "per-P work and market mask must be parallel slices"
    );
    let mut sum = 0u64;
    for (&work, &in_market) in per_p_work_milli.iter().zip(market_mask.iter()) {
        sum = sum.saturating_add(capped_work_milli(work, in_market));
    }
    sum
}

/// One `P`'s capped work term `Curve(work_P)` — the single definition of the
/// per-`P` contribution to `Σwork(E)`. Non-members and zero-work members
/// contribute nothing. Sourced here so the persisted denominator
/// ([`sigma_work_milli`]), the emission numerator FFI
/// (`shekyl_archival_emission_epoch_work`), and the verify body
/// (`emission_verify`) cannot drift on the guard — the M-2 sourcing-divergence
/// the WS-1 design makes unrepresentable rather than tested-against.
#[must_use]
pub fn capped_work_milli(work_milli: u64, is_member: bool) -> u64 {
    if is_member {
        work_milli
    } else {
        0
    }
}

/// Shard age as a **relative depth fraction** in milli at `close_block_height`
/// (ARCHIVAL_REWARD_ARITHMETIC.md §"Shard age", normalization pinned 2026-06-11).
///
/// `age = floor((close − freeze) / SEB) / floor(close / SEB)` — settlement
/// epochs since freeze over chain depth in settlement epochs — scaled by
/// [`WORK_MILLI_SCALE`] and floored, so the result is bounded to
/// `[0, WORK_MILLI_SCALE]` and `g(age)` spans exactly `[1, 1 + age_weight]`
/// for the life of the chain (the scale-free shape the Layer-2 band run
/// sealed; raw epoch counts would grow `g` without bound, concentrating
/// `Σwork` onto oldest-band holders over mission timeframes).
///
/// Zero when the segment is not yet frozen past the close height, before the
/// first settlement epoch completes (`chain_epochs = 0` — everything is hot
/// at genesis), or when `settlement_epoch_blocks` is zero.
#[must_use]
pub fn shard_age_milli(
    close_block_height: u64,
    freeze_height: u64,
    settlement_epoch_blocks: u64,
) -> u64 {
    if settlement_epoch_blocks == 0 || close_block_height <= freeze_height {
        return 0;
    }
    let age_epochs = (close_block_height - freeze_height) / settlement_epoch_blocks;
    let chain_epochs = close_block_height / settlement_epoch_blocks;
    if chain_epochs == 0 {
        return 0;
    }
    // `age_epochs <= chain_epochs` (freeze_height >= 0, floor is monotone),
    // so the quotient is bounded by WORK_MILLI_SCALE and the fallback is
    // unreachable for in-range inputs.
    mul_div_floor(age_epochs, WORK_MILLI_SCALE, chain_epochs).unwrap_or(WORK_MILLI_SCALE)
}

/// One market candidate's bond fields at epoch close (LMDB-shape-free gather output).
///
/// The gather contract: the caller supplies one entry per **distinct** `P_id`
/// holding at least one serve-credit row for the settlement epoch. Bonded `P`s
/// without credit rows contribute zero to `R_market` and `Σwork` by
/// construction and may be omitted.
///
/// Deliberately **not** carrying the bond's current holdings descriptor
/// (WS-1, `REWARD_EMISSION_E3_GATING_ROUND.md` §5): a serve-credit row is
/// admitted only after the acceptance gate proves `P` held the shard at the
/// challenge fire height, so the credit ledger *is* the as-of-`E`
/// held-and-served witness. Re-filtering credits against tip holdings here
/// was the M2-1 drop-after-serve under-count; the descriptor is out of the
/// work channel's scope entirely so no future edit can reintroduce it.
#[derive(Debug, Clone)]
pub struct EpochCloseBond<'a> {
    pub join_settlement_epoch: u64,
    pub is_foundation_complete_tree: bool,
    pub bad_intervals: &'a [BadInterval],
}

/// One shard's registry row at epoch close.
///
/// `has_segment` is `false` when no frozen segment row exists for the shard;
/// its age is then zero (pre-freeze shards accrue no age weighting).
#[derive(Debug, Clone, Copy)]
pub struct EpochCloseShard {
    pub shard_id: u64,
    pub has_segment: bool,
    pub freeze_height: u64,
}

/// One serve-credit row at epoch close, as indices into the gather arrays.
///
/// Pairs are **distinct** by construction at the storage layer (the
/// serve-credit ledger is keyed `(P_id, shard_id, E)`); duplicates would
/// double-count `R_market` and work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreditPair {
    pub bond_idx: usize,
    pub shard_idx: usize,
}

/// Gathered inputs for [`epoch_close_compute`].
#[derive(Debug, Clone)]
pub struct EpochCloseInputs<'a> {
    pub settlement_epoch: u64,
    pub close_block_height: u64,
    pub settlement_epoch_blocks: u64,
    pub age_weight_milli: u64,
    pub bonds: &'a [EpochCloseBond<'a>],
    pub shards: &'a [EpochCloseShard],
    pub credit_pairs: &'a [CreditPair],
}

impl<'a> EpochCloseInputs<'a> {
    /// The close-path construction: the pinned consensus params
    /// (schedule, age weight) filled from the compiled
    /// constants pipeline — the **single** source both this and
    /// [`Self::verify_view`] draw from, so the close FFI shim and the
    /// verify views cannot drift on a param (the
    /// `SETTLEMENT_EPOCH_BLOCKS → effective_settlement_epoch_blocks()`
    /// swap previously had to edit the FFI's struct literal and this
    /// constructor in lockstep; now the params exist once).
    #[must_use]
    pub fn close_view(
        settlement_epoch: u64,
        close_block_height: u64,
        bonds: &'a [EpochCloseBond<'a>],
        shards: &'a [EpochCloseShard],
        credit_pairs: &'a [CreditPair],
    ) -> Self {
        Self {
            settlement_epoch,
            close_block_height,
            settlement_epoch_blocks: effective_settlement_epoch_blocks(),
            age_weight_milli: ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
            bonds,
            shards,
            credit_pairs,
        }
    }

    /// The verify-view construction (`EMISSION_CLAIM_BUILDER.md` §7.3):
    /// [`Self::close_view`]'s pinned params — deliberately never a wire
    /// copy, which would be a second source that can drift. Single-sourced
    /// here so the verify FFI shims and the wallet's §2 step-7 self-check
    /// construct byte-identical views and cannot drift. (Identical to the
    /// close view since the M1 gate's retirement removed the close-only
    /// operands; the alias is kept as the verify-side name.)
    #[must_use]
    pub fn verify_view(
        settlement_epoch: u64,
        close_block_height: u64,
        bonds: &'a [EpochCloseBond<'a>],
        shards: &'a [EpochCloseShard],
        credit_pairs: &'a [CreditPair],
    ) -> Self {
        Self::close_view(
            settlement_epoch,
            close_block_height,
            bonds,
            shards,
            credit_pairs,
        )
    }
}

/// Epoch-close outputs: `R_market` per input shard (parallel to
/// `EpochCloseInputs::shards`) and the finalized `Σwork(E)` milli value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochCloseResult {
    pub r_market_by_shard: Vec<u64>,
    pub sigma_work_milli: u64,
}

/// A credit pair referenced a bond or shard index outside the gather arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreditIndexOutOfRange {
    pub pair_index: usize,
}

impl core::fmt::Display for CreditIndexOutOfRange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "credit pair {} references a bond/shard index outside the gather arrays",
            self.pair_index
        )
    }
}

impl std::error::Error for CreditIndexOutOfRange {}

/// Per-bond served-work derivation over the frozen serve-credit ledger — the
/// **single sourcing function** for every consensus quantity built from
/// "which shards did `P` hold-and-serve in `E`" (WS-1,
/// `REWARD_EMISSION_E3_GATING_ROUND.md` §5).
///
/// Epoch close calls [`as_of_e_served_work`] to build the stored `Σwork(E)`
/// denominator; the PR-E3 emission verify body calls it with the same frozen
/// gather to build `P`'s `capped_P` numerator. Because both sides run this
/// one function over the same as-of-`E` inputs, the numerator is `P`'s exact
/// term in the denominator *by definition* — sourcing divergence (the M-2
/// silent over/under-mint) is unrepresentable rather than tested-against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedWork {
    /// Market membership per input bond (parallel to `EpochCloseInputs::bonds`).
    pub member: Vec<bool>,
    /// `R_market(shard, E)` per input shard (parallel to `EpochCloseInputs::shards`).
    pub r_market_by_shard: Vec<u64>,
    /// `work_P(E)` in **micro-units** per input bond — the un-floored sum of
    /// per-shard [`scarcity_micro`] terms (parallel to `EpochCloseInputs::bonds`).
    /// This is the wire-compare quantity: the emission verify body sums the
    /// claim's per-entry `scarcity_micro` and demands equality with this **before**
    /// any floor, so an omitted or padded shard worth `< 1` milli cannot hide
    /// under a milli-granular total (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`
    /// F-E, wargame W3).
    pub work_micro_by_bond: Vec<u64>,
    /// `work_P(E)` in **milli** per input bond — `work_micro_by_bond` floored
    /// once via [`work_milli_from_micro`] (the single floor-site). Curve-ready:
    /// `Σwork(E)` ([`sigma_work_milli`]) and the emission numerator consume this.
    pub work_by_bond: Vec<u64>,
}

/// Reject a gather whose credit pairs index outside the bond/shard arrays —
/// the single validation both [`as_of_e_served_work`] and the M1-gated
/// early-return in [`epoch_close_compute`] share, so a malformed gather fails
/// loudly on every path (gated or not) from one source of truth.
fn validate_credit_pair_indices(
    inputs: &EpochCloseInputs<'_>,
) -> Result<(), CreditIndexOutOfRange> {
    for (pair_index, pair) in inputs.credit_pairs.iter().enumerate() {
        if pair.bond_idx >= inputs.bonds.len() || pair.shard_idx >= inputs.shards.len() {
            return Err(CreditIndexOutOfRange { pair_index });
        }
    }
    Ok(())
}

/// Derive [`ServedWork`] from the gathered as-of-`E` inputs.
///
/// The held-and-served set is sourced **solely** from `inputs.credit_pairs`
/// (the serve-credit ledger rows for `E`): acceptance gates every credit on
/// holding at the challenge fire height, so each pair is a proven
/// held-and-served fact for `E`. No holdings descriptor participates — see
/// the [`EpochCloseBond`] doc for the WS-1 rationale.
///
/// Errors on malformed gather indices; performs no reward-gate comparison
/// (the M1 gate is [`epoch_close_compute`]'s zero-at-top concern).
pub fn as_of_e_served_work(
    inputs: &EpochCloseInputs<'_>,
) -> Result<ServedWork, CreditIndexOutOfRange> {
    let bonds = inputs.bonds;
    let shards = inputs.shards;

    validate_credit_pair_indices(inputs)?;

    let member: Vec<bool> = bonds
        .iter()
        .map(|b| {
            market_member_at_epoch(
                b.join_settlement_epoch,
                inputs.settlement_epoch,
                b.bad_intervals,
                b.is_foundation_complete_tree,
            )
        })
        .collect();

    let mut r_market_by_shard = vec![0u64; shards.len()];
    for pair in inputs.credit_pairs {
        if member[pair.bond_idx] {
            r_market_by_shard[pair.shard_idx] = r_market_by_shard[pair.shard_idx].saturating_add(1);
        }
    }

    // A member-credited shard's contribution is a pure function of its index
    // (its `r_market`, age, and the epoch's age-weight), so compute it via the
    // single `shard_contribution_micro` source and memoize per shard index — a
    // shard whose only credit comes from a non-member bond never pays the two
    // `shard_age_milli` divisions. Accumulate in **micro** so no shard is
    // floored before the sum (the D1 fix): the pre-fix per-shard milli floor
    // zeroed every shard past the co-holder cliff.
    let mut contribution_by_shard: Vec<Option<u64>> = vec![None; shards.len()];

    let mut work_micro_by_bond = vec![0u64; bonds.len()];
    for pair in inputs.credit_pairs {
        if !member[pair.bond_idx] {
            continue;
        }
        let contribution = *contribution_by_shard[pair.shard_idx].get_or_insert_with(|| {
            shard_contribution_micro(inputs, &r_market_by_shard, pair.shard_idx)
        });
        work_micro_by_bond[pair.bond_idx] =
            work_micro_by_bond[pair.bond_idx].saturating_add(contribution);
    }

    // The single floor-to-milli site (F-E): one `work_milli_from_micro` per
    // bond, shared with the verify body because both reach here through this
    // one function. Floors down (§11.5) — the dropped sub-milli favours the
    // protocol.
    let work_by_bond: Vec<u64> = work_micro_by_bond
        .iter()
        .map(|&micro| work_milli_from_micro(micro))
        .collect();

    Ok(ServedWork {
        member,
        r_market_by_shard,
        work_micro_by_bond,
        work_by_bond,
    })
}

/// The per-shard work term (**micro-units**) for a member-credited shard,
/// exactly as [`as_of_e_served_work`] accumulates it into `work_micro_by_bond`.
/// Single source for the per-shard math so the close's denominator and the
/// verify body's per-shard `ScarcityMismatch` recompute cannot drift (WS-1
/// §5.5): a shard's contribution is `shard_work_micro(r_market[s], age[s],
/// age_weight)` with `age[s] = 0` for a shard with no frozen segment. The caller
/// establishes membership and credit; this computes the term those two facts
/// imply. The claim carries this micro value per entry; the floor to milli is
/// deferred to the per-bond aggregate.
#[must_use]
pub fn shard_contribution_micro(
    inputs: &EpochCloseInputs<'_>,
    r_market_by_shard: &[u64],
    shard_idx: usize,
) -> u64 {
    let shard = &inputs.shards[shard_idx];
    let age_milli = if shard.has_segment {
        shard_age_milli(
            inputs.close_block_height,
            shard.freeze_height,
            inputs.settlement_epoch_blocks,
        )
    } else {
        0
    };
    shard_work_micro(
        r_market_by_shard[shard_idx],
        age_milli,
        inputs.age_weight_milli,
        true,
    )
}

/// Full epoch-close consensus computation (ARCHIVAL_CONSENSUS_STATE.md §3.3, §3.5).
///
/// Composes the pinned semantics in one deterministic pass:
///
/// 1. **Market membership** per bond — [`market_member_at_epoch`].
/// 2. **`R_market(shard, E)`** — count of serve-credit rows whose `P` is a
///    market member (§3.3 pinned measure).
/// 3. **`work_P`** — Σ over credited shards of [`shard_work_micro`]
///    (scarcity × age weighting) in micro, floored to milli once at the
///    aggregate, saturating. The held-and-served set is the serve-credit ledger
///    itself (WS-1 §5) via [`as_of_e_served_work`], the single sourcing function
///    shared with the emission verify body.
/// 4. **`Σwork(E)`** — [`sigma_work_milli`] over per-bond `Curve(work_P)`.
///
/// Errors (rather than panics) on malformed gather indices so the FFI shim
/// can map the failure to a loud daemon-side abort.
///
/// The retired M1 `K_COVER` gate ran here as a zero-at-top early return
/// (`ARCHIVAL_REWARD_GATE_M1.md`, RETIRED — see its retirement record):
/// reward withholding is individually-caused only (slash/bad-intervals,
/// membership onset, holdings shape, claim expiry); no collective gate
/// precedes the derivation.
pub fn epoch_close_compute(
    inputs: &EpochCloseInputs<'_>,
) -> Result<EpochCloseResult, CreditIndexOutOfRange> {
    // `as_of_e_served_work` validates the gather indices internally.
    let served = as_of_e_served_work(inputs)?;
    let sigma = sigma_work_milli(&served.work_by_bond, &served.member);

    Ok(EpochCloseResult {
        r_market_by_shard: served.r_market_by_shard,
        sigma_work_milli: sigma,
    })
}

/// Foundation excluded from market_R / Σwork (E-2 footnote — immediate, not lagged).
pub const FOUNDATION_EXCLUDED_FROM_MARKET: bool = true;

#[cfg(test)]
mod tests {
    use super::*;

    fn row(shard: u64, serve: bool, bad: Vec<BadInterval>) -> ServeCreditRow {
        ServeCreditRow {
            p_id: [0u8; 32],
            shard_id: shard,
            serve_credit: serve,
            join_settlement_epoch: 0,
            bad_intervals: bad,
            is_foundation: false,
        }
    }

    #[test]
    fn bonded_without_serve_credit_not_in_r_market() {
        let shard = 7u64;
        let e = 5u64;
        assert_eq!(r_market_count(&[row(shard, false, vec![])], shard, e), 0);
        assert_eq!(r_market_count(&[row(shard, true, vec![])], shard, e), 1);
    }

    #[test]
    fn partial_slash_bad_interval_excludes_from_r_market() {
        let shard = 3u64;
        let e = 10u64;
        let bad = vec![BadInterval {
            start_epoch: 8,
            end_exclusive: u64::MAX,
        }];
        assert!(!good_through(0, e, &bad));
        assert_eq!(r_market_count(&[row(shard, true, bad)], shard, e), 0);
    }

    #[test]
    fn good_through_before_slash_interval() {
        let bad = vec![BadInterval {
            start_epoch: 11,
            end_exclusive: u64::MAX,
        }];
        assert!(good_through(0, 10, &bad));
        assert!(!good_through(0, 11, &bad));
    }

    fn close_inputs<'a>(
        bonds: &'a [EpochCloseBond<'a>],
        shards: &'a [EpochCloseShard],
        pairs: &'a [CreditPair],
    ) -> EpochCloseInputs<'a> {
        EpochCloseInputs {
            settlement_epoch: 5,
            close_block_height: 60_000,
            settlement_epoch_blocks: 10_000,
            age_weight_milli: 0,
            bonds,
            shards,
            credit_pairs: pairs,
        }
    }

    fn shard(shard_id: u64, freeze_height: u64) -> EpochCloseShard {
        EpochCloseShard {
            shard_id,
            has_segment: true,
            freeze_height,
        }
    }

    #[test]
    fn epoch_close_single_member_full_pipeline() {
        let bonds = [EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &[],
        }];
        let shards = [shard(7, 0)];
        let pairs = [CreditPair {
            bond_idx: 0,
            shard_idx: 0,
        }];
        let out = epoch_close_compute(&close_inputs(&bonds, &shards, &pairs)).unwrap();
        assert_eq!(out.r_market_by_shard, vec![1]);
        // R=1, age_weight=0 → scarcity = 1000 milli; curve below first band → identity.
        assert_eq!(out.sigma_work_milli, 1_000);
    }

    /// `work_P(E)` for one bond that credits `n_shards` **fresh** shards
    /// (`has_segment == false` ⇒ age 0 ⇒ `g_milli == 1000`), each also credited
    /// by `crowd` other market members so `r_market == crowd + 1`. The victim is
    /// bond 0; the crowd is bonds `1..=crowd`. Every bond is a member
    /// (`join_epoch 0`, no bad intervals, not Foundation).
    fn victim_work_over_crowded_shards(n_shards: usize, crowd: usize) -> u64 {
        let bonds: Vec<EpochCloseBond<'_>> = (0..=crowd)
            .map(|_| EpochCloseBond {
                join_settlement_epoch: 0,
                is_foundation_complete_tree: false,
                bad_intervals: &[],
            })
            .collect();
        let shards: Vec<EpochCloseShard> = (0..n_shards)
            .map(|i| EpochCloseShard {
                shard_id: i as u64,
                has_segment: false,
                freeze_height: 0,
            })
            .collect();
        // Every bond credits every shard ⇒ r_market[s] = crowd + 1.
        let mut pairs = Vec::with_capacity((crowd + 1) * n_shards);
        for bond_idx in 0..=crowd {
            for shard_idx in 0..n_shards {
                pairs.push(CreditPair {
                    bond_idx,
                    shard_idx,
                });
            }
        }
        let inputs = EpochCloseInputs {
            settlement_epoch: 5,
            close_block_height: 60_000,
            settlement_epoch_blocks: 10_000,
            // The real age weight; irrelevant here since fresh shards have age 0
            // (g_milli = 1000 regardless), but faithful to production params.
            age_weight_milli: ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
            bonds: &bonds,
            shards: &shards,
            credit_pairs: &pairs,
        };
        let served = as_of_e_served_work(&inputs).expect("crowded gather is well-formed");
        assert_eq!(served.r_market_by_shard[0], (crowd + 1) as u64);
        assert!(served.member[0], "victim must be a market member");
        served.work_by_bond[0]
    }

    /// The D1 fix (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §7 acceptance
    /// gate): a bulk holder whose shards are each past the co-holder cliff
    /// (`r_market > g_milli`) earns `work_P > 0` and proportional to how many
    /// shards they serve — **not zero**.
    ///
    /// The pre-fix `as_of_e_served_work` summed `floor(g_milli / r_market)` PER
    /// SHARD before aggregating (`Σ floor(1000 / 1001) = Σ 0`), so a holder of
    /// any number of common shards scored exactly 0 — 13.6 GB served, every
    /// challenge passed, no reward (D1). The micro path sums per-shard
    /// [`scarcity_micro`] first and floors **once** at the aggregate, giving a
    /// positive value that grows with the shard count.
    ///
    /// This asserts only the **fix-shape-agnostic** property (non-zero +
    /// proportional), landed here as this crate's §7 red test. Introduced
    /// `#[ignore]`'d (red against the truncating code) and un-ignored in the same
    /// Stage-1 diff that landed the micro fix — the ratified acceptance gate. It
    /// is enabled and green; the history is recorded because it is *why* the test
    /// exists, not a pending step.
    /// **D3/R2 acceptance gate — the plateau is deleted from the reward path.**
    ///
    /// Mirror of [`bulk_holder_past_cliff_earns_proportional_not_zero`] (the
    /// Stage-1 gate): written to be **red against the capping code** and green
    /// only once `curve_milli` no longer gates `capped_work_milli`, so "the
    /// plateau is gone" is a checkmark rather than an absence a reader must
    /// verify by inspection.
    ///
    /// Drives the **production** constructor `EpochCloseInputs::close_view`, whose
    /// signature does not carry the curve — so this test compiles on both sides of
    /// the deletion and the only thing that moves is the verdict.
    ///
    /// The expectation is **derived from the production primitives**
    /// (`scarcity_micro` → `work_milli_from_micro`), never hardcoded, and the test
    /// **arms itself**: it asserts the configuration actually lands past the
    /// plateau knee, so it cannot pass vacuously if the fixture drifts below the
    /// regime it is meant to exercise.
    #[test]
    fn credited_work_is_linear_no_plateau_compression() {
        // Sole holder of many shards ⇒ r_market = 1, maximal per-shard scarcity,
        // and enough shards to land well past the plateau knee.
        const N_SHARDS: usize = 40;
        let bonds = [EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &[],
        }];
        // `has_segment: true` so the age term is LIVE — with it false the age is
        // zeroed (`epoch_close_missing_segment_zeroes_age_not_scarcity`) and the
        // fixture would silently exercise a weaker `g`, weakening the arm.
        let shards: Vec<EpochCloseShard> = (0..N_SHARDS)
            .map(|i| EpochCloseShard {
                shard_id: i as u64,
                has_segment: true,
                freeze_height: 0,
            })
            .collect();
        let pairs: Vec<CreditPair> = (0..N_SHARDS)
            .map(|shard_idx| CreditPair {
                bond_idx: 0,
                shard_idx,
            })
            .collect();

        let inputs = EpochCloseInputs::close_view(5, 60_000, &bonds, &shards, &pairs);

        // Linear expectation through the same primitives consensus uses.
        let age = shard_age_milli(60_000, 0, inputs.settlement_epoch_blocks);
        let per_shard = scarcity_micro(1, age, inputs.age_weight_milli);
        let linear_milli = work_milli_from_micro(per_shard * N_SHARDS as u64);

        // ARM: the fixture must sit in the regime the plateau *used to* compress,
        // or this test proves nothing. The retired value is carried here as a
        // literal precisely because the constant is deleted — the marker has to
        // outlive the mechanism it marks, else the arm silently stops arming.
        const RETIRED_PLATEAU_VALUE_MILLI: u64 = 8_000;
        assert!(
            linear_milli > RETIRED_PLATEAU_VALUE_MILLI,
            "fixture must exceed the retired plateau value to exercise the \
             compression regime: linear={linear_milli} retired_plateau={RETIRED_PLATEAU_VALUE_MILLI}"
        );

        let sigma = epoch_close_compute(&inputs).unwrap().sigma_work_milli;
        assert_eq!(
            sigma, linear_milli,
            "credited work must be LINEAR: the plateau no longer compresses the \
             reward path (got {sigma}, linear {linear_milli})"
        );
    }

    #[test]
    fn bulk_holder_past_cliff_earns_proportional_not_zero() {
        // crowd = 1000 ⇒ r_market = 1001 > g_milli = 1000 ⇒ the pre-fix per-shard
        // floor was 0 (`floor(1000/1001)`). This is the real fresh-shard cliff.
        const CROWD: usize = 1000;
        let work_10 = victim_work_over_crowded_shards(10, CROWD);
        let work_20 = victim_work_over_crowded_shards(20, CROWD);

        assert!(
            work_10 > 0,
            "a bulk holder of 10 common shards (r_market=1001) must earn > 0, got {work_10} milli"
        );
        assert!(
            work_20 > 0,
            "a bulk holder of 20 common shards must earn > 0, got {work_20} milli"
        );
        // Proportional to shard count: 2x the shards ⇒ ~2x the work (integer
        // floor slack of a few milli is fine — the property is proportionality,
        // not exact doubling).
        assert!(
            work_20 > work_10,
            "work must grow with shard count: 20-shard {work_20} !> 10-shard {work_10}"
        );
        assert!(
            work_20.abs_diff(2 * work_10) <= 2,
            "work should be ~proportional to shard count: 2 x (10-shard {work_10}) vs 20-shard {work_20}"
        );
    }

    /// §11.5 rounding-direction demonstration (ERC-4626 post-mortem discipline):
    /// every rounding in the micro path floors **against the claimant**, so the
    /// residual error always favours the protocol — never the reverse.
    ///
    /// Worked at the fresh-shard cliff (`r_market = 1001`, `g_milli = 1000`):
    /// 1. Per-shard [`scarcity_micro`] floors `10⁶·1000/1001 = 999.0009…` down to
    ///    `999` micro — the claimant loses the `.0009`, not gains a rounded-up
    ///    `1000`.
    /// 2. The single aggregate [`work_milli_from_micro`] floors the 10-shard sum
    ///    `9990` micro `= 9.99` milli down to `9` — the claimant's honest
    ///    `9.99` milli entitlement is truncated to `9`; the dropped `0.99`
    ///    milli stays with the protocol.
    ///
    /// Both directions asserted explicitly (equal to the floor, strictly less
    /// than the round-up) so a future change to `mul_div_floor` or the divide
    /// that silently rounded up would fail here.
    #[test]
    fn micro_path_rounds_against_the_claimant() {
        // Step 1: per-shard scarcity floors down.
        assert_eq!(
            scarcity_micro(1001, 0, 0),
            999,
            "scarcity_micro floors 10^6/1001 = 999.0009… down to 999"
        );
        assert!(
            scarcity_micro(1001, 0, 0) < 1000,
            "must not round up to 1000"
        );

        // Step 2: the single aggregate floor drops the sub-milli remainder.
        let ten_shard_micro = 10 * scarcity_micro(1001, 0, 0); // 9990 micro = 9.99 milli
        assert_eq!(ten_shard_micro, 9_990);
        assert_eq!(
            work_milli_from_micro(ten_shard_micro),
            9,
            "9.99 milli floors down to 9 — the .99 favours the protocol"
        );
        assert!(
            work_milli_from_micro(ten_shard_micro) < 10,
            "must not round up to 10"
        );
    }

    #[test]
    fn epoch_close_complete_tree_excluded_from_market_and_sigma() {
        let bonds = [EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: true,
            bad_intervals: &[],
        }];
        let shards = [shard(7, 0)];
        let pairs = [CreditPair {
            bond_idx: 0,
            shard_idx: 0,
        }];
        let out = epoch_close_compute(&close_inputs(&bonds, &shards, &pairs)).unwrap();
        assert_eq!(out.r_market_by_shard, vec![0]);
        assert_eq!(out.sigma_work_milli, 0);
    }

    #[test]
    fn drop_after_serve_credit_counts_toward_work() {
        // WS-1 drop-after-serve KAT (REWARD_EMISSION_E3_GATING_ROUND.md §5.6):
        // a serve-credit row is a proven held-and-served-at-fire fact, so it
        // earns work even when `P` no longer holds the shard by close. The
        // retired descriptor filter got exactly this case wrong (under-count →
        // M2-1 over/under-mint once verify copies the sourcing); the work
        // channel now carries no holdings descriptor for any filter to
        // consult, and this KAT is the regression guard on that deletion.
        let bonds = [EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &[],
        }];
        let shards = [shard(7, 0)];
        let pairs = [CreditPair {
            bond_idx: 0,
            shard_idx: 0,
        }];
        let out = epoch_close_compute(&close_inputs(&bonds, &shards, &pairs)).unwrap();
        assert_eq!(out.r_market_by_shard, vec![1]);
        // R=1, age_weight=0 → scarcity 1000 milli; the credit's work is
        // counted from the ledger alone.
        assert_eq!(out.sigma_work_milli, 1_000);
    }

    // The close/verify shared-sourcing identity — that summing the emission
    // numerator's per-P `Curve(work_P)` terms reproduces the persisted Σwork(E)
    // denominator exactly — is pinned end-to-end through the real FFI numerator
    // in `shekyl-ffi::archival_ffi::emission_epoch_work_sums_to_persisted_sigma`
    // (distinct per-P terms, non-members zeroed). A unit-level restatement here
    // could only re-run `epoch_close_compute`'s own `sigma_work_milli` +
    // `as_of_e_served_work` expressions against themselves (tautological), so it
    // is deliberately not duplicated at this layer.

    #[test]
    fn epoch_close_bad_interval_excludes_bond_everywhere() {
        let bad = [BadInterval {
            start_epoch: 4,
            end_exclusive: u64::MAX,
        }];
        let bonds = [EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &bad,
        }];
        let shards = [shard(7, 0)];
        let pairs = [CreditPair {
            bond_idx: 0,
            shard_idx: 0,
        }];
        let out = epoch_close_compute(&close_inputs(&bonds, &shards, &pairs)).unwrap();
        assert_eq!(out.r_market_by_shard, vec![0]);
        assert_eq!(out.sigma_work_milli, 0);
    }

    #[test]
    fn epoch_close_missing_segment_zeroes_age_not_scarcity() {
        let bonds = [EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &[],
        }];
        let shards = [EpochCloseShard {
            shard_id: 7,
            has_segment: false,
            freeze_height: 0,
        }];
        let pairs = [CreditPair {
            bond_idx: 0,
            shard_idx: 0,
        }];
        let mut inputs = close_inputs(&bonds, &shards, &pairs);
        inputs.age_weight_milli = 500;
        let out = epoch_close_compute(&inputs).unwrap();
        // age 0 → g(age) = 1000 milli → scarcity 1000/R = 1000.
        assert_eq!(out.sigma_work_milli, 1_000);
    }

    #[test]
    fn epoch_close_shared_shard_splits_scarcity() {
        let bond = EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &[],
        };
        let bonds = [bond.clone(), bond];
        let shards = [shard(7, 0)];
        let pairs = [
            CreditPair {
                bond_idx: 0,
                shard_idx: 0,
            },
            CreditPair {
                bond_idx: 1,
                shard_idx: 0,
            },
        ];
        let out = epoch_close_compute(&close_inputs(&bonds, &shards, &pairs)).unwrap();
        assert_eq!(out.r_market_by_shard, vec![2]);
        // R=2 → scarcity 500 each; two bonds → Σ curve(500) = 1000.
        assert_eq!(out.sigma_work_milli, 1_000);
    }

    #[test]
    fn epoch_close_rejects_out_of_range_indices() {
        let bonds: [EpochCloseBond<'_>; 0] = [];
        let shards = [shard(7, 0)];
        let pairs = [CreditPair {
            bond_idx: 0,
            shard_idx: 0,
        }];
        let err = epoch_close_compute(&close_inputs(&bonds, &shards, &pairs)).unwrap_err();
        assert_eq!(err.pair_index, 0);
    }

    #[test]
    fn shard_age_milli_is_relative_depth_fraction() {
        // Genesis-band shard: frozen in the first epoch, age = chain depth → 1000.
        assert_eq!(shard_age_milli(60_000, 0, 10_000), 1_000);
        // Frozen this epoch → 0 (epoch floor).
        assert_eq!(shard_age_milli(60_000, 55_000, 10_000), 0);
        assert_eq!(shard_age_milli(60_000, 60_000, 10_000), 0);
        // Interior depth: age_epochs 4 over chain_epochs 11 → floor(4000/11) = 363.
        assert_eq!(shard_age_milli(110_000, 70_000, 10_000), 363);
        assert_eq!(shard_age_milli(110_000, 5_000, 10_000), 909);
        // Before the first settlement epoch completes, everything is hot.
        assert_eq!(shard_age_milli(9_999, 0, 10_000), 0);
        // Degenerate SEB.
        assert_eq!(shard_age_milli(60_000, 0, 0), 0);
        // Bounded at pathological heights — never exceeds WORK_MILLI_SCALE.
        assert_eq!(shard_age_milli(u64::MAX, 0, 1), 1_000);
    }

    #[test]
    fn epoch_close_due_only_at_nonzero_boundaries() {
        assert_eq!(epoch_close_due_at_height(0), None);
        assert_eq!(epoch_close_due_at_height(1), None);
        assert_eq!(epoch_close_due_at_height(SETTLEMENT_EPOCH_BLOCKS - 1), None);
        assert_eq!(epoch_close_due_at_height(SETTLEMENT_EPOCH_BLOCKS), Some(0));
        assert_eq!(epoch_close_due_at_height(SETTLEMENT_EPOCH_BLOCKS + 1), None);
        assert_eq!(
            epoch_close_due_at_height(7 * SETTLEMENT_EPOCH_BLOCKS),
            Some(6)
        );
    }

    #[test]
    fn epoch_close_height_is_the_inverse_of_epoch_close_due() {
        // The genesis-frozen close-boundary mapping, single-sourced here so callers don't
        // re-derive `(E+1)·SEB` and drift. Epoch E closes at (E+1)·SEB, and the inverse
        // round-trips.
        for epoch in 0..6u64 {
            let close = epoch_close_height(epoch).expect("no overflow for small epochs");
            assert_eq!(close, (epoch + 1) * SETTLEMENT_EPOCH_BLOCKS);
            assert_eq!(
                epoch_close_due_at_height(close),
                Some(epoch),
                "epoch_close_due_at_height ∘ epoch_close_height is identity at the boundary"
            );
        }
        // Fails closed on overflow rather than wrapping.
        assert_eq!(epoch_close_height(u64::MAX), None);
    }

    #[test]
    fn prune_horizon_opens_after_claim_window() {
        let w = 26;
        assert_eq!(prune_below_epoch_at_height(0, w), None);
        assert_eq!(
            prune_below_epoch_at_height(26 * SETTLEMENT_EPOCH_BLOCKS, w),
            None
        );
        assert_eq!(
            prune_below_epoch_at_height(27 * SETTLEMENT_EPOCH_BLOCKS, w),
            Some(1)
        );
    }

    #[test]
    fn settlement_epoch_at_height_floors() {
        assert_eq!(settlement_epoch_at_height(0), 0);
        assert_eq!(settlement_epoch_at_height(SETTLEMENT_EPOCH_BLOCKS - 1), 0);
        assert_eq!(settlement_epoch_at_height(SETTLEMENT_EPOCH_BLOCKS), 1);
    }
}
