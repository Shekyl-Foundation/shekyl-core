//! Pure consensus-state computation for emission reads (ARCHIVAL_CONSENSUS_STATE.md §3–§5).
//!
//! No LMDB. This module is the **single implementation** of the epoch-close
//! consensus semantics: the C++ daemon gathers raw rows from LMDB, calls
//! [`epoch_close_compute`] through `shekyl-ffi`, and stores the returned
//! `R_market` / `Σwork` values. C++ performs no consensus arithmetic of its
//! own (`20-rust-vs-cpp-policy.mdc` §4; `40-ffi-discipline.mdc` coarse-call rule).

use crate::constants::SETTLEMENT_EPOCH_BLOCKS;
use crate::reward_arithmetic::{
    curve_milli, mul_div_floor, scarcity_milli, BandedCurveParams, WORK_MILLI_SCALE,
};

const _: () = assert!(
    SETTLEMENT_EPOCH_BLOCKS > 0,
    "settlement epoch must be nonzero"
);

/// Settlement epoch containing `block_height` (`floor(height / SETTLEMENT_EPOCH_BLOCKS)`).
///
/// Used for bond-connect `join_settlement_epoch` derivation and prune-horizon
/// arithmetic; the daemon performs no epoch arithmetic of its own.
#[must_use]
pub fn settlement_epoch_at_height(block_height: u64) -> u64 {
    block_height / SETTLEMENT_EPOCH_BLOCKS
}

/// Settlement epoch that closes at `block_height`, when one does.
///
/// Epoch `E` covers heights `[E·SEB, (E+1)·SEB)`; its close is processed at
/// the first height of the next epoch (`(E+1)·SEB`). Returns `None` at
/// height 0 and at non-boundary heights.
#[must_use]
pub fn epoch_close_due_at_height(block_height: u64) -> Option<u64> {
    if block_height == 0 || !block_height.is_multiple_of(SETTLEMENT_EPOCH_BLOCKS) {
        return None;
    }
    Some(block_height / SETTLEMENT_EPOCH_BLOCKS - 1)
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
        .and_then(|next| next.checked_mul(SETTLEMENT_EPOCH_BLOCKS))
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

/// Half-open bad-standing interval `[start_epoch, end_exclusive)`.
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

/// Work milli for one held shard with serve credit.
#[must_use]
pub fn shard_work_milli(
    r_market: u64,
    age_milli: u64,
    age_weight_milli: u64,
    serve_credit: bool,
) -> u64 {
    if !serve_credit || r_market == 0 {
        return 0;
    }
    scarcity_milli(r_market, age_milli, age_weight_milli)
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
pub fn sigma_work_milli(
    per_p_work_milli: &[u64],
    curve: &BandedCurveParams,
    market_mask: &[bool],
) -> u64 {
    assert_eq!(
        per_p_work_milli.len(),
        market_mask.len(),
        "per-P work and market mask must be parallel slices"
    );
    let mut sum = 0u64;
    for (&work, &in_market) in per_p_work_milli.iter().zip(market_mask.iter()) {
        if !in_market || work == 0 {
            continue;
        }
        sum = sum.saturating_add(curve_milli(work, curve));
    }
    sum
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
#[derive(Debug, Clone)]
pub struct EpochCloseBond<'a> {
    pub join_settlement_epoch: u64,
    pub is_foundation_complete_tree: bool,
    pub bad_intervals: &'a [BadInterval],
    pub held_shard_ids: &'a [u64],
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
    pub curve: BandedCurveParams,
    pub bonds: &'a [EpochCloseBond<'a>],
    pub shards: &'a [EpochCloseShard],
    pub credit_pairs: &'a [CreditPair],
    /// M1 reward-gate input (`ARCHIVAL_REWARD_GATE_M1.md` §1.1): the
    /// segment-table count at `H_close(E)` — rows in
    /// `m_archival_shard_segment` with `freeze_height ≤ H_close(E)`, counted
    /// by the C++ gather's single `count_frozen_shards_at_close` helper
    /// inside the close's write transaction. **Not** derivable from
    /// [`Self::shards`]: the gather enumerates credit-bearing shards (a
    /// participation measurement — exactly the sensor class the gate
    /// refuses, §11 M2-1); the segment-table count is structural and
    /// monotone per branch.
    pub frozen_shard_count: u64,
    /// The M1 cover threshold. Production callers (the FFI shim) thread
    /// [`crate::k_cover::K_COVER`] here verbatim; the KAT injects per-case
    /// values so the fixtures survive the §4 constant finalization without
    /// rewrite. The *comparison* lives only in [`epoch_close_compute`]
    /// (§6 tripwire) — threading the value is not a second predicate site.
    pub k_cover: u64,
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

/// Full epoch-close consensus computation (ARCHIVAL_CONSENSUS_STATE.md §3.3, §3.5).
///
/// Composes the pinned semantics in one deterministic pass:
///
/// 0. **M1 reward gate** (`ARCHIVAL_REWARD_GATE_M1.md` §2.1) — for epochs
///    whose `frozen_shard_count` is below `k_cover` (threaded from
///    [`K_COVER`](crate::k_cover::K_COVER) by the production FFI caller),
///    the result is the zero output (`r_market_by_shard: [0; n]`,
///    `sigma_work_milli: 0`) **without computing the internal derivation** —
///    zero-at-top, so no consensus quantity derived from a gated epoch is
///    ever non-zero. This is the **only** `K_COVER` comparison site in the
///    codebase (§6 tripwire); the claimability rule inherits through the
///    zeroed stored `Σwork` + wire positivity, never through a second
///    predicate.
/// 1. **Market membership** per bond — [`market_member_at_epoch`].
/// 2. **`R_market(shard, E)`** — count of serve-credit rows whose `P` is a
///    market member (§3.3 pinned measure).
/// 3. **`work_P`** — Σ over credited *held* shards of
///    [`shard_work_milli`] (scarcity × age weighting), saturating.
/// 4. **`Σwork(E)`** — [`sigma_work_milli`] over per-bond `Curve(work_P)`.
///
/// Errors (rather than panics) on malformed gather indices so the FFI shim
/// can map the failure to a loud daemon-side abort. The gather-index check
/// runs **before** the gate so a malformed gather aborts loudly on gated
/// epochs too (the gate zeroes outputs, never accountability — §3.1).
pub fn epoch_close_compute(
    inputs: &EpochCloseInputs<'_>,
) -> Result<EpochCloseResult, CreditIndexOutOfRange> {
    let bonds = inputs.bonds;
    let shards = inputs.shards;

    for (pair_index, pair) in inputs.credit_pairs.iter().enumerate() {
        if pair.bond_idx >= bonds.len() || pair.shard_idx >= shards.len() {
            return Err(CreditIndexOutOfRange { pair_index });
        }
    }

    if inputs.frozen_shard_count < inputs.k_cover {
        return Ok(EpochCloseResult {
            r_market_by_shard: vec![0u64; shards.len()],
            sigma_work_milli: 0,
        });
    }

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

    // Shard age feeds `shard_work_milli` only for member-held credited shards
    // (the guarded branch below), so compute it lazily and memoize per shard
    // index — a shard whose only credit comes from a non-member or non-holding
    // bond never pays the two `shard_age_milli` divisions.
    let mut age_milli_by_shard: Vec<Option<u64>> = vec![None; shards.len()];

    let mut work_by_bond = vec![0u64; bonds.len()];
    for pair in inputs.credit_pairs {
        if !member[pair.bond_idx] {
            continue;
        }
        let shard = &shards[pair.shard_idx];
        if !bonds[pair.bond_idx]
            .held_shard_ids
            .contains(&shard.shard_id)
        {
            continue;
        }
        let age_milli = *age_milli_by_shard[pair.shard_idx].get_or_insert_with(|| {
            if shard.has_segment {
                shard_age_milli(
                    inputs.close_block_height,
                    shard.freeze_height,
                    inputs.settlement_epoch_blocks,
                )
            } else {
                0
            }
        });
        let contribution = shard_work_milli(
            r_market_by_shard[pair.shard_idx],
            age_milli,
            inputs.age_weight_milli,
            true,
        );
        work_by_bond[pair.bond_idx] = work_by_bond[pair.bond_idx].saturating_add(contribution);
    }

    let sigma = sigma_work_milli(&work_by_bond, &inputs.curve, &member);

    Ok(EpochCloseResult {
        r_market_by_shard,
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
            curve: BandedCurveParams::from_sim_cap_milli(8_000),
            bonds,
            shards,
            credit_pairs: pairs,
            // Ungated by data (1 ≥ 1), not by the k_cover = 0 degenerate:
            // these tests pin the pre-gate computation through a live gate.
            frozen_shard_count: 1,
            k_cover: 1,
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
        let held = [7u64];
        let bonds = [EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &[],
            held_shard_ids: &held,
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

    #[test]
    fn epoch_close_complete_tree_excluded_from_market_and_sigma() {
        let held: [u64; 0] = [];
        let bonds = [EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: true,
            bad_intervals: &[],
            held_shard_ids: &held,
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
    fn epoch_close_credit_on_unheld_shard_counts_market_not_work() {
        // Member credit on a shard outside its holdings inflates R_market for
        // that shard (§3.3 counts member credits) but earns the bond no work.
        let held = [9u64];
        let bonds = [EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &[],
            held_shard_ids: &held,
        }];
        let shards = [shard(7, 0)];
        let pairs = [CreditPair {
            bond_idx: 0,
            shard_idx: 0,
        }];
        let out = epoch_close_compute(&close_inputs(&bonds, &shards, &pairs)).unwrap();
        assert_eq!(out.r_market_by_shard, vec![1]);
        assert_eq!(out.sigma_work_milli, 0);
    }

    #[test]
    fn epoch_close_bad_interval_excludes_bond_everywhere() {
        let held = [7u64];
        let bad = [BadInterval {
            start_epoch: 4,
            end_exclusive: u64::MAX,
        }];
        let bonds = [EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &bad,
            held_shard_ids: &held,
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
        let held = [7u64];
        let bonds = [EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &[],
            held_shard_ids: &held,
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
        let held = [7u64];
        let bond = EpochCloseBond {
            join_settlement_epoch: 0,
            is_foundation_complete_tree: false,
            bad_intervals: &[],
            held_shard_ids: &held,
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
