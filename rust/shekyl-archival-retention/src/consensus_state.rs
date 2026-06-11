//! Pure consensus-state computation for emission reads (ARCHIVAL_CONSENSUS_STATE.md §3–§5).
//!
//! No LMDB. This module is the **single implementation** of the epoch-close
//! consensus semantics: the C++ daemon gathers raw rows from LMDB, calls
//! [`epoch_close_compute`] through `shekyl-ffi`, and stores the returned
//! `R_market` / `Σwork` values. C++ performs no consensus arithmetic of its
//! own (`20-rust-vs-cpp-policy.mdc` §4; `40-ffi-discipline.mdc` coarse-call rule).

use crate::constants::SETTLEMENT_EPOCH_BLOCKS;
use crate::reward_arithmetic::{curve_milli, scarcity_milli, BandedCurveParams, WORK_MILLI_SCALE};

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

/// Shard age in milli-epochs at `close_block_height` (ARCHIVAL_REWARD_ARITHMETIC.md §"Shard age").
///
/// `age = floor((close_block_height − freeze_height) / settlement_epoch_blocks)`
/// epochs, scaled by [`WORK_MILLI_SCALE`]. Zero when the shard segment is not
/// yet frozen past the close height or `settlement_epoch_blocks` is zero.
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
    age_epochs.saturating_mul(WORK_MILLI_SCALE)
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
/// 1. **Market membership** per bond — [`market_member_at_epoch`].
/// 2. **`R_market(shard, E)`** — count of serve-credit rows whose `P` is a
///    market member (§3.3 pinned measure).
/// 3. **`work_P`** — Σ over credited *held* shards of
///    [`shard_work_milli`] (scarcity × age weighting), saturating.
/// 4. **`Σwork(E)`** — [`sigma_work_milli`] over per-bond `Curve(work_P)`.
///
/// Errors (rather than panics) on malformed gather indices so the FFI shim
/// can map the failure to a loud daemon-side abort.
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

    let age_milli_by_shard: Vec<u64> = shards
        .iter()
        .map(|s| {
            if s.has_segment {
                shard_age_milli(
                    inputs.close_block_height,
                    s.freeze_height,
                    inputs.settlement_epoch_blocks,
                )
            } else {
                0
            }
        })
        .collect();

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
        let contribution = shard_work_milli(
            r_market_by_shard[pair.shard_idx],
            age_milli_by_shard[pair.shard_idx],
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
    fn shard_age_milli_floors_by_settlement_epoch() {
        assert_eq!(shard_age_milli(60_000, 0, 10_000), 6_000);
        assert_eq!(shard_age_milli(60_000, 55_000, 10_000), 0);
        assert_eq!(shard_age_milli(60_000, 60_000, 10_000), 0);
        assert_eq!(shard_age_milli(60_000, 0, 0), 0);
        // saturates instead of overflowing on pathological heights
        assert_eq!(shard_age_milli(u64::MAX, 0, 1), u64::MAX);
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
