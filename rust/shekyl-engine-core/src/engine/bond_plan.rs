// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! When a planned stake comes due, and how long it may wait past that
//! (`ARCHIVAL_BOND_POST_DELAY.md` BD-Q2, BD-Q3; how a plan ends, ruled
//! 2026-11-26).
//!
//! Pure arithmetic over the plan and the live records of the funding it
//! reserved. The dispatch driver reads it to decide what to sign, and the
//! staking read reads the same functions, so the two cannot disagree about
//! whether a plan is due.

use std::collections::BTreeMap;

use shekyl_curve_tree::reference::{select_reference_height, REF_ANCHOR_AGE};
use shekyl_engine_state::pscan_state::PFundingOutputRecord;
use shekyl_engine_state::PendingBondPlan;
use shekyl_types::{BlockCount, BlockHeight, ChainCount, GlobalOutputIndex, PSlot};

use super::stake_timing::DEFAULT_ENTRY_GAP;

/// How long a plan may wait past its due block for a limited reason (a fee
/// above its funding, a node that is not the wallet's own) before it ends
/// and its funding is drained (BD-Q3 as ruled 2026-11-26: measured from the
/// due block; never the 94-block proof lifetime, because a plan holds no
/// proof).
///
/// **One draw window** (ruled 2026-11-27), read from the window's own
/// constant so it moves with BD-Q4: at 600 blocks a plan that cannot sign
/// gives up about 20 hours after it came due.
pub(crate) const PLAN_MAX_WAIT: BlockCount = BlockCount::from_raw(DEFAULT_ENTRY_GAP.as_blocks());

/// Where one live funding output sits: what a plan's anchor and an ended
/// plan's drain read of it. Filled from the scan's accrual by the dispatch
/// tick and from the sealed records by the staking read, so both compute
/// the same due from the same three facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FundingPlace {
    /// The persona slot that owns the output.
    pub(crate) p_slot: PSlot,
    /// The block the output is in.
    pub(crate) height: BlockHeight,
    /// The first height it can be spent at.
    pub(crate) spendable_height: BlockHeight,
}

impl From<&PFundingOutputRecord> for FundingPlace {
    fn from(record: &PFundingOutputRecord) -> Self {
        Self {
            p_slot: record.p_slot,
            height: record.height,
            spendable_height: record.spendable_height,
        }
    }
}

/// The first tip at which the funding output can be swept into a bond
/// (BD-Q2): its leaf in the tree at the canonical reference, and its block
/// covered by the sealed persona scan, whose horizon trails the tip by
/// `reorg_depth`.
fn sweepable_from(record: &FundingPlace, reorg_depth: BlockCount) -> BlockHeight {
    let in_tree = record.spendable_height.saturating_add(REF_ANCHOR_AGE);
    let scanned = record.height.saturating_add(reorg_depth);
    in_tree.max(scanned)
}

/// The plan's due count on the daemon-claimed count clock (BD-Q2):
/// `max(a + 1 + draw, requested_at)`, where `a` is the latest
/// [`sweepable_from`] over the reserved funding.
///
/// `None` when a reserved output has no live record: it was spent by another
/// transaction or reorged away, and the plan cannot be signed against it.
pub(crate) fn plan_due(
    plan: &PendingBondPlan,
    funding: &BTreeMap<GlobalOutputIndex, FundingPlace>,
    reorg_depth: BlockCount,
) -> Option<ChainCount> {
    let mut anchor: Option<BlockHeight> = None;
    for gindex in &plan.funding_gindexes {
        let record = funding.get(gindex)?;
        let from = sweepable_from(record, reorg_depth);
        anchor = Some(anchor.map_or(from, |held| held.max(from)));
    }
    let anchor = anchor?;
    let anchored = ChainCount::with_tip(anchor)?.saturating_add(plan.draw);
    Some(anchored.max(plan.requested_at))
}

/// Whether a plan due at `due` has waited past its maximum at `tip`.
pub(crate) fn past_max_wait(due: ChainCount, tip: ChainCount) -> bool {
    tip >= due.saturating_add(PLAN_MAX_WAIT)
}

/// The canonical reference height for a post first sent at `tip`
/// (BD-Q3 Rule 1): `tip − REF_ANCHOR_AGE` on the daemon-claimed clock, so the
/// first send carries reference age 6 and the full proof lifetime. `None`
/// below the first legal reference.
pub(crate) fn canonical_reference(tip: ChainCount) -> Option<BlockHeight> {
    tip.tip().and_then(select_reference_height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_engine_state::pscan_state::MintLineageOutput;
    use shekyl_engine_state::PlannedPosture;
    use shekyl_types::{PCanonicalId, PSlot};

    fn record(gindex: u64, height: u64, spendable: u64) -> PFundingOutputRecord {
        let mut r = crate::engine::test_support::funding_record(
            0,
            gindex,
            height,
            1_000,
            MintLineageOutput::ExternalTransfer,
        );
        r.spendable_height = BlockHeight::from_raw(spendable);
        r
    }

    fn plan(gindexes: &[u64], draw: u64, requested_at: u64) -> PendingBondPlan {
        PendingBondPlan {
            p_slot: PSlot::from_raw(0),
            persona: PCanonicalId::from_bytes([1; 32]),
            posture: PlannedPosture::SupportCompleteTree,
            draw: BlockCount::from_raw(draw),
            requested_at: ChainCount::from_raw(requested_at),
            funding_gindexes: gindexes
                .iter()
                .copied()
                .map(GlobalOutputIndex::from_raw)
                .collect(),
            funded_through: BlockHeight::from_raw(1_300),
            wait: None,
        }
    }

    /// BD-Q2's instant staker: a funding output at `h_f` anchors at
    /// `h_f + 720` (the scan's horizon dominates the leaf term), and a
    /// request at the anchor is due at count `a + 1 + s`.
    #[test]
    fn an_ordinary_funding_output_anchors_at_its_scan_horizon() {
        let depth = BlockCount::from_raw(720);
        let r = record(7, 1_000, 1_010);
        let funding = BTreeMap::from([(r.gindex, FundingPlace::from(&r))]);
        let due = plan_due(&plan(&[7], 37, 1_721), &funding, depth).expect("live funding");
        assert_eq!(due, ChainCount::from_raw(1_720 + 1 + 37));
    }

    /// The latest anchor governs a multi-input bond (BD-Q2).
    #[test]
    fn the_latest_funding_anchor_governs() {
        let depth = BlockCount::from_raw(720);
        let early = record(1, 1_000, 1_010);
        let late = record(2, 1_300, 1_310);
        let funding = BTreeMap::from([
            (early.gindex, FundingPlace::from(&early)),
            (late.gindex, FundingPlace::from(&late)),
        ]);
        let due = plan_due(&plan(&[1, 2], 0, 0), &funding, depth).expect("live funding");
        assert_eq!(due, ChainCount::from_raw(2_020 + 1));
    }

    /// Elapsed time counts: a request past `a + 1 + s` is due at once, with
    /// no added draw.
    #[test]
    fn a_late_request_is_due_at_its_own_count() {
        let depth = BlockCount::from_raw(720);
        let r = record(7, 1_000, 1_010);
        let funding = BTreeMap::from([(r.gindex, FundingPlace::from(&r))]);
        let due = plan_due(&plan(&[7], 5, 9_000), &funding, depth).expect("live funding");
        assert_eq!(due, ChainCount::from_raw(9_000));
    }

    /// A reserved output with no live record has no due: it was spent.
    #[test]
    fn a_missing_funding_record_has_no_due() {
        let funding = BTreeMap::new();
        assert_eq!(
            plan_due(&plan(&[7], 5, 0), &funding, BlockCount::from_raw(720)),
            None
        );
    }
}
