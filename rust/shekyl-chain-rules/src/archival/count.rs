// Copyright (c) 2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The count phase (`SO-D12` increment 3).
//!
//! The last phase of the archival transition. Every connecting height
//! records one [`BlockDraws`]: how many draws this block's producer makes,
//! the fraction carried to the next block, and the visible shortfall the
//! count was computed from. `issued_short` stays zero until admission
//! (increment 4) writes it, and `revealed` stays false until a bundle is
//! admitted.
//!
//! The row is written at every height, including a schedule with no
//! response window, which draws nothing. A failure here is [`Corrupt`]:
//! the writer halts, and the block is not refused.

use shekyl_archival_retention::{draw_count, draw_horizon, DrawableEpoch};
use shekyl_types::archival::{BlockDraws, COUNTED_DRAWS};
use shekyl_types::{BlockHash, BlockHeight};

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::epoch_floor::{BlockDrawsFloor, EpochFloor, ReleaseJournalFloor};
use crate::fault::{Corrupt, DrawCountFault, DrawableEpochFault, ViewRead};
use crate::rules::Rule;
use crate::view::{AtHeight, ChainView};

use super::drawable;
use super::memo::DrawableMemo;

/// CEN-L17: the count. One row per connected height, derived here and
/// written by the store. A windowless schedule records a zero row; every
/// other failure is a [`Corrupt`] that halts the writer.
pub(crate) struct L17;

impl Rule for L17 {
    const ROW: CenRow = CenRow::L17;
}

/// The opening block's hash and the memo keyed by it.
///
/// One value: the transition takes the pair the count reads together,
/// rather than two arguments beside the five the transition already holds.
pub(crate) struct CountMemo<'a> {
    /// The connecting block's hash. At an epoch's open the memo stores
    /// the post-state set under it.
    pub open_hash: BlockHash,
    /// The connect loop's memo. [`None`] rebuilds on every miss.
    pub memo: Option<&'a mut DrawableMemo>,
}

fn zero() -> BlockDraws {
    BlockDraws {
        count: 0,
        carry: 0,
        shortfall: 0,
        issued_short: 0,
        revealed: false,
    }
}

/// The row stores the count in a `u32`. A count that does not fit is the
/// width fault, not a wrapped value. Production's cap keeps a count far
/// below this; the fault is what a target past it becomes.
fn narrow_count(count: u64) -> Result<u32, DrawCountFault> {
    u32::try_from(count).map_err(|_| DrawCountFault::CountPastWidth { count })
}

fn fault<VF>(height: BlockHeight, why: DrawCountFault) -> ViewRead<VF> {
    ViewRead::Corrupt(Corrupt::DrawCount { height, why })
}

impl super::Transition {
    /// The count of the block this transition is connecting.
    ///
    /// `opened` is the post-state drawable set when the block is
    /// `h_open(E)`, and [`None`] at every other height. At the open the
    /// count reads that set and does not consult the memo.
    ///
    /// # Errors
    ///
    /// [`ViewRead::View`] for the view's own fault. [`ViewRead::Corrupt`] when
    /// the prior row is missing, an admission issued more than the shortfall,
    /// the count does not fit `u32`, the horizon arithmetic has no target, or
    /// the drawable set cannot be read — the same class a settlement compare
    /// already raises for a drifted or missing set.
    pub(super) fn block_draws<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        opened: Option<&DrawableEpoch>,
        count_memo: &mut CountMemo<'_>,
        coverage: &mut RuleCoverage,
    ) -> Result<BlockDraws, ViewRead<V::Fault>> {
        let connecting = self.connecting;
        let schedule = self.schedule;
        let epoch = self.epoch;
        // One match, the same fact `bundle_section::inside_window` reads: a
        // schedule with no window has nothing a bundle can land inside, so it
        // draws nothing. `draw_horizon` is not called — a stand-in window is
        // not a window. The row is still written, so the next height's read of
        // this one finds it. The shortfall is zero because the count is not
        // computed: there is no visible shortfall to carry when nothing is drawn.
        let Some(window) = schedule.challenge_response_blocks() else {
            coverage.insert(L17::ROW);
            return Ok(zero());
        };

        let height = connecting.to_raw();
        let h_open = schedule.open_height(epoch.to_raw());
        let at_open = height == h_open;
        let floor = BlockDrawsFloor::in_force(connecting, schedule);
        let prior = if height > 0 {
            Some(require_row(
                view,
                BlockHeight::from_raw(height - 1),
                floor,
                connecting,
            )?)
        } else {
            None
        };

        let set_size = self.resolve_len(view, at_open, opened, count_memo)?;
        let (visible, carry_in) = if at_open {
            let visible = u64::try_from(COUNTED_DRAWS)
                .ok()
                .and_then(|counted| counted.checked_mul(set_size))
                .ok_or_else(|| fault(connecting, DrawCountFault::ShortfallOverflow))?;
            (visible, 0)
        } else {
            let prior = prior.ok_or_else(|| {
                fault(
                    connecting,
                    DrawCountFault::MissingPrior {
                        prior: BlockHeight::from_raw(height.saturating_sub(1)),
                    },
                )
            })?;
            let issued = u64::from(prior.issued_short);
            if issued > prior.shortfall {
                return Err(fault(
                    connecting,
                    DrawCountFault::IssuedExceedsShortfall {
                        issued: prior.issued_short,
                        shortfall: prior.shortfall,
                    },
                ));
            }
            (prior.shortfall - issued, prior.carry)
        };

        let in_flight = in_flight(view, height, h_open, window.get(), floor, connecting)?;
        let unsettled = visible.saturating_sub(in_flight);
        let horizon = draw_horizon(height - h_open, schedule.blocks().get(), window.get());
        let Some((count, carry)) = draw_count(
            set_size,
            unsettled,
            horizon,
            schedule.blocks().get(),
            carry_in,
        ) else {
            return Err(fault(connecting, DrawCountFault::NoTarget));
        };
        let count = narrow_count(count).map_err(|why| fault(connecting, why))?;
        coverage.insert(L17::ROW);
        Ok(BlockDraws {
            count,
            carry,
            shortfall: visible,
            issued_short: 0,
            revealed: false,
        })
    }

    /// `|D|` for this block's count.
    ///
    /// At `h_open` that is the post-state set the transition just built, and
    /// the memo learns it under the opening hash. Later heights read the memo
    /// and, on a miss, rebuild from the view and keep the rebuild only when
    /// it matches the recorded digest.
    fn resolve_len<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        at_open: bool,
        opened: Option<&DrawableEpoch>,
        count_memo: &mut CountMemo<'_>,
    ) -> Result<u64, ViewRead<V::Fault>> {
        let connecting = self.connecting;
        let schedule = self.schedule;
        let epoch = self.epoch;
        let reorg_cap = self.reorg_cap;
        let slash_floor = self.slash_floor;
        let open_hash = count_memo.open_hash;
        if at_open {
            let drawable =
                opened.ok_or_else(|| fault(connecting, DrawCountFault::OpenUnrecorded))?;
            let len = drawable.len();
            if let Some(memo) = count_memo.memo.as_mut() {
                memo.evict(connecting, schedule);
                memo.insert(epoch, open_hash, drawable.clone());
            }
            return Ok(len);
        }

        let h_open = BlockHeight::from_raw(schedule.open_height(epoch.to_raw()));
        let recorded = match view.header_at(h_open).map_err(ViewRead::View)? {
            AtHeight::Recorded(header) => header.hash,
            AtHeight::AboveTip => return Err(fault(connecting, DrawCountFault::OpenUnrecorded)),
        };
        if let Some(memo) = count_memo.memo.as_mut() {
            memo.evict(connecting, schedule);
            if let Some(cached) = memo.get(epoch, &recorded) {
                return Ok(cached.len());
            }
        }

        let journal = ReleaseJournalFloor::of(EpochFloor::under(connecting, schedule), schedule);
        let rebuilt = super::drawable_epoch_walked_back(
            view,
            epoch,
            schedule,
            reorg_cap,
            journal,
            slash_floor,
        )?;
        let written = view
            .drawable_digest(epoch, EpochFloor::under(connecting, schedule))
            .map_err(ViewRead::View)?;
        drawable::compare_recorded_digest(epoch, h_open, written, rebuilt.as_ref())
            .map_err(ViewRead::Corrupt)?;
        let Some(rebuilt) = rebuilt else {
            return Err(ViewRead::Corrupt(Corrupt::DrawableEpoch {
                epoch,
                why: DrawableEpochFault::Unopened { h_open },
            }));
        };
        let len = rebuilt.len();
        if let Some(memo) = count_memo.memo.as_mut() {
            memo.insert(epoch, recorded, rebuilt);
        }
        Ok(len)
    }
}

fn require_row<'id, V: ChainView<'id>>(
    view: &V,
    height: BlockHeight,
    floor: BlockDrawsFloor,
    reporting: BlockHeight,
) -> Result<BlockDraws, ViewRead<V::Fault>> {
    match view.block_draws(height, floor).map_err(ViewRead::View)? {
        Some(row) => Ok(row),
        None => Err(fault(
            reporting,
            DrawCountFault::MissingPrior { prior: height },
        )),
    }
}

/// The draws still in flight: the `count` of every unrevealed row in
/// `[max(h − W₂, h_open), h)`.
fn in_flight<'id, V: ChainView<'id>>(
    view: &V,
    height: u64,
    h_open: u64,
    window: u64,
    floor: BlockDrawsFloor,
    connecting: BlockHeight,
) -> Result<u64, ViewRead<V::Fault>> {
    let start = height.saturating_sub(window).max(h_open);
    let mut sum = 0u64;
    let mut at = start;
    while at < height {
        let row = require_row(view, BlockHeight::from_raw(at), floor, connecting)?;
        if !row.revealed {
            sum = sum
                .checked_add(u64::from(row.count))
                .ok_or_else(|| fault(connecting, DrawCountFault::InFlightOverflow))?;
        }
        at += 1;
    }
    Ok(sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::fixture::chain_of;
    use crate::view::{AtHeight, HeaderView};
    use crate::RuleSet;
    use shekyl_archival_retention::{draw_count, draw_horizon, DrawablePair};
    use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
    use shekyl_types::archival::SettlementEpochBlocks;
    use shekyl_types::{BlockCount, PCanonicalId, SettlementEpoch, ShardId};

    fn one_pair(epoch: SettlementEpoch) -> DrawableEpoch {
        let persona = PCanonicalId::from_bytes([0x10; 32]);
        let key = HybridEd25519FnDsa::keypair_from_seeds(&[1; 32], &[101; 32])
            .expect("keygen")
            .0
            .to_receipt_sign_pk();
        DrawableEpoch::new(
            epoch,
            [(persona, key)],
            [DrawablePair {
                persona,
                shard: ShardId::from_raw(1),
            }],
        )
        .expect("one pair, one key")
    }

    /// The count is stored in a `u32`. A chain's cap never reaches the next
    /// value; the narrowing is the fault that would. Red edit: `as u32`.
    #[test]
    fn a_count_past_u32_does_not_narrow() {
        assert_eq!(
            narrow_count(u64::from(u32::MAX)).expect("the width"),
            u32::MAX
        );
        assert_eq!(
            narrow_count(u64::from(u32::MAX) + 1),
            Err(DrawCountFault::CountPastWidth {
                count: u64::from(u32::MAX) + 1
            })
        );
    }

    /// A schedule with no window draws nothing, and the row is still
    /// written. Height 0 with no post-state set would be `OpenUnrecorded`
    /// if the count were computed. Red edit: pass `0` to `draw_horizon`,
    /// or skip the row.
    #[test]
    fn a_windowless_schedule_records_a_zero_row_without_a_set() {
        let blocks = SettlementEpochBlocks::new(2).expect("non-zero");
        let paired = crate::FakechainSchedule::new(blocks, BlockCount::from_raw(1))
            .expect("the cap is inside the epoch");
        let rules = RuleSet::fakechain(None, paired);
        let chain = chain_of(1);
        chain.with_view(|view| {
            let mut coverage = RuleCoverage::EMPTY;
            let transition = super::super::Transition::new(
                BlockHeight::ZERO,
                rules.settlement_schedule(),
                rules.reorg_cap(),
            );
            let mut count_memo = CountMemo {
                open_hash: BlockHash::NULL,
                memo: None,
            };
            let row = transition
                .block_draws(&view, None, &mut count_memo, &mut coverage)
                .expect("a windowless count does not read the chain");
            assert_eq!(row, zero());
            assert!(coverage.contains(CenRow::L17));
        });
    }

    /// The memo answers `|D|` only for the opening block's own hash. A
    /// different hash misses and rebuilds this view's empty set, whose
    /// digest the harness records. The missing-digest halt is the store
    /// test. Red edit: key the memo by the epoch alone.
    #[test]
    fn the_count_reads_the_set_stored_under_the_opening_hash() {
        let rules = RuleSet::GENESIS;
        let schedule = rules.settlement_schedule();
        let window = schedule
            .challenge_response_blocks()
            .expect("genesis has a window")
            .get();
        let chain = chain_of(2);
        chain.with_view(|view| {
            let open = match view.header_at(BlockHeight::ZERO).expect("header") {
                AtHeight::Recorded(header) => header.hash,
                AtHeight::AboveTip => panic!("height 0 is on the chain"),
            };
            let epoch = SettlementEpoch::from_raw(0);
            let mut memo = DrawableMemo::new();
            memo.insert(epoch, open, one_pair(epoch));
            let connecting = BlockHeight::from_raw(1);
            let transition = super::super::Transition::new(connecting, schedule, rules.reorg_cap());
            let mut coverage = RuleCoverage::EMPTY;
            let mut count_memo = CountMemo {
                open_hash: open,
                memo: Some(&mut memo),
            };
            let hit = transition
                .block_draws(&view, None, &mut count_memo, &mut coverage)
                .expect("the opening hash hits");
            let (count, carry) = draw_count(
                1,
                0,
                draw_horizon(1, schedule.blocks().get(), window),
                schedule.blocks().get(),
                0,
            )
            .expect("the horizon fits");
            assert_eq!(hit.count, u32::try_from(count).expect("the count fits"));
            assert_eq!(hit.carry, carry);
            assert_eq!(hit.shortfall, 0);
            assert_eq!(hit.issued_short, 0);
            assert!(!hit.revealed);

            let mut other = DrawableMemo::new();
            other.insert(epoch, BlockHash::from_bytes([0xff; 32]), one_pair(epoch));
            let mut miss_coverage = RuleCoverage::EMPTY;
            let mut miss_memo = CountMemo {
                open_hash: open,
                memo: Some(&mut other),
            };
            let miss = transition
                .block_draws(&view, None, &mut miss_memo, &mut miss_coverage)
                .expect("the miss rebuilds this view's empty set");
            assert_eq!(
                miss,
                zero(),
                "a set stored under another opening hash is not this chain's"
            );
            assert_ne!(miss.carry, hit.carry);
        });
    }
}
