// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`StoreBundleView`]: [`BundleView`] over a [`BatchView`] and the count
//! phase's [`DrawableMemo`] (`SO-D12` increment 4a).
//!
//! `D` is rules-side state. The store does not compute it, so the view is
//! the batch plus the memo, not the batch alone. A memo miss is SI-35: the
//! count phase of this block has already filed every epoch a section inside
//! the response window can name, and this path does not rebuild.

use std::cell::RefCell;
use std::collections::BTreeMap;

use shekyl_chain_rules::{
    AtHeight, BlockDrawsFloor, BundleView, ChainView, DrawableEpoch, DrawableMemo, EpochFloor,
    HeaderView, SettlementSchedule, Settling,
};
use shekyl_types::archival::{DrawCommitment, IndexedDraw, COUNTED_DRAWS};
use shekyl_types::{BlockHash, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

use super::error::{StoreError, StoreInvariant};
use super::view::BatchView;

/// The admission view: one batch and the memo the count phase filled.
pub struct StoreBundleView<'a, 'b, 'id> {
    view: &'a BatchView<'b, 'id>,
    memo: &'a DrawableMemo,
    /// The block being admitted. Floors and the window are read from it.
    h_incl: BlockHeight,
    schedule: SettlementSchedule,
    /// Issued-draw rows already read, by epoch. One admission reads an
    /// epoch's index once, then answers every pair from that read.
    issued: RefCell<BTreeMap<SettlementEpoch, Vec<IndexedDraw>>>,
}

impl<'a, 'b, 'id> StoreBundleView<'a, 'b, 'id> {
    /// A view of `view` at `h_incl`, reading `D` from `memo`.
    #[must_use]
    pub fn new(
        view: &'a BatchView<'b, 'id>,
        memo: &'a DrawableMemo,
        h_incl: BlockHeight,
        schedule: SettlementSchedule,
    ) -> Self {
        Self {
            view,
            memo,
            h_incl,
            schedule,
            issued: RefCell::new(BTreeMap::new()),
        }
    }

    fn miss(&self, epoch: SettlementEpoch) -> StoreError {
        self.view
            .arm_row(StoreInvariant::DrawableMemoMiss { epoch })
    }

    fn draws_row(
        &self,
        h: BlockHeight,
    ) -> Result<Option<shekyl_types::archival::BlockDraws>, StoreError> {
        let floor = BlockDrawsFloor::in_force(self.h_incl, self.schedule);
        ChainView::block_draws(self.view, h, floor)
    }

    fn issued_of(&self, epoch: SettlementEpoch) -> Result<(), StoreError> {
        if self.issued.borrow().contains_key(&epoch) {
            return Ok(());
        }
        let floor = EpochFloor::<Settling>::under(self.h_incl, self.schedule);
        let rows = ChainView::issued_draws(self.view, epoch, floor)?;
        self.issued.borrow_mut().insert(epoch, rows);
        Ok(())
    }

    /// The block this view admits into.
    #[must_use]
    pub fn including(&self) -> BlockHeight {
        self.h_incl
    }

    /// The schedule the floors and the epochs are read from.
    #[must_use]
    pub fn schedule(&self) -> SettlementSchedule {
        self.schedule
    }

    /// How many of each pair's draws in `epoch` are visible below `below`:
    /// `revealed_at < below`. One read of the epoch's index, shared with
    /// [`BundleView::visibly_short`].
    ///
    /// # Errors
    ///
    /// The index read's fault, or a count that does not fit `u32`.
    pub fn visible_counts(
        &self,
        epoch: SettlementEpoch,
        below: BlockHeight,
    ) -> Result<BTreeMap<(PCanonicalId, ShardId), u32>, StoreError> {
        self.issued_of(epoch)?;
        let mut counts = BTreeMap::new();
        let rows = self.issued.borrow();
        let Some(rows) = rows.get(&epoch) else {
            return Ok(counts);
        };
        for row in rows {
            if row.state.revealed_at < below {
                let count = counts.entry((row.persona, row.shard)).or_insert(0);
                *count = count.checked_add(1).ok_or_else(|| {
                    self.view.arm_row(StoreInvariant::AdmissionWrite {
                        height: below,
                        observed: super::error::AdmissionWriteFault::ReductionPastWidth,
                    })
                })?;
            }
        }
        Ok(counts)
    }
}

impl BundleView for StoreBundleView<'_, '_, '_> {
    type Fault = StoreError;

    fn draw_count(&self, h: BlockHeight) -> Result<Option<u32>, StoreError> {
        Ok(self.draws_row(h)?.map(|row| row.count))
    }

    fn draw_commitment(&self, h: BlockHeight) -> Result<Option<DrawCommitment>, StoreError> {
        self.view.draw_commitment_at(h)
    }

    fn block_hash(&self, height: BlockHeight) -> Result<Option<BlockHash>, StoreError> {
        Ok(match HeaderView::header_at(self.view, height)? {
            AtHeight::Recorded(header) => Some(header.hash),
            AtHeight::AboveTip => None,
        })
    }

    fn visibly_short(&self, h: BlockHeight, index: u64) -> Result<bool, StoreError> {
        let epoch = self.schedule.epoch_at(h);
        let Some(drawable) = self.drawable_epoch(epoch)? else {
            return Err(self.miss(epoch));
        };
        let Some(pair) = drawable.pair(index) else {
            return Err(self.view.arm_row(StoreInvariant::AdmissionWrite {
                height: h,
                observed: super::error::AdmissionWriteFault::IndexPastSet,
            }));
        };
        self.issued_of(epoch)?;
        let visible = self
            .issued
            .borrow()
            .get(&epoch)
            .map(|rows| {
                rows.iter()
                    .filter(|row| {
                        row.persona == pair.persona
                            && row.shard == pair.shard
                            && row.state.revealed_at < h
                    })
                    .count()
            })
            .unwrap_or(0);
        Ok(visible < COUNTED_DRAWS)
    }

    fn revealed(&self, h: BlockHeight) -> Result<bool, StoreError> {
        Ok(self.draws_row(h)?.is_some_and(|row| row.revealed))
    }

    fn drawable_epoch(&self, epoch: SettlementEpoch) -> Result<Option<&DrawableEpoch>, StoreError> {
        let open = BlockHeight::from_raw(self.schedule.open_height(epoch.to_raw()));
        let hash = match HeaderView::header_at(self.view, open)? {
            AtHeight::Recorded(header) => header.hash,
            AtHeight::AboveTip => return Err(self.miss(epoch)),
        };
        match self.memo.get(epoch, &hash) {
            Some(drawable) => Ok(Some(drawable)),
            None => Err(self.miss(epoch)),
        }
    }
}
