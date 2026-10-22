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
//!
//! Issued draws are read once per epoch and kept as [`IssuedVisibility`]:
//! each pair's reveal heights, sorted. `revealed_at < h` is one partition
//! of that list. The count the reduction uses and the flag the verifier
//! reads are that partition.

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

/// Reveal heights of the issued draws of one epoch, by pair.
///
/// Filed once from the epoch's index. The heights of a pair are sorted, so
/// [`Self::before`] is the only definition of `revealed_at < below`.
struct IssuedVisibility {
    by_epoch: BTreeMap<SettlementEpoch, BTreeMap<(PCanonicalId, ShardId), Vec<BlockHeight>>>,
}

impl IssuedVisibility {
    fn new() -> Self {
        Self {
            by_epoch: BTreeMap::new(),
        }
    }

    fn contains(&self, epoch: SettlementEpoch) -> bool {
        self.by_epoch.contains_key(&epoch)
    }

    /// File `rows` under `epoch`. A pair's heights are sorted so a later
    /// count is a partition, not a second scan.
    fn file(&mut self, epoch: SettlementEpoch, rows: Vec<IndexedDraw>) {
        let mut pairs: BTreeMap<(PCanonicalId, ShardId), Vec<BlockHeight>> = BTreeMap::new();
        for row in rows {
            pairs
                .entry((row.persona, row.shard))
                .or_default()
                .push(row.state.revealed_at);
        }
        for heights in pairs.values_mut() {
            heights.sort_unstable();
        }
        self.by_epoch.insert(epoch, pairs);
    }

    /// How many of `pair`'s draws in `epoch` were revealed strictly below
    /// `below`. The epoch was filed by [`StoreBundleView::issued_of`].
    fn count_before(
        &self,
        epoch: SettlementEpoch,
        pair: (PCanonicalId, ShardId),
        below: BlockHeight,
    ) -> usize {
        self.by_epoch
            .get(&epoch)
            .expect("issued_of inserts the epoch")
            .get(&pair)
            .map(|revealed| Self::before(revealed, below))
            .unwrap_or(0)
    }

    /// Each pair in `epoch` and how many of its draws were revealed strictly
    /// below `below`. A pair whose reveals are all at or after `below`
    /// contributes zero; the caller drops that zero.
    fn pairs_before(
        &self,
        epoch: SettlementEpoch,
        below: BlockHeight,
    ) -> impl Iterator<Item = ((PCanonicalId, ShardId), usize)> + '_ {
        self.by_epoch
            .get(&epoch)
            .expect("issued_of inserts the epoch")
            .iter()
            .map(move |(pair, revealed)| (*pair, Self::before(revealed, below)))
    }

    /// The count of `revealed_at < below`. `revealed` is sorted.
    fn before(revealed: &[BlockHeight], below: BlockHeight) -> usize {
        revealed.partition_point(|revealed_at| *revealed_at < below)
    }
}

/// The admission view: one batch and the memo the count phase filled.
pub struct StoreBundleView<'a, 'b, 'id> {
    view: &'a BatchView<'b, 'id>,
    memo: &'a DrawableMemo,
    /// The block being admitted. Floors and the window are read from it.
    h_incl: BlockHeight,
    schedule: SettlementSchedule,
    /// Issued draws already read, by epoch. One admission reads an epoch's
    /// index once, then answers every pair from that read.
    visibility: RefCell<IssuedVisibility>,
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
            visibility: RefCell::new(IssuedVisibility::new()),
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

    /// Read `epoch`'s issued-draw index into [`IssuedVisibility`], once.
    fn issued_of(&self, epoch: SettlementEpoch) -> Result<(), StoreError> {
        if self.visibility.borrow().contains(epoch) {
            return Ok(());
        }
        let floor = EpochFloor::<Settling>::under(self.h_incl, self.schedule);
        let rows = ChainView::issued_draws(self.view, epoch, floor)?;
        self.visibility.borrow_mut().file(epoch, rows);
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
    /// [`BundleView::visibly_short`]. A pair with none is absent.
    ///
    /// # Errors
    ///
    /// The index read's fault, or a count that does not fit `u32` (SI-39).
    pub fn visible_counts(
        &self,
        epoch: SettlementEpoch,
        below: BlockHeight,
    ) -> Result<BTreeMap<(PCanonicalId, ShardId), u32>, StoreError> {
        self.issued_of(epoch)?;
        let visible: Vec<_> = self
            .visibility
            .borrow()
            .pairs_before(epoch, below)
            .filter(|(_, count)| *count != 0)
            .collect();
        let mut counts = BTreeMap::new();
        for (pair, visible) in visible {
            let count = u32::try_from(visible).map_err(|_| {
                self.view
                    .arm_row(StoreInvariant::VisibleDrawCountPastWidth { height: below })
            })?;
            counts.insert(pair, count);
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
        match self.view.recorded_block_at(h)? {
            AtHeight::AboveTip => Ok(None),
            AtHeight::Recorded(block) => {
                singular_draw_commitment(&block).map(Some).ok_or_else(|| {
                    self.view
                        .arm_row(StoreInvariant::DrawCommitmentUnreadable { height: h })
                })
            }
        }
    }

    fn block_hash(&self, height: BlockHeight) -> Result<Option<BlockHash>, StoreError> {
        Ok(match HeaderView::header_at(self.view, height)? {
            AtHeight::Recorded(header) => Some(header.hash),
            AtHeight::AboveTip => None,
        })
    }

    fn visibly_short(&self, h: BlockHeight, index: u64) -> Result<bool, StoreError> {
        let epoch = self.schedule.epoch_at(h);
        // The store view does not answer `Ok(None)`. The `None` is the
        // trait's absent set, and on this view that absence is SI-35.
        let Some(drawable) = self.drawable_epoch(epoch)? else {
            return Err(self.miss(epoch));
        };
        let Some(pair) = drawable.pair(index) else {
            return Err(self
                .view
                .arm_row(StoreInvariant::DrawableIndexPastSet { height: h, index }));
        };
        self.issued_of(epoch)?;
        let visible = self
            .visibility
            .borrow()
            .count_before(epoch, (pair.persona, pair.shard), h);
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

/// Exactly one `0x0C` in the coinbase extra. A parse that fails, an extra
/// with no draw commitment, or two of them, is `None`. The all-zero value
/// is a commitment: genesis publishes it, and "none" means no field.
fn singular_draw_commitment(block: &shekyl_wire::Block) -> Option<DrawCommitment> {
    let fields = block.miner_transaction.prefix.parse_extra().ok()?;
    let mut found = None;
    for field in fields {
        if let shekyl_wire::tx_extra::TxExtraField::DrawCommitment(commitment) = field {
            if found.is_some() {
                return None;
            }
            found = Some(commitment);
        }
    }
    found
}
