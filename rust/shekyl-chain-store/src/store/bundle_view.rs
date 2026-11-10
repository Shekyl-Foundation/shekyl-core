// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`StoreBundleView`]: [`BundleView`] over a chain view and the count
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
//! reads are that partition. A drawable epoch is resolved once too: the
//! opening block is parsed and checked, then the set is kept for the view.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::num::NonZeroU64;

use shekyl_chain_rules::{
    support_step, AtHeight, BlockDrawsFloor, BundleView, ChainView, DrawableEpoch, DrawableMemo,
    EpochFloor, HeaderRecord, HeaderView, SettlementSchedule, Settling, SupportStepFault,
    WindowClosed,
};
use shekyl_types::archival::{
    BlockDraws, DrawCommitment, IndexedDraw, SupportCarryAfter, SupportRow, COUNTED_DRAWS,
};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

use super::error::{StoreError, StoreInvariant};
use super::view::BatchView;

/// What the bundle view asks of the chain it reads, and what an invariant does.
///
/// A [`BatchView`] arms the row: the batch is poisoned and will not commit.
/// A [`SnapshotView`](super::SnapshotView) returns the same row as a plain
/// [`StoreError`] and arms nothing. The reads are that view's own, so a
/// second copy of a table walk cannot drift from it.
pub trait BundleRows {
    /// An invariant this view observed. A batch poisons; a snapshot returns it.
    fn arm_row(&self, row: StoreInvariant) -> StoreError;

    /// The block recorded at `height`, coinbase included. Above the tip is
    /// [`AtHeight::AboveTip`].
    fn recorded_block_at(
        &self,
        height: BlockHeight,
    ) -> Result<AtHeight<shekyl_wire::Block>, StoreError>;

    /// [`ChainView::block_draws`], under this view's arming.
    fn block_draws_row(
        &self,
        height: BlockHeight,
        floor: BlockDrawsFloor,
    ) -> Result<Option<BlockDraws>, StoreError>;

    /// [`ChainView::issued_draws`], under this view's arming.
    fn issued_draws_row(
        &self,
        epoch: SettlementEpoch,
        floor: EpochFloor<Settling>,
    ) -> Result<Vec<IndexedDraw>, StoreError>;

    /// [`ChainView::support_row`], under this view's arming.
    fn support_row_at(
        &self,
        height: BlockHeight,
        floor: BlockDrawsFloor,
    ) -> Result<Option<SupportRow>, StoreError>;

    /// [`HeaderView::header_at`], under this view's arming.
    fn header_row(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, StoreError>;
}

impl<'id> BundleRows for BatchView<'_, 'id> {
    fn arm_row(&self, row: StoreInvariant) -> StoreError {
        BatchView::arm_row(self, row)
    }

    fn recorded_block_at(
        &self,
        height: BlockHeight,
    ) -> Result<AtHeight<shekyl_wire::Block>, StoreError> {
        BatchView::recorded_block_at(self, height)
    }

    fn block_draws_row(
        &self,
        height: BlockHeight,
        floor: BlockDrawsFloor,
    ) -> Result<Option<BlockDraws>, StoreError> {
        ChainView::block_draws(self, height, floor)
    }

    fn issued_draws_row(
        &self,
        epoch: SettlementEpoch,
        floor: EpochFloor<Settling>,
    ) -> Result<Vec<IndexedDraw>, StoreError> {
        ChainView::issued_draws(self, epoch, floor)
    }

    fn support_row_at(
        &self,
        height: BlockHeight,
        floor: BlockDrawsFloor,
    ) -> Result<Option<SupportRow>, StoreError> {
        ChainView::support_row(self, height, floor)
    }

    fn header_row(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, StoreError> {
        HeaderView::header_at(self, height)
    }
}

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

/// Drawable sets this view has already resolved, by epoch.
///
/// The opening block is parsed and its hash checked once. A later read of
/// the epoch returns that set. A miss is SI-35 and is not filed: the view's
/// [`BundleRows::arm_row`] is that row, and a poisoned batch does not
/// answer it again.
struct OpenedEpochs<'a> {
    by_epoch: BTreeMap<SettlementEpoch, &'a DrawableEpoch>,
}

impl<'a> OpenedEpochs<'a> {
    fn new() -> Self {
        Self {
            by_epoch: BTreeMap::new(),
        }
    }

    fn get(&self, epoch: SettlementEpoch) -> Option<&'a DrawableEpoch> {
        self.by_epoch.get(&epoch).copied()
    }

    fn insert(&mut self, epoch: SettlementEpoch, drawable: &'a DrawableEpoch) {
        self.by_epoch.insert(epoch, drawable);
    }
}

/// The admission view: one chain view and the memo the count phase filled.
///
/// `V` is a [`BatchView`] when a connect journals what this view admits,
/// and a snapshot when a read must not commit. The journal names the
/// batch, so a snapshot cannot be written.
pub struct StoreBundleView<'a, V> {
    view: &'a V,
    memo: &'a DrawableMemo,
    /// The block being admitted. Floors and the window are read from it.
    h_incl: BlockHeight,
    schedule: SettlementSchedule,
    /// Issued draws already read, by epoch. One admission reads an epoch's
    /// index once, then answers every pair from that read.
    visibility: RefCell<IssuedVisibility>,
    /// Drawable sets already resolved, by epoch. One admission checks an
    /// epoch's opening hash once, then answers every draw from that set.
    opened: RefCell<OpenedEpochs<'a>>,
}

impl<'a, V: BundleRows> StoreBundleView<'a, V> {
    /// A view of `view` at `h_incl`, reading `D` from `memo`.
    #[must_use]
    pub fn new(
        view: &'a V,
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
            opened: RefCell::new(OpenedEpochs::new()),
        }
    }

    fn miss(&self, epoch: SettlementEpoch) -> StoreError {
        self.view
            .arm_row(StoreInvariant::DrawableMemoMiss { epoch })
    }

    fn draws_row(&self, h: BlockHeight) -> Result<Option<BlockDraws>, StoreError> {
        let floor = BlockDrawsFloor::in_force(self.h_incl, self.schedule);
        self.view.block_draws_row(h, floor)
    }

    /// The support row the transition writes at `h`, recomputed from what
    /// the store holds (SI-43): one step of the carry ([`support_step`])
    /// from the carry the row at `h − 1` left (empty when `h` opens its
    /// epoch, `SO-D12r`) and the row and `revealed` of the block whose
    /// window closes at `h`, when that block is in the epoch. These are the
    /// facts the connect at `h` read, and none of them moves after it: the
    /// earlier rows are written once, and the closing block's window closed
    /// at `h`. Both rows are above the draw rows' floor in force at
    /// `h_incl`, because `h` is inside `h_incl`'s window and the floor never
    /// passes the open of the epoch before `h_incl`'s.
    ///
    /// An earlier row that is absent is SI-7 on the cell: every connected
    /// height writes one (SI-40). A carry before `h` past `c` is SI-43 at
    /// `h − 1`, whose row no transition writes.
    fn one_step(
        &self,
        drawable: &DrawableEpoch,
        h: BlockHeight,
        floor: BlockDrawsFloor,
    ) -> Result<SupportRow, StoreError> {
        let absent = |key: &'static str| {
            self.view.arm_row(StoreInvariant::CellCorrupt {
                key,
                fault: super::error::CellFault::Absent,
            })
        };
        let open = BlockHeight::from_raw(
            self.schedule
                .open_height(self.schedule.epoch_at(h).to_raw()),
        );
        let before = if h == open {
            SupportCarryAfter::EMPTY
        } else {
            self.view
                .support_row_at(h - BlockCount::ONE, floor)?
                .ok_or_else(|| absent("archival_support_block"))?
                .carry_after
        };
        let closing = self
            .schedule
            .challenge_response_blocks()
            .and_then(|window| {
                h.checked_sub_count(BlockCount::from_raw(window.get().saturating_add(1)))
            })
            .filter(|at| *at >= open);
        let closed = match closing {
            None => None,
            Some(at) => {
                let row = self
                    .view
                    .support_row_at(at, floor)?
                    .ok_or_else(|| absent("archival_support_block"))?;
                let filed = self
                    .view
                    .block_draws_row(at, floor)?
                    .ok_or_else(|| absent("archival_block_draws"))?
                    .revealed;
                Some((row.seats, filed))
            }
        };
        let closed = closed.as_ref().map(|(seats, filed)| WindowClosed {
            seats,
            filed: *filed,
        });
        support_step(drawable, h, self.schedule, &before, closed).map_err(|why| match why {
            SupportStepFault::PastCap { persona, .. } => {
                self.view.arm_row(StoreInvariant::SupportRowNotOneStep {
                    height: h - BlockCount::ONE,
                    persona,
                })
            }
            SupportStepFault::Corrupt(corrupt) => {
                self.view.arm_row(super::write::invariant_of(corrupt))
            }
        })
    }

    /// Read `epoch`'s issued-draw index into [`IssuedVisibility`], once.
    fn issued_of(&self, epoch: SettlementEpoch) -> Result<(), StoreError> {
        if self.visibility.borrow().contains(epoch) {
            return Ok(());
        }
        let floor = EpochFloor::<Settling>::under(self.h_incl, self.schedule);
        let rows = self.view.issued_draws_row(epoch, floor)?;
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

impl<V: BundleRows> BundleView for StoreBundleView<'_, V> {
    type Fault = StoreError;

    fn draw_count(&self, h: BlockHeight) -> Result<Option<u32>, StoreError> {
        Ok(self.draws_row(h)?.map(|row| row.count))
    }

    fn draw_commitment(&self, h: BlockHeight) -> Result<Option<DrawCommitment>, StoreError> {
        match BundleRows::recorded_block_at(self.view, h)? {
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
        Ok(match self.view.header_row(height)? {
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
        if let Some(drawable) = self.opened.borrow().get(epoch) {
            return Ok(Some(drawable));
        }
        let open = BlockHeight::from_raw(self.schedule.open_height(epoch.to_raw()));
        let hash = match self.view.header_row(open)? {
            AtHeight::Recorded(header) => header.hash,
            AtHeight::AboveTip => return Err(self.miss(epoch)),
        };
        let Some(drawable) = self.memo.get(epoch, &hash) else {
            return Err(self.miss(epoch));
        };
        self.opened.borrow_mut().insert(epoch, drawable);
        Ok(Some(drawable))
    }

    fn support_count(&self, h: BlockHeight) -> Result<Option<u32>, StoreError> {
        let floor = BlockDrawsFloor::in_force(self.h_incl, self.schedule);
        Ok(self.view.support_row_at(h, floor)?.map(|row| {
            u32::try_from(row.seats.len()).expect("a block seats fewer than 2^32 trees")
        }))
    }

    fn support_roster(
        &self,
        h: BlockHeight,
    ) -> Result<Option<Vec<shekyl_chain_rules::SupportSeat>>, StoreError> {
        // `h`'s support row, as written when `h` connected, with each
        // seat's key from `h`'s epoch snapshot (`SO-D12` S1). A missing row
        // is the hole, never an empty roster. The snapshot's miss is SI-35,
        // as for `D`: admission never rebuilds.
        let floor = BlockDrawsFloor::in_force(self.h_incl, self.schedule);
        let Some(row) = self.view.support_row_at(h, floor)? else {
            return Ok(None);
        };
        let epoch = self.schedule.epoch_at(h);
        let Some(drawable) = self.drawable_epoch(epoch)? else {
            return Err(self.miss(epoch));
        };
        // SI-43: the row is one step of the carry from the row before it.
        let stepped = self.one_step(drawable, h, floor)?;
        if let Some(persona) = row
            .seats
            .first_one_sided(&stepped.seats)
            .or_else(|| first_carry_difference(&row.carry_after, &stepped.carry_after))
        {
            return Err(self
                .view
                .arm_row(StoreInvariant::SupportRowNotOneStep { height: h, persona }));
        }
        // The row is the step, so every seat is a member: `support_step`
        // seats only members of this snapshot. No roster means no seats.
        let members = drawable.support_roster();
        let mut roster = Vec::with_capacity(row.seats.len());
        for persona in row.seats.as_slice() {
            let receipt_key = members
                .and_then(|members| members.key(persona))
                .expect("support_step seats only members of this snapshot")
                .clone();
            roster.push(shekyl_chain_rules::SupportSeat {
                persona: *persona,
                receipt_key,
            });
        }
        Ok(Some(roster))
    }

    fn archive_width(&self, h: BlockHeight) -> Result<Option<NonZeroU64>, StoreError> {
        // The roster's width at `h_open` of `h`'s epoch, from the same
        // snapshot the roster's keys come from. An epoch with no roster has
        // no support stream and so no width. The verifier asks only after
        // `support_roster` answered seats, and a seated row under no roster
        // is SI-43 there, so that `None` is never read as a hole.
        let epoch = self.schedule.epoch_at(h);
        let Some(drawable) = self.drawable_epoch(epoch)? else {
            return Err(self.miss(epoch));
        };
        Ok(drawable
            .support_roster()
            .map(shekyl_archival_retention::SupportRoster::width))
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

/// The first persona, in persona order, whose carried count differs
/// between `held` and `stepped`: on one side only, or owed a different
/// count. [`None`] when the carries are equal.
fn first_carry_difference(
    held: &SupportCarryAfter,
    stepped: &SupportCarryAfter,
) -> Option<PCanonicalId> {
    let mut here = held.as_slice().iter();
    let mut there = stepped.as_slice().iter();
    let mut left = here.next();
    let mut right = there.next();
    loop {
        match (left, right) {
            (None, None) => return None,
            (Some((only, _)), None) | (None, Some((only, _))) => return Some(*only),
            (Some((a, x)), Some((b, y))) => match a.cmp(b) {
                core::cmp::Ordering::Equal if x == y => {
                    left = here.next();
                    right = there.next();
                }
                core::cmp::Ordering::Equal | core::cmp::Ordering::Less => return Some(*a),
                core::cmp::Ordering::Greater => return Some(*b),
            },
        }
    }
}
