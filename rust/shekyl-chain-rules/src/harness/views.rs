// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Views that exhibit a fault, or a state a conforming store refuses to hold.
//!
//! [`FaultingView`] fails every read. [`WithholdingView`] answers `AboveTip`
//! for one per-height read while the tip still says the chain is dense.
//! When a mock is the right instrument at all is
//! [`MockChain`](super::MockChain)'s charter.

use core::convert::Infallible;

use shekyl_types::{
    BlockCount, BlockHash, BlockHeight, CurveTreeRoot, KeyImage, LongTermWeight, TxHash,
};
use shekyl_units::AtomicUnits;

use super::{Brand, MockView};
use crate::tree_growth::TreeFrontier;
use crate::view::{
    AtHeight, BlockOutputs, ChainView, HeaderRecord, HeaderView, RecordedBlock, RecordedWeights,
    Tip,
};

/// The bundle view of a test view that holds no bundle rows.
///
/// Every read is unanswered: no count, no commitment, no hash, no drawable
/// epoch, no roster. A section that is not empty therefore stops at the
/// budget's read of `D` as awaiting, which `validate` faults as
/// [`Corrupt::BundleUnanswered`](crate::Corrupt::BundleUnanswered). It
/// never refuses a block, so a view with no rows cannot turn its missing
/// rows into a verdict. `revealed` and `visibly_short` are read only after
/// `D` is answered, so their `false` is never reached. An empty section
/// reads nothing.
pub struct NoBundleRows<F>(core::marker::PhantomData<F>);

impl<F> NoBundleRows<F> {
    /// The view.
    #[must_use]
    pub const fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<F> Default for NoBundleRows<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F> crate::archival::BundleView for NoBundleRows<F> {
    type Fault = F;

    fn draw_count(&self, _: BlockHeight) -> Result<Option<u32>, F> {
        Ok(None)
    }

    fn draw_commitment(
        &self,
        _: BlockHeight,
    ) -> Result<Option<shekyl_types::archival::DrawCommitment>, F> {
        Ok(None)
    }

    fn block_hash(&self, _: BlockHeight) -> Result<Option<BlockHash>, F> {
        Ok(None)
    }

    fn visibly_short(&self, _: BlockHeight, _: u64) -> Result<bool, F> {
        Ok(false)
    }

    fn revealed(&self, _: BlockHeight) -> Result<bool, F> {
        Ok(false)
    }

    fn drawable_epoch(
        &self,
        _: shekyl_types::SettlementEpoch,
    ) -> Result<Option<&shekyl_archival_retention::DrawableEpoch>, F> {
        Ok(None)
    }

    fn support_count(&self, _: BlockHeight) -> Result<Option<u32>, F> {
        Ok(None)
    }

    fn support_roster(
        &self,
        _: BlockHeight,
    ) -> Result<Option<Vec<crate::archival::SupportSeat>>, F> {
        Ok(None)
    }

    fn archive_width(&self, _: BlockHeight) -> Result<Option<core::num::NonZeroU64>, F> {
        Ok(None)
    }
}

/// The fault a [`FaultingView`] raises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Faulted;

/// A view whose every read faults — the substrate failing under the rule.
#[derive(Default)]
pub struct FaultingView<'id>(Brand<'id>);

impl<'id> HeaderView<'id> for FaultingView<'id> {
    type Fault = Faulted;

    fn tip(&self) -> Result<Option<Tip>, Faulted> {
        Err(Faulted)
    }

    fn header_at(&self, _: BlockHeight) -> Result<AtHeight<HeaderRecord>, Faulted> {
        Err(Faulted)
    }
}

impl<'id> ChainView<'id> for FaultingView<'id> {
    type Bundles<'m>
        = crate::harness::NoBundleRows<Faulted>
    where
        Self: 'm;

    fn bundles<'m>(
        &'m self,
        _: &'m crate::DrawableMemo,
        _: BlockHeight,
        _: shekyl_archival_retention::SettlementSchedule,
    ) -> Self::Bundles<'m> {
        crate::harness::NoBundleRows::new()
    }

    fn has_key_image(&self, _: &KeyImage) -> Result<bool, Faulted> {
        Err(Faulted)
    }

    fn total_burned(&self) -> Result<AtomicUnits, Faulted> {
        Err(Faulted)
    }

    fn long_term_effective_median_at(
        &self,
        _: BlockHeight,
    ) -> Result<AtHeight<LongTermWeight>, Faulted> {
        Err(Faulted)
    }

    fn burned_through(&self, _: BlockHeight) -> Result<AtHeight<AtomicUnits>, Faulted> {
        Err(Faulted)
    }

    fn tree_frontier(&self) -> Result<TreeFrontier, Faulted> {
        Err(Faulted)
    }

    fn leaf_count_at(&self, _: BlockHeight) -> Result<AtHeight<u64>, Faulted> {
        Err(Faulted)
    }

    fn outputs_at(&self, _: BlockHeight) -> Result<AtHeight<BlockOutputs>, Faulted> {
        Err(Faulted)
    }

    fn block_at(&self, _: BlockHeight) -> Result<AtHeight<RecordedBlock>, Faulted> {
        Err(Faulted)
    }

    fn height_of(&self, _: &BlockHash) -> Result<Option<BlockHeight>, Faulted> {
        Err(Faulted)
    }

    fn root_at(&self, _: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Faulted> {
        Err(Faulted)
    }

    fn weights_window(
        &self,
        _: BlockHeight,
        _: BlockCount,
    ) -> Result<AtHeight<Vec<RecordedWeights>>, Faulted> {
        Err(Faulted)
    }

    fn has_transaction(&self, _: &TxHash) -> Result<bool, Faulted> {
        Err(Faulted)
    }

    crate::archival_reads!(fault Faulted);
}

/// The one per-height read a [`WithholdingView`] answers `AboveTip` for.
///
/// One read, one height. A view that withholds several, or that lies about
/// its tip, is a different instrument and is not this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithheldRead {
    /// [`ChainView::block_at`] at this height — the block row, as an
    /// executed-fact reader asks for it. `header_at` at the same height
    /// still answers: one read, one height.
    BlockAt(BlockHeight),
    /// [`HeaderView::header_at`] at this height — the header record, as
    /// a header rule asks for it (DRS-E5 PR-a). `block_at` still answers.
    HeaderAt(BlockHeight),
    /// [`ChainView::root_at`] at this height — the curve-tree root.
    RootAt(BlockHeight),
    /// [`ChainView::weights_window`] ending at this height — the weights
    /// projection answers `AboveTip` for a height the tip says is
    /// recorded (slice 7, CEN-G6's read).
    WeightsBelow(BlockHeight),
    /// [`ChainView::leaf_count_at`] at this height — the tree's size,
    /// and so [`ChainView::depth_at`] (slice 8, CEN-J21's I13 read).
    LeafCountAt(BlockHeight),
}

/// A [`MockView`] with one per-height read withheld.
///
/// Charter job 3. A conforming store refuses to hold this (SI-7): the tip
/// still says the chain is dense, and one row answers [`AtHeight::AboveTip`].
/// The assertion a test makes with it is the fault class — [`crate::Corrupt`]
/// — never a verdict. Every read other than the withheld one is the inner
/// mock's, so the contradiction is exactly one fact.
pub struct WithholdingView<'a, 'id> {
    inner: MockView<'a, 'id>,
    withheld: WithheldRead,
}

impl<'a, 'id> MockView<'a, 'id> {
    /// Withhold `read`. The mock moves into the wrapper; the chain it
    /// borrows is unchanged.
    #[must_use]
    pub fn withholding(self, read: WithheldRead) -> WithholdingView<'a, 'id> {
        WithholdingView {
            inner: self,
            withheld: read,
        }
    }
}

impl<'id> HeaderView<'id> for WithholdingView<'_, 'id> {
    type Fault = Infallible;

    fn tip(&self) -> Result<Option<Tip>, Infallible> {
        self.inner.tip()
    }

    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, Infallible> {
        if let WithheldRead::HeaderAt(at) = self.withheld {
            if height == at {
                return Ok(AtHeight::AboveTip);
            }
        }
        self.inner.header_at(height)
    }
}

impl<'id> ChainView<'id> for WithholdingView<'_, 'id> {
    type Bundles<'m>
        = crate::harness::NoBundleRows<Infallible>
    where
        Self: 'm;

    fn bundles<'m>(
        &'m self,
        _: &'m crate::DrawableMemo,
        _: BlockHeight,
        _: shekyl_archival_retention::SettlementSchedule,
    ) -> Self::Bundles<'m> {
        crate::harness::NoBundleRows::new()
    }

    fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, Infallible> {
        self.inner.has_key_image(key_image)
    }

    fn total_burned(&self) -> Result<AtomicUnits, Infallible> {
        self.inner.total_burned()
    }

    fn long_term_effective_median_at(
        &self,
        height: BlockHeight,
    ) -> Result<AtHeight<LongTermWeight>, Infallible> {
        self.inner.long_term_effective_median_at(height)
    }

    fn burned_through(&self, height: BlockHeight) -> Result<AtHeight<AtomicUnits>, Infallible> {
        self.inner.burned_through(height)
    }

    fn block_at(&self, height: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
        if let WithheldRead::BlockAt(at) = self.withheld {
            if height == at {
                return Ok(AtHeight::AboveTip);
            }
        }
        self.inner.block_at(height)
    }

    fn height_of(&self, hash: &BlockHash) -> Result<Option<BlockHeight>, Infallible> {
        self.inner.height_of(hash)
    }

    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
        if let WithheldRead::RootAt(at) = self.withheld {
            if height == at {
                return Ok(AtHeight::AboveTip);
            }
        }
        self.inner.root_at(height)
    }

    fn weights_window(
        &self,
        end: BlockHeight,
        at_most: BlockCount,
    ) -> Result<AtHeight<Vec<RecordedWeights>>, Infallible> {
        if let WithheldRead::WeightsBelow(at) = self.withheld {
            if end == at {
                return Ok(AtHeight::AboveTip);
            }
        }
        self.inner.weights_window(end, at_most)
    }

    fn has_transaction(&self, hash: &TxHash) -> Result<bool, Infallible> {
        self.inner.has_transaction(hash)
    }

    fn tree_frontier(&self) -> Result<TreeFrontier, Infallible> {
        self.inner.tree_frontier()
    }

    fn leaf_count_at(&self, height: BlockHeight) -> Result<AtHeight<u64>, Infallible> {
        if let WithheldRead::LeafCountAt(at) = self.withheld {
            if height == at {
                return Ok(AtHeight::AboveTip);
            }
        }
        self.inner.leaf_count_at(height)
    }

    fn outputs_at(&self, height: BlockHeight) -> Result<AtHeight<BlockOutputs>, Infallible> {
        self.inner.outputs_at(height)
    }

    crate::archival_reads!(delegate inner);
}
