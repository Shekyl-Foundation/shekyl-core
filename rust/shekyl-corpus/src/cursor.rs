// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The height law the writer and the reader share.
//!
//! The cursor starts at the header's `first_height`. An `extend` must
//! carry [`HeightCursor::next_extend`], and both an `extend` and a
//! `rewind` then move the cursor to the successor of the height they
//! named. A record that does not move the tip does not touch the cursor.
//!
//! [`HeightCursor::next`] is `None` once `u64::MAX` has been passed: there
//! is no further height, and the next `extend` is
//! [`CorpusFault::HeightExhausted`] rather than a wrapped gap.

use shekyl_types::{BlockCount, BlockHeight};

use crate::fault::CorpusFault;

/// The last height a corpus can carry.
pub(crate) const LAST_HEIGHT: BlockHeight = BlockHeight::from_raw(u64::MAX);

/// Where the next `extend` must sit, and the tip a `rewind` may name.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HeightCursor {
    first: BlockHeight,
    /// `None` once [`LAST_HEIGHT`] has been passed.
    next: Option<BlockHeight>,
}

impl HeightCursor {
    /// A corpus whose first record is at `first`.
    pub(crate) const fn starting_at(first: BlockHeight) -> Self {
        Self {
            first,
            next: Some(first),
        }
    }

    /// The header's `first_height`.
    pub(crate) const fn first(self) -> BlockHeight {
        self.first
    }

    /// The height the next `extend` must carry.
    ///
    /// # Errors
    ///
    /// [`CorpusFault::HeightExhausted`] once [`LAST_HEIGHT`] has been passed.
    pub(crate) const fn next_extend(self) -> Result<BlockHeight, CorpusFault> {
        match self.next {
            Some(height) => Ok(height),
            None => Err(CorpusFault::HeightExhausted { after: LAST_HEIGHT }),
        }
    }

    /// Accept `rewind { to }`.
    ///
    /// `to` lies in `[first, tip)`. The tip is the predecessor of `next`,
    /// or [`LAST_HEIGHT`] when the cursor is exhausted. Nothing recorded
    /// yet (`next == first`) has no tip.
    ///
    /// # Errors
    ///
    /// [`CorpusFault::RewindOnEmpty`], [`CorpusFault::RewindNotBackward`],
    /// [`CorpusFault::RewindOutOfCorpus`].
    pub(crate) fn check_rewind(self, to: BlockHeight) -> Result<(), CorpusFault> {
        let tip = match self.next {
            Some(next) if next == self.first => return Err(CorpusFault::RewindOnEmpty),
            Some(next) => next.checked_sub_count(BlockCount::ONE).expect(
                "next is past first, so it has a predecessor: the cursor advances only by one height",
            ),
            None => LAST_HEIGHT,
        };
        if to >= tip {
            return Err(CorpusFault::RewindNotBackward { to, tip });
        }
        if to < self.first {
            return Err(CorpusFault::RewindOutOfCorpus {
                to,
                first_height: self.first,
            });
        }
        Ok(())
    }

    /// Move to the successor of `height`, or to exhausted when `height` is
    /// [`LAST_HEIGHT`].
    pub(crate) fn advance_past(&mut self, height: BlockHeight) {
        self.next = height.checked_add(BlockCount::ONE);
    }
}
