// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The branch view (brief §4.3). One [`HeaderView`]: main at and below
//! the fork, and `T` above it by height. Header judgement and the seed
//! and target claims read this, so a header whose parent is in `T` is
//! judged against that parent and not against the main tip.

use shekyl_chain_rules::{AtHeight, HeaderRecord, HeaderView, Tip};
use shekyl_types::{BlockHash, BlockHeight};

use crate::peer::Checked;
use crate::tree::HeaderTree;

// Reads of pending headers on this thread: the cost test's count of the
// work the run buffer does per header (`scaling_tests`).
#[cfg(test)]
thread_local! {
    pub(crate) static PENDING_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn count_pending_read() {
    PENDING_READS.with(|reads| reads.set(reads.get().saturating_add(1)));
}

#[cfg(not(test))]
pub(crate) const fn count_pending_read() {}

/// Cheap-checked or proven headers that are not in `T` yet, served by
/// height above the view's base: a run's headers, then the headers of a
/// response checked so far. Borrowed, never copied, and contiguous by
/// height, so a height is found by its offset from the first.
#[derive(Clone, Copy)]
pub(crate) struct Pending<'a> {
    earlier: &'a [Checked],
    later: &'a [Checked],
}

impl<'a> Pending<'a> {
    /// No pending headers.
    pub(crate) const NONE: Pending<'static> = Pending {
        earlier: &[],
        later: &[],
    };

    /// `earlier`, then `later`, the second continuing the first.
    pub(crate) const fn new(earlier: &'a [Checked], later: &'a [Checked]) -> Self {
        Self { earlier, later }
    }

    fn first(&self) -> Option<&'a Checked> {
        self.earlier.first().or_else(|| self.later.first())
    }

    fn last(&self) -> Option<&'a Checked> {
        self.later.last().or_else(|| self.earlier.last())
    }

    /// The pending header at `height`, in O(1). A header found by offset
    /// whose height is not `height` means the two slices do not continue
    /// each other, and it is not served.
    fn at(&self, height: BlockHeight) -> Option<&'a Checked> {
        count_pending_read();
        let offset = height.to_raw().checked_sub(self.first()?.height.to_raw())?;
        let offset = usize::try_from(offset).ok()?;
        let found = match offset.checked_sub(self.earlier.len()) {
            None => self.earlier.get(offset),
            Some(later) => self.later.get(later),
        }?;
        (found.height == height).then_some(found)
    }
}

pub(crate) struct BranchView<'a, H> {
    main: &'a H,
    tree: Option<&'a HeaderTree>,
    /// In `T`, or on main. Ancestor walks start here. The overlay tip is
    /// not in `T`, so it cannot be this hash.
    anchor: BlockHash,
    tip_hash: BlockHash,
    tip_height: BlockHeight,
    /// Heights at and below this are on `main`.
    fork: BlockHeight,
    empty: bool,
    run: Pending<'a>,
}

impl<'a, H> BranchView<'a, H> {
    pub(crate) fn on_main(main: &'a H, tip_hash: BlockHash, tip_height: BlockHeight) -> Self {
        Self {
            main,
            tree: None,
            anchor: tip_hash,
            tip_hash,
            tip_height,
            fork: tip_height,
            empty: false,
            run: Pending::NONE,
        }
    }

    pub(crate) fn empty_main(main: &'a H) -> Self {
        Self {
            main,
            tree: None,
            anchor: BlockHash::NULL,
            tip_hash: BlockHash::NULL,
            tip_height: BlockHeight::ZERO,
            fork: BlockHeight::ZERO,
            empty: true,
            run: Pending::NONE,
        }
    }

    pub(crate) fn above(
        main: &'a H,
        tree: &'a HeaderTree,
        tip_hash: BlockHash,
        tip_height: BlockHeight,
        fork: BlockHeight,
    ) -> Self {
        Self {
            main,
            tree: Some(tree),
            anchor: tip_hash,
            tip_hash,
            tip_height,
            fork,
            empty: false,
            run: Pending::NONE,
        }
    }

    /// The pending headers sit above `anchor`. `tip()` reports the last
    /// of them. Lookups below them and above the fork still walk `T` from
    /// `anchor`.
    pub(crate) fn with_run(mut self, run: Pending<'a>) -> Self {
        if let Some(last) = run.last() {
            self.tip_hash = last.hash;
            self.tip_height = last.height;
        }
        self.run = run;
        self
    }
}

impl<'id, H: HeaderView<'id>> HeaderView<'id> for BranchView<'_, H> {
    type Fault = H::Fault;

    fn tip(&self) -> Result<Option<Tip>, Self::Fault> {
        if self.empty {
            return Ok(None);
        }
        Ok(Some(Tip {
            height: self.tip_height,
            hash: self.tip_hash,
        }))
    }

    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, Self::Fault> {
        if self.empty {
            return self.main.header_at(height);
        }
        if height.to_raw() > self.tip_height.to_raw() {
            return Ok(AtHeight::AboveTip);
        }
        if let Some(pending) = self.run.at(height) {
            return Ok(AtHeight::Recorded(HeaderRecord {
                hash: pending.hash,
                header: pending.header.clone(),
                cumulative_difficulty: pending.work,
            }));
        }
        let Some(tree) = self.tree else {
            return self.main.header_at(height);
        };
        if height.to_raw() <= self.fork.to_raw() {
            return self.main.header_at(height);
        }
        match tree
            .ancestor_at(self.anchor, height)
            .and_then(|hash| tree.record(hash))
        {
            Some(record) => Ok(AtHeight::Recorded(record)),
            None => Ok(AtHeight::AboveTip),
        }
    }
}
