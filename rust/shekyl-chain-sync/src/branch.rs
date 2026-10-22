// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The branch view (brief §4.3). One [`HeaderView`]: main at and below
//! the fork, and `T` above it by height. Header judgement and the seed
//! and target claims read this, so a header whose parent is in `T` is
//! judged against that parent and not against the main tip.

use shekyl_chain_rules::{AtHeight, HeaderRecord, HeaderView, Tip};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::BlockHeader;

use crate::tree::HeaderTree;

/// One cheap-checked or proven header that is not in `T` yet. The branch
/// view serves it by height, above the fork.
pub(crate) struct Overlay {
    pub height: BlockHeight,
    pub hash: BlockHash,
    pub header: BlockHeader,
    pub work: CumulativeDifficulty,
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
    run: &'a [Overlay],
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
            run: &[],
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
            run: &[],
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
            run: &[],
        }
    }

    /// The run's headers sit above `anchor`. `tip()` reports the overlay
    /// tip. Lookups below that tip and above the fork still walk `T`
    /// from `anchor`.
    pub(crate) fn with_run(mut self, run: &'a [Overlay]) -> Self {
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
        if let Some(over) = self.run.iter().find(|over| over.height == height) {
            return Ok(AtHeight::Recorded(HeaderRecord {
                hash: over.hash,
                header: over.header.clone(),
                cumulative_difficulty: over.work,
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
