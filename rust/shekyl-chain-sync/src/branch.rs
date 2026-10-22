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

use crate::tree::HeaderTree;

pub(crate) struct BranchView<'a, H> {
    main: &'a H,
    tree: Option<&'a HeaderTree>,
    tip_hash: BlockHash,
    tip_height: BlockHeight,
    /// Heights at and below this are on `main`.
    fork: BlockHeight,
    empty: bool,
}

impl<'a, H> BranchView<'a, H> {
    pub(crate) fn on_main(main: &'a H, tip_hash: BlockHash, tip_height: BlockHeight) -> Self {
        Self {
            main,
            tree: None,
            tip_hash,
            tip_height,
            fork: tip_height,
            empty: false,
        }
    }

    pub(crate) fn empty_main(main: &'a H) -> Self {
        Self {
            main,
            tree: None,
            tip_hash: BlockHash::NULL,
            tip_height: BlockHeight::ZERO,
            fork: BlockHeight::ZERO,
            empty: true,
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
            tip_hash,
            tip_height,
            fork,
            empty: false,
        }
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
        let Some(tree) = self.tree else {
            return self.main.header_at(height);
        };
        if height.to_raw() <= self.fork.to_raw() {
            return self.main.header_at(height);
        }
        match tree
            .ancestor_at(self.tip_hash, height)
            .and_then(|hash| tree.record(hash))
        {
            Some(record) => Ok(AtHeight::Recorded(record)),
            None => Ok(AtHeight::AboveTip),
        }
    }
}
