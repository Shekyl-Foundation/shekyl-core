// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The header tree `T` (CS-Q2). Only headers the proof accepted, keyed
//! by hash. Children and the tip set are indexes, so a walk is the
//! branch and not the whole tree. `H*` is a tip: its hash and its
//! work. A heavier tip displaces the incumbent only when its fork is
//! within the reorg cap. Equal work leaves the incumbent.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_chain_rules::{AtHeight, HeaderJudged, HeaderView};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockCount, BlockHash, BlockHeight};

const ONE: BlockCount = BlockCount::ONE;

struct Node {
    judged: HeaderJudged,
    parent: BlockHash,
}

/// The chain `H*` names: a hash and the work through it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Star {
    pub hash: BlockHash,
    pub work: CumulativeDifficulty,
}

impl Star {
    pub(crate) const fn local(hash: BlockHash, work: CumulativeDifficulty) -> Self {
        Self { hash, work }
    }
}

/// Verified headers above the main chain.
#[derive(Default)]
pub(crate) struct HeaderTree {
    nodes: BTreeMap<BlockHash, Node>,
    children: BTreeMap<BlockHash, BTreeSet<BlockHash>>,
    tips: BTreeSet<BlockHash>,
    /// A header marked invalid, and every header that descends from one.
    /// The hash is remembered so a later child is excluded too.
    invalid: BTreeSet<BlockHash>,
}

impl HeaderTree {
    pub(crate) fn insert(&mut self, judged: HeaderJudged) {
        let hash = judged.hash();
        let parent = judged.previous();
        let excluded = self.invalid.contains(&parent);
        self.nodes.insert(hash, Node { judged, parent });
        self.children.entry(parent).or_default().insert(hash);
        if self.nodes.contains_key(&parent) {
            self.tips.remove(&parent);
        }
        self.tips.insert(hash);
        if excluded {
            self.mark_invalid(hash);
        }
    }

    /// The header and its descendants, by the children index.
    pub(crate) fn mark_invalid(&mut self, hash: BlockHash) {
        let mut stack = vec![hash];
        while let Some(hash) = stack.pop() {
            if !self.invalid.insert(hash) {
                continue;
            }
            self.tips.remove(&hash);
            if let Some(children) = self.children.get(&hash) {
                stack.extend(children.iter().copied());
            }
        }
    }

    /// The height of `hash` when it is in `T`.
    pub(crate) fn connecting(&self, hash: BlockHash) -> Option<BlockHeight> {
        self.nodes.get(&hash).map(|node| node.judged.connecting())
    }

    /// Hashes of `H*`'s branch in `T`, keyed by their connecting height.
    /// Heights on main, at and below the fork, are absent: the caller
    /// reads those from the view, and only the ones the locator names.
    pub(crate) fn above_fork(&self, tip: BlockHash) -> BTreeMap<BlockHeight, BlockHash> {
        let mut out = BTreeMap::new();
        let mut hash = tip;
        let mut guard = 0usize;
        while let Some(node) = self.nodes.get(&hash) {
            out.insert(node.judged.connecting(), hash);
            if !self.nodes.contains_key(&node.parent) {
                break;
            }
            hash = node.parent;
            guard += 1;
            if guard > self.nodes.len() {
                break;
            }
        }
        out
    }

    /// `incumbent` stays unless a tip in the tip set is strictly heavier
    /// and its fork is within `cap`. Each such tip costs one
    /// [`HeaderView::header_at`]: the fork height comes from
    /// [`HeaderJudged::connecting`], and that one read checks the anchor.
    pub(crate) fn select<'id, H: HeaderView<'id>>(
        &self,
        main: &H,
        incumbent: Star,
        local_height: Option<BlockHeight>,
        cap: BlockCount,
    ) -> Result<Star, H::Fault> {
        let floor = incumbent.work;
        let mut best = incumbent;
        for hash in &self.tips {
            let Some(node) = self.nodes.get(hash) else {
                continue;
            };
            let work = node.judged.cumulative_difficulty();
            // Heavier than the incumbent this call started with. A tip
            // that only beats a tip we already chose this call is still
            // a candidate: one read each, then the heaviest within the
            // cap wins. Equal work is not a candidate.
            if work <= floor {
                continue;
            }
            if self.within_cap(main, *hash, local_height, cap)? && work > best.work {
                best = Star { hash: *hash, work };
            }
        }
        Ok(best)
    }

    /// The parent that is not in `T`, and its height: one below the
    /// first header of the branch. A header connecting at 0 has no
    /// block below it; the anchor is its parent and the height is 0.
    fn fork(&self, tip: BlockHash) -> Option<(BlockHash, BlockHeight)> {
        let mut hash = tip;
        let mut guard = 0usize;
        loop {
            let node = self.nodes.get(&hash)?;
            if !self.nodes.contains_key(&node.parent) {
                let height = node.judged.connecting();
                let fork = match height.checked_sub_count(ONE) {
                    Some(fork) => fork,
                    None => BlockHeight::ZERO,
                };
                return Some((node.parent, fork));
            }
            hash = node.parent;
            guard += 1;
            if guard > self.nodes.len() {
                return None;
            }
        }
    }

    fn within_cap<'id, H: HeaderView<'id>>(
        &self,
        main: &H,
        tip: BlockHash,
        local_height: Option<BlockHeight>,
        cap: BlockCount,
    ) -> Result<bool, H::Fault> {
        let Some((anchor, fork)) = self.fork(tip) else {
            return Ok(false);
        };
        let at = main.header_at(fork)?;
        let Some(local_height) = local_height else {
            return Ok(anchor == BlockHash::NULL && matches!(at, AtHeight::AboveTip));
        };
        let AtHeight::Recorded(record) = at else {
            return Ok(false);
        };
        if record.hash != anchor || fork > local_height {
            return Ok(false);
        }
        Ok(local_height - fork <= cap)
    }
}
