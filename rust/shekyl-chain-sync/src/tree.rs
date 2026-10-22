// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The header tree `T` (CS-Q2). Only headers the proof accepted, keyed
//! by hash. Children and the tip set are indexes. A height on a branch
//! is reached by a skip pointer, the way Bitcoin Core's block index
//! reaches an ancestor (`pskip`, `GetAncestor`): no operation walks a
//! branch. `H*` is a tip: its hash and its work. A heavier tip displaces
//! the incumbent only when its fork is within the reorg cap. Equal work
//! leaves the incumbent.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use shekyl_chain_rules::{AtHeight, HeaderJudged, HeaderRecord, HeaderView};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockCount, BlockHash, BlockHeight};

const ONE: BlockCount = BlockCount::ONE;

struct Node {
    judged: HeaderJudged,
    parent: BlockHash,
    /// Ancestor at [`skip_height`] of this header's height, when that
    /// header is itself in `T`. `None` when the skip would land on main.
    skip: Option<BlockHash>,
    /// Connecting height of the first header of this branch in `T`.
    /// Copied from the parent at insert, so a later removal of a node
    /// (when main connects it) is the only thing that has to recompute it.
    base: BlockHeight,
    /// Parent of [`Self::base`]. On main, or null at genesis.
    anchor: BlockHash,
}

/// Where a header in `T` sits: its own height, and the fork below it.
pub(crate) struct Placement {
    pub height: BlockHeight,
    pub fork: BlockHeight,
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
    /// Node loads. Ancestor lookups and the cap check count; the children
    /// index does not.
    visits: Cell<u64>,
}

impl HeaderTree {
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) fn contains(&self, hash: BlockHash) -> bool {
        self.nodes.contains_key(&hash)
    }

    #[cfg(test)]
    pub(crate) fn visits(&self) -> u64 {
        self.visits.get()
    }

    #[cfg(test)]
    pub(crate) fn reset_visits(&self) {
        self.visits.set(0);
    }

    pub(crate) fn insert(&mut self, judged: HeaderJudged) {
        let hash = judged.hash();
        let parent = judged.previous();
        let height = judged.connecting().to_raw();
        let parent_in_tree = self.nodes.contains_key(&parent);
        let skip = if parent_in_tree {
            self.ancestor_at(parent, BlockHeight::from_raw(skip_height(height)))
        } else {
            None
        };
        let (base, anchor) = if parent_in_tree {
            let parent_node = self
                .node(parent)
                .expect("the parent was present before the skip lookup");
            (parent_node.base, parent_node.anchor)
        } else {
            (judged.connecting(), parent)
        };
        let excluded = self.invalid.contains(&parent);
        self.nodes.insert(
            hash,
            Node {
                judged,
                parent,
                skip,
                base,
                anchor,
            },
        );
        self.children.entry(parent).or_default().insert(hash);
        if parent_in_tree {
            self.tips.remove(&parent);
        }
        self.tips.insert(hash);
        if excluded {
            self.mark_invalid(hash);
        }
    }

    /// A header already marked invalid, so a later child of it is not a
    /// new chain. The session that serves it is closed.
    pub(crate) fn remembers(&self, hash: BlockHash) -> bool {
        self.invalid.contains(&hash)
    }

    pub(crate) fn tip_hashes(&self) -> Vec<BlockHash> {
        self.tips.iter().copied().collect()
    }

    /// Headers at or below `height` whose hash is on `main` have been
    /// connected. They leave `T`. The first header still in `T` above
    /// each of them becomes that branch's base.
    pub(crate) fn connected<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        height: BlockHeight,
    ) -> Result<(), H::Fault> {
        let mut leaving = Vec::new();
        for (hash, node) in &self.nodes {
            let at = node.judged.connecting();
            if at.to_raw() > height.to_raw() {
                continue;
            }
            if let AtHeight::Recorded(record) = main.header_at(at)? {
                if record.hash == *hash {
                    leaving.push((at.to_raw(), *hash));
                }
            }
        }
        leaving.sort_by_key(|(at, _)| *at);
        for (_, hash) in leaving {
            self.drop_connected(hash);
        }
        self.rebuild_skips();
        Ok(())
    }

    fn drop_connected(&mut self, hash: BlockHash) {
        let kids = self
            .children
            .get(&hash)
            .map(|kids| kids.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        for kid in kids {
            let Some(base) = self.nodes.get(&kid).map(|node| node.judged.connecting()) else {
                continue;
            };
            if let Some(node) = self.nodes.get_mut(&kid) {
                node.base = base;
                node.anchor = hash;
            }
            self.retarget(kid, base, hash);
        }
        self.nodes.remove(&hash);
        self.tips.remove(&hash);
        self.children.remove(&hash);
    }

    fn retarget(&mut self, hash: BlockHash, base: BlockHeight, anchor: BlockHash) {
        let kids = self
            .children
            .get(&hash)
            .map(|kids| kids.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        for kid in kids {
            if let Some(node) = self.nodes.get_mut(&kid) {
                node.base = base;
                node.anchor = anchor;
            }
            self.retarget(kid, base, anchor);
        }
    }

    fn rebuild_skips(&mut self) {
        let mut rows = Vec::new();
        for (hash, node) in &self.nodes {
            rows.push((*hash, node.parent, node.judged.connecting().to_raw()));
        }
        rows.sort_by_key(|(_, _, height)| *height);
        for (hash, parent, height) in rows {
            let skip = if self.nodes.contains_key(&parent) {
                self.ancestor_at(parent, BlockHeight::from_raw(skip_height(height)))
            } else {
                None
            };
            if let Some(node) = self.nodes.get_mut(&hash) {
                node.skip = skip;
            }
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

    /// The height of `hash` when it is in `T`, and the fork below its branch.
    pub(crate) fn placement(&self, hash: BlockHash) -> Option<Placement> {
        let node = self.node(hash)?;
        let fork = node
            .base
            .checked_sub_count(ONE)
            .unwrap_or(BlockHeight::ZERO);
        Some(Placement {
            height: node.judged.connecting(),
            fork,
        })
    }

    /// The height of `hash` when it is in `T`.
    pub(crate) fn connecting(&self, hash: BlockHash) -> Option<BlockHeight> {
        self.nodes.get(&hash).map(|node| node.judged.connecting())
    }

    /// The judged header, when `T` holds it. Bodies bind against this token.
    pub(crate) fn judged(&self, hash: BlockHash) -> Option<HeaderJudged> {
        self.nodes.get(&hash).map(|node| node.judged.clone())
    }

    /// The header `hash` records, when it is in `T`.
    pub(crate) fn record(&self, hash: BlockHash) -> Option<HeaderRecord> {
        let node = self.node(hash)?;
        Some(HeaderRecord {
            hash: node.judged.hash(),
            header: node.judged.header().clone(),
            cumulative_difficulty: node.judged.cumulative_difficulty(),
        })
    }

    /// The ancestor of `tip` at `height`, in O(log n) node loads.
    /// `None` when `tip` is not in `T`, or `height` is below the branch.
    pub(crate) fn ancestor_at(&self, tip: BlockHash, height: BlockHeight) -> Option<BlockHash> {
        let target = height.to_raw();
        let mut hash = tip;
        let mut walk = self.node(hash)?.judged.connecting().to_raw();
        if walk < target {
            return None;
        }
        let mut steps = 0u64;
        let limit = walk - target + 2;
        while walk > target {
            steps += 1;
            if steps > limit {
                return None;
            }
            let node = self.node(hash)?;
            let skip_h = skip_height(walk);
            let skip_prev = skip_height(walk - 1);
            if let Some(skip) = node.skip {
                if skip_reaches(skip_h, skip_prev, target) {
                    hash = skip;
                    walk = skip_h;
                    continue;
                }
            }
            hash = node.parent;
            if walk == 0 || self.node(hash).is_none() {
                return None;
            }
            walk -= 1;
        }
        Some(hash)
    }

    /// `incumbent` stays unless a tip in the tip set is strictly heavier
    /// and its fork is within `cap`. Each such tip costs one
    /// [`HeaderView::header_at`]: the fork height is stored on the node,
    /// and that one read checks the anchor.
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
            let Some(node) = self.node(*hash) else {
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

    /// The fork is the ancestor at the branch's base. Its parent is the
    /// anchor, and one `header_at` of the fork height checks that anchor
    /// against main.
    fn within_cap<'id, H: HeaderView<'id>>(
        &self,
        main: &H,
        tip: BlockHash,
        local_height: Option<BlockHeight>,
        cap: BlockCount,
    ) -> Result<bool, H::Fault> {
        let Some(node) = self.node(tip) else {
            return Ok(false);
        };
        let base = node.base;
        let anchor = node.anchor;
        let Some(at_base) = self.ancestor_at(tip, base) else {
            return Ok(false);
        };
        let Some(base_node) = self.node(at_base) else {
            return Ok(false);
        };
        if base_node.parent != anchor {
            return Ok(false);
        }
        let fork = base.checked_sub_count(ONE).unwrap_or(BlockHeight::ZERO);
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

    fn node(&self, hash: BlockHash) -> Option<&Node> {
        self.visits.set(self.visits.get().saturating_add(1));
        self.nodes.get(&hash)
    }
}

/// Bitcoin Core's `GetSkipHeight`: the height a node's skip pointer names.
fn skip_height(height: u64) -> u64 {
    if height < 2 {
        return 0;
    }
    if height & 1 == 1 {
        invert_lowest_one(invert_lowest_one(height - 1)) + 1
    } else {
        invert_lowest_one(height)
    }
}

fn invert_lowest_one(n: u64) -> u64 {
    n & n.wrapping_sub(1)
}

/// Bitcoin Core's `GetAncestor` skip predicate, on signed heights so a
/// skip of 0 or 1 subtracts the way the C++ `int` does.
fn skip_reaches(skip_h: u64, skip_prev: u64, target: u64) -> bool {
    if skip_h == target {
        return true;
    }
    if skip_h <= target {
        return false;
    }
    let skip_h = i128::from(skip_h);
    let skip_prev = i128::from(skip_prev);
    let target = i128::from(target);
    !(skip_prev < skip_h - 2 && skip_prev >= target)
}
