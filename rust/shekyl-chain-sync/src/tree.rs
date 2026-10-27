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
use std::cmp::Reverse;
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
    /// The branch record. Every header of one branch shares it, so
    /// connecting the branch root updates the base once.
    branch: u64,
}

/// Where a branch meets main. One record per branch, shared by its headers.
struct Branch {
    /// Connecting height of the first header of this branch still in `T`.
    base: BlockHeight,
    /// Parent of [`Self::base`]. On main, or null at genesis.
    anchor: BlockHash,
}

/// Where a header in `T` sits: its own height, and the fork below it.
pub(crate) struct Placement {
    pub height: BlockHeight,
    pub fork: BlockHeight,
}

/// The headers in `T` with no valid child, ordered heaviest first and, at
/// equal work, by hash. Selection and the alarm read the heaviest until
/// one answers, so they cost the tips heavier than their answer and never
/// the whole set.
#[derive(Default)]
struct Tips {
    work: BTreeMap<BlockHash, CumulativeDifficulty>,
    heaviest: BTreeSet<(Reverse<CumulativeDifficulty>, BlockHash)>,
}

impl Tips {
    fn insert(&mut self, hash: BlockHash, work: CumulativeDifficulty) {
        if let Some(old) = self.work.insert(hash, work) {
            self.heaviest.remove(&(Reverse(old), hash));
        }
        self.heaviest.insert((Reverse(work), hash));
    }

    fn remove(&mut self, hash: &BlockHash) {
        if let Some(work) = self.work.remove(hash) {
            self.heaviest.remove(&(Reverse(work), *hash));
        }
    }

    /// Heaviest first; equal work in hash order.
    fn heaviest(&self) -> impl Iterator<Item = (BlockHash, CumulativeDifficulty)> + '_ {
        self.heaviest
            .iter()
            .map(|(Reverse(work), hash)| (*hash, *work))
    }
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
    tips: Tips,
    /// A header marked invalid, and every header that descends from one.
    /// The hash is remembered so a later child is excluded too.
    invalid: BTreeSet<BlockHash>,
    branches: BTreeMap<u64, Branch>,
    next_branch: u64,
    /// Headers by connecting height, so a connect reads the prefix it
    /// removes and not the whole tree.
    by_height: BTreeMap<u64, BTreeSet<BlockHash>>,
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
        let work = judged.cumulative_difficulty();
        // A refused header stays refused. Inserting it again must not
        // put it back in the tip set.
        if self.invalid.contains(&hash) {
            return;
        }
        let parent = judged.previous();
        let height = judged.connecting().to_raw();
        let parent_in_tree = self.nodes.contains_key(&parent);
        let skip = if parent_in_tree {
            self.ancestor_at(parent, BlockHeight::from_raw(skip_height(height)))
        } else {
            None
        };
        let branch = if parent_in_tree {
            self.nodes
                .get(&parent)
                .expect("the parent was present before the skip lookup")
                .branch
        } else {
            let id = self.next_branch;
            self.next_branch = self.next_branch.saturating_add(1);
            self.branches.insert(
                id,
                Branch {
                    base: judged.connecting(),
                    anchor: parent,
                },
            );
            id
        };
        let excluded = self.invalid.contains(&parent);
        self.nodes.insert(
            hash,
            Node {
                judged,
                parent,
                skip,
                branch,
            },
        );
        self.by_height.entry(height).or_default().insert(hash);
        self.children.entry(parent).or_default().insert(hash);
        if parent_in_tree {
            self.tips.remove(&parent);
        }
        self.tips.insert(hash, work);
        if excluded {
            self.mark_invalid(hash);
        }
    }

    /// Connecting height of the first header of `hash`'s branch still in `T`.
    pub(crate) fn branch_base(&self, hash: BlockHash) -> Option<BlockHeight> {
        let branch = self.nodes.get(&hash)?.branch;
        self.branches.get(&branch).map(|branch| branch.base)
    }

    /// A header already marked invalid, so a later child of it is not a
    /// new chain. The session that serves it is closed.
    pub(crate) fn remembers(&self, hash: BlockHash) -> bool {
        self.invalid.contains(&hash)
    }

    /// The tips heavier than `floor`, heaviest first.
    pub(crate) fn tips_heavier_than(
        &self,
        floor: CumulativeDifficulty,
    ) -> impl Iterator<Item = (BlockHash, CumulativeDifficulty)> + '_ {
        self.tips
            .heaviest()
            .take_while(move |(_, work)| *work > floor)
    }

    /// Headers at or below `height` whose hash is on `main` have been
    /// connected. They leave `T`. The first header still in `T` above
    /// each of them becomes that branch's base.
    pub(crate) fn connected<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        height: BlockHeight,
    ) -> Result<(), H::Fault> {
        let heights: Vec<u64> = self
            .by_height
            .range(..=height.to_raw())
            .map(|(at, _)| *at)
            .collect();
        let mut leaving = Vec::new();
        for at in heights {
            let Some(hashes) = self.by_height.get(&at).cloned() else {
                continue;
            };
            for hash in hashes {
                let Some(node) = self.nodes.get(&hash) else {
                    continue;
                };
                let connecting = node.judged.connecting();
                if let AtHeight::Recorded(record) = main.header_at(connecting)? {
                    if record.hash == hash {
                        leaving.push((connecting.to_raw(), hash));
                    }
                }
            }
        }
        leaving.sort_by_key(|(at, _)| *at);
        for (_, hash) in leaving {
            self.drop_connected(hash);
        }
        // Skip pointers into the connected prefix are left as they are. One
        // that names a header now gone names an ancestor on main, so every
        // height at or below it is below its branch's base: main answers
        // those, and `ancestor_at` returns `None` for them on reaching the
        // missing header, as it would after any rebuild.
        Ok(())
    }

    /// The connected header leaves. One child keeps the branch record,
    /// which now starts at that child. Each other child becomes its own
    /// branch. A single chain moves the base once and does not walk.
    fn drop_connected(&mut self, hash: BlockHash) {
        let Some(branch_id) = self.nodes.get(&hash).map(|node| node.branch) else {
            return;
        };
        let connecting = self
            .nodes
            .get(&hash)
            .map(|node| node.judged.connecting())
            .expect("the node was present");
        let kids = self
            .children
            .get(&hash)
            .map(|kids| kids.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        let is_root = self
            .branches
            .get(&branch_id)
            .is_some_and(|branch| branch.base == connecting);
        if is_root {
            if kids.is_empty() {
                self.branches.remove(&branch_id);
            } else if let Some((first, rest)) = kids.split_first() {
                if let Some(child_at) = self.nodes.get(first).map(|node| node.judged.connecting()) {
                    if let Some(branch) = self.branches.get_mut(&branch_id) {
                        branch.base = child_at;
                        branch.anchor = hash;
                    }
                }
                for kid in rest {
                    self.split_branch(*kid, hash);
                }
            }
        }
        self.nodes.remove(&hash);
        self.tips.remove(&hash);
        self.children.remove(&hash);
        let at = connecting.to_raw();
        let empty = self.by_height.get_mut(&at).is_some_and(|hashes| {
            hashes.remove(&hash);
            hashes.is_empty()
        });
        if empty {
            self.by_height.remove(&at);
        }
    }

    /// `hash` and its descendants become a branch rooted at `hash`,
    /// anchored at the connected parent.
    fn split_branch(&mut self, hash: BlockHash, anchor: BlockHash) {
        let Some(base) = self.nodes.get(&hash).map(|node| node.judged.connecting()) else {
            return;
        };
        let id = self.next_branch;
        self.next_branch = self.next_branch.saturating_add(1);
        self.branches.insert(id, Branch { base, anchor });
        let mut stack = vec![hash];
        while let Some(hash) = stack.pop() {
            if let Some(node) = self.nodes.get_mut(&hash) {
                node.branch = id;
            }
            if let Some(kids) = self.children.get(&hash) {
                stack.extend(kids.iter().copied());
            }
        }
    }

    /// The header and its descendants, by the children index.
    pub(crate) fn mark_invalid(&mut self, hash: BlockHash) {
        let mut stack = vec![hash];
        while let Some(hash) = stack.pop() {
            self.tips.remove(&hash);
            if !self.invalid.insert(hash) {
                continue;
            }
            if let Some(children) = self.children.get(&hash) {
                stack.extend(children.iter().copied());
            }
        }
        self.expose_parent(hash);
    }

    /// The last valid header of a branch is a tip once its descendants
    /// are refused. A parent on main is not in `T`.
    fn expose_parent(&mut self, hash: BlockHash) {
        let Some(parent) = self.nodes.get(&hash).map(|node| node.parent) else {
            return;
        };
        if !self.nodes.contains_key(&parent) || self.invalid.contains(&parent) {
            return;
        }
        let live = self.children.get(&parent).is_some_and(|kids| {
            kids.iter()
                .any(|kid| self.nodes.contains_key(kid) && !self.invalid.contains(kid))
        });
        if !live {
            if let Some(work) = self
                .nodes
                .get(&parent)
                .map(|node| node.judged.cumulative_difficulty())
            {
                self.tips.insert(parent, work);
            }
        }
    }

    /// The height of `hash` when it is in `T`, and the fork below its branch.
    pub(crate) fn placement(&self, hash: BlockHash) -> Option<Placement> {
        let (branch_id, height) = {
            let node = self.node(hash)?;
            (node.branch, node.judged.connecting())
        };
        let base = self.branches.get(&branch_id)?.base;
        let fork = base.checked_sub_count(ONE).unwrap_or(BlockHeight::ZERO);
        Some(Placement { height, fork })
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
    /// and its fork is within `cap`; then the heaviest such tip is chosen.
    /// The tips are read heaviest first and the first within the cap is
    /// the answer, so only the heavier tips that fail the cap are read
    /// before it. Each costs one [`HeaderView::header_at`]: the fork height
    /// is the branch record's base, and that one read checks the anchor.
    pub(crate) fn select<'id, H: HeaderView<'id>>(
        &self,
        main: &H,
        incumbent: Star,
        local_height: Option<BlockHeight>,
        cap: BlockCount,
    ) -> Result<Star, H::Fault> {
        // Heaviest first, so the first tip within the cap is the answer.
        // Equal work with the incumbent is not a candidate.
        for (hash, work) in self.tips_heavier_than(incumbent.work) {
            if self.within_cap(main, hash, local_height, cap)? {
                return Ok(Star { hash, work });
            }
        }
        Ok(incumbent)
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
        let Some(branch_id) = self.node(tip).map(|node| node.branch) else {
            return Ok(false);
        };
        let Some((base, anchor)) = self
            .branches
            .get(&branch_id)
            .map(|branch| (branch.base, branch.anchor))
        else {
            return Ok(false);
        };
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
