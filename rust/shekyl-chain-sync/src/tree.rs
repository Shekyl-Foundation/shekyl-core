// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The header tree `T` (CS-Q2). Only headers the proof accepted, keyed
//! by hash. `H*` is the most work among the local tip and the valid
//! tips whose fork is within the reorg cap. Equal work leaves the
//! incumbent.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_chain_rules::{AtHeight, HeaderJudged, HeaderView};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockCount, BlockHash, BlockHeight};

const ONE: BlockCount = BlockCount::from_raw(1);

struct Node {
    judged: HeaderJudged,
    parent: BlockHash,
}

/// Verified headers above the main chain.
#[derive(Default)]
pub(crate) struct HeaderTree {
    nodes: BTreeMap<BlockHash, Node>,
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
        if excluded {
            self.mark_invalid(hash);
        }
    }

    /// The header and every stored descendant. Selection skips them.
    pub(crate) fn mark_invalid(&mut self, hash: BlockHash) {
        self.invalid.insert(hash);
        let descendants: Vec<BlockHash> = self
            .nodes
            .keys()
            .copied()
            .filter(|node| self.reaches(*node, hash))
            .collect();
        self.invalid.extend(descendants);
    }

    fn reaches(&self, mut from: BlockHash, ancestor: BlockHash) -> bool {
        if from == ancestor {
            return false;
        }
        let mut guard = 0usize;
        while let Some(node) = self.nodes.get(&from) {
            if node.parent == ancestor {
                return true;
            }
            from = node.parent;
            guard += 1;
            if guard > self.nodes.len() {
                return false;
            }
        }
        false
    }

    /// Work of `H*`. Starts from the local chain and replaces it only
    /// with a strictly heavier reachable tip, so an equal-work tip does
    /// not flap the incumbent.
    pub(crate) fn select<'id, H: HeaderView<'id>>(
        &self,
        main: &H,
        local_height: Option<BlockHeight>,
        local_work: CumulativeDifficulty,
        cap: BlockCount,
    ) -> Result<CumulativeDifficulty, H::Fault> {
        let mut best = local_work;
        for hash in self.tips() {
            if self.invalid.contains(&hash) {
                continue;
            }
            let Some(node) = self.nodes.get(&hash) else {
                continue;
            };
            let work = node.judged.cumulative_difficulty();
            if work <= best {
                continue;
            }
            if self.within_cap(main, hash, local_height, cap)? {
                best = work;
            }
        }
        Ok(best)
    }

    fn tips(&self) -> Vec<BlockHash> {
        self.nodes
            .keys()
            .copied()
            .filter(|hash| !self.nodes.values().any(|node| node.parent == *hash))
            .collect()
    }

    /// The fork anchor is the parent hash that is not itself in `T`.
    /// It is within the cap when that block is on `main` and
    /// `L.height − fork.height` does not exceed `cap`. An empty chain's
    /// anchor is the null hash: the branch is genesis, and the depth is
    /// the whole local chain.
    fn within_cap<'id, H: HeaderView<'id>>(
        &self,
        main: &H,
        tip: BlockHash,
        local_height: Option<BlockHeight>,
        cap: BlockCount,
    ) -> Result<bool, H::Fault> {
        let anchor = self.anchor(tip);
        let Some(local_height) = local_height else {
            return Ok(anchor == BlockHash::NULL);
        };
        let Some(fork) = height_of(main, anchor)? else {
            return Ok(false);
        };
        if fork > local_height {
            return Ok(false);
        }
        Ok(local_height - fork <= cap)
    }

    fn anchor(&self, mut hash: BlockHash) -> BlockHash {
        let mut guard = 0usize;
        while let Some(node) = self.nodes.get(&hash) {
            if !self.nodes.contains_key(&node.parent) {
                return node.parent;
            }
            hash = node.parent;
            guard += 1;
            if guard > self.nodes.len() {
                return hash;
            }
        }
        hash
    }
}

fn height_of<'id, H: HeaderView<'id>>(
    main: &H,
    hash: BlockHash,
) -> Result<Option<BlockHeight>, H::Fault> {
    let Some(tip) = main.tip()? else {
        return Ok((hash == BlockHash::NULL).then_some(BlockHeight::ZERO));
    };
    let mut height = tip.height;
    loop {
        let AtHeight::Recorded(record) = main.header_at(height)? else {
            return Ok(None);
        };
        if record.hash == hash {
            return Ok(Some(height));
        }
        if record.header.previous == hash {
            return Ok(height.checked_sub_count(ONE));
        }
        let Some(below) = height.checked_sub_count(ONE) else {
            return Ok(None);
        };
        height = below;
    }
}
