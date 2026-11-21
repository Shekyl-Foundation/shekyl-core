// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which block an `extend` may follow, the law the writer and the reader
//! share beside the height cursor.
//!
//! An `extend` follows the tip: its header names the last block the corpus
//! extended as its parent. From layout 5 it may instead follow a block an
//! earlier `offer` carried, the first block a corpus writes after the
//! chain switched to an offered branch. Its height is then one past the
//! offered block's, and that branch is the chain the corpus extends from
//! there on. An `extend` whose parent is neither is refused
//! ([`CorpusFault::ExtendUnfollowed`]).
//!
//! Nothing here says the chain switched. Whether the fork choice switches
//! to an offered branch is the replay's to derive; an `extend` on an
//! offered block that did not become the tip is a corpus the replay
//! refuses, because the block's parent is not its tip (CEN-A2).
//!
//! An offered block's height is the one its coinbase names
//! (`Block::number`). The first `extend` of a corpus follows whatever its
//! header names: the block before `first_height` is not in the corpus. An
//! offered branch may root there too, below the corpus, when its lowest
//! block is at `first_height`: the corpus is a partial one replayed
//! against a store that holds the ancestry, and the replay judges it.
//!
//! A block the chain leaves, demoted by a switch or popped by a rewind, is
//! kept with its height and parent, so a later branch that builds on it
//! (a switch back) walks down through it to the chain. Only a block an
//! `offer` carried may be an `extend`'s parent off the tip.

use std::collections::{HashMap, HashSet};

use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use shekyl_wire::Block;

use crate::fault::CorpusFault;

/// Where an `extend` sits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Placed {
    /// On the tip: at the height cursor's next height.
    Tip,
    /// On an offered block, at the height one past it.
    Offered {
        /// The height the `extend` carries.
        height: BlockHeight,
        /// Where the branch meets the chain: the chain's index of the
        /// highest block both share, or `None` when the branch roots below
        /// the corpus (its lowest block at `first_height`).
        fork: Option<usize>,
        /// The branch from above the fork up to the parent, lowest first.
        branch: Vec<BlockHash>,
    },
}

/// The chain the corpus extends, by hash, and every block known beside it.
#[derive(Clone, Debug)]
pub(crate) struct Lineage {
    first: BlockHeight,
    /// The chain the corpus extends, one hash per height from `first`.
    chain: Vec<BlockHash>,
    /// The parent `chain[0]` names (below the corpus).
    root: Option<BlockHash>,
    /// Every block known off the chain, offered or left by it: its height
    /// and its parent.
    side: HashMap<BlockHash, (BlockHeight, BlockHash)>,
    /// The blocks an `offer` carried: the ones an `extend` may follow off
    /// the tip.
    offered: HashSet<BlockHash>,
}

impl Lineage {
    /// A corpus whose first record is at `first`.
    pub(crate) fn starting_at(first: BlockHeight) -> Self {
        Self {
            first,
            chain: Vec::new(),
            root: None,
            side: HashMap::new(),
            offered: HashSet::new(),
        }
    }

    /// Whether an offer has been read: until then an `extend` can only
    /// follow the tip.
    pub(crate) fn holds_offers(&self) -> bool {
        !self.offered.is_empty()
    }

    /// Where an `extend` of `block` sits, refused when its parent is
    /// neither the tip nor an offered block. `claimed` names the record in
    /// the fault.
    ///
    /// # Errors
    ///
    /// [`CorpusFault::ExtendUnfollowed`]; [`CorpusFault::HeightExhausted`]
    /// for an offered parent at the last height.
    pub(crate) fn place(&self, block: &Block, claimed: BlockHeight) -> Result<Placed, CorpusFault> {
        let parent = block.header.previous;
        match self.chain.last() {
            None => return Ok(Placed::Tip),
            Some(tip) if *tip == parent => return Ok(Placed::Tip),
            Some(_) => {}
        }
        let unfollowed = CorpusFault::ExtendUnfollowed {
            height: claimed,
            parent,
        };
        if !self.offered.contains(&parent) {
            return Err(unfollowed);
        }
        let Some(&(at, _)) = self.side.get(&parent) else {
            return Err(unfollowed);
        };
        let height = at
            .checked_add(BlockCount::ONE)
            .ok_or(CorpusFault::HeightExhausted { after: at })?;
        // Walk the branch down to the chain: each block's parent is the
        // chain's block one height below it, which is the fork, a block
        // known off the chain (offered, or left by the chain), or, for a
        // branch whose lowest block is at `first_height`, a block below
        // the corpus.
        let mut branch = Vec::new();
        let mut cursor = parent;
        let fork = loop {
            let Some(&(at, up)) = self.side.get(&cursor) else {
                return Err(unfollowed);
            };
            branch.push(cursor);
            if at == self.first {
                // The branch's lowest block is the corpus's first height:
                // its parent is below the corpus, the replay's to judge.
                break None;
            }
            let Some(below) = at.checked_sub_count(BlockCount::ONE) else {
                return Err(unfollowed);
            };
            if below < self.first {
                return Err(unfollowed);
            }
            match self.index(below) {
                Some(index) if self.chain[index] == up => break Some(index),
                _ => cursor = up,
            }
        };
        branch.reverse();
        Ok(Placed::Offered {
            height,
            fork,
            branch,
        })
    }

    /// Record the `extend` of `hash` on `parent`, placed by [`Self::place`].
    /// On an offered parent, the chain the corpus extends becomes that
    /// branch: the chain to the fork, the branch above it, then this block.
    /// The blocks the chain leaves are kept beside it.
    pub(crate) fn extend(&mut self, placed: Placed, hash: BlockHash, parent: BlockHash) {
        match placed {
            Placed::Tip => {
                if self.chain.is_empty() {
                    self.root = Some(parent);
                }
            }
            Placed::Offered { fork, branch, .. } => {
                self.leave_above(fork);
                if fork.is_none() {
                    self.root = branch
                        .first()
                        .and_then(|lowest| self.side.get(lowest))
                        .map(|&(_, up)| up);
                }
                self.chain.extend(branch);
            }
        }
        self.chain.push(hash);
    }

    /// Record an offered block.
    ///
    /// # Errors
    ///
    /// [`CorpusFault::OfferUnnumbered`] for a coinbase that names no
    /// height; a block that parsed always names one (its miner transaction
    /// has its one `gen` input).
    pub(crate) fn offer(&mut self, block: &Block) -> Result<(), CorpusFault> {
        let Some(number) = block.number() else {
            return Err(CorpusFault::OfferUnnumbered);
        };
        let hash = block.hash();
        self.side
            .insert(hash, (BlockHeight::from_raw(number), block.header.previous));
        self.offered.insert(hash);
        Ok(())
    }

    /// Pop the chain to `to`, as a `rewind` does; the popped blocks are
    /// kept beside it.
    pub(crate) fn rewind(&mut self, to: BlockHeight) {
        if let Some(index) = self.index(to) {
            self.leave_above(Some(index));
        }
    }

    /// Move the chain's blocks above `keep` (an index, or `None` for all of
    /// them) beside it, each with its height and parent.
    fn leave_above(&mut self, keep: Option<usize>) {
        let start = keep.map_or(0, |index| index + 1);
        if start >= self.chain.len() {
            return;
        }
        let mut parent = match start.checked_sub(1) {
            Some(below) => Some(self.chain[below]),
            None => self.root,
        };
        let left: Vec<BlockHash> = self.chain.drain(start..).collect();
        for (offset, hash) in left.into_iter().enumerate() {
            let height = self
                .first
                .checked_add(BlockCount::from_raw(
                    u64::try_from(start + offset).expect("a chain index fits u64"),
                ))
                .expect("a chain height was a height");
            if let Some(up) = parent {
                self.side.insert(hash, (height, up));
            }
            parent = Some(hash);
        }
    }

    /// The chain's index of `height`, when the chain holds it.
    fn index(&self, height: BlockHeight) -> Option<usize> {
        let offset = height.to_raw().checked_sub(self.first.to_raw())?;
        let index = usize::try_from(offset).ok()?;
        (index < self.chain.len()).then_some(index)
    }
}
