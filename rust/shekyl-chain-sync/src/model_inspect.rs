// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the tests read off the coordinator. Production asks the holder
//! methods on [`Sync`](crate::model::Sync) directly.

use shekyl_chain_rules::{HeaderRecord, RuleSet};
use shekyl_types::{BlockHash, BlockHeight};

use crate::branch::BranchView;
use crate::model::Sync;
use crate::tree::Star;

impl<K, R> Sync<K, R>
where
    K: Copy + Ord + std::hash::Hash + std::fmt::Debug,
    R: Fn(BlockHeight) -> RuleSet,
{
    /// `H*`: the hash and the work selection last chose.
    #[must_use]
    pub(crate) fn selected(&self) -> Star {
        self.star
    }

    /// Headers in `T`.
    #[must_use]
    pub(crate) fn header_count(&self) -> usize {
        self.tree.len()
    }

    /// Whether `T` holds `hash`.
    #[must_use]
    pub(crate) fn contains_header(&self, hash: BlockHash) -> bool {
        self.tree.contains(hash)
    }

    /// Whether `hash` was marked invalid, with its descendants.
    #[must_use]
    pub(crate) fn remembers_header(&self, hash: BlockHash) -> bool {
        self.tree.remembers(hash)
    }

    /// Node loads since the tree was built, or since [`Self::reset_visits`].
    #[must_use]
    pub(crate) fn tree_visits(&self) -> u64 {
        self.tree.visits()
    }

    /// Start the node-load count over.
    pub(crate) fn reset_visits(&self) {
        self.tree.reset_visits();
    }

    /// Cheap-checked headers the session's run still holds.
    #[must_use]
    pub(crate) fn run_len(&self, session: K) -> usize {
        self.peers
            .get(&session)
            .and_then(|peer| peer.run.as_ref())
            .map(|run| run.chain.checked.len())
            .unwrap_or(0)
    }

    /// The record `T` holds for `hash`.
    pub(crate) fn header_record(&self, hash: BlockHash) -> Option<HeaderRecord> {
        self.tree.record(hash)
    }

    /// The run's cheap-checked headers, in order. A past-cap run keeps
    /// only its window, so this is that window.
    #[must_use]
    pub(crate) fn run_records(&self, session: K) -> Vec<HeaderRecord> {
        self.peers
            .get(&session)
            .and_then(|peer| peer.run.as_ref())
            .map(|run| {
                run.chain
                    .checked
                    .iter()
                    .map(|checked| HeaderRecord {
                        hash: checked.hash,
                        header: checked.header.clone(),
                        cumulative_difficulty: checked.work,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The branch whose tip is `parent`: `T` when the parent is in the
    /// tree, main when the parent is the local tip. `None` when it is
    /// neither, and the caller judges against `main` and records the result.
    pub(crate) fn branch_of<'a, H>(
        &'a self,
        main: &'a H,
        parent: BlockHash,
    ) -> Option<BranchView<'a, H>> {
        if let Some(placed) = self.tree.placement(parent) {
            return Some(BranchView::above(
                main,
                &self.tree,
                parent,
                placed.height,
                placed.fork,
            ));
        }
        let local = self.local?;
        if local.hash == parent {
            return match local.height {
                Some(height) => Some(BranchView::on_main(main, parent, height)),
                None if parent == BlockHash::NULL => Some(BranchView::empty_main(main)),
                None => None,
            };
        }
        if local.height.is_none() && parent == BlockHash::NULL {
            return Some(BranchView::empty_main(main));
        }
        None
    }
}
