// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where an intent and this wallet's membership paths meet (R-26):
//! [`SpendPaths`].
//!
//! The intent comes from another member; the paths come from this wallet's
//! own curve tree, as one sealed [`AssembledPaths`] batch the tree's actor
//! assembled. No type can remove the comparison between the two, so this
//! module makes it happen exactly once: [`SpendPaths::new`] is the only
//! constructor, it checks that the batch was assembled against the intent's
//! reference block and holds exactly the intent's inputs, and
//! [`DerivedSpend::derive`](super::DerivedSpend::derive) takes nothing
//! else. Every path in a batch is to one tree by construction, so no
//! reader checks that either.
//!
//! A `SpendPaths` cannot be written out by hand:
//!
//! ```compile_fail,E0451
//! use shekyl_curve_tree::TreeContext;
//! use shekyl_multisig::ceremony::SpendPaths;
//! use shekyl_multisig::ValidatedIntent;
//!
//! fn forge(intent: ValidatedIntent, tree: TreeContext) -> SpendPaths {
//!     SpendPaths {
//!         intent,
//!         tree,
//!         paths: Vec::new(),
//!     }
//! }
//! ```

use std::collections::BTreeMap;

use shekyl_curve_tree::{AssembledPath, AssembledPaths, TreeContext};
use shekyl_types::BlockHash;

use crate::invariants::ValidatedIntent;

/// A validated intent and the membership paths of the inputs it spends,
/// matched once (R-26): the paths were assembled against the intent's
/// reference block, and there is exactly one for each of its inputs, held
/// in the intent's input order. What
/// [`DerivedSpend::derive`](super::DerivedSpend::derive) takes.
#[derive(Clone)]
pub struct SpendPaths {
    intent: ValidatedIntent,
    tree: TreeContext,
    paths: Vec<AssembledPath>,
}

/// Why a batch of paths does not match an intent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpendPathsError {
    /// The batch was assembled against another block than the intent's
    /// reference block.
    #[error(
        "the paths were assembled against block {batch}, not the intent's reference block {intent}"
    )]
    OtherBlock {
        /// The intent's reference block.
        intent: BlockHash,
        /// The block the batch was assembled against.
        batch: BlockHash,
    },
    /// The batch holds no path for an input the intent spends.
    #[error("the paths hold none for input {global_index}")]
    MissingInput {
        /// The input's global index.
        global_index: u64,
    },
    /// The batch holds a path for an input the intent does not spend, or a
    /// second path for one it does.
    #[error("the paths hold one for input {global_index} the intent does not spend once")]
    ExtraInput {
        /// The input's global index.
        global_index: u64,
    },
}

impl SpendPaths {
    /// Match `paths` to `intent`.
    ///
    /// # Errors
    ///
    /// [`SpendPathsError::OtherBlock`] when the batch was assembled against
    /// another block than the intent's reference block;
    /// [`SpendPathsError::ExtraInput`] when it holds a path for an input the
    /// intent does not spend, or two for one it does;
    /// [`SpendPathsError::MissingInput`] when it holds none for an input the
    /// intent spends.
    pub fn new(intent: &ValidatedIntent, paths: AssembledPaths) -> Result<Self, SpendPathsError> {
        let reference = BlockHash::from_bytes(intent.intent().reference_block_hash);
        let assembled_at = paths.reference().block_hash;
        if assembled_at != reference {
            return Err(SpendPathsError::OtherBlock {
                intent: reference,
                batch: assembled_at,
            });
        }
        let tree = paths.tree();
        let spent = &intent.intent().input_global_indices;
        let mut by_input = BTreeMap::new();
        for (asked, path) in paths.into_paths() {
            let global_index = asked.gindex.to_raw();
            if !spent.contains(&global_index) || by_input.insert(global_index, path).is_some() {
                return Err(SpendPathsError::ExtraInput { global_index });
            }
        }
        let paths = spent
            .iter()
            .map(|&global_index| {
                by_input
                    .remove(&global_index)
                    .ok_or(SpendPathsError::MissingInput { global_index })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            intent: intent.clone(),
            tree,
            paths,
        })
    }

    /// The intent the paths were matched to.
    #[must_use]
    pub fn intent(&self) -> &ValidatedIntent {
        &self.intent
    }

    /// The one tree every path is to: the intent's reference block, its
    /// header root and the tree's depth there.
    #[must_use]
    pub fn tree(&self) -> TreeContext {
        self.tree
    }

    /// The intent, the tree and each input's path in the intent's input
    /// order, for the derivation that consumes them.
    pub(super) fn into_parts(self) -> (ValidatedIntent, TreeContext, Vec<AssembledPath>) {
        (self.intent, self.tree, self.paths)
    }
}
