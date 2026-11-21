// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One corpus record, after it has been verified.
//!
//! [`Record`] is the enum a new layout extends. Layout 4 has `extend` and
//! `rewind`; layout 5 adds `offer`. A later tag is a new variant here, plus
//! the writer's encoder and the reader's decoder for that tag. It is not a
//! change to the height cursor unless the tag moves the tip.

use shekyl_archival_retention::BundleBody;
use shekyl_types::archival::BundleReferences;
use shekyl_types::BlockHeight;
use shekyl_wire::{Block, Transaction};

/// One `extend`, verified: the block, its listed bodies in header order,
/// and its bundle section with each body held to its reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extend {
    /// The record's height.
    pub height: BlockHeight,
    /// The block.
    pub block: Block,
    /// The bodies of the block's listed transactions, in header order.
    pub transactions: Vec<Transaction>,
    /// The block's bundle references, or `None` for a block that admits no
    /// bundle.
    pub bundle_references: Option<BundleReferences>,
    /// Each reference's body, in section order.
    pub bundle_bodies: Vec<BundleBody>,
}

/// One `offer`, verified: a block that does not extend the tip, with what
/// an [`Extend`] carries but its height. Its parent is named by its own
/// header (`prev_id`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    /// The block.
    pub block: Block,
    /// The bodies of the block's listed transactions, in header order.
    pub transactions: Vec<Transaction>,
    /// The block's bundle references, or `None` for a block that admits no
    /// bundle.
    pub bundle_references: Option<BundleReferences>,
    /// Each reference's body, in section order.
    pub bundle_bodies: Vec<BundleBody>,
}

/// One record of a corpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// A block at the next height.
    Extend(Box<Extend>),
    /// Pop to `to`; the next `extend` carries `to + 1` (crate docs).
    Rewind {
        /// The tip after the pop.
        to: BlockHeight,
    },
    /// A block that arrived and does not extend the tip (layout 5).
    Offer(Box<Offer>),
}

/// One more record in the header's count.
///
/// The count is a `u64`. Exhausting it is not a corpus a caller can build:
/// the `expect` names that invariant, the same way a sequence number does.
pub(crate) fn note_one_more(records: u64) -> u64 {
    records
        .checked_add(1)
        .expect("corpus record count exhausted")
}
