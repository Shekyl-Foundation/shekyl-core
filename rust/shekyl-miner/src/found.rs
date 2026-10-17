// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`FoundBlocks`]: the found-block sink. A channel whose receiving end the
//! composition root hands to the connector's door (PR 2); the miner holds
//! the sending end.

use std::sync::mpsc;

use shekyl_types::{BlockHeight, PowHash};
use shekyl_wire::Block;

use crate::job::Generation;

/// A block the search found: the job's block with the nonce that meets its
/// difficulty, the height it was mined for, the job's generation, and the
/// longhash the worker computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The mined block.
    pub block: Block,
    /// The height it connects at.
    pub height: BlockHeight,
    /// The job it was mined from.
    pub generation: Generation,
    /// Its longhash under the job's seed.
    pub pow: PowHash,
}

/// The sending end of the found-block channel.
#[derive(Debug, Clone)]
pub struct FoundBlocks(mpsc::Sender<Found>);

impl FoundBlocks {
    /// Deliver `found`. `false` when the receiving end is gone: nothing
    /// will connect the block, and the worker that found it says so.
    pub(crate) fn deliver(&self, found: Found) -> bool {
        self.0.send(found).is_ok()
    }
}

/// A found-block channel: the sink the miner sends on, and the end the
/// connector's door receives from.
#[must_use]
pub fn found_blocks() -> (FoundBlocks, mpsc::Receiver<Found>) {
    let (sender, receiver) = mpsc::channel();
    (FoundBlocks(sender), receiver)
}
