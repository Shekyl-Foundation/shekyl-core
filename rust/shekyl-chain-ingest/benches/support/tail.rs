// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The tail the serve, the frame and the wallet-read rows request.
//!
//! One connected unit chain, and the last [`TAIL_BLOCKS`] of it. The three
//! benches include this module and not each other's setup, so a change to
//! the request changes all three rows together.

#[path = "block_path.rs"]
mod block_path;

use block_path::connected;
use shekyl_chain_ingest::bench_support::BlockPath;

/// Blocks one sync or wallet request names on a unit fixture: the subject
/// and the coinbase-only blocks behind it.
pub const TAIL_BLOCKS: usize = 8;

/// Spends the unit subject's block lists. The fixture test holds a unit
/// block to the same count (`UNIT_TRANSACTIONS`).
pub const SUBJECT_SPENDS: usize = 4;

/// A connected unit chain and the block hashes a request of its tail names.
///
/// Hashes are oldest first, the subject last, and there are [`TAIL_BLOCKS`]
/// of them.
pub struct RequestedTail {
    pub chain: BlockPath,
    pub hashes: Vec<[u8; 32]>,
}

impl RequestedTail {
    /// `corpus` replayed through connect, and its last [`TAIL_BLOCKS`] hashes.
    ///
    /// # Panics
    ///
    /// The chain is shorter than the request.
    #[must_use]
    pub fn connected(corpus: &[u8]) -> Self {
        let chain = connected(corpus);
        let recorded = chain.hashes();
        assert!(recorded.len() >= TAIL_BLOCKS, "the chain holds the request");
        let hashes = recorded[recorded.len() - TAIL_BLOCKS..]
            .iter()
            .map(|hash| *hash.as_bytes())
            .collect();
        Self { chain, hashes }
    }
}
