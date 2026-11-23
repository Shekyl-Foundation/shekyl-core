// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bodies a plan built, recorded so the identity test can re-sign one
//! of each kind. The runner appends them as it lists; the test reads them.
//! A popped reorg branch's body stays here and the test skips it.

use shekyl_types::BlockHeight;

/// A body the plan built, with what re-signing it takes
/// ([`shekyl_harness_spender::Spender::signed_under`]): the identity test's
/// proof leg re-signs one of each kind under another network's id.
#[derive(Clone, Debug)]
pub struct Built {
    /// The body as listed.
    pub body: shekyl_wire::Transaction,
    /// The height its block connected at.
    pub connecting: BlockHeight,
    /// What it is.
    pub kind: BuiltKind,
}

/// What a [`Built`] body is.
#[derive(Clone, Debug)]
pub enum BuiltKind {
    /// A spend of the miner's coinbases at these heights.
    Spend {
        /// The coinbases spent.
        coinbases: Vec<BlockHeight>,
    },
    /// A coinbase spend carrying persona `slot`'s compact join of `shards`.
    Join {
        /// The coinbase spent.
        coinbase: BlockHeight,
        /// The persona.
        slot: u32,
        /// The shards joined.
        shards: Vec<u64>,
    },
    /// A spend of one coinbase paying the miner past the usual two outputs.
    Paying {
        /// The coinbase spent.
        coinbase: BlockHeight,
    },
    /// A coinbase spend paying the harness seed's persona.
    Funding {
        /// The coinbase spent.
        coinbase: BlockHeight,
    },
    /// A coinbase spend carrying a post of persona `slot`: a Reinstate or
    /// a Release.
    Post {
        /// The coinbase spent.
        coinbase: BlockHeight,
        /// The persona.
        slot: u32,
    },
    /// A spend of one output a block paid: a persona's collect, or the
    /// miner's spend of an output in a discarded shard.
    Owned {
        /// The output's key.
        output_key: [u8; 32],
    },
    /// Persona `slot`'s emission claim.
    Claim {
        /// The persona.
        slot: u32,
        /// The height its join connected at: its owned outputs are paid
        /// there.
        join_height: BlockHeight,
        /// The claim's backing output.
        backing_key: [u8; 32],
        /// The claim's fee input.
        fee_key: [u8; 32],
    },
}
