// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Blocks: headers, bodies, the template, submission, proof of work and
//! the armed levers.

use super::shared::{OrArchived, Selector, Slot};
use crate::hash::HashHex;
use crate::hex128::HexU128;
use crate::kinds::{Bytes, Count, Height, Integer, Size, Time};
use crate::nullable::Nullable;
use shekyl_units::wire::AtomicUnitsString as Amount;

crate::wire_object! {
    /// A block's header.
    ["block header"]
    pub struct BlockHeader {
        pub version_major: Integer,
        pub version_minor: Integer,
        pub time: Time,
        pub parent: HashHex,
        pub nonce: Integer,
        pub orphan: bool,
        pub height: Height,
        /// Blocks above this one.
        pub depth: Count,
        pub hash: HashHex,
        pub difficulty: HexU128,
        pub difficulty_cumulative: HexU128,
        pub reward: Amount,
        pub weight: Size,
        /// `null` for a block off the main chain, which has none.
        pub weight_longterm: Nullable<Size>,
        pub tx_count: Count,
        /// The proof-of-work hash, when asked for (IG-Q56); `null` when not.
        pub pow: Nullable<HashHex>,
        /// The coinbase transaction's id.
        pub coinbase: HashHex,
        pub curve_root: HashHex,
        /// The root of the block's bundle section (`ARCHIVAL_SERVE_CREDIT_SPEC.md`
        /// §7.5).
        pub section_root: HashHex,
    }
}

/// A one-block read's request: exactly one selector (IG-Q94), and the
/// switches the method takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockSelect {
    /// Which block.
    pub select: Selector,
    /// Fill the header's `pow` (IG-Q56). Off by default.
    pub pow: bool,
    /// Carry each body pruned (IG-Q55); `None` on a method with no such
    /// switch.
    pub prune: Option<bool>,
}

/// `block_header_show`'s request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderSelect(pub BlockSelect);

/// `block_show`'s request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockShowSelect(pub BlockSelect);

fn write_select<S: serde::Serializer>(
    select: &BlockSelect,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut map = serializer.serialize_map(None)?;
    select.select.write(&mut map)?;
    map.serialize_entry("pow", &select.pow)?;
    if let Some(prune) = select.prune {
        map.serialize_entry("prune", &prune)?;
    }
    map.end()
}

impl serde::Serialize for HeaderSelect {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        write_select(&self.0, serializer)
    }
}

crate::wire_exclusive! {
    HeaderSelect ["block"] keys HeaderSelectKeys {
        [height: Height] => Selector::Height(height);
        [hash: HashHex] => Selector::Hash(hash);
        [tip: null] => Selector::Tip;
        switch pow ["block header"];
        build(select, pow) Self(BlockSelect { select, pow, prune: None })
    }
}

impl serde::Serialize for BlockShowSelect {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        write_select(&self.0, serializer)
    }
}

crate::wire_exclusive! {
    BlockShowSelect ["block"] keys BlockShowSelectKeys {
        [height: Height] => Selector::Height(height);
        [hash: HashHex] => Selector::Hash(hash);
        [tip: null] => Selector::Tip;
        switch pow ["block header"];
        switch prune ["tx"];
        build(select, pow, prune) Self(BlockSelect { select, pow, prune: Some(prune) })
    }
}

/// `block_header_list`'s request: an inclusive range of heights, or a
/// list of hashes, never both; and the `pow` switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderRange {
    /// Which headers.
    pub select: HeaderRangeSelect,
    /// Fill each header's `pow`.
    pub pow: bool,
}

/// Which headers `block_header_list` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderRangeSelect {
    /// The headers from `from` to `to`, inclusive.
    Range {
        /// The first height.
        from: Height,
        /// The last height.
        to: Height,
    },
    /// The headers with these hashes, in this order.
    Hash(Vec<HashHex>),
}

impl serde::Serialize for HeaderRange {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        match &self.select {
            HeaderRangeSelect::Range { from, to } => {
                map.serialize_entry("from", from)?;
                map.serialize_entry("to", to)?;
            }
            HeaderRangeSelect::Hash(hash) => map.serialize_entry("hash", hash)?,
        }
        map.serialize_entry("pow", &self.pow)?;
        map.end()
    }
}

crate::wire_exclusive! {
    HeaderRange ["block"] keys HeaderRangeKeys {
        [from: Height, to: Height] => HeaderRangeSelect::Range { from, to };
        [hash: Vec<HashHex>] => HeaderRangeSelect::Hash(hash);
        switch pow ["block header"];
        build(select, pow) Self { select, pow }
    }
}

crate::wire_object! {
    /// A transaction of a block, and the txid's operands (`SB-Q2`). Under
    /// `prune`, `body` is the pruned segment.
    ["tx"]
    pub struct BlockTx {
        pub id: HashHex,
        pub body: Bytes,
        pub prunable_hash: HashHex,
        /// `null` where the identity has no third operand: the coinbase.
        pub pqc_auth_hash: Nullable<HashHex>,
        pub archival_size: Size,
    }
}

crate::wire_object! {
    /// A block.
    ["block"]
    pub struct Block {
        pub header: BlockHeader,
        pub body: Bytes,
        pub tx: Vec<OrArchived<BlockTx>>,
        /// The global index of the block's first output (RW-Q5).
        pub output_index: Integer,
        /// The block's bundle references, in section order, as its header's
        /// `section_root` commits them. Empty when the block admits no
        /// bundle.
        pub section: Vec<Bytes>,
        /// The body of each reference this node still holds, in no set
        /// order: a reader matches each to its reference by hash.
        pub section_body: Vec<Bytes>,
    }
}

crate::wire_object! {
    /// `block_list`'s request: heights, and the `prune` switch.
    ["block"]
    pub struct BlockListQuery {
        pub height: Vec<Height>,
        #[serde(default)]
        pub prune [optional "tx"]: bool,
    }
}

/// `block_list`'s reply: a block for each height, in order.
pub type BlockList = Vec<Slot<Block>>;

crate::wire_object! {
    /// The posted job (`block_template`).
    ["block template"]
    pub struct BlockTemplate {
        pub difficulty: HexU128,
        /// The height the block connects at.
        pub height: Height,
        /// Where the coinbase's reserved extra-nonce bytes start in `body`.
        pub extra_offset: Integer,
        /// Where the header's nonce bytes start, in both blobs (IG-Q78).
        pub nonce_offset: Integer,
        pub reward: Amount,
        pub parent: HashHex,
        pub seed_height: Height,
        pub body: Bytes,
        pub hashing: Bytes,
        pub seed: HashHex,
        /// The next epoch's seed, once known and different; `null` until.
        pub seed_next: Nullable<HashHex>,
        pub version_major: Integer,
        pub weight_median: Size,
        pub emission: Amount,
    }
}

crate::wire_object! {
    /// A block handed to the daemon.
    ["block"]
    pub struct BlockBody {
        pub body: Bytes,
    }
}

crate::wire_object! {
    /// The accepted block's hash.
    ["block"]
    pub struct BlockId {
        pub hash: HashHex,
    }
}

crate::wire_object! {
    /// `pow`'s input: the hashing bytes and the seed to hash under.
    ["pow"]
    pub struct PowInput {
        pub height: Height,
        pub hashing: Bytes,
        /// The seed; when left out, the seed at `height`.
        pub seed [optional]: Option<HashHex>,
    }
}

crate::wire_object! {
    /// A block's proof-of-work hash.
    ["block"]
    pub struct Pow {
        pub pow: HashHex,
    }
}

crate::wire_object! {
    /// `dev_block_generate`'s request (an armed lever).
    ["block"]
    pub struct GenerateCount {
        pub count: Count,
    }
}

crate::wire_object! {
    /// The blocks a generate mined.
    ["block"]
    pub struct Generated {
        /// The new tip.
        pub height: Height,
        pub hash: Vec<HashHex>,
    }
}

crate::wire_object! {
    /// `dev_chain_pop`'s request (an armed lever).
    ["chain"]
    pub struct PopCount {
        pub count: Count,
    }
}

crate::wire_object! {
    /// The tip after a pop.
    ["chain"]
    pub struct Popped {
        pub height: Height,
    }
}
