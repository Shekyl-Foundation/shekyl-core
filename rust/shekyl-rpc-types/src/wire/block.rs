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
use crate::schema::{Field, Schema, Shape};
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
        pub weight_longterm: Size,
        pub tx_count: Count,
        /// The proof-of-work hash, when asked for (IG-Q56); `null` when not.
        pub pow: Nullable<HashHex>,
        /// The coinbase transaction's id.
        pub coinbase: HashHex,
        pub curve_root: HashHex,
        pub attestation_root: HashHex,
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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderKeys {
    #[serde(default)]
    height: Option<Height>,
    #[serde(default)]
    hash: Option<HashHex>,
    #[serde(default, deserialize_with = "crate::wire::shared::tip_given")]
    tip: Option<super::shared::Null>,
    #[serde(default)]
    pow: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockKeys {
    #[serde(default)]
    height: Option<Height>,
    #[serde(default)]
    hash: Option<HashHex>,
    #[serde(default, deserialize_with = "crate::wire::shared::tip_given")]
    tip: Option<super::shared::Null>,
    #[serde(default)]
    pow: bool,
    #[serde(default)]
    prune: bool,
}

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

impl<'de> serde::Deserialize<'de> for HeaderSelect {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let keys = HeaderKeys::deserialize(deserializer)?;
        let select = Selector::one(keys.height, keys.hash, keys.tip, true)
            .map_err(serde::de::Error::custom)?;
        Ok(Self(BlockSelect {
            select,
            pow: keys.pow,
            prune: None,
        }))
    }
}

impl serde::Serialize for BlockShowSelect {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        write_select(&self.0, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for BlockShowSelect {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let keys = BlockKeys::deserialize(deserializer)?;
        let select = Selector::one(keys.height, keys.hash, keys.tip, true)
            .map_err(serde::de::Error::custom)?;
        Ok(Self(BlockSelect {
            select,
            pow: keys.pow,
            prune: Some(keys.prune),
        }))
    }
}

fn switch(name: &'static str, under: &'static str) -> Field {
    Field {
        name,
        under: Some(under),
        shape: Shape::Optional(Box::new(Shape::Scalar("switch"))),
    }
}

impl Schema for HeaderSelect {
    fn shape() -> Shape {
        Shape::Object {
            holder: "block",
            fields: vec![switch("pow", "block header")],
            parts: Vec::new(),
            choice: Selector::choice(true),
        }
    }
}

impl Schema for BlockShowSelect {
    fn shape() -> Shape {
        Shape::Object {
            holder: "block",
            fields: vec![switch("pow", "block header"), switch("prune", "tx")],
            parts: Vec::new(),
            choice: Selector::choice(true),
        }
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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RangeKeys {
    #[serde(default)]
    from: Option<Height>,
    #[serde(default)]
    to: Option<Height>,
    #[serde(default)]
    hash: Option<Vec<HashHex>>,
    #[serde(default)]
    pow: bool,
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

impl<'de> serde::Deserialize<'de> for HeaderRange {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let keys = RangeKeys::deserialize(deserializer)?;
        let select = match (keys.from, keys.to, keys.hash) {
            (Some(from), Some(to), None) => HeaderRangeSelect::Range { from, to },
            (None, None, Some(hash)) => HeaderRangeSelect::Hash(hash),
            _ => {
                return Err(serde::de::Error::custom(
                    "name either from and to, or hash; exactly one of the two",
                ))
            }
        };
        Ok(Self {
            select,
            pow: keys.pow,
        })
    }
}

impl Schema for HeaderRange {
    fn shape() -> Shape {
        Shape::Object {
            holder: "block",
            fields: vec![
                Field {
                    name: "from",
                    under: None,
                    shape: Shape::Optional(Box::new(Height::shape())),
                },
                Field {
                    name: "to",
                    under: None,
                    shape: Shape::Optional(Box::new(Height::shape())),
                },
                Field {
                    name: "hash",
                    under: None,
                    shape: Shape::Optional(Box::new(<Vec<HashHex>>::shape())),
                },
                switch("pow", "block header"),
            ],
            parts: Vec::new(),
            choice: Vec::new(),
        }
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
