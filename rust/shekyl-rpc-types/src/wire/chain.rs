// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The chain's reads: the version, the tip, the fee, the coinbase sum, the
//! alternative chains, spent key images and the curve tree.

use super::shared::{Null, Selector, SelectorKeys};
use crate::hash::HashHex;
use crate::hex128::HexU128;
use crate::kinds::{Count, Height, Integer};
use crate::nullable::Nullable;
use crate::schema::{Schema, Shape};
use shekyl_units::wire::AtomicUnitsString as Amount;

crate::wire_keywords! {
    /// Which chain a daemon runs (§3's `network`).
    pub enum NetworkName {
        Mainnet = "mainnet",
        Testnet = "testnet",
        Stagenet = "stagenet",
        Regtest = "regtest",
    }
}

crate::wire_object! {
    /// The version read (`RPC_WIRE.md` RW-Q6). Only `version`, a JSON
    /// integer `(major << 16) | minor`, is frozen (RK-D25).
    ["daemon"]
    pub struct Version {
        pub version: Integer,
        pub tagged: bool,
        pub height: Height,
        pub target_height: Nullable<Height>,
        pub consensus_digest: HashHex,
        pub network: NetworkName,
        pub genesis: HashHex,
    }
}

crate::wire_object! {
    /// What halted the chain store's writer (IG-Q92).
    ["chain writer"]
    pub struct Halt {
        /// The height the halting connect or pop was working at.
        pub height: Height,
        /// The `SI-` row of the store-invariant register that caught it.
        pub invariant: Integer,
    }
}

crate::wire_states! {
    /// The chain store's writer (IG-Q92): live, or halted on an invariant.
    /// A halted writer's tip is stale.
    pub enum Writer {
        Live(Null) = "live",
        Halted(Halt) = "halted",
    }
}

crate::wire_object! {
    /// The tip (`chain_height`).
    ["chain"]
    pub struct ChainHeight {
        pub height: Height,
        pub hash: HashHex,
        pub writer: Writer,
    }
}

crate::wire_object! {
    /// The fee tiers, each an amount per unit of weight (IG-Q52).
    ["fee"]
    pub struct Fee {
        pub economy: Amount,
        pub standard: Amount,
        pub high: Amount,
    }
}

crate::wire_object! {
    /// `chain_coinbase_sum`'s range, inclusive heights.
    ["chain coinbase sum"]
    pub struct CoinbaseSumRange {
        pub from: Height,
        pub to: Height,
    }
}

crate::wire_object! {
    /// The coinbase sum over a range.
    ["chain coinbase sum"]
    pub struct CoinbaseSum {
        pub emission: Amount,
        pub fee: Amount,
    }
}

crate::wire_object! {
    /// One alternative chain.
    ["chain alt"]
    pub struct AltChain {
        /// Its tip's hash.
        pub hash: HashHex,
        pub height: Height,
        pub difficulty_cumulative: HexU128,
        /// Its blocks' hashes, tip first.
        pub block: Vec<HashHex>,
        /// The main-chain block it extends.
        pub parent: HashHex,
    }
}

crate::wire_object! {
    /// `chain_spent`'s input.
    ["chain spent"]
    pub struct SpentQuery {
        pub key_image: Vec<HashHex>,
    }
}

crate::wire_keywords! {
    /// Where a key image is spent, if anywhere.
    pub enum Spent {
        Unspent = "unspent",
        Chain = "chain",
        Txpool = "txpool",
    }
}

/// `curve_show`'s selector: exactly one of `height` or `tip` (IG-Q94).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurveSelect(pub Selector);

impl serde::Serialize for CurveSelect {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        self.0.write(&mut map)?;
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for CurveSelect {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let keys = SelectorKeys::deserialize(deserializer)?;
        Selector::one(keys.height, keys.hash, keys.tip, false)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

impl Schema for CurveSelect {
    fn shape() -> Shape {
        Shape::Object {
            holder: "curve",
            fields: Vec::new(),
            parts: Vec::new(),
            choice: Selector::choice(false),
        }
    }
}

crate::wire_object! {
    /// The curve tree at a height (IG-Q47).
    ["curve"]
    pub struct Curve {
        pub root: HashHex,
        pub layers: Count,
        pub leaf_count: Count,
        pub height: Height,
    }
}
