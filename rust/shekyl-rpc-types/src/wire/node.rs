// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The miner, the runtime options and the bans.

use super::daemon::Diagnostic;
use super::shared::OpenMap;
use crate::hex128::HexU128;
use crate::kinds::{Address, Count, Duration, Height, Text};
use crate::nullable::Nullable;
use crate::schema::{Schema, Shape};
use shekyl_units::wire::AtomicUnitsString as Amount;

/// How many threads to mine with: a count, or `auto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Threads {
    /// This many.
    Count(Count),
    /// The node's `mine-threads`.
    Auto(AutoWord),
}

crate::wire_keywords! {
    /// The `auto` keyword.
    pub enum AutoWord {
        Auto = "auto",
    }
}

impl Schema for Threads {
    fn shape() -> Shape {
        Shape::Either(Box::new(Count::shape()), Box::new(AutoWord::shape()))
    }
}

crate::wire_object! {
    /// `mine_start`'s argument. The node mines to its `mine-address`.
    ["mine"]
    pub struct MineStart {
        pub threads: Threads,
    }
}

crate::wire_object! {
    /// Hashes counted over a window of complete seconds.
    ["mine speed"]
    pub struct MineSpeed {
        pub count: Count,
        pub window: Duration,
    }
}

crate::wire_object! {
    /// The miner and its posted job (`mine_status`, IG-Q77).
    ["mine"]
    pub struct MineStatus {
        pub active: bool,
        pub speed: MineSpeed,
        pub threads: Count,
        /// `null` when `mine-address` is unset.
        pub address: Nullable<Address>,
        pub block_spacing: Duration,
        /// The posted job's height; `null` with no job.
        pub height: Nullable<Height>,
        /// `null` with no job.
        pub reward: Nullable<Amount>,
        /// `null` with no job.
        pub difficulty: Nullable<HexU128>,
        /// Why no job is posted; `null` when one is.
        pub cause: Nullable<Diagnostic>,
        pub txpool_retired: bool,
    }
}

crate::wire_object! {
    /// `option_set`'s argument: a value for each option named.
    ["option"]
    pub struct OptionSet {
        pub value: OpenMap<Text>,
    }
}

crate::wire_object! {
    /// `option_show`'s selector: the options to show, or every one the
    /// caller may see when left out.
    ["option"]
    pub struct OptionShow {
        pub name [optional]: Option<Vec<Text>>,
    }
}

crate::wire_keywords! {
    /// Where an option's value came from.
    pub enum OptionSource {
        Default = "default",
        File = "file",
        Cli = "cli",
        Runtime = "runtime",
    }
}

crate::wire_object! {
    /// An option that is not a secret.
    ["option"]
    pub struct OptionValue {
        pub name: Text,
        pub source: OptionSource,
        pub runtime: bool,
        /// Always false here.
        pub secret: bool,
        /// Valid input to `option_set`; `null` when unset.
        pub value: Nullable<Text>,
    }
}

crate::wire_object! {
    /// A secret option: whether it has a value, never the value.
    ["option"]
    pub struct OptionSecret {
        pub name: Text,
        pub source: OptionSource,
        pub runtime: bool,
        /// Always true here.
        pub secret: bool,
        pub assigned: bool,
    }
}

/// One option row: a value, or a secret's assignment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum OptionRow {
    /// Not a secret.
    Value(OptionValue),
    /// A secret.
    Secret(OptionSecret),
}

impl Schema for OptionRow {
    fn shape() -> Shape {
        Shape::Either(
            Box::new(OptionValue::shape()),
            Box::new(OptionSecret::shape()),
        )
    }
}

crate::wire_object! {
    /// A ban to add.
    ["ban"]
    pub struct BanAdd {
        pub host: Text,
        /// How long; permanent when left out.
        pub duration [optional]: Option<Duration>,
    }
}

crate::wire_object! {
    /// A host, to unban or to show.
    ["ban"]
    pub struct BanHost {
        pub host: Text,
    }
}

crate::wire_object! {
    /// One ban.
    ["ban"]
    pub struct Ban {
        pub host: Text,
        /// Time remaining; `null` for a permanent ban.
        pub duration: Nullable<Duration>,
        pub permanent: bool,
    }
}
