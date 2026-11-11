// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival layer's reads: the claim source, shard coverage and a
//! closed shard's view.

use crate::hash::HashHex;
use crate::kinds::{Count, Duration, Height, Integer, Micro, Milli, Size};
use crate::nullable::Nullable;
use shekyl_units::wire::AtomicUnitsString as Amount;

crate::wire_object! {
    /// `archival_claim_show`'s selector.
    ["archival"]
    pub struct PersonaQuery {
        pub persona: HashHex,
    }
}

crate::wire_keywords! {
    /// What a persona holds.
    pub enum Holding {
        Shards = "shards",
        CompleteTree = "complete-tree",
    }
}

crate::wire_object! {
    /// An interval the bond failed, inclusive.
    ["bond failure"]
    pub struct Failure {
        pub from: Height,
        pub to: Height,
    }
}

crate::wire_object! {
    /// A bond in an epoch.
    ["bond"]
    pub struct ClaimBond {
        pub joined_epoch: Integer,
        pub complete_tree: bool,
        pub failure: Vec<Failure>,
    }
}

crate::wire_object! {
    /// A shard in an epoch.
    ["shard"]
    pub struct ClaimShard {
        pub id: Integer,
        pub freeze_height: Height,
        pub segment: bool,
    }
}

crate::wire_object! {
    /// A credit pair: indices into the epoch's bonds and shards.
    ["credit"]
    pub struct Credit {
        pub bond: Integer,
        pub shard: Integer,
    }
}

crate::wire_object! {
    /// One settlement epoch.
    ["epoch"]
    pub struct Epoch {
        pub id: Integer,
        pub closing_height: Height,
        pub work: Milli,
        /// `null` with no budget row.
        pub budget: Nullable<Amount>,
        pub bond: Vec<ClaimBond>,
        pub shard: Vec<ClaimShard>,
        pub credit: Vec<Credit>,
        /// The claiming bond's index; `null` for none.
        pub claimant: Nullable<Integer>,
    }
}

crate::wire_object! {
    /// A persona's emission claim source.
    ["archival claim"]
    pub struct ClaimSource {
        pub height: Height,
        /// The hash of the block at `height`, in the same snapshot (IG-Q84).
        pub hash: HashHex,
        pub settled_epoch: Integer,
        /// `null`: no bond record.
        pub joined_epoch: Nullable<Integer>,
        pub holding: Holding,
        pub shard: Vec<Integer>,
        pub claimed: Vec<Integer>,
        pub bond_total: Amount,
        pub failure_count: Count,
        /// `null`: never served.
        pub served_epoch: Nullable<Integer>,
        /// `null`: never slashed.
        pub slash_epoch: Nullable<Integer>,
        pub epoch: Vec<Epoch>,
    }
}

crate::wire_object! {
    /// One shard's coverage.
    ["shard"]
    pub struct CoverageShard {
        pub id: Integer,
        pub bonded_count: Count,
        pub served_count: Count,
        pub freeze_height: Height,
        pub scarcity: Micro,
        /// `null` when not estimated.
        pub profit: Nullable<Amount>,
    }
}

crate::wire_object! {
    /// Holders per shard.
    ["shard coverage"]
    pub struct Coverage {
        pub height: Height,
        pub leaf_count: Count,
        pub frozen_count: Count,
        pub settled_epoch: Integer,
        pub budget: Amount,
        pub work: Milli,
        pub shard: Vec<CoverageShard>,
    }
}

crate::wire_object! {
    /// `shard_fetch`'s argument.
    ["shard"]
    pub struct ShardId {
        pub id: Integer,
    }
}

crate::wire_object! {
    /// A closed shard's view.
    ["shard"]
    pub struct ShardView {
        pub id: Integer,
        pub hash: HashHex,
        pub size: Size,
        pub block_count: Count,
        pub tx_count: Count,
        pub output_count: Count,
        pub coinbase_output_count: Count,
        pub duration: Duration,
        pub closing_height: Height,
    }
}
