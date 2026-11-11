// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transactions and the pool: reads, submission, relay and flush.

use super::shared::{Null, OrArchived, Slot};
use crate::hash::HashHex;
use crate::kinds::{Bytes, Count, Height, Integer, Size, Text, Time};
use crate::nullable::Nullable;
use crate::schema::{Field, Schema, Shape};
use shekyl_units::wire::AtomicUnitsString as Amount;

crate::wire_object! {
    /// `tx_show`'s request: one id, and the `prune` switch.
    ["tx"]
    pub struct TxQuery {
        pub id: HashHex,
        #[serde(default)]
        pub prune [optional]: bool,
    }
}

crate::wire_object! {
    /// `tx_list`'s request: ids, and the `prune` switch.
    ["tx"]
    pub struct TxListQuery {
        pub id: Vec<HashHex>,
        #[serde(default)]
        pub prune [optional]: bool,
    }
}

crate::wire_object! {
    /// A transaction the daemon holds, on the chain or in the pool.
    ["tx"]
    pub struct TxEntry {
        pub id: HashHex,
        /// Under `prune`, the pruned segment (IG-Q55).
        pub body: Bytes,
        pub prunable_hash: HashHex,
        /// `null` where the identity has no third operand: the coinbase.
        pub pqc_auth_hash: Nullable<HashHex>,
        pub archival_size: Size,
        /// In the pool, not yet in a block.
        pub pooled: bool,
        /// The block that holds it; `null` while pooled.
        pub mined_height: Nullable<Height>,
        /// `null` while pooled.
        pub confirmations: Nullable<Count>,
        /// `null` while pooled.
        pub mined_time: Nullable<Time>,
        /// Its outputs' global indices; `[]` while pooled.
        pub output_index: Vec<Integer>,
        /// The pool's one bit (IG-Q57); `null` once mined.
        pub public: Nullable<bool>,
    }
}

/// `tx_show`'s reply: the entry, or the archived state in its place.
pub type TxShow = OrArchived<TxEntry>;

/// `tx_list`'s reply: a slot for each id, in order (IG-Q73).
pub type TxList = Vec<Slot<TxEntry>>;

crate::wire_object! {
    /// A transaction handed to the daemon.
    ["tx"]
    pub struct TxBody {
        pub body: Bytes,
    }
}

crate::wire_keywords! {
    /// Where the caller's own transaction stands with the relay (IG-Q75).
    pub enum Publication {
        /// Unpublished, inside the daemon's publication budget.
        Held = "held",
        /// Unpublished at or past that budget, judged on the daemon's clock
        /// when read.
        Overdue = "overdue",
        /// The relay has made it public.
        Public = "public",
        /// Pool-resident, with no origin row.
        Untracked = "untracked",
    }
}

crate::wire_states! {
    /// Why a transaction was refused (IG-Q76): one key, its payload or
    /// `null`.
    pub enum Rejection {
        Malformed(Null) = "malformed",
        FeeTooLow(Null) = "fee-too-low",
        DoubleSpendConflict(Null) = "double-spend-conflict",
        StaleRoot(Null) = "stale-root",
        ReferenceTooRecent(Null) = "reference-too-recent",
        ReferenceUnknown(Null) = "reference-unknown",
        /// The consensus row that refused it (`"CEN-J15"`).
        ConsensusRule(Text) = "consensus-rule",
    }
}

/// The daemon's verdict on a submitted transaction
/// (`DAEMON_SUBMIT_VERDICT.md` §2.1), tagged by `verdict` (IG-Q86).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "verdict", deny_unknown_fields)]
pub enum Verdict {
    /// Admitted to the pool.
    #[serde(rename = "accepted")]
    Accepted,
    /// These bytes are in the pool.
    #[serde(rename = "already-in-pool")]
    AlreadyInPool {
        /// Where it stands with the relay.
        publication: Publication,
    },
    /// This id is in the chain.
    #[serde(rename = "already-in-chain")]
    AlreadyInChain {
        /// The block that holds it.
        mined_height: Height,
    },
    /// Refused, and why.
    #[serde(rename = "rejected")]
    Rejected {
        /// Why.
        cause: Rejection,
    },
}

impl Schema for Verdict {
    fn shape() -> Shape {
        let field = |name, shape| Field {
            name,
            under: None,
            shape,
        };
        Shape::Tagged {
            holder: "tx",
            tag: "verdict",
            variants: vec![
                ("accepted", vec![]),
                (
                    "already-in-pool",
                    vec![field("publication", Publication::shape())],
                ),
                (
                    "already-in-chain",
                    vec![field("mined_height", Height::shape())],
                ),
                ("rejected", vec![field("cause", Rejection::shape())]),
            ],
        }
    }
}

crate::wire_object! {
    /// `tx_relay`'s request: the ids to offer again.
    ["tx"]
    pub struct RelayIds {
        pub id: Vec<HashHex>,
    }
}

crate::wire_object! {
    /// `txpool_flush`'s request: the ids to remove, or every entry the
    /// caller may see when left out.
    ["txpool"]
    pub struct FlushIds {
        pub id [optional]: Option<Vec<HashHex>>,
    }
}

/// `tx_relay`'s and `txpool_flush`'s reply: each id acted on, or
/// `{"missing": null}` where the pool the caller may see holds none (IG-Q89).
pub type Acted = Vec<Slot<HashHex>>;

crate::wire_object! {
    /// One pool entry (IG-Q57): its id, weight and fee, never a receive
    /// time.
    ["tx"]
    pub struct PoolEntry {
        pub id: HashHex,
        pub weight: Size,
        pub fee: Amount,
    }
}

crate::wire_object! {
    /// The pool's statistics.
    ["txpool"]
    pub struct TxpoolStats {
        pub count: Count,
        pub weight_total: Size,
        pub weight_min: Size,
        pub weight_max: Size,
        pub weight_median: Size,
        pub fee_total: Amount,
        /// Entries not yet public: host-only (RT-O9.3).
        #[serde(default, skip_serializing_if = "crate::kinds::Withheld::is_withheld")]
        pub private_count [shown crate::method::Policy::HostOnly]: crate::kinds::Withheld<Count>,
    }
}
