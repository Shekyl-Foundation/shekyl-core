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

/// Why a transaction was refused (IG-Q76): one key, its payload or `null`.
///
/// **The skew rule** (`DAEMON_SUBMIT_VERDICT.md` §2.3, F38): a cause this
/// build does not know reads as [`Rejection::Unrecognized`], the fail-safe
/// release, never a parse error. New rejection semantics are added keys.
/// A daemon never writes `Unrecognized`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// Parse, structural, semantic or static-policy failure.
    Malformed,
    /// Below the fee floor.
    FeeTooLow,
    /// Another transaction consumes one of its inputs.
    DoubleSpendConflict,
    /// The FCMP++ reference is no longer canonical.
    StaleRoot,
    /// The reference block is younger than the minimum age.
    ReferenceTooRecent,
    /// The reference block is unknown to this daemon.
    ReferenceUnknown,
    /// A consensus row refused it against this chain: the row's id.
    ConsensusRule(Text),
    /// A cause this build does not know. Read-side only.
    Unrecognized,
}

const REJECTION_KEYS: &[&str] = &[
    "malformed",
    "fee-too-low",
    "double-spend-conflict",
    "stale-root",
    "reference-too-recent",
    "reference-unknown",
    "consensus-rule",
];

const _: () = {
    let mut i = 0;
    while i < REJECTION_KEYS.len() {
        super::shared::assert_keyword(REJECTION_KEYS[i]);
        i += 1;
    }
};

impl serde::Serialize for Rejection {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            Self::Malformed => map.serialize_entry("malformed", &Null)?,
            Self::FeeTooLow => map.serialize_entry("fee-too-low", &Null)?,
            Self::DoubleSpendConflict => map.serialize_entry("double-spend-conflict", &Null)?,
            Self::StaleRoot => map.serialize_entry("stale-root", &Null)?,
            Self::ReferenceTooRecent => map.serialize_entry("reference-too-recent", &Null)?,
            Self::ReferenceUnknown => map.serialize_entry("reference-unknown", &Null)?,
            Self::ConsensusRule(row) => map.serialize_entry("consensus-rule", row)?,
            Self::Unrecognized => {
                return Err(serde::ser::Error::custom(
                    "unrecognized is read-side only; a daemon names its cause",
                ))
            }
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for Rejection {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let object = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
        let mut entries = object.into_iter();
        let (Some((key, payload)), None) = (entries.next(), entries.next()) else {
            return Err(serde::de::Error::custom("a cause is one key"));
        };
        let null = |cause: Self| {
            if payload.is_null() {
                Ok(cause)
            } else {
                Err(serde::de::Error::custom(format!(
                    "`{key}` carries no payload"
                )))
            }
        };
        match key.as_str() {
            "malformed" => null(Self::Malformed),
            "fee-too-low" => null(Self::FeeTooLow),
            "double-spend-conflict" => null(Self::DoubleSpendConflict),
            "stale-root" => null(Self::StaleRoot),
            "reference-too-recent" => null(Self::ReferenceTooRecent),
            "reference-unknown" => null(Self::ReferenceUnknown),
            "consensus-rule" => serde_json::from_value(payload)
                .map(Self::ConsensusRule)
                .map_err(serde::de::Error::custom),
            _ => Ok(Self::Unrecognized),
        }
    }
}

impl Schema for Rejection {
    fn shape() -> Shape {
        let mut states: Vec<(&'static str, Option<Shape>)> =
            REJECTION_KEYS.iter().map(|key| (*key, None)).collect();
        states[6].1 = Some(Text::shape());
        Shape::States(states)
    }
}

/// The daemon's verdict on a submitted transaction
/// (`DAEMON_SUBMIT_VERDICT.md` §2.1), tagged by `verdict` (IG-Q86).
///
/// **The skew rules** (§2.3): an unknown `verdict` is a parse error, the
/// client's ambiguous arm; a required field missing is a parse error; and
/// an unknown field inside a known verdict is tolerated, so that a field a
/// newer daemon adds never turns a definite verdict into an ambiguous
/// submit. That last is the one reply on the wire that does not refuse an
/// unknown key, and the schema's strict shape describes what a daemon
/// writes, not what a client accepts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "verdict")]
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
