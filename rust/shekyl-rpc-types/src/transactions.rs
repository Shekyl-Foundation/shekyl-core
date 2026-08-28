// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transaction read set — the RK-4c slice of the daemon RPC KV cutover
//! (`docs/design/DAEMON_RPC_KV_CUTOVER.md` §3.1).
//!
//! The single Rust definitions of what `COMMAND_RPC_GET_TRANSACTIONS` and
//! `COMMAND_RPC_IS_KEY_IMAGE_SPENT` carried in C++. The conventions are
//! [`crate::chain`]'s: wire field names, `u64` as a JSON number, hashes as
//! lowercase hex, every `KV_SERIALIZE_OPT` mirrored by `skip_serializing_if`,
//! and no `deny_unknown_fields`. Parity against the captured epee output is
//! pinned by `tests/rpc_parity.rs` over `tests/vectors/rpc/` (RK-D4).
//!
//! One thing here is not a straight mirror. `COMMAND_RPC_GET_TRANSACTIONS`'s
//! `entry` has a KV map that *branches* — `if (!this_ref.in_pool)` emits the
//! four chain members, `else` the two pool ones — so the field set is a
//! function of a value in the same object. A flat struct with six optional
//! members would round-trip every captured vector while still being able to
//! emit both groups at once, or the pool group on a mined transaction:
//! documents the daemon cannot produce. [`TxLocation`] is that branch as a
//! type, so the unrepresentable stays unrepresentable and `in_pool` is
//! derived rather than stored beside the fields it selects.

use serde::{Deserialize, Serialize};

use crate::hash::HashHex;

/// Params of `GET|POST /get_transactions` (alias `/gettransactions`).
///
/// `txs_hashes` is `Vec<String>`, not `Vec<HashHex>`, for RK-D12's reason:
/// typed, serde would fold a malformed hash into this method's generic params
/// refusal, where the handler can instead answer the two specific statuses
/// the C++ handler distinguished — "Failed to parse hex representation of
/// transaction hash" for a non-hex string and "Failed, size of data mismatch"
/// for hex of the wrong length.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetTransactionsRequest {
    #[serde(default)]
    pub txs_hashes: Vec<String>,
    #[serde(default)]
    pub decode_as_json: bool,
    /// `KV_SERIALIZE_OPT(prune, false)` — omitted at its default.
    #[serde(default, skip_serializing_if = "is_false")]
    pub prune: bool,
    /// `KV_SERIALIZE_OPT(split, false)` — omitted at its default.
    #[serde(default, skip_serializing_if = "is_false")]
    pub split: bool,
}

/// Where a transaction was found, and the members that travel with each
/// answer — the `entry` KV map's branch as a type.
///
/// The two field sets are disjoint in the wire document and disjoint here.
/// Serialization can emit one or the other and never both, which is the
/// property a flat struct of optional members cannot hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxLocation {
    /// In a block: `in_pool` is false and the chain members are emitted.
    Mined {
        block_height: u64,
        confirmations: u64,
        block_timestamp: u64,
        /// Global output indices. Empty for a transaction with no outputs
        /// the daemon indexes, and an empty sequence is dropped from the
        /// document like every other one.
        output_indices: Vec<u64>,
    },
    /// In the mempool: `in_pool` is true and the pool members are emitted.
    /// The chain members are meaningless here — the C++ handler set
    /// `block_height` and `block_timestamp` to `u64::MAX` and
    /// `confirmations` to 0 before the KV map dropped all three, so their
    /// absence is the contract and those sentinels never reached a client.
    Pooled {
        relayed: bool,
        received_timestamp: u64,
    },
}

impl TxLocation {
    /// The wire's `in_pool`, derived from the arm rather than stored beside
    /// it — the two can never disagree.
    pub fn in_pool(&self) -> bool {
        matches!(self, TxLocation::Pooled { .. })
    }
}

/// One entry of [`GetTransactionsResponse::txs`].
///
/// `as_hex` / `pruned_as_hex` / `prunable_as_hex` / `as_json` are plain
/// `KV_SERIALIZE` members, so they are emitted even when empty; which of them
/// the daemon fills is the `(split, prune, decode_as_json)` matrix and is
/// content, not shape. `as_json` is epee's rendering of the transaction,
/// produced in C++ and passed through untouched (RK-D11); it duplicates the
/// hex members and retires with `get_block`'s `json` in RK-W.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawTxEntry", into = "RawTxEntry")]
pub struct TxEntry {
    pub tx_hash: HashHex,
    pub as_hex: String,
    pub pruned_as_hex: String,
    pub prunable_as_hex: String,
    pub prunable_hash: HashHex,
    pub as_json: String,
    /// `KV_SERIALIZE_OPT(pruned, false)` — omitted at its default. True when
    /// the daemon holds no prunable data for the transaction.
    pub pruned: bool,
    pub double_spend_seen: bool,
    /// Chain or pool, and the members that come with it. `in_pool` on the
    /// wire is [`TxLocation::in_pool`].
    pub location: TxLocation,
}

/// The wire shape of [`TxEntry`], flat as epee wrote it.
///
/// Private, and the only reason it exists: serde derives over a field list,
/// and the field list is what branches. [`TxEntry`] converts through this so
/// the branch is decided once, in [`TryFrom`], rather than by six
/// independently optional members that no invariant relates.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawTxEntry {
    tx_hash: HashHex,
    as_hex: String,
    pruned_as_hex: String,
    prunable_as_hex: String,
    prunable_hash: HashHex,
    as_json: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pruned: bool,
    in_pool: bool,
    double_spend_seen: bool,
    // The chain arm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confirmations: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block_timestamp: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    output_indices: Vec<u64>,
    // The pool arm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relayed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    received_timestamp: Option<u64>,
}

/// Why a `txs` entry could not be read.
///
/// The daemon's own replies never produce these; a remote node's can, which
/// is the point — a missing member is refused rather than defaulted to zero,
/// so a node cannot answer "mined at height 0, 0 confirmations" by simply
/// omitting the fields that would have said otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxEntryError {
    /// The member that decided it, for a message that names the field.
    pub missing: &'static str,
    /// Which arm `in_pool` selected.
    pub in_pool: bool,
}

impl std::fmt::Display for TxEntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "transaction entry with in_pool={} is missing `{}`",
            self.in_pool, self.missing
        )
    }
}

impl std::error::Error for TxEntryError {}

impl TryFrom<RawTxEntry> for TxEntry {
    type Error = TxEntryError;

    fn try_from(raw: RawTxEntry) -> Result<Self, Self::Error> {
        let missing = |field: &'static str| TxEntryError {
            missing: field,
            in_pool: raw.in_pool,
        };
        // `in_pool` selects the arm. Members of the arm it did not select are
        // ignored rather than refused: they are known fields in a combination
        // this daemon does not emit, and tolerating them is the same
        // additive-evolution rule the crate applies to unknown fields. What
        // is *not* tolerated is a selected arm with a member absent.
        let location = if raw.in_pool {
            TxLocation::Pooled {
                relayed: raw.relayed.ok_or_else(|| missing("relayed"))?,
                received_timestamp: raw
                    .received_timestamp
                    .ok_or_else(|| missing("received_timestamp"))?,
            }
        } else {
            TxLocation::Mined {
                block_height: raw.block_height.ok_or_else(|| missing("block_height"))?,
                confirmations: raw.confirmations.ok_or_else(|| missing("confirmations"))?,
                block_timestamp: raw
                    .block_timestamp
                    .ok_or_else(|| missing("block_timestamp"))?,
                output_indices: raw.output_indices,
            }
        };
        Ok(TxEntry {
            tx_hash: raw.tx_hash,
            as_hex: raw.as_hex,
            pruned_as_hex: raw.pruned_as_hex,
            prunable_as_hex: raw.prunable_as_hex,
            prunable_hash: raw.prunable_hash,
            as_json: raw.as_json,
            pruned: raw.pruned,
            double_spend_seen: raw.double_spend_seen,
            location,
        })
    }
}

impl From<TxEntry> for RawTxEntry {
    fn from(e: TxEntry) -> Self {
        let in_pool = e.location.in_pool();
        let mut raw = RawTxEntry {
            tx_hash: e.tx_hash,
            as_hex: e.as_hex,
            pruned_as_hex: e.pruned_as_hex,
            prunable_as_hex: e.prunable_as_hex,
            prunable_hash: e.prunable_hash,
            as_json: e.as_json,
            pruned: e.pruned,
            in_pool,
            double_spend_seen: e.double_spend_seen,
            block_height: None,
            confirmations: None,
            block_timestamp: None,
            output_indices: Vec::new(),
            relayed: None,
            received_timestamp: None,
        };
        match e.location {
            TxLocation::Mined {
                block_height,
                confirmations,
                block_timestamp,
                output_indices,
            } => {
                raw.block_height = Some(block_height);
                raw.confirmations = Some(confirmations);
                raw.block_timestamp = Some(block_timestamp);
                raw.output_indices = output_indices;
            }
            TxLocation::Pooled {
                relayed,
                received_timestamp,
            } => {
                raw.relayed = Some(relayed);
                raw.received_timestamp = Some(received_timestamp);
            }
        }
        raw
    }
}

/// Response of `GET|POST /get_transactions` (alias `/gettransactions`).
///
/// Every sequence here is dropped from the document when empty — epee omits
/// an empty sequence rather than emitting `[]`, and that is true of plain
/// `KV_SERIALIZE` members too, not only OPT ones.
///
/// `txs_as_hex` and `txs_as_json` are **gone** (rule 60). The C++ filled them
/// "in case an old wallet asks", and the old wallet is `src/wallet/`, deleted
/// — so they duplicated `txs[i].as_hex` / `.as_json` for a reader that does
/// not exist. The `_v2` oracle vectors are the shape without them, captured
/// from the edited C++ struct rather than written by hand, and `_v1` stays
/// beside them so the deletion itself is checkable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetTransactionsResponse {
    pub status: crate::chain::RpcStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub txs: Vec<TxEntry>,
    /// Hashes the daemon could find neither on the chain nor in the pool.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missed_tx: Vec<HashHex>,
}

/// What the daemon knows about a key image.
///
/// The C++ spelling was `std::vector<int>` over an unnamed-on-the-wire enum,
/// so a client compared against integer literals. Typed here: a value outside
/// the three the daemon can produce is a malformed reply, not a fourth state
/// to be carried into a caller's `match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(try_from = "u8", into = "u8")]
pub enum KeyImageStatus {
    /// `COMMAND_RPC_IS_KEY_IMAGE_SPENT::UNSPENT`.
    Unspent = 0,
    /// `SPENT_IN_BLOCKCHAIN` — spent by a transaction in a block.
    SpentInBlockchain = 1,
    /// `SPENT_IN_POOL` — spent by a transaction in the mempool. Only a
    /// *broadcast* one: the pool read filters on
    /// `relay_category::broadcasted`, so a transaction still in its stem
    /// phase does not answer here (§7, 2026-08-26).
    SpentInPool = 2,
}

/// A `spent_status` value outside the three the daemon defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyImageStatusError(pub u8);

impl std::fmt::Display for KeyImageStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "spent_status {} is not one of 0 (unspent), 1 (spent in blockchain), 2 (spent in pool)",
            self.0
        )
    }
}

impl std::error::Error for KeyImageStatusError {}

impl TryFrom<u8> for KeyImageStatus {
    type Error = KeyImageStatusError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(KeyImageStatus::Unspent),
            1 => Ok(KeyImageStatus::SpentInBlockchain),
            2 => Ok(KeyImageStatus::SpentInPool),
            other => Err(KeyImageStatusError(other)),
        }
    }
}

impl From<KeyImageStatus> for u8 {
    fn from(s: KeyImageStatus) -> u8 {
        s as u8
    }
}

/// Params of `GET|POST /is_key_image_spent`.
///
/// `key_images` is `Vec<String>` for [`GetTransactionsRequest`]'s reason: the
/// handler owns the two parse refusals, so it must see what was sent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsKeyImageSpentRequest {
    #[serde(default)]
    pub key_images: Vec<String>,
}

/// Response of `GET|POST /is_key_image_spent`.
///
/// `spent_status` is **positional** — it carries no key image back, so the
/// only thing tying an answer to its question is its index. A reply of a
/// different length than the request is therefore unreadable rather than
/// partially readable, which is why the handler refuses one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsKeyImageSpentResponse {
    pub status: crate::chain::RpcStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spent_status: Vec<KeyImageStatus>,
}

fn is_false(v: &bool) -> bool {
    !*v
}

#[cfg(test)]
mod tests {
    use super::{
        GetTransactionsResponse, KeyImageStatus, KeyImageStatusError, TxEntry, TxLocation,
    };
    use crate::hash::HashHex;

    fn entry(location: TxLocation) -> TxEntry {
        TxEntry {
            tx_hash: HashHex::from_bytes([1u8; 32]),
            as_hex: "00".to_owned(),
            pruned_as_hex: String::new(),
            prunable_as_hex: String::new(),
            prunable_hash: HashHex::from_bytes([2u8; 32]),
            as_json: String::new(),
            pruned: false,
            double_spend_seen: false,
            location,
        }
    }

    fn mined() -> TxLocation {
        TxLocation::Mined {
            block_height: 5,
            confirmations: 2,
            block_timestamp: 99,
            output_indices: vec![3],
        }
    }

    fn pooled() -> TxLocation {
        TxLocation::Pooled {
            relayed: true,
            received_timestamp: 77,
        }
    }

    fn keys(entry: &TxEntry) -> Vec<String> {
        let v: serde_json::Value = serde_json::to_value(entry).expect("serialize");
        let mut k: Vec<String> = v
            .as_object()
            .expect("an entry is an object")
            .keys()
            .cloned()
            .collect();
        k.sort();
        k
    }

    /// The invariant the enum exists for. Deleting either arm's members from
    /// the `From` impl, or adding the other arm's, fails this — which is what
    /// a flat struct of six optional members could not have detected.
    #[test]
    fn each_arm_emits_only_its_own_members() {
        let chain = keys(&entry(mined()));
        assert!(chain.contains(&"block_height".to_owned()));
        assert!(chain.contains(&"confirmations".to_owned()));
        assert!(chain.contains(&"block_timestamp".to_owned()));
        assert!(chain.contains(&"output_indices".to_owned()));
        assert!(
            !chain.contains(&"relayed".to_owned())
                && !chain.contains(&"received_timestamp".to_owned()),
            "a mined entry emitted pool members: {chain:?}"
        );

        let pool = keys(&entry(pooled()));
        assert!(pool.contains(&"relayed".to_owned()));
        assert!(pool.contains(&"received_timestamp".to_owned()));
        assert!(
            !pool.contains(&"block_height".to_owned())
                && !pool.contains(&"confirmations".to_owned())
                && !pool.contains(&"block_timestamp".to_owned())
                && !pool.contains(&"output_indices".to_owned()),
            "a pooled entry emitted chain members: {pool:?}"
        );
    }

    /// `in_pool` is derived, so it cannot disagree with the members beside it.
    #[test]
    fn in_pool_follows_the_arm() {
        let v: serde_json::Value = serde_json::to_value(entry(mined())).expect("serialize");
        assert_eq!(v["in_pool"], serde_json::json!(false));
        let v: serde_json::Value = serde_json::to_value(entry(pooled())).expect("serialize");
        assert_eq!(v["in_pool"], serde_json::json!(true));
    }

    /// An empty `output_indices` is dropped, matching epee — but only inside
    /// the arm that has one at all.
    #[test]
    fn empty_output_indices_is_omitted() {
        let e = entry(TxLocation::Mined {
            block_height: 5,
            confirmations: 2,
            block_timestamp: 99,
            output_indices: Vec::new(),
        });
        assert!(!keys(&e).contains(&"output_indices".to_owned()));
    }

    /// A remote node cannot answer "mined at height 0" by omitting the field
    /// that would have said otherwise: the member is required, not defaulted.
    #[test]
    fn a_selected_arm_with_a_missing_member_is_refused() {
        let doc = r#"{"tx_hash":"0101010101010101010101010101010101010101010101010101010101010101",
            "as_hex":"00","pruned_as_hex":"","prunable_as_hex":"",
            "prunable_hash":"0202020202020202020202020202020202020202020202020202020202020202",
            "as_json":"","in_pool":false,"double_spend_seen":false,
            "confirmations":2,"block_timestamp":99}"#;
        let err = serde_json::from_str::<TxEntry>(doc).expect_err("block_height is missing");
        assert!(
            err.to_string().contains("block_height"),
            "the refusal names the member: {err}"
        );

        let doc = doc.replace("\"in_pool\":false", "\"in_pool\":true");
        let err = serde_json::from_str::<TxEntry>(&doc).expect_err("relayed is missing");
        assert!(
            err.to_string().contains("relayed"),
            "the refusal names the member: {err}"
        );
    }

    /// A document carrying both groups is read by `in_pool`, and the members
    /// of the arm it did not select are ignored rather than refused — the
    /// same additive-evolution rule the crate applies to unknown fields.
    #[test]
    fn in_pool_decides_when_both_groups_are_present() {
        let doc = r#"{"tx_hash":"0101010101010101010101010101010101010101010101010101010101010101",
            "as_hex":"00","pruned_as_hex":"","prunable_as_hex":"",
            "prunable_hash":"0202020202020202020202020202020202020202020202020202020202020202",
            "as_json":"","in_pool":true,"double_spend_seen":false,
            "block_height":5,"confirmations":2,"block_timestamp":99,"output_indices":[3],
            "relayed":true,"received_timestamp":77}"#;
        let e: TxEntry = serde_json::from_str(doc).expect("in_pool selects the pool arm");
        assert_eq!(e.location, pooled());
        // And re-serializing drops what it did not select, so the
        // contradiction cannot be relayed onward.
        assert!(!keys(&e).contains(&"block_height".to_owned()));
    }

    /// Every empty sequence is dropped from the response, as epee dropped it.
    #[test]
    fn empty_response_is_only_its_status() {
        let res = GetTransactionsResponse {
            status: crate::chain::RpcStatus::ok(),
            txs: Vec::new(),
            missed_tx: Vec::new(),
        };
        let v: serde_json::Value = serde_json::to_value(&res).expect("serialize");
        let keys: Vec<&String> = v.as_object().expect("object").keys().collect();
        assert_eq!(keys, vec!["status"], "an empty reply carries only status");
    }

    /// A fourth spent-status is a malformed reply, not a fourth state.
    #[test]
    fn spent_status_outside_the_three_is_refused() {
        assert_eq!(KeyImageStatus::try_from(0), Ok(KeyImageStatus::Unspent));
        assert_eq!(KeyImageStatus::try_from(2), Ok(KeyImageStatus::SpentInPool));
        assert_eq!(KeyImageStatus::try_from(3), Err(KeyImageStatusError(3)));
        assert!(serde_json::from_str::<KeyImageStatus>("3").is_err());
        // And the three that are defined keep the integers the wire used.
        assert_eq!(
            serde_json::to_string(&KeyImageStatus::Unspent).unwrap(),
            "0"
        );
        assert_eq!(
            serde_json::to_string(&KeyImageStatus::SpentInBlockchain).unwrap(),
            "1"
        );
        assert_eq!(
            serde_json::to_string(&KeyImageStatus::SpentInPool).unwrap(),
            "2"
        );
    }
}
