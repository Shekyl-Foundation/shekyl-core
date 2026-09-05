// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The header projection's remainder, hard-fork voting info, and the fee
//! estimate — the RK-5b slice of the daemon RPC KV cutover
//! (`docs/design/DAEMON_RPC_KV_CUTOVER.md` §3.1).
//!
//! Conventions are [`crate::chain`]'s: wire field names, `deny_unknown_fields`,
//! and every `KV_SERIALIZE_OPT(field, default)` mirrored by `#[serde(default,
//! skip_serializing_if = …)]`. The shared 24-field [`BlockHeader`] is RK-3's
//! and is reused unchanged.
//!
//! **This module deliberately diverges from the C++ in four places**, which is
//! why RK-5b carries `CORE_RPC_VERSION` 3.27. Each is recorded in the design
//! doc's §7 with the evidence that settled it; the short forms are on the
//! types below.

use serde::{Deserialize, Serialize};

use crate::chain::{BlockHeader, RpcStatus};

/// Request of `get_last_block_header` (alias `getlastblockheader`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetLastBlockHeaderRequest {
    /// `OPT(false)`. Computing the long hash is the expensive part of the
    /// call, so it is skipped unless asked for.
    #[serde(default, skip_serializing_if = "is_false")]
    pub fill_pow_hash: bool,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
const fn is_false(b: &bool) -> bool {
    !*b
}

/// Result of `get_last_block_header`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetLastBlockHeaderResponse {
    pub status: RpcStatus,
    pub block_header: BlockHeader,
}

/// Request of `get_block_header_by_hash` (alias `getblockheaderbyhash`).
///
/// **The singular `hash` is gone.** It had zero live consumers — the console's
/// `alt_chain_info` sets `hashes` exclusively and the `utils/python-rpc`
/// wrapper exposing it has no caller in the tree — and removing it deletes a
/// defect rather than fixing one: the C++ capped `hashes.len()` and *then* did
/// one more lookup from `hash`, so a restricted caller got 1001 block reads
/// against a cap of 1000.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBlockHeaderByHashRequest {
    /// Block hashes, answered positionally in [`GetBlockHeaderByHashResponse`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<crate::hash::HashHex>,
    /// `OPT(false)`. **Refused, not blanked, on the restricted listener** —
    /// the C++ computed `fill_pow_hash && !restricted`, handing back an empty
    /// field with status OK when a caller asked for a privileged one.
    #[serde(default, skip_serializing_if = "is_false")]
    pub fill_pow_hash: bool,
}

/// One requested hash's answer.
///
/// **A miss is data.** The C++ returned `INTERNAL_ERROR` for a hash the chain
/// does not hold, which is reachable in ordinary operation: `alt_chain_info`
/// asks `get_alternate_chains` and then requests headers for what it returned,
/// so a reorg between the two calls made the console report a daemon fault for
/// a benign race.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockHeaderSlot {
    /// The hash this slot answers, echoed so a caller need not rely on order
    /// alone to associate an answer with its request.
    pub hash: crate::hash::HashHex,
    /// `None` when this chain does not hold that block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_header: Option<BlockHeader>,
}

/// Result of `get_block_header_by_hash`.
///
/// **Per-element, not all-or-nothing.** The C++ returned on the first failure
/// and discarded every header already filled, so one unknown hash in a
/// thousand produced zero headers and the only way to learn *which* hash
/// failed was to parse an error string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBlockHeaderByHashResponse {
    pub status: RpcStatus,
    /// One slot per requested hash, in request order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block_headers: Vec<BlockHeaderSlot>,
}

/// Request of `get_block_headers_range` (alias `getblockheadersrange`).
/// **Deliberately not `Default`.** Every other request in this module has a
/// meaningful empty form — `get_last_block_header` means the tip,
/// `hard_fork_info` means the active fork — and a generic params parser can
/// hand them `T::default()` for absent params. A *range* has no such form:
/// the C++ value-initialised both heights to zero and answered for block 0,
/// so a client that forgot to set them was told about genesis instead of
/// being told it forgot. Removing the derive makes
/// `methods::object_params::<GetBlockHeadersRangeRequest>` fail to compile,
/// so the absent-params path cannot be restored by accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBlockHeadersRangeRequest {
    pub start_height: u64,
    /// Inclusive, as the C++ loop was (`h <= end_height`).
    pub end_height: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub fill_pow_hash: bool,
}

/// Result of `get_block_headers_range`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBlockHeadersRangeResponse {
    pub status: RpcStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<BlockHeader>,
}

/// Request of `hard_fork_info`.
///
/// **`version` is an `Option`, because 0 was a sentinel.** The C++ read
/// `req.version > 0 ? req.version : get_next_hard_fork_version()`, so zero
/// meant "the next fork" — a value hiding in the same field as the versions
/// it is not. Absent means the next fork; present means that version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardForkInfoRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,
}

/// Result of `hard_fork_info`.
///
/// **Two versions, named apart.** The C++ reply's `version` was the chain's
/// *current* fork while every voting field below described the version the
/// caller asked about, and nothing echoed the query. `show_status` asks with
/// the sentinel and prints that field beside `earliest_height`, so one status
/// line carried the current fork's version and the next fork's height with
/// nothing saying which was which.
///
/// The voting fields are carried **verbatim** from what the daemon reports.
/// Nothing here re-expresses threshold accounting, the rolling window or the
/// vote predicate: CEN-B2 and CEN-B3 are bucket-4 rows reserved for the R4
/// round that owns the hard-fork subsystem, so a reimplementation would be
/// work that round has to undo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardForkInfoResponse {
    pub status: RpcStatus,
    /// The version the voting fields below describe — the caller's, or the
    /// resolved next-fork version when the caller asked with none.
    pub queried_version: u8,
    /// The chain's current fork version. **Not** the subject of the fields
    /// below.
    pub active_version: u8,
    pub enabled: bool,
    pub window: u32,
    pub votes: u32,
    pub threshold: u32,
    pub voting: u8,
    pub state: u32,
    pub earliest_height: u64,
}

/// Which tier of the dynamic fee estimate a caller wants.
///
/// The 2021 scaling derivation produces four tiers — Fl, Fn, Fm, Fh — and the
/// wire has always carried them as a bare array, so the tier a caller meant
/// lived in an index. Naming them is what stops `fees[3]` being reachable by
/// position.
///
/// These are the **derivation's** tiers, deliberately not the wallet's
/// `FeePriority` (economy / standard / priority). Those are a UX policy that
/// *maps onto* these — `economy = Low`, `standard = Normal`,
/// `priority = High` — and collapsing the two vocabularies into one would bake
/// a wallet policy into the daemon's wire contract. `Medium` currently has no
/// consumer at all, which is only visible once the tiers have names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeTier {
    Low,
    Normal,
    Medium,
    High,
}

/// The four fee tiers, in derivation order.
///
/// A fixed array, so a reply carrying three tiers **fails to deserialize**
/// rather than being read as a shorter answer. The four-ness lived in one
/// C++ function (`get_dynamic_base_fee_estimate_2021_scaling`'s `resize(4)`)
/// and nothing downstream asserted it; a derivation that returned three would
/// otherwise have produced a silently wrong base fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FeeTiers(pub [u64; 4]);

impl FeeTiers {
    /// The fee for one tier. Total: every [`FeeTier`] indexes a slot that
    /// exists, because the array is fixed at four.
    #[must_use]
    pub const fn get(self, tier: FeeTier) -> u64 {
        let Self(fees) = self;
        match tier {
            FeeTier::Low => fees[0],
            FeeTier::Normal => fees[1],
            FeeTier::Medium => fees[2],
            FeeTier::High => fees[3],
        }
    }
}

/// Request of `get_fee_estimate`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetFeeEstimateRequest {
    /// Blocks of grace to assume when estimating. The daemon refuses a value
    /// above the reward window rather than letting the estimator throw.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub grace_blocks: u64,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
const fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Result of `get_fee_estimate`.
///
/// **The scalar `fee` is gone.** It was `fees[0]` under a second name, and it
/// existed only because the unreachable non-scaling arm had nothing else to
/// return. Callers name the tier they mean via [`FeeTiers::get`].
// Not `Copy`: `RpcStatus` owns a `String`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetFeeEstimateResponse {
    pub status: RpcStatus,
    pub fees: FeeTiers,
    /// `OPT(1)`.
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub quantization_mask: u64,
}

const fn one() -> u64 {
    1
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
const fn is_one(v: &u64) -> bool {
    *v == 1
}

#[cfg(test)]
mod tests {
    use super::{
        FeeTier, FeeTiers, GetBlockHeaderByHashRequest, GetFeeEstimateResponse, HardForkInfoRequest,
    };

    /// The four-ness is enforced by the type, not trusted. A reply carrying
    /// three tiers is a parse error — which is the whole point, since the
    /// `resize(4)` it mirrors lives in one C++ function and nothing
    /// downstream asserted it.
    #[test]
    fn a_fee_reply_with_the_wrong_tier_count_does_not_parse() {
        let four = r#"{"status":"OK","fees":[1,2,3,4]}"#;
        let parsed: GetFeeEstimateResponse =
            serde_json::from_str(four).expect("four tiers is the contract");
        assert_eq!(parsed.fees.get(FeeTier::Low), 1);
        assert_eq!(parsed.fees.get(FeeTier::Normal), 2);
        assert_eq!(parsed.fees.get(FeeTier::Medium), 3);
        assert_eq!(parsed.fees.get(FeeTier::High), 4);
        assert_eq!(parsed.quantization_mask, 1, "OPT(1) when absent");

        for wrong in [
            r#"{"status":"OK","fees":[1,2,3]}"#,
            r#"{"status":"OK","fees":[1,2,3,4,5]}"#,
            r#"{"status":"OK","fees":[]}"#,
        ] {
            assert!(
                serde_json::from_str::<GetFeeEstimateResponse>(wrong).is_err(),
                "a tier count other than four must not parse: {wrong}"
            );
        }
    }

    /// `fees` stays a bare array on the wire — the tiers are named in the
    /// type, not in the document, so the captured oracle still matches.
    #[test]
    fn the_tiers_are_named_in_rust_and_positional_on_the_wire() {
        let tiers = FeeTiers([10, 20, 30, 40]);
        assert_eq!(
            serde_json::to_string(&tiers).expect("serialize"),
            "[10,20,30,40]"
        );
    }

    /// The sentinel is gone: absent means "the next fork", and there is no
    /// value of `version` that means anything other than a version.
    #[test]
    fn the_hard_fork_request_has_no_sentinel() {
        let absent: HardForkInfoRequest =
            serde_json::from_str("{}").expect("an empty request is valid");
        assert_eq!(absent.version, None);
        assert_eq!(
            serde_json::to_string(&absent).expect("serialize"),
            "{}",
            "the default omits the field rather than sending 0"
        );

        let asked: HardForkInfoRequest =
            serde_json::from_str(r#"{"version":3}"#).expect("an explicit version is valid");
        assert_eq!(asked.version, Some(3));
    }

    /// The deleted singular `hash` is refused rather than ignored, so a
    /// caller still sending it learns that it stopped meaning anything.
    #[test]
    fn the_retired_singular_hash_is_refused() {
        assert!(
            serde_json::from_str::<GetBlockHeaderByHashRequest>(
                r#"{"hash":"0b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4"}"#
            )
            .is_err(),
            "`hash` was deleted in 3.27; silently ignoring it would answer a \
             different question than the caller asked"
        );
    }
}
