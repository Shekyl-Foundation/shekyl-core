// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The header projection's remainder and the fee estimate — the RK-5b slice
//! of the daemon RPC KV cutover (`docs/design/DAEMON_RPC_KV_CUTOVER.md` §3.1).
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
/// meaningful empty form — `get_last_block_header` means the tip — and a
/// generic params parser can
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

/// Which priced rung of the dynamic fee estimate a caller wants.
///
/// The wire is a three-element array `[economy, standard, priority]`.
/// Naming the rungs is what stops a caller reaching a slot by position.
///
/// These are the **derivation's** tiers, deliberately not the wallet's
/// `FeePriority` (economy / standard / priority). Those are a UX policy that
/// *maps onto* these — `economy = Low`, `standard = Normal`,
/// `priority = High` — and collapsing the two vocabularies into one would bake
/// a wallet policy into the daemon's wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeTier {
    Low,
    Normal,
    High,
}

/// The three fee tiers, in derivation order: `[economy, standard, priority]`.
///
/// Fixed, so a reply carrying any other count **fails to deserialize**
/// rather than being read as a shorter answer with the priority rate in
/// the wrong position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FeeTiers(pub [u64; 3]);

impl FeeTiers {
    /// The fee for one tier. Every [`FeeTier`] indexes a slot that exists.
    #[must_use]
    pub const fn get(self, tier: FeeTier) -> u64 {
        let Self(fees) = self;
        match tier {
            FeeTier::Low => fees[0],
            FeeTier::Normal => fees[1],
            FeeTier::High => fees[2],
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
    use super::{FeeTier, FeeTiers, GetBlockHeaderByHashRequest, GetFeeEstimateResponse};

    /// The arity is enforced by the type, not trusted. A reply carrying any
    /// count but three is a parse error, including the four-slot shape that
    /// used to be the contract.
    #[test]
    fn a_fee_reply_with_the_wrong_tier_count_does_not_parse() {
        let three = r#"{"status":"OK","fees":[1,2,4]}"#;
        let parsed: GetFeeEstimateResponse =
            serde_json::from_str(three).expect("three tiers is the contract");
        assert_eq!(parsed.fees.get(FeeTier::Low), 1);
        assert_eq!(parsed.fees.get(FeeTier::Normal), 2);
        assert_eq!(parsed.fees.get(FeeTier::High), 4);
        assert_eq!(parsed.quantization_mask, 1, "OPT(1) when absent");

        for wrong in [
            r#"{"status":"OK","fees":[1,2]}"#,
            r#"{"status":"OK","fees":[1,2,3,4]}"#,
            r#"{"status":"OK","fees":[1,2,3,4,5]}"#,
            r#"{"status":"OK","fees":[]}"#,
        ] {
            assert!(
                serde_json::from_str::<GetFeeEstimateResponse>(wrong).is_err(),
                "a tier count other than three must not parse: {wrong}"
            );
        }
    }

    /// `fees` stays a bare array on the wire — the tiers are named in the
    /// type, not in the document, so the captured oracle still matches.
    #[test]
    fn the_tiers_are_named_in_rust_and_positional_on_the_wire() {
        let tiers = FeeTiers([10, 20, 30]);
        assert_eq!(
            serde_json::to_string(&tiers).expect("serialize"),
            "[10,20,30]"
        );
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
