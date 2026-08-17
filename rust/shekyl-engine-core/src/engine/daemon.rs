// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Engine → daemon RPC client wrapper.
//!
//! [`DaemonClient`] is the [`Engine`](super::Engine)-facing type for
//! reaching `shekyld` over HTTP(S). It is a thin wrapper around
//! [`shekyl_rpc_transport::HttpRpc`], chosen as the
//! default transport because it is the only daemon-RPC client crate
//! already in the workspace and it implements
//! [`shekyl_rpc_client::Rpc`].
//!
//! # Why a wrapper rather than `pub use`
//!
//! Three reasons, each independently sufficient:
//!
//! 1. **Insulates `Engine`'s public API from the transport choice.**
//!    The `Engine::daemon()` accessor returns a stable type. If a
//!    later phase swaps the underlying transport (UDS, gRPC, in-process
//!    test fake) the `Engine`-level signature is unchanged.
//! 2. **One audited site for daemon-bound calls.** The wallet's
//!    daemon-touching operations (`get_info` for network verification,
//!    `get_fee_estimates` for fee-priority resolution, transfer
//!    submission) ultimately go through this type, which gives Phase 2a
//!    a single place to add tracing spans, fee-sanity checks, and
//!    network-mismatch detection without touching every call site.
//! 3. **Keeps the cross-cutting lock 1 contract local.** The
//!    "caller-provided multi-threaded `tokio` runtime" requirement
//!    sits on a [`HttpRpc`] field rather than radiating through
//!    the wallet API.
//!
//! # Network verification (Phase 2a)
//!
//! [`DaemonClient`] does not yet verify the daemon's network on
//! construction; that ships with `Engine::open_*`'s lifecycle commit,
//! which calls `get_info` and compares the daemon-reported network with
//! the wallet file's region 1 declaration. Mismatches surface as
//! [`OpenError::NetworkMismatch`](super::error::OpenError::NetworkMismatch).

use std::future::Future;

use serde_json::{json, Value};
use shekyl_rpc_client::{FeeRate, RejectCause, Rpc, RpcError};
use shekyl_rpc_transport::HttpRpc;
use shekyl_scanner::ScannableBlock;
use shekyl_wire::Transaction;

use crate::engine::pending::TxHash;
use crate::engine::traits::{DaemonEngine, DaemonHealth, FeeEstimates, TxSubmitOutcome};
use crate::engine::transaction_submitter::submit_outcome_from_verdict;

// One owner for the grace-block horizon: the constant lives in
// `shekyl-rpc-client` (a first-class workspace crate since the
// un-vendoring — the old "not re-exporting vendored internals"
// rationale for a local copy no longer applies).
use shekyl_rpc_client::GRACE_BLOCKS_FOR_FEE_ESTIMATE;

/// Map a daemon `get_fee_estimate` JSON-RPC `result` object onto the
/// three-tier [`FeeEstimates`] snapshot (§3.3), deriving every tier
/// and the rounding mask from this **one** response.
///
/// Mirrors `shekyl_rpc_client::Rpc::get_fee_rate`'s response handling but
/// resolves **all three** non-`Custom` tiers from a single call rather
/// than one tier per call. Tiers map to `fees` indices `0` (economy),
/// `1` (standard), `3` (priority) per `V3_WALLET_DECISION_LOG.md`.
/// Index `2` (`Fm`, "elevated") is deliberately unmapped: the wallet
/// offers three named tiers, and the ladder's ends — cheapest and
/// fastest — are the ones a user picks between.
///
/// # `fees` is required, and its absence is not a legacy shape
///
/// The ArticMine 2021 fee ladder is live **from genesis**:
/// `HF_VERSION_2021_SCALING` is `1` (`src/cryptonote_config.h`), so
/// `core_rpc_server::on_get_base_fee_estimate` always takes the
/// `version >= HF_VERSION_2021_SCALING` branch and always answers with
/// a four-element `fees` array (`Blockchain::
/// get_dynamic_base_fee_estimate_2021_scaling` `resize(4)`s it). This
/// holds for a reply forwarded from a bootstrap daemon too — that
/// forward reaches another Shekyl daemon, which is subject to the same
/// rule.
///
/// A pre-2021-scaling daemon answering with a bare scalar `fee` is
/// therefore a shape that **cannot occur on this chain**; it is
/// Monero-lineage inheritance, and the multiplier ladder the wallet
/// used to synthesize from it (`×1 / ×5 / ×1000`) was an invented
/// tier band with no daemon behind it — one that put `priority`
/// three orders of magnitude above `economy` and so tripped the
/// absolute cap on any base fee over 100, refusing the whole snapshot
/// (Economy included) for a daemon that had charged nothing unusual.
/// Deleted per rules 60 / 15 / 16: a missing `fees` array is a
/// malformed reply, like any other missing field.
///
/// Untrusted-daemon input is parsed defensively (rule
/// `20-rust-vs-cpp-policy.mdc` §3): every field is validated, and
/// missing or non-numeric fields and `status != "OK"` map to
/// [`RpcError::InvalidFee`] / [`RpcError::InvalidPriority`].
fn fee_estimates_from_value(result: &Value) -> Result<FeeEstimates, RpcError> {
    if result.get("status").and_then(Value::as_str) != Some("OK") {
        return Err(RpcError::InvalidFee);
    }

    let mask = result
        .get("quantization_mask")
        .and_then(Value::as_u64)
        .ok_or(RpcError::InvalidFee)?;

    // `FeeRate::new` already rejects `mask == 0` / `per_weight == 0`;
    // surface a per-tier rate or the upstream error verbatim.
    let rate = |per_weight: u64| FeeRate::new(per_weight, mask);

    // `fees` must be an array of at least the four tiers every Shekyl
    // daemon emits. Absent, null, or any non-array (`fees: "oops"`) is
    // a malformed reply — there is no fallback shape to degrade to, so
    // nothing here can silently accept a snapshot the daemon did not
    // actually quote.
    let Some(Value::Array(fees)) = result.get("fees") else {
        return Err(RpcError::InvalidFee);
    };
    // A short array is a malformed estimate, not a silently-clamped
    // one. Destructured once rather than indexed three times, so the
    // ladder positions are named here and nowhere else — including
    // `_elevated` (`Fm`), whose absence from the wallet's tier set is
    // now visible in the code instead of only in prose. A longer array
    // from a future daemon keeps working (rule 75).
    let [economy, standard, _elevated, priority, ..] = &fees[..] else {
        return Err(RpcError::InvalidPriority);
    };
    let tier = |value: &Value| -> Result<u64, RpcError> {
        value.as_u64().ok_or(RpcError::InvalidPriority)
    };
    let (economy, standard, priority) = (
        rate(tier(economy)?)?,
        rate(tier(standard)?)?,
        rate(tier(priority)?)?,
    );

    Ok(FeeEstimates {
        economy,
        standard,
        priority,
        quantization_mask: mask,
    })
}

/// Engine's view of the daemon RPC connection.
///
/// Held on [`Engine`](super::Engine) and shared, by clone, with
/// `shekyl-scanner` and the tx-submission path. The underlying
/// [`HttpRpc`] is `Clone + Send + Sync`; cloning it is cheap
/// (an `Arc`-wrapped HTTP client + URL string).
///
/// `DaemonClient` implements [`shekyl_rpc_client::Rpc`] (delegating `post` to
/// the wrapped transport) and the crate-internal `DaemonEngine` Stage 1
/// trait (in `crate::engine::traits`); callers reach the upstream
/// `Rpc` methods (block / height / output / mempool) via the
/// supertrait bound on `DaemonEngine` rather than going through the
/// underlying transport directly.
#[derive(Clone, Debug)]
pub struct DaemonClient {
    inner: HttpRpc,
}

impl DaemonClient {
    /// Wrap an existing [`HttpRpc`] connection.
    ///
    /// The caller has already constructed the connection (with whatever
    /// authentication / URL / timeout policy is appropriate); this
    /// wrapper does no additional handshake on construction. Daemon
    /// network verification is performed by `Engine::open_*` against
    /// the on-disk wallet file's network declaration.
    pub fn new(inner: HttpRpc) -> Self {
        Self { inner }
    }

    /// Fetch the block at `number` as a [`ScannableBlock`] via the native
    /// `shekyl-wire` parse (`engine::block_fetch`).
    ///
    /// Public inherent wrapper around the crate-private
    /// [`DaemonEngine::fetch_scannable_block`] default so transitional
    /// consumers (GUI `wallet_bridge` sync loop) can use the same path as
    /// `Engine` without depending on the private trait. Replaces the
    /// deleted `shekyl_rpc_client::Rpc::get_scannable_block_by_number`.
    ///
    /// The return type is the scanner crate's [`ScannableBlock`], re-exported
    /// from `shekyl-engine-core` so callers can name it without a direct
    /// `shekyl-scanner` dependency. A local wrapper/newtype is rejected:
    /// that would duplicate the canonical type and drift (type-placement).
    pub async fn fetch_scannable_block(&self, number: usize) -> Result<ScannableBlock, RpcError> {
        crate::engine::block_fetch::default_fetch_scannable_block(self, number).await
    }
}

impl Rpc for DaemonClient {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
        self.inner.post(route, body)
    }
}

impl DaemonEngine for DaemonClient {
    type Error = RpcError;

    /// Atomic single-RPC fee snapshot (§3.3).
    ///
    /// Issues **one** `get_fee_estimate` JSON-RPC call and maps its
    /// response onto all three non-`Custom`
    /// [`FeePriority`](super::FeePriority) tiers plus the snapshot
    /// `quantization_mask` via [`fee_estimates_from_value`] — not
    /// three per-tier [`Rpc::get_fee_rate`] calls, so the tier band
    /// carries no tier-vs-tier skew from interleaved reads.
    fn get_fee_estimates(&self) -> impl Send + Future<Output = Result<FeeEstimates, Self::Error>> {
        async move {
            let result: Value = self
                .json_rpc_call(
                    "get_fee_estimate",
                    Some(json!({ "grace_blocks": GRACE_BLOCKS_FOR_FEE_ESTIMATE })),
                )
                .await?;
            fee_estimates_from_value(&result)
        }
    }

    /// Offer `tx_bytes` to the daemon over the typed submit route and
    /// map its [`SubmitVerdict`](shekyl_rpc_client::SubmitVerdict) to a
    /// [`TxSubmitOutcome`].
    ///
    /// 1. Parse `tx_bytes` back into a [`Transaction`]. A round-trip
    ///    failure is a malformed-tx rejection — these are the wallet's
    ///    *own* serialized bytes, so a parse failure is a build-path
    ///    defect, not a daemon verdict; no round-trip is issued
    ///    (mirrors the daemon's own Phase-A `Rejected{Malformed}`, so
    ///    the local guard and the wire verdict agree).
    /// 2. Compute the tx id **locally** from the parsed transaction;
    ///    never read it back from a daemon field, so an untrusted
    ///    daemon cannot influence the id the wallet records.
    /// 3. [`Rpc::publish_transaction`]; a transport/protocol failure
    ///    (including an unknown top-level verdict tag per the §2.3 skew
    ///    rules) surfaces as [`Self::Error`] — the orchestrator maps it
    ///    to the ambiguous-reservation path, not to an outcome.
    /// 4. Map the daemon verdict via [`submit_outcome_from_verdict`].
    fn submit_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> impl Send + Future<Output = Result<TxSubmitOutcome, Self::Error>> {
        async move {
            let Ok(tx) = Transaction::from_bytes(&tx_bytes) else {
                return Ok(TxSubmitOutcome::Rejected {
                    cause: RejectCause::Malformed,
                });
            };

            let hash = TxHash::from_bytes(tx.hash());

            let verdict = self.publish_transaction(&tx_bytes).await?;
            Ok(submit_outcome_from_verdict(&verdict, hash))
        }
    }

    /// Snapshot daemon health via **one** `get_info` JSON-RPC read
    /// (§5.2 item 3) — the same info surface `Engine::open_*` already
    /// queries for network verification, so this adds no new RPC method.
    ///
    /// The summed outgoing/incoming connection counts and the sync
    /// position feed the §5.3 escape ladder's health gate. Untrusted-
    /// daemon input is parsed defensively (rule `20-rust-vs-cpp-policy`
    /// §3): a response missing the mandatory `height` field is a
    /// malformed reply ([`RpcError::InvalidNode`]), not a silently
    /// defaulted zero (a false "synced at height 0" would mislead the
    /// ladder's sync gate). Absent connection counts map to `0` — the
    /// safe direction, since a peerless reading only ever routes to the
    /// operator-alarm rung, never to a rebuild. `target_height` follows
    /// the info surface's "0 when synced" convention, so its absence
    /// maps to `0`, and the connection sum is `saturating_add` (rule §4).
    fn get_health(&self) -> impl Send + Future<Output = Result<DaemonHealth, Self::Error>> {
        async move {
            let info: Value = self.json_rpc_call("get_info", None).await?;
            let height = info
                .get("height")
                .and_then(Value::as_u64)
                .ok_or_else(|| RpcError::InvalidNode("get_info missing height".to_string()))?;
            let target_height = info
                .get("target_height")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let outgoing = info
                .get("outgoing_connections_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let incoming = info
                .get("incoming_connections_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            Ok(DaemonHealth {
                connections: outgoing.saturating_add(incoming),
                height,
                target_height,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    //! `fee_estimates_from_value` mapping regression (§3.3).
    //!
    //! The single-RPC snapshot's daemon-response mapping is a pure
    //! function, so it is exercised directly against synthetic
    //! `result` objects without a live daemon. The `DaemonClient`
    //! transport (`json_rpc_call` → `post`) is covered by the Phase 6
    //! live-`shekyld` harness, not here.
    use super::*;

    /// V3 daemon: `fees` array present, tiers map to indices 0/1/3
    /// and the shared `quantization_mask` lands on the snapshot.
    #[test]
    fn fee_estimates_array_maps_indices_0_1_3() {
        let result = json!({
            "status": "OK",
            "fees": [100u64, 200, 300, 400],
            "fee": 100,
            "quantization_mask": 8u64,
        });
        let est = fee_estimates_from_value(&result).expect("well-formed fee array");
        assert_eq!(est.economy, FeeRate::new(100, 8).unwrap());
        assert_eq!(est.standard, FeeRate::new(200, 8).unwrap());
        // Index 3, *not* 2 — the "elevated" tier (index 2) has no
        // wallet `FeePriority`.
        assert_eq!(est.priority, FeeRate::new(400, 8).unwrap());
        assert_eq!(est.quantization_mask, 8);
        // Tiers are distinct (regression for a collapsed mapping).
        assert_ne!(est.economy, est.priority);
    }

    /// A reply carrying only the scalar `fee` is malformed, not a
    /// legacy shape to synthesize tiers from.
    ///
    /// `HF_VERSION_2021_SCALING` is `1`, so every Shekyl daemon emits
    /// `fees[4]`; the `×1 / ×5 / ×1000` ladder the wallet used to
    /// invent here had no daemon behind it, and its `×1000` priority
    /// meant any base fee above 100 blew the absolute cap and got the
    /// **whole** snapshot refused — Economy included — for a daemon
    /// charging nothing unusual.
    ///
    /// This bites against the ladder being reintroduced. It does NOT
    /// cover the `fees` mapping (that is
    /// `fee_estimates_array_maps_indices_0_1_3`).
    #[test]
    fn fee_estimates_refuses_a_scalar_only_reply() {
        for reply in [
            json!({"status": "OK", "fee": 10u64, "quantization_mask": 4u64}),
            json!({"status": "OK", "fees": null, "fee": 10u64, "quantization_mask": 4u64}),
        ] {
            assert!(
                matches!(fee_estimates_from_value(&reply), Err(RpcError::InvalidFee)),
                "a scalar-only reply must not synthesize a tier band: {reply}"
            );
        }
    }

    #[test]
    fn fee_estimates_rejects_non_ok_status() {
        let result = json!({
            "status": "BUSY",
            "fees": [100u64, 200, 300, 400],
            "quantization_mask": 8u64,
        });
        assert!(matches!(
            fee_estimates_from_value(&result),
            Err(RpcError::InvalidFee)
        ));
    }

    /// A `fees` array too short to carry the priority tier (index 3)
    /// is malformed, not silently clamped to a lower tier.
    #[test]
    fn fee_estimates_rejects_short_fees_array() {
        let result = json!({
            "status": "OK",
            "fees": [100u64, 200],
            "quantization_mask": 8u64,
        });
        assert!(matches!(
            fee_estimates_from_value(&result),
            Err(RpcError::InvalidPriority)
        ));
    }

    /// A present-but-non-array `fees` (e.g. a string) is malformed, and
    /// the neighbouring scalar `fee` does not rescue it.
    #[test]
    fn fee_estimates_rejects_non_array_fees() {
        let result = json!({
            "status": "OK",
            "fees": "oops",
            "fee": 10u64,
            "quantization_mask": 8u64,
        });
        assert!(matches!(
            fee_estimates_from_value(&result),
            Err(RpcError::InvalidFee)
        ));
    }

    /// A daemon that grows the ladder past four tiers keeps working:
    /// the wallet reads its three positions and ignores the rest
    /// (rule 75 — no coordinated wallet upgrade for a tier it does not
    /// offer).
    #[test]
    fn fee_estimates_tolerates_a_longer_fees_array() {
        let result = json!({
            "status": "OK",
            "fees": [100u64, 200, 300, 400, 500, 600],
            "quantization_mask": 8u64,
        });
        let est = fee_estimates_from_value(&result).expect("a longer ladder is not malformed");
        assert_eq!(est.economy, FeeRate::new(100, 8).unwrap());
        assert_eq!(est.standard, FeeRate::new(200, 8).unwrap());
        assert_eq!(est.priority, FeeRate::new(400, 8).unwrap());
    }

    #[test]
    fn fee_estimates_rejects_missing_mask() {
        let result = json!({
            "status": "OK",
            "fees": [100u64, 200, 300, 400],
        });
        assert!(matches!(
            fee_estimates_from_value(&result),
            Err(RpcError::InvalidFee)
        ));
    }

    /// `quantization_mask == 0` would make `FeeRate::new` reject; the
    /// mapping surfaces that as `InvalidFee` rather than panicking.
    #[test]
    fn fee_estimates_rejects_zero_mask() {
        let result = json!({
            "status": "OK",
            "fees": [100u64, 200, 300, 400],
            "quantization_mask": 0u64,
        });
        assert!(matches!(
            fee_estimates_from_value(&result),
            Err(RpcError::InvalidFee)
        ));
    }
}
