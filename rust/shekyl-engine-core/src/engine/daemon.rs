// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Engine → daemon RPC client wrapper.
//!
//! [`DaemonClient`] is the [`Engine`](super::Engine)-facing type for
//! reaching `shekyld` over HTTP(S). It is a thin wrapper around
//! [`shekyl_simple_request_rpc::SimpleRequestRpc`], chosen as the
//! default transport because it is the only daemon-RPC client crate
//! already in the workspace and it implements
//! [`shekyl_rpc::Rpc`].
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
//!    sits on a [`SimpleRequestRpc`] field rather than radiating through
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
use shekyl_rpc::{FeeRate, Rpc, RpcError};
use shekyl_simple_request_rpc::SimpleRequestRpc;

use crate::engine::traits::{DaemonEngine, FeeEstimates, TxSubmitOutcome};

/// Grace-block horizon passed to the daemon's `get_fee_estimate`
/// JSON-RPC (matches `shekyl_rpc`'s private
/// `GRACE_BLOCKS_FOR_FEE_ESTIMATE`). The daemon estimates a fee rate
/// expected to stay above the relay floor for this many blocks. Held
/// here (rather than reaching for the upstream constant, which is not
/// `pub`) so the single-RPC snapshot path (§3.3) does not re-export
/// vendored internals.
const GRACE_BLOCKS_FOR_FEE_ESTIMATE: u64 = 10;

/// Map a daemon `get_fee_estimate` JSON-RPC `result` object onto the
/// three-tier [`FeeEstimates`] snapshot (§3.3), deriving every tier
/// and the rounding mask from this **one** response.
///
/// Mirrors `shekyl_rpc::Rpc::get_fee_rate`'s response handling but
/// resolves **all three** non-`Custom` tiers from a single call
/// rather than one tier per call:
///
/// - **`fees` array present** (V3 daemon): tiers map to array indices
///   `0` (economy), `1` (standard), `3` (priority) per
///   `V3_WALLET_DECISION_LOG.md` (index `2`, "elevated", has no
///   wallet tier). Requires `fees.len() >= 4`.
/// - **`fees` absent** (scalar `fee` only): the canonical upstream
///   multiplier ladder `[1, 5, 25, 1000]` applies at the same indices,
///   i.e. economy `×1`, standard `×5`, priority `×1000`.
///
/// Untrusted-daemon input is parsed defensively (rule
/// `20-rust-vs-cpp-policy.mdc` §3): every field is validated, missing
/// or non-numeric fields and `status != "OK"` map to
/// [`RpcError::InvalidFee`] / [`RpcError::InvalidPriority`], and the
/// scalar-`fee` multiply is `checked_mul` (rule §4).
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

    let (economy, standard, priority) = match result.get("fees").and_then(Value::as_array) {
        Some(fees) => {
            // Indices 0/1/3 must exist; a short array is a malformed
            // estimate, not a silently-clamped one.
            let at = |idx: usize| -> Result<u64, RpcError> {
                fees.get(idx)
                    .and_then(Value::as_u64)
                    .ok_or(RpcError::InvalidPriority)
            };
            (rate(at(0)?)?, rate(at(1)?)?, rate(at(3)?)?)
        }
        None => {
            let fee = result
                .get("fee")
                .and_then(Value::as_u64)
                .ok_or(RpcError::InvalidFee)?;
            let scaled = |mult: u64| -> Result<u64, RpcError> {
                fee.checked_mul(mult).ok_or(RpcError::InvalidFee)
            };
            (rate(scaled(1)?)?, rate(scaled(5)?)?, rate(scaled(1000)?)?)
        }
    };

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
/// [`SimpleRequestRpc`] is `Clone + Send + Sync`; cloning it is cheap
/// (an `Arc`-wrapped HTTP client + URL string).
///
/// `DaemonClient` implements [`shekyl_rpc::Rpc`] (delegating `post` to
/// the wrapped transport) and the crate-internal `DaemonEngine` Stage 1
/// trait (in `crate::engine::traits`); callers reach the upstream
/// `Rpc` methods (block / height / output / mempool) via the
/// supertrait bound on `DaemonEngine` rather than going through the
/// underlying transport directly.
#[derive(Clone, Debug)]
pub struct DaemonClient {
    inner: SimpleRequestRpc,
}

impl DaemonClient {
    /// Wrap an existing [`SimpleRequestRpc`] connection.
    ///
    /// The caller has already constructed the connection (with whatever
    /// authentication / URL / timeout policy is appropriate); this
    /// wrapper does no additional handshake on construction. Daemon
    /// network verification is performed by `Engine::open_*` against
    /// the on-disk wallet file's network declaration.
    pub fn new(inner: SimpleRequestRpc) -> Self {
        Self { inner }
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

    /// Phase 2a target. The Stage 1 surface defines the contract; the
    /// production wiring parses `tx_bytes`, calls
    /// [`Rpc::publish_transaction`], and observes the daemon's response
    /// to distinguish [`TxSubmitOutcome::Submitted`] from
    /// [`TxSubmitOutcome::AlreadyKnown`]. Phase 2a lands the body
    /// alongside `Engine::submit_pending_tx`'s real-broadcast wiring.
    fn submit_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> impl Send + Future<Output = Result<TxSubmitOutcome, Self::Error>> {
        async move {
            let _ = tx_bytes;
            todo!(
                "Phase 2a: parse tx_bytes, call Rpc::publish_transaction, observe daemon response \
                 for AlreadyKnown vs Submitted distinction per docs/V3_ENGINE_TRAIT_BOUNDARIES.md §2.5"
            )
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

    /// Legacy daemon: scalar `fee` only → upstream multiplier ladder
    /// `[1, 5, _, 1000]` at the economy/standard/priority tiers.
    #[test]
    fn fee_estimates_scalar_fallback_multipliers() {
        let result = json!({
            "status": "OK",
            "fee": 10u64,
            "quantization_mask": 4u64,
        });
        let est = fee_estimates_from_value(&result).expect("well-formed scalar fee");
        assert_eq!(est.economy, FeeRate::new(10, 4).unwrap());
        assert_eq!(est.standard, FeeRate::new(50, 4).unwrap());
        assert_eq!(est.priority, FeeRate::new(10_000, 4).unwrap());
        assert_eq!(est.quantization_mask, 4);
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
