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

use shekyl_rpc::{Rpc, RpcError};
use shekyl_simple_request_rpc::SimpleRequestRpc;

use crate::engine::traits::{DaemonEngine, FeeEstimates, TxSubmitOutcome};

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

    /// Borrow the underlying RPC client. Intended for internal use by
    /// `shekyl-engine-core`'s scan / send paths and for advanced callers
    /// that need to issue daemon RPCs not yet exposed as wallet methods.
    ///
    /// Stable across V3.x: the inner type is `SimpleRequestRpc` until a
    /// transport migration plan ships, at which point this accessor
    /// changes signature and the migration commit announces it.
    pub fn inner(&self) -> &SimpleRequestRpc {
        &self.inner
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

    /// Phase 2a target. The Stage 1 surface defines the contract; the
    /// production wiring composes [`Rpc::get_fee_rate`] for each of
    /// the three non-`Custom`
    /// [`FeePriority`](super::FeePriority) tiers and assembles the
    /// [`FeeEstimates`] snapshot. Phase 2a lands the body alongside
    /// `Engine::build_pending_tx`'s fee-priority resolution.
    fn get_fee_estimates(&self) -> impl Send + Future<Output = Result<FeeEstimates, Self::Error>> {
        async move {
            todo!(
                "Phase 2a: compose three Rpc::get_fee_rate calls (Economy/Standard/Priority) \
                 into a FeeEstimates snapshot per docs/V3_ENGINE_TRAIT_BOUNDARIES.md §2.5"
            )
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
