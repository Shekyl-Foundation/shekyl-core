// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet → daemon RPC client wrapper.
//!
//! [`DaemonClient`] is the [`Wallet`](super::Wallet)-facing type for
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
//! 1. **Insulates `Wallet`'s public API from the transport choice.**
//!    The `Wallet::daemon()` accessor returns a stable type. If a
//!    later phase swaps the underlying transport (UDS, gRPC, in-process
//!    test fake) the `Wallet`-level signature is unchanged.
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
//! construction; that ships with `Wallet::open_*`'s lifecycle commit,
//! which calls `get_info` and compares the daemon-reported network with
//! the wallet file's region 1 declaration. Mismatches surface as
//! [`OpenError::NetworkMismatch`](super::error::OpenError::NetworkMismatch).

use shekyl_simple_request_rpc::SimpleRequestRpc;

/// Wallet's view of the daemon RPC connection.
///
/// Held on [`Wallet`](super::Wallet) and shared, by clone, with
/// `shekyl-scanner` and the tx-submission path. The underlying
/// [`SimpleRequestRpc`] is `Clone + Send + Sync`; cloning it is cheap
/// (an `Arc`-wrapped HTTP client + URL string).
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
    /// network verification is performed by `Wallet::open_*` against
    /// the on-disk wallet file's network declaration.
    pub fn new(inner: SimpleRequestRpc) -> Self {
        Self { inner }
    }

    /// Borrow the underlying RPC client. Intended for internal use by
    /// `shekyl-wallet-core`'s scan / send paths and for advanced callers
    /// that need to issue daemon RPCs not yet exposed as wallet methods.
    ///
    /// Stable across V3.x: the inner type is `SimpleRequestRpc` until a
    /// transport migration plan ships, at which point this accessor
    /// changes signature and the migration commit announces it.
    pub fn inner(&self) -> &SimpleRequestRpc {
        &self.inner
    }
}
