// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A channel target a synchronous caller can hold.

use std::sync::Arc;
use std::time::Duration;

use shekyl_rpc_grants::GrantSet;

use super::handshake::ChannelTarget;
use super::pool::Pool;
use super::ChannelFault;

/// A channel target a synchronous caller can hold.
///
/// This is the same [`Pool`] the async wallet holds, on a current-thread
/// runtime, as [`crate::SyncDaemon`] holds one for HTTP. `within` bounds
/// every post. A deadline is [`ChannelFault::Budget`]. A connection that
/// ends is rechecked by the pool, and the body is not sent again.
pub struct ChannelDaemon {
    runtime: tokio::runtime::Runtime,
    pool: Arc<Pool>,
    within: Duration,
    granted: GrantSet,
}

impl ChannelDaemon {
    /// Open a pool with the permissions enrolled on the daemon. `within`
    /// bounds every later post.
    ///
    /// # Errors
    ///
    /// As for [`Self::connect`].
    pub fn connect_enrolled(
        target: &ChannelTarget,
        within: Duration,
    ) -> Result<Self, ChannelFault> {
        Self::connect(target, GrantSet::ALL, within)
    }

    /// Open a pool to `target` asking for `request`. The kept session is
    /// opened now, so a refusal is this call's. `within` bounds every later post.
    ///
    /// # Errors
    ///
    /// [`ChannelFault`]: the runtime, or why the channel did not open.
    pub fn connect(
        target: &ChannelTarget,
        request: GrantSet,
        within: Duration,
    ) -> Result<Self, ChannelFault> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(ChannelFault::Local(
                "the channel's client was made inside an async runtime".to_owned(),
            ));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ChannelFault::Local(format!("runtime: {e}")))?;
        let pool = Pool::new(target.clone(), request);
        let (_ceiling, granted) = runtime.block_on(pool.open_kept())?;
        Ok(Self {
            runtime,
            pool,
            within,
            granted,
        })
    }

    /// What the kept session holds.
    #[must_use]
    pub fn granted(&self) -> GrantSet {
        self.granted
    }

    /// POST `body` to `route` and return the response's body.
    ///
    /// # Errors
    ///
    /// [`ChannelFault`], from the pool. [`ChannelFault::Budget`] when
    /// [`Self::connect`]'s bound elapses. [`ChannelFault::Closed`] when the
    /// session ends and the recheck does not name a stronger fault. The body
    /// is not sent again.
    pub fn post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, ChannelFault> {
        self.runtime
            .block_on(self.pool.post(route, body, self.within))
    }

    /// One call of method `M`: the envelope and checks every target makes.
    ///
    /// # Errors
    ///
    /// The channel, a body that is not the reply, a method the daemon does
    /// not serve, or the daemon's refusal.
    pub fn call<M: shekyl_rpc_client::RpcMethod>(
        &self,
        request: &M::Request,
    ) -> Result<M::Reply, crate::JsonRpcError<ChannelFault>> {
        crate::call_via::<M, _>(request, |route, body| self.post(route, body))
    }

    /// One JSON-RPC call by name, its result decoded as `Reply`.
    ///
    /// # Errors
    ///
    /// As [`Self::call`].
    pub fn json_rpc<Req, Reply>(
        &self,
        method: &str,
        request: &Req,
    ) -> Result<Reply, crate::JsonRpcError<ChannelFault>>
    where
        Req: serde::Serialize,
        Reply: serde::de::DeserializeOwned,
    {
        crate::json_rpc_via(method, request, |route, body| self.post(route, body))
    }
}
