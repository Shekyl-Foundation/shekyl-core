// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A channel target a synchronous caller can hold.

use std::sync::{Mutex, PoisonError};

use shekyl_rpc_grants::GrantSet;

use super::handshake::ChannelTarget;
use super::session::Session;
use super::ChannelFault;

/// A channel target a synchronous caller can hold: one session on a
/// current-thread runtime of its own, as [`crate::SyncDaemon`] holds one
/// for HTTP. `shekyl-cli` reaches a daemon on another host, or a service's
/// console leg, through it.
pub struct ChannelDaemon {
    runtime: tokio::runtime::Runtime,
    session: Mutex<Session>,
}

impl ChannelDaemon {
    /// Open a session to `target` asking for `request`.
    ///
    /// # Errors
    ///
    /// [`ChannelFault`]: the runtime, or why the channel did not open.
    pub fn connect(target: &ChannelTarget, request: GrantSet) -> Result<Self, ChannelFault> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(ChannelFault::Local(
                "the channel's client was made inside an async runtime".to_owned(),
            ));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ChannelFault::Local(format!("runtime: {e}")))?;
        let session = runtime.block_on(async {
            let opened = target.open(request).await?;
            Session::start(opened, None).await
        })?;
        Ok(Self {
            runtime,
            session: Mutex::new(session),
        })
    }

    /// What the session holds.
    #[must_use]
    pub fn granted(&self) -> GrantSet {
        self.session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .granted()
    }

    /// POST `body` to `route` and return the response's body.
    ///
    /// # Errors
    ///
    /// [`ChannelFault::Closed`] when the session ends under the request.
    pub fn post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, ChannelFault> {
        let mut session = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        self.runtime.block_on(session.post(route, body))
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
