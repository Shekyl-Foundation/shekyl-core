// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain sync's owner, started once when the node opens (CS-5 §2).
//!
//! The owner registers on the process's timing engine, class `Sync`, and
//! draws from the production CSPRNG. Its router sender and hub one-shot
//! are left for the seam's bind (`shekyl_ffi::chain_sync_ffi::install`).
//! The lease from that install is this node's: a later node in the same
//! process does not drop this hub sender, and dropping the lease releases
//! only this owner.

use std::sync::{Arc, Mutex, PoisonError};

use shekyl_chain_ingest::service::{Alarm, Door};
use shekyl_chain_ingest::ChainRules;
use shekyl_chain_store::store::ChainStore;
use shekyl_chain_sync::SyncState;
use shekyl_chain_sync::{Declaration, Requesting};
use shekyl_chain_sync_runtime::executor::Executor;
use shekyl_chain_sync_runtime::owner::{OwnerParts, Running};
use shekyl_ffi::chain_sync_ffi::OwnerLease;
use shekyl_ffi::secure_relay_rng::SecureRelayRng;
use shekyl_mempool::Pool;
use shekyl_timing_engine::OwnerClass;

use crate::OpenError;

/// What [`spawn`] builds chain sync's owner from, beside the router and
/// the hub it makes and leaves for the seam's bind.
pub(crate) struct Parts {
    pub(crate) store: Arc<ChainStore>,
    pub(crate) door: Door,
    pub(crate) alarm: Alarm,
    pub(crate) tips: tokio::sync::watch::Receiver<shekyl_chain_ingest::TipChanged>,
    pub(crate) latch:
        tokio::sync::watch::Receiver<Option<shekyl_chain_store::codec::FollowingDegraded>>,
    pub(crate) executor: Arc<Executor>,
    pub(crate) rules: ChainRules,
    pub(crate) requesting: Requesting,
    pub(crate) declaration: Declaration,
    pub(crate) pool: Arc<Mutex<Pool>>,
    pub(crate) state: tokio::sync::watch::Sender<SyncState>,
}

/// The running owner and the lease that keeps its hub sender alive.
///
/// The lease is not the bind's slot. The seam takes the latest owner still
/// waiting; releasing this value ends only the owner it holds.
pub(crate) struct Held {
    running: Running,
    lease: OwnerLease,
}

impl Held {
    /// How the owner's task ended, once it has.
    #[must_use]
    pub(crate) fn ended(
        &self,
    ) -> tokio::sync::watch::Receiver<Option<shekyl_chain_sync_runtime::owner::Ended>> {
        self.running.ended()
    }

    /// The model's view.
    #[must_use]
    pub(crate) fn view(
        &self,
    ) -> tokio::sync::watch::Receiver<shekyl_chain_sync::SyncView<shekyl_seam::SocketId>> {
        self.running.view()
    }

    /// Ask the task to stop, without joining it and without releasing the hub.
    pub(crate) fn request_stop(&self) {
        self.running.request_stop();
    }

    /// Ask the task to publish `state`. The task is the only publisher.
    #[cfg(test)]
    pub(crate) fn publish_for_test(&self, state: SyncState) {
        self.running.publish_for_test(state);
    }

    /// Ask the task to stop, release this node's hub sender, and join it.
    ///
    /// The stop is asked before the sender drops. An owner still waiting on
    /// the hub would otherwise report that close as its own failure.
    pub(crate) fn stop(self, timeout: std::time::Duration) {
        let Self { running, lease } = self;
        running.request_stop();
        drop(lease);
        running.stop(timeout);
    }
}

/// Start chain sync's owner and install its router and hub for the seam.
pub(crate) fn spawn(parts: Parts) -> Result<Held, OpenError> {
    let timer = shekyl_ffi::zone_ffi::process_engine()
        .register(OwnerClass::Sync)
        .map_err(|error| OpenError::Sync(format!("the timing engine: {error:?}")))?;
    let (router_tx, routed) = tokio::sync::mpsc::unbounded_channel();
    let (hub_tx, hub) = tokio::sync::oneshot::channel();
    let state = parts.state.subscribe();
    let pool = parts.pool;
    let pool_hashes: Arc<dyn Fn() -> Vec<[u8; 32]> + Send + Sync> = Arc::new(move || {
        pool.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .peer_sync()
            .map(|(txid, _)| *txid.as_bytes())
            .collect()
    });
    let running = shekyl_chain_sync_runtime::owner::spawn(OwnerParts {
        store: parts.store,
        door: parts.door,
        alarm: parts.alarm,
        tips: parts.tips,
        latch: parts.latch,
        hub,
        executor: parts.executor,
        timer,
        rules: parts.rules,
        requesting: parts.requesting,
        declaration: parts.declaration,
        rng: SecureRelayRng,
        pool_hashes,
        routed,
        state: parts.state,
    })
    .map_err(OpenError::Runtime)?;
    let lease = shekyl_ffi::chain_sync_ffi::install(router_tx, hub_tx, state);
    Ok(Held { running, lease })
}
