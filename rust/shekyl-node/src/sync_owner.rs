// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain sync's owner, started once when the node opens (CS-5 §2).
//!
//! The owner registers on the network's timing engine, class `Sync`, and
//! draws from the production CSPRNG. Its inbound channel is the port the
//! session layer dispatches to (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1,
//! "2008, 2009, 2011–2014"): the node opens the port before the network
//! starts, hands the port to the network and the receiver here.

use std::sync::{Arc, Mutex, PoisonError};

use shekyl_chain_ingest::service::{Alarm, Door};
use shekyl_chain_ingest::ChainRules;
use shekyl_chain_store::store::ChainStore;
use shekyl_chain_sync::SyncState;
use shekyl_chain_sync::{Declaration, Requesting};
use shekyl_chain_sync_runtime::executor::Executor;
use shekyl_chain_sync_runtime::owner::{OwnerParts, Running};
use shekyl_chain_sync_runtime::port::Inbound;
use shekyl_mempool::Pool;
use shekyl_relay::owner::SecureRelayRng;
use shekyl_timing_engine::{Handle, MonotonicClock, OwnerClass};
use shekyl_transport_layer::SocketId;

use crate::OpenError;

/// What the owner is started with.
pub(crate) struct Parts {
    pub(crate) store: Arc<ChainStore>,
    pub(crate) door: Door,
    pub(crate) alarm: Alarm,
    pub(crate) tips: tokio::sync::watch::Receiver<shekyl_chain_ingest::TipChanged>,
    pub(crate) latch:
        tokio::sync::watch::Receiver<Option<shekyl_chain_store::codec::FollowingDegraded>>,
    pub(crate) executor: Arc<Executor>,
    /// The network's timing engine, which the owner's wakes register on.
    pub(crate) engine: Handle<MonotonicClock>,
    pub(crate) rules: ChainRules,
    pub(crate) requesting: Requesting,
    pub(crate) declaration: Declaration,
    pub(crate) pool: Arc<Mutex<Pool>>,
    /// The port's receiving end ([`shekyl_chain_sync_runtime::port::port`]).
    pub(crate) inbound: tokio::sync::mpsc::UnboundedReceiver<Inbound>,
    pub(crate) state: tokio::sync::watch::Sender<SyncState>,
}

/// The running owner.
pub(crate) struct Held {
    running: Running,
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
    ) -> tokio::sync::watch::Receiver<shekyl_chain_sync::SyncView<SocketId>> {
        self.running.view()
    }

    /// Ask the task to stop, without joining it.
    pub(crate) fn request_stop(&self) {
        self.running.request_stop();
    }

    /// Ask the task to publish `state`. The task is the only publisher.
    #[cfg(test)]
    pub(crate) fn publish_for_test(&self, state: SyncState) {
        self.running.publish_for_test(state);
    }

    /// Ask the task to stop and join it.
    pub(crate) fn stop(self, timeout: std::time::Duration) {
        let Self { running } = self;
        running.request_stop();
        running.stop(timeout);
    }
}

/// Start chain sync's owner on the network's engine.
pub(crate) fn spawn(parts: Parts) -> Result<Held, OpenError> {
    let timer = parts
        .engine
        .register(OwnerClass::Sync)
        .map_err(|error| OpenError::Sync(format!("the timing engine: {error:?}")))?;
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
        executor: parts.executor,
        timer,
        rules: parts.rules,
        requesting: parts.requesting,
        declaration: parts.declaration,
        rng: SecureRelayRng,
        pool_hashes,
        inbound: parts.inbound,
        state: parts.state,
    })
    .map_err(OpenError::Runtime)?;
    Ok(Held { running })
}
