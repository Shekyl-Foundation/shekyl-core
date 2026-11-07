// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The network, seated once the chain service is running.
//!
//! [`start`] publishes the handshake tip and the relay's sync watch, starts
//! the [`Network`], then seats the two things that exist only because it
//! does: chain sync's owner, on the network's timing engine and the
//! session port, and the submit nudge, which hands a transaction this node
//! committed to the relay. Departures attach and the producer's network
//! slot fills before the owner starts, so a departure during that start
//! reaches the relay.
//!
//! A failure leaves nothing of the network running. [`Network::start`]
//! stops what it started. If the owner does not start, [`start`] stops the
//! network before it returns. The bridges keep running until the caller
//! shuts the runtime down; this module does not stop the ingest service.

use std::sync::{Arc, Mutex, OnceLock};

use shekyl_chain_ingest::service::{Alarm, Departed, Door, PoolHealth};
use shekyl_chain_ingest::{ChainRules, ProductionSubstrate, TipChanged};
use shekyl_chain_store::store::ChainStore;
use shekyl_chain_sync::{Declaration, Requesting, SyncState};
use shekyl_chain_sync_runtime::executor::Executor;
use shekyl_hash_budget::Budget;
use shekyl_mempool::Pool;
use shekyl_p2p::{CoreSyncData, Network, NetworkParts, NetworkPlan, NodeSync, SupervisorFeeds};
use shekyl_relay::owner::{PoolDoor, RelayHandle};
use shekyl_relay::TxId;
use shekyl_transport_layer::Sockets;
use shekyl_types::TxHash;

use crate::pool_door::{Departures, NodePoolDoor};
use crate::sync_owner;
use crate::OpenError;

/// A started network and the chain-sync owner registered on its engine.
pub(crate) struct Started {
    pub network: Network,
    pub sync_owner: sync_owner::Held,
}

/// What [`start`] needs once the ingest service is running.
pub(crate) struct Parts<'a> {
    pub runtime: &'a shekyl_runtime::Pool,
    /// Cloned into the handshake bridge. The sync owner keeps this receiver.
    pub tips: tokio::sync::watch::Receiver<TipChanged>,
    /// Cloned into the relay's sync bridge. The node keeps its own.
    pub sync: tokio::sync::watch::Receiver<SyncState>,
    pub plan: NetworkPlan,
    pub supervisor: Option<SupervisorFeeds>,
    pub sockets: Sockets,
    /// The relay owner's pool door.
    pub relay_door: Arc<dyn PoolDoor>,
    pub departures: Arc<Departures>,
    /// Filled once, here, before the sync owner starts. The bundle producer
    /// reads it when it builds.
    pub network_slot: Arc<OnceLock<Network>>,
    pub store: Arc<ChainStore>,
    pub door: Door,
    pub alarm: Alarm,
    pub latch: tokio::sync::watch::Receiver<Option<shekyl_chain_store::codec::FollowingDegraded>>,
    pub budget: Budget,
    pub sync_substrate: ProductionSubstrate,
    pub rules: ChainRules,
    pub requesting: Requesting,
    pub declaration: Declaration,
    /// The pool chain sync reads when a peer asks which transactions this
    /// node holds. The same pool as [`Self::submit_pool`].
    pub sync_pool: Arc<Mutex<Pool>>,
    /// The owner's sender. It is the only publisher of the node's sync watch.
    pub sync_state: tokio::sync::watch::Sender<SyncState>,
    /// The pool the submit shim admits into.
    pub submit_pool: Arc<Mutex<Pool>>,
    pub pool_health: PoolHealth,
    /// Shown transactions the relay did not take are marked here.
    pub nudge_door: Arc<NodePoolDoor>,
    pub departed: Departed,
    /// An offline node has no relay to hand a committed transaction to.
    pub offline: bool,
}

/// Publish the watches, start the network, and seat the sync owner and the
/// submit nudge.
///
/// # Errors
///
/// [`OpenError::Network`] when the network refuses to start.
/// [`OpenError::Sync`] when the owner does not: the network is stopped
/// first. Either way the caller still shuts the runtime down.
pub(crate) fn start(parts: Parts<'_>) -> Result<Started, OpenError> {
    let Parts {
        runtime,
        tips,
        sync,
        plan,
        supervisor,
        sockets,
        relay_door,
        departures,
        network_slot,
        store,
        door,
        alarm,
        latch,
        budget,
        sync_substrate,
        rules,
        requesting,
        declaration,
        sync_pool,
        sync_state,
        submit_pool,
        pool_health,
        nudge_door,
        departed,
        offline,
    } = parts;
    let (tip, node_sync) = publish_watches(runtime, tips.clone(), sync);
    let (sync_port, inbound) = shekyl_chain_sync_runtime::port::port();
    let network = Network::start(NetworkParts {
        plan,
        sockets,
        sync: Arc::new(sync_port),
        pool: relay_door,
        node_sync,
        tip,
        supervisor,
    })
    .map_err(|error| OpenError::Network(error.to_string()))?;
    departures.attach(network.relay().clone());
    network_slot
        .set(network.clone())
        .unwrap_or_else(|_| unreachable!("the network slot is set once, here"));
    let sync_owner = match sync_owner::spawn(sync_owner::Parts {
        store: Arc::clone(&store),
        door,
        alarm,
        tips,
        latch,
        executor: Arc::new(Executor::new(budget, sync_substrate)),
        engine: network.engine(),
        rules,
        requesting,
        declaration,
        pool: sync_pool,
        inbound,
        state: sync_state,
    }) {
        Ok(owner) => owner,
        Err(error) => {
            // The network is up and the owner is not. Stop it here: the
            // caller's unwind stops the service and the runtime, and does
            // not know a network was started.
            network.stop();
            return Err(error);
        }
    };
    install_submit(Submit {
        store,
        rules,
        pool: submit_pool,
        health: pool_health,
        relay: network.relay().clone(),
        door: nudge_door,
        departed,
        offline,
    });
    Ok(Started {
        network,
        sync_owner,
    })
}

/// The handshake's tip and the relay's reading of chain sync, each kept
/// current on `runtime` for as long as the runtime runs.
fn publish_watches(
    runtime: &shekyl_runtime::Pool,
    mut tips: tokio::sync::watch::Receiver<TipChanged>,
    mut sync: tokio::sync::watch::Receiver<SyncState>,
) -> (
    tokio::sync::watch::Receiver<CoreSyncData>,
    tokio::sync::watch::Receiver<NodeSync>,
) {
    let (tip_tx, tip) = tokio::sync::watch::channel(core_sync_data(tips.borrow_and_update().tip));
    runtime.spawn(async move {
        while tips.changed().await.is_ok() {
            let tip = tips.borrow_and_update().tip;
            tip_tx.send_replace(core_sync_data(tip));
        }
    });
    let (node_sync_tx, node_sync) =
        tokio::sync::watch::channel(node_sync_of(*sync.borrow_and_update()));
    runtime.spawn(async move {
        while sync.changed().await.is_ok() {
            let state = node_sync_of(*sync.borrow_and_update());
            node_sync_tx.send_if_modified(|current| {
                let changed = *current != state;
                *current = state;
                changed
            });
        }
    });
    (tip, node_sync)
}

/// The chain tip as the handshake and timed sync carry it
/// (`CORE_SYNC_DATA`). No tip is the empty claim: height zero, no work.
fn core_sync_data(tip: Option<shekyl_chain_ingest::ChainTip>) -> CoreSyncData {
    tip.map_or(
        CoreSyncData {
            current_height: 0,
            cumulative_difficulty: 0,
            cumulative_difficulty_top64: 0,
            top_id: [0; 32],
        },
        |tip| {
            let wide = tip.cumulative_difficulty.to_raw();
            CoreSyncData {
                current_height: tip.count.to_raw(),
                cumulative_difficulty: u64::try_from(wide & u128::from(u64::MAX))
                    .expect("masked to the low 64 bits"),
                cumulative_difficulty_top64: u64::try_from(wide >> 64)
                    .expect("a u128 shifted by 64 fits"),
                top_id: tip.top_id.to_bytes(),
            }
        },
    )
}

/// The relay owner's reading of chain sync's state: it relays what it
/// receives only while the node is `Synced`.
const fn node_sync_of(state: SyncState) -> NodeSync {
    match state {
        SyncState::Synced => NodeSync::Synchronised,
        SyncState::NoView | SyncState::Behind { .. } | SyncState::Following { .. } => {
            NodeSync::Unsynchronised
        }
    }
}

/// The submit shim's relay hook, installed for the process.
struct Submit {
    store: Arc<ChainStore>,
    rules: ChainRules,
    pool: Arc<Mutex<Pool>>,
    health: PoolHealth,
    relay: RelayHandle,
    door: Arc<NodePoolDoor>,
    departed: Departed,
    offline: bool,
}

fn install_submit(submit: Submit) {
    let Submit {
        store,
        rules,
        pool,
        health,
        relay,
        door,
        departed,
        offline,
    } = submit;
    shekyl_daemon_rpc::submit::install_production(
        shekyl_daemon_rpc::submit::RustPoolShim::new(
            shekyl_daemon_rpc::submit::StoreChain::new(store, Arc::new(crate::RulesOf(rules))),
            pool,
            shekyl_chain_rules::AdmissionPolicy::GENESIS,
            crate::wall_now,
            rules.trust().network_id(),
        )
        .retiring(Arc::new(move |fault| health.retire(fault)))
        .nudging(Arc::new(move |txid: &TxHash, blob: &[u8]| {
            // An offline node has no network to hide from, so the
            // transaction is shown at once (RX-2, Rick 2026-10-29).
            // With one, the relay owner takes it before the zone plans
            // on its strand, so `NoOwnEdge` and `AwaitSync` never reach
            // this branch: the zone holds those (`hold_origin`),
            // neither fluffed nor shown. The owner refuses only once it
            // has stopped. An empty blob is nothing to relay.
            let taken = !offline
                && !blob.is_empty()
                && relay.relay_local(TxId::from_bytes(txid.to_bytes()), blob.to_vec());
            if !taken {
                door.note_shown(*txid);
            }
        }))
        .departing(departed),
    );
}
