// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The node's one fetch scheduler, and the bundle producer that reads
//! through it when this node mines (`SO-D12` increment 4c, IG-Q90).
//!
//! A node with a Tor builds one scheduler over the store's facts. Its
//! client dials through this node's Tor: an operator's at its `tor-socks`
//! endpoint, or the managed one at the route its supervisor publishes,
//! read at each fetch (`TOR_SUPERVISOR.md` §4.5, `TSR-F10`). The managed
//! route appears after the node opens and moves when Tor respawns; a read
//! while there is none is a stall that retries, and nothing is sent.
//!
//! The client carries two lanes. Only a mining daemon is a witness: its
//! producer reads each drawn pair's shard and starts at most
//! [`READS_AT_ONCE`] reads. The shard view's flights hold at most
//! [`VIEW_SLOTS`]. The client has exactly the slots its lanes use, so a
//! started producer read never waits behind a view. A node with Tor off
//! builds no scheduler: no producer runs (the templates still draw from
//! the ring, which keeps its bound, and the node says once why it files
//! nothing), and `shard_fetch` refuses as Tor off.
//!
//! Only the endpoint of the operator's SOCKS row is used. The fetch client
//! presents credentials derived from each read's nonce (`SF-D3`: a fresh
//! circuit per read through `IsolateSOCKSAuth`), so a configured
//! `tor-socks-username`/`password` pair is not sent, and a proxy that
//! authenticates refuses every read.

use std::num::NonZeroUsize;
use std::sync::Arc;

use shekyl_archival_fetch_sched::{FetchScheduler, NeedBudget, ViewDesk, VIEW_SLOTS};
use shekyl_bundle_producer::read::READS_AT_ONCE;
use shekyl_chain_ingest::shard_facts::{StoreHolderSource, StoreShardFacts};
use shekyl_daemon_config::sections::DaemonConfig;
use shekyl_daemon_rpc::shard_view::{ShardViewHandle, TorOff};

/// The node's fetch scheduler.
pub(crate) type Scheduler = FetchScheduler<StoreShardFacts, StoreHolderSource>;

/// A mining node's client: the producer's reads and the view lane.
const MINING_SLOTS: NonZeroUsize = match READS_AT_ONCE.checked_add(VIEW_SLOTS.get()) {
    Some(slots) => slots,
    None => panic!("the fetch client's slots fit a usize"),
};

/// The node's one fetch scheduler, when it runs a Tor.
pub(crate) fn scheduler(
    config: &DaemonConfig,
    store: &Arc<shekyl_chain_store::store::ChainStore>,
    network: Arc<std::sync::OnceLock<shekyl_p2p::Network>>,
) -> Option<Arc<Scheduler>> {
    use shekyl_archival_fetch_sched::PFetchClient;
    let tor = tor_of(config)?;
    let timeouts = shekyl_bundle_producer::read::CHALLENGE_TIMEOUTS;
    let client = match tor {
        FetchTor::Operator(endpoint) => PFetchClient::with_timeouts(endpoint, timeouts),
        FetchTor::Managed => PFetchClient::with_route(
            // The managed route is read at use: the network starts after
            // the scheduler is built, and the route moves with the
            // supervisor's incarnation.
            Arc::new(move || network.get().and_then(shekyl_p2p::Network::managed_socks)),
            timeouts,
        ),
    };
    Some(Arc::new(FetchScheduler::new(
        Arc::new(StoreShardFacts::new(Arc::clone(store))),
        Arc::new(StoreHolderSource::new(Arc::clone(store))),
        client.with_slots(client_slots(config)),
    )))
}

/// The bundle producer, when this node mines and has a Tor.
pub(crate) fn seat(
    config: &DaemonConfig,
    scheduler: Option<&Arc<Scheduler>>,
    witness: &Arc<shekyl_bundle_producer::WitnessRing>,
) -> Option<shekyl_chain_ingest::bundle_producer::ProducerSeat> {
    config.mine.address.as_ref()?;
    let Some(scheduler) = scheduler else {
        tracing::info!(
            "the bundle producer is off: it reads through this node's Tor, and Tor is off"
        );
        return None;
    };
    Some(shekyl_chain_ingest::bundle_producer::ProducerSeat {
        witness: Arc::clone(witness),
        read: shekyl_chain_ingest::bundle_producer::read_through(Arc::clone(scheduler)),
        start_spread: shekyl_bundle_producer::READ_START_SPREAD,
    })
}

/// What `shard_fetch` reads: a view desk over the scheduler, or the Tor-off
/// refusal when there is none (IG-Q90).
pub(crate) fn shard_view(scheduler: Option<&Arc<Scheduler>>) -> ShardViewHandle {
    match scheduler {
        Some(scheduler) => Arc::new(crate::shard_view::DeskViewFacts::new(ViewDesk::new(
            Arc::clone(scheduler),
            NeedBudget::DEFAULT,
        ))),
        None => Arc::new(TorOff),
    }
}

/// The Tor the fetch client reads through.
enum FetchTor {
    /// The operator's, at its `tor-socks` endpoint.
    Operator(std::net::SocketAddr),
    /// The managed one, at the route its supervisor publishes.
    Managed,
}

/// The Tor the fetch client reads through. `None` builds no scheduler.
/// The one decision [`scheduler`] and [`descriptors`] both read.
fn tor_of(config: &DaemonConfig) -> Option<FetchTor> {
    use shekyl_daemon_config::sections::Tor;
    match &config.tor {
        Tor::Operator { socks, .. } => Some(FetchTor::Operator(socks.endpoint)),
        Tor::Managed { .. } => Some(FetchTor::Managed),
        Tor::Off => None,
    }
}

/// The client's slots: the view lane, and the producer's reads when this
/// node mines.
fn client_slots(config: &DaemonConfig) -> NonZeroUsize {
    if config.mine.address.is_some() {
        MINING_SLOTS
    } else {
        VIEW_SLOTS
    }
}

/// The descriptors the fetch client can hold, for the daemon's inbound
/// ceiling: one SOCKS stream per slot, and the client has exactly the slots
/// its lanes use (the producer's [`READS_AT_ONCE`] when this node mines,
/// and the view lane's [`VIEW_SLOTS`]). Zero when Tor is off, under which no
/// scheduler is built.
#[must_use]
pub fn descriptors(config: &DaemonConfig) -> u64 {
    if tor_of(config).is_none() {
        return 0;
    }
    // A slot count fits a descriptor count on every platform this node
    // builds for.
    u64::try_from(client_slots(config).get()).expect("the client's slots fit a descriptor count")
}
