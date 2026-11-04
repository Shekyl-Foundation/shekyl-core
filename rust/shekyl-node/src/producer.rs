// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle producer for a node that mines and has a Tor (`SO-D12`
//! increment 4c).
//!
//! Only a mining daemon is a witness. The producer reads each drawn pair's
//! shard through the daemon's fetch scheduler over the store's facts, and
//! the scheduler dials through this node's Tor: an operator's at its
//! `tor-socks` endpoint, or the managed one at the route its supervisor
//! publishes, read at each fetch (`TOR_SUPERVISOR.md` §4.5, `TSR-F10`). The
//! managed route appears after the node opens and moves when Tor respawns;
//! a read while there is none is a stall that retries, and nothing is sent.
//! A node with Tor off runs no producer: the templates still draw from the
//! ring, which keeps its bound, and the node says once why it files nothing.
//!
//! Only the endpoint of the operator's SOCKS row is used. The fetch client
//! presents credentials derived from each read's nonce (`SF-D3`: a fresh
//! circuit per read through `IsolateSOCKSAuth`), so a configured
//! `tor-socks-username`/`password` pair is not sent, and a proxy that
//! authenticates refuses every read.

use std::sync::Arc;

use shekyl_daemon_config::sections::DaemonConfig;

/// The bundle producer, when this node mines and has a Tor.
pub(crate) fn seat(
    config: &DaemonConfig,
    store: &Arc<shekyl_chain_store::store::ChainStore>,
    witness: &Arc<shekyl_bundle_producer::WitnessRing>,
) -> Option<shekyl_chain_ingest::bundle_producer::ProducerSeat> {
    use shekyl_archival_fetch_sched::{FetchScheduler, PFetchClient};
    use shekyl_chain_ingest::shard_facts::{StoreHolderSource, StoreShardFacts};
    let Some(tor) = tor_of(config) else {
        if config.mine.address.is_some() {
            tracing::info!(
                "the bundle producer is off: it reads through this node's Tor, and Tor is off"
            );
        }
        return None;
    };
    let timeouts = shekyl_bundle_producer::read::CHALLENGE_TIMEOUTS;
    let client = match tor {
        ProducerTor::Operator(endpoint) => PFetchClient::with_timeouts(endpoint, timeouts),
        ProducerTor::Managed => {
            PFetchClient::with_route(Arc::new(shekyl_ffi::zone_ffi::managed_socks), timeouts)
        }
    };
    let scheduler = Arc::new(FetchScheduler::new(
        Arc::new(StoreShardFacts::new(Arc::clone(store))),
        Arc::new(StoreHolderSource::new(Arc::clone(store))),
        client,
    ));
    Some(shekyl_chain_ingest::bundle_producer::ProducerSeat {
        witness: Arc::clone(witness),
        read: shekyl_chain_ingest::bundle_producer::read_through(scheduler),
        start_spread: shekyl_bundle_producer::READ_START_SPREAD,
    })
}

/// The Tor the bundle producer reads through.
enum ProducerTor {
    /// The operator's, at its `tor-socks` endpoint.
    Operator(std::net::SocketAddr),
    /// The managed one, at the route its supervisor publishes.
    Managed,
}

/// The Tor the bundle producer reads through, when this configuration runs
/// it: the node mines and has a Tor. `None` runs no producer. The one
/// decision [`seat`] and [`descriptors`] both read.
fn tor_of(config: &DaemonConfig) -> Option<ProducerTor> {
    use shekyl_daemon_config::sections::Tor;
    config.mine.address.as_ref()?;
    match &config.tor {
        Tor::Operator { socks, .. } => Some(ProducerTor::Operator(socks.endpoint)),
        Tor::Managed { .. } => Some(ProducerTor::Managed),
        Tor::Off => None,
    }
}

/// The descriptors the bundle producer can hold, for the daemon's inbound
/// ceiling: each started read holds one SOCKS stream for as long as it
/// holds a slot of the fetch client, and the producer starts at most
/// [`READS_AT_ONCE`](shekyl_bundle_producer::read::READS_AT_ONCE), the
/// client's slots. Zero when this configuration runs no producer, under
/// either Tor.
#[must_use]
pub fn descriptors(config: &DaemonConfig) -> u64 {
    if tor_of(config).is_none() {
        return 0;
    }
    // One stream per fetch slot. `READS_AT_ONCE` is the client's slot count,
    // and that count fits a descriptor count on every platform this node
    // builds for.
    u64::try_from(shekyl_bundle_producer::read::READS_AT_ONCE.get())
        .expect("READS_AT_ONCE fits a descriptor count")
}
