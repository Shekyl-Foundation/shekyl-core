// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The peers owner as the network runs it: the one [`Dialer`] over the
//! peer lists, its address file, the operator's and the compiled seeds,
//! and one owner loop per connector on a dedicated thread of the ledger.

use std::path::Path;
use std::sync::{Arc, Mutex};

use shekyl_dialer::{seeds, Dialer, LoadError, SeedNetwork};
use shekyl_peerlist::{NetworkAddress, Peerlist};
use shekyl_relay::owner::SecureRelayRng;
use shekyl_thread_ledger::{spawn_dedicated, DedicatedThread, ThreadName};
use shekyl_timing_engine::{EngineError, Handle, MonotonicClock, OwnerClass};
use shekyl_transport_layer::ConnectorId;

use crate::plan::PeerPlan;

pub(crate) type Peers = Arc<Dialer<MonotonicClock>>;

/// The owner loops' threads, joined at stop.
pub(crate) struct OwnerLoops {
    threads: Mutex<[Option<DedicatedThread>; ConnectorId::COUNT]>,
}

impl OwnerLoops {
    pub(crate) fn new() -> Self {
        Self {
            threads: Mutex::new([const { None }; ConnectorId::COUNT]),
        }
    }

    /// Start `connector`'s owner loop: claim the connector, register its
    /// wake with the engine, admit the compiled seeds, and run the loop on
    /// a dedicated thread. `false` when the loop is already running or
    /// could not start; nothing is half-started then.
    pub(crate) fn start(
        &self,
        dialer: &Peers,
        connector: ConnectorId,
        engine: &Handle<MonotonicClock>,
        seeds_of: SeedNetwork,
    ) -> bool {
        if !dialer.claim_owner(connector) {
            tracing::debug!("{connector:?} already has its owner loop; not started again");
            return false;
        }
        let owner = match engine.register(OwnerClass::Discovery) {
            Ok(owner) => owner,
            Err(err) => {
                tracing::error!("the dialer's wake for {connector:?} could not register: {err:?}");
                dialer.release_owner(connector);
                return false;
            }
        };
        admit_compiled_seeds(dialer, connector, seeds_of);
        let name = match ThreadName::new(&format!("p2p-dial-{connector:?}").to_lowercase()) {
            Ok(name) => name,
            Err(err) => {
                tracing::error!("the dialer's thread for {connector:?} has no name: {err:?}");
                dialer.release_owner(connector);
                return false;
            }
        };
        let running = Arc::clone(dialer);
        let spawned = spawn_dedicated(&name, move || {
            running.run(connector, &owner, &mut SecureRelayRng);
            if let Err(err) = owner.deregister() {
                // The engine closes at shutdown and drops every owner. That
                // is the loop's expected end, not a failure of the
                // deregister.
                if err == EngineError::Closed {
                    tracing::debug!(
                        "{connector:?}: the dialer's wake ended because the engine closed"
                    );
                } else {
                    tracing::warn!("{connector:?}: the dialer's wake did not deregister: {err:?}");
                }
            }
        });
        match spawned {
            Ok(thread) => {
                self.threads.lock().expect("dialer loops")[connector.index()] = Some(thread);
                true
            }
            Err(err) => {
                tracing::error!("the dialer's thread for {connector:?} could not start: {err}");
                dialer.release_owner(connector);
                false
            }
        }
    }

    /// Stop the dialer and join every loop. The dialer's own stop runs
    /// first, so the loops see it and return; the join is inside its stop
    /// so the in-flight attempts are abandoned before the threads end.
    pub(crate) fn stop(&self, dialer: &Peers) {
        let loops = std::mem::replace(
            &mut *self.threads.lock().expect("dialer loops"),
            [const { None }; ConnectorId::COUNT],
        );
        dialer.stop_joining(move || {
            for (connector, running) in ConnectorId::ALL.iter().zip(loops) {
                if let Some(mut running) = running {
                    if running.join().is_err() {
                        tracing::warn!("{connector:?}: the dialer's owner loop panicked");
                    }
                }
            }
        });
    }
}

/// The compiled seeds for `connector`, admitted as operator addresses.
fn admit_compiled_seeds(dialer: &Peers, connector: ConnectorId, seeds_of: SeedNetwork) {
    let now = dialer.now();
    for seed in seeds(seeds_of) {
        if Peerlist::connector_of(&seed) != Some(connector) {
            continue;
        }
        if let Err(refusal) = dialer.admit_operator(&seed, now, &mut SecureRelayRng) {
            tracing::warn!("{connector:?}: seed {seed:?} was not admitted: {refusal:?}");
        }
    }
}

/// Apply the plan's peer inputs to a dialer that has its lists: the
/// address file, then the operator's peers, the exclusive set, and the
/// early-disclosure lever.
pub(crate) fn apply(dialer: &Peers, plan: &PeerPlan) {
    open_file(dialer, &plan.address_file);
    let now = dialer.now();
    for address in &plan.operator {
        if let Err(refusal) = dialer.admit_operator(address, now, &mut SecureRelayRng) {
            tracing::warn!("operator peer {address:?} was not admitted: {refusal:?}");
        }
    }
    if !plan.exclusive.is_empty() {
        dialer.set_exclusive(plan.exclusive.clone(), now, &mut SecureRelayRng);
    }
    if plan.disclose_early {
        dialer.set_disclose_early(now);
    }
}

/// The address file: what it held enters gray, or why it did not.
fn open_file(dialer: &Peers, path: &Path) {
    match dialer.open_address_file(path.to_path_buf(), &mut SecureRelayRng) {
        Ok(count) => tracing::info!("{count} address(es) from {} entered gray", path.display()),
        Err(LoadError::Dropped(why)) => tracing::warn!(
            "{} is not an address file this build reads ({why:?}); dropped whole, replaced at \
             the next store",
            path.display()
        ),
        Err(LoadError::Io(err)) => tracing::warn!(
            "{} could not be read ({err}); the lists start empty",
            path.display()
        ),
    }
}

/// This node's own Tor address, once the daemon publishes its onion.
pub(crate) fn note_own_onion(dialer: &Peers, service_id: &str, virtual_port: u16) {
    dialer.set_own_addresses(
        ConnectorId::Tor,
        vec![NetworkAddress::Tor {
            host: format!("{service_id}.onion"),
            port: virtual_port,
        }],
    );
}
