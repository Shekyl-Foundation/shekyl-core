// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The node's pool as the relay owner reaches it
//! (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1, "2002" and "2010").
//!
//! A received batch is admitted here: the blob is parsed and checked for
//! form, judged statelessly against the rules in force at the tip, then
//! offered to the pool under its own lock. A transaction the relay has
//! shown moves to shown in the pool, and the tip follower is told so it
//! rebuilds the posted job (`DRS_X_STORE_FLIP.md` Q9). The 2010 answer is
//! the pool's bodies the asking peer does not hold.
//!
//! Departures (an eviction at admission, a reconcile, a flush) reach the
//! relay owner through [`Departures`]: the relay owner starts after the
//! pool is wired into the ingest service, so the hook is a slot the node
//! fills once the network is up. A departure before that has nothing to
//! forget.
//!
//! The door reads the store and the pool through the node's slots, the
//! ones its stop clears. The network outlives the stop in every handle
//! that holds it (the daemon's Tor supervisor, the facts, the producer's
//! route), so a door that held the store itself would keep `chain.db`
//! open past the node. A verb on a cleared slot finds nothing: an
//! admission is a fault, a complement is empty.

use std::sync::{Arc, Mutex, PoisonError};

use shekyl_chain_ingest::ChainRules;
use shekyl_chain_rules::{AdmissionPolicy, HeaderView, Tip};
use shekyl_chain_store::store::{ChainStore, SnapshotView};
use shekyl_mempool::{stateless, Admission, Duplicate, Judged, Pool, PoolFault};
use shekyl_relay::owner::{Admit, PoolDoor, RelayHandle};
use shekyl_relay::TxId;
use shekyl_types::{TxHash, UnixSeconds};
use shekyl_wire::Transaction;
use tokio::sync::Notify;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Where departures go: the relay owner's handle, once the network starts.
#[derive(Default)]
pub(crate) struct Departures {
    relay: Mutex<Option<RelayHandle>>,
}

impl Departures {
    /// The network is up: departures reach its relay owner from here on.
    pub(crate) fn attach(&self, relay: RelayHandle) {
        *lock(&self.relay) = Some(relay);
    }

    /// Tell the relay owner `ids` left the pool.
    pub(crate) fn departed(&self, ids: &[TxHash]) {
        if ids.is_empty() {
            return;
        }
        let relay = lock(&self.relay).clone();
        if let Some(relay) = relay {
            relay.departed(
                ids.iter()
                    .map(|id| TxId::from_bytes(id.to_bytes()))
                    .collect(),
            );
        }
    }
}

/// The store slot: the node's handle while it runs, absent after its stop.
pub(crate) type StoreSlot = Arc<Mutex<Option<Arc<ChainStore>>>>;

/// The pool slot, as the handles' bridges read it.
pub(crate) type PoolSlot = Arc<Mutex<Option<Arc<Mutex<Pool>>>>>;

/// The node's pool behind the relay owner's door.
pub(crate) struct NodePoolDoor {
    store: StoreSlot,
    pool: PoolSlot,
    rules: ChainRules,
    policy: AdmissionPolicy,
    departures: Arc<Departures>,
    /// The tip follower's wake: a shown transaction rebuilds the job.
    shown: Arc<Notify>,
}

impl NodePoolDoor {
    pub(crate) fn new(
        store: StoreSlot,
        pool: PoolSlot,
        rules: ChainRules,
        policy: AdmissionPolicy,
        departures: Arc<Departures>,
        shown: Arc<Notify>,
    ) -> Self {
        Self {
            store,
            pool,
            rules,
            policy,
            departures,
            shown,
        }
    }

    /// The pool shows `id` (`Pool::fluffed`): the relay fluffed it, or saw
    /// it circulating. Idempotent; the follower is woken when the state
    /// moved. A pool-file fault is logged: the relay keeps its own record,
    /// and the pool's next write reports the fault to its health.
    pub(crate) fn note_shown(&self, id: TxHash) {
        let Some(pool) = self.pool() else {
            return;
        };
        let moved = lock(&pool).fluffed(&id);
        match moved {
            Ok(true) => self.shown.notify_one(),
            Ok(false) => {}
            Err(error) => tracing::warn!(%error, "the pool could not record a shown transaction"),
        }
    }

    /// The pool while the node runs: a clone out of the slot, so the slot
    /// lock does not span the pool's.
    fn pool(&self) -> Option<Arc<Mutex<Pool>>> {
        lock(&self.pool).clone()
    }

    fn admit_tx(&self, tx: Transaction) -> Admit {
        let id = TxId::from_bytes(tx.hash().to_bytes());
        let (Some(store), Some(pool)) = (lock(&self.store).clone(), self.pool()) else {
            return Admit::Fault;
        };
        let Ok(snap) = store.begin_read() else {
            return Admit::Fault;
        };
        let view = SnapshotView::new(&snap);
        let Ok(tip) = HeaderView::tip(&view) else {
            return Admit::Fault;
        };
        // A transaction the pool holds or the chain carries is answered
        // before its proofs run: a peer re-sending transactions this node
        // already has must not buy one verification each. The pool asks
        // again under its lock when it admits.
        match lock(&pool).duplicate(&TxHash::from_bytes(*id.as_bytes()), &view) {
            Ok(Some(_)) => return Admit::Held(id),
            Ok(None) => {}
            Err(_) => return Admit::Fault,
        }
        let height = Tip::connecting_height(tip.as_ref());
        let rule_set = self.rules.in_force(height);
        // The id the pool was opened under: this run's trust, so a
        // signature made for another network is refused before admission.
        let network = self.rules.trust().network_id();
        let prior = match stateless(&tx, &view, &rule_set, &network, None) {
            Ok(Ok(pass)) => Some(pass),
            Ok(Err(_)) => return Admit::RefusedForm,
            Err(_) => return Admit::Fault,
        };
        let outcome = lock(&pool).admit_judged(tx, prior, now(), &view, &rule_set, &self.policy);
        match outcome {
            Ok(Admission::Admitted { evicted }) => {
                self.departures.departed(&evicted);
                Admit::Admitted(id)
            }
            Ok(Admission::Duplicate(Duplicate::InPool | Duplicate::OnChain)) => Admit::Held(id),
            Ok(Admission::Refused(Judged::Stateless(_))) => Admit::RefusedForm,
            Ok(Admission::Refused(_) | Admission::PoolFull) => Admit::RefusedState(id),
            Err(PoolFault::Chain(_) | PoolFault::TipMoved { .. } | PoolFault::Store(_)) => {
                Admit::Fault
            }
        }
    }
}

impl PoolDoor for NodePoolDoor {
    fn admit(&self, blob: &[u8]) -> Admit {
        match parse(blob) {
            Some(tx) => self.admit_tx(tx),
            None => Admit::RefusedForm,
        }
    }

    fn holds(&self, tx: &TxId) -> bool {
        let id = TxHash::from_bytes(*tx.as_bytes());
        self.pool()
            .is_some_and(|pool| lock(&pool).relay_view().record(&id).is_some())
    }

    fn shown(&self, tx: &TxId) {
        self.note_shown(TxHash::from_bytes(*tx.as_bytes()));
    }

    fn complement(&self, known: &[TxId]) -> Vec<Vec<u8>> {
        let Some(pool) = self.pool() else {
            return Vec::new();
        };
        let pool = lock(&pool);
        pool.peer_sync()
            .filter(|(id, _)| !known.iter().any(|k| k.as_bytes() == &id.to_bytes()))
            .map(|(_, tx)| tx.serialize())
            .collect()
    }
}

/// The blob as a transaction this chain can admit: canonical bytes, valid
/// form, not a coinbase, no unlock time.
fn parse(blob: &[u8]) -> Option<Transaction> {
    let tx = Transaction::from_bytes(blob).ok()?;
    if tx.serialize() != blob || tx.validate().is_err() || tx.is_coinbase() {
        return None;
    }
    if tx.prefix.unlock_time != 0 {
        return None;
    }
    Some(tx)
}

fn now() -> UnixSeconds {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    UnixSeconds::from_raw(secs)
}
