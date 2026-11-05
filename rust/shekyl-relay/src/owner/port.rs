// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owner's seat: the session layer's `RelayOwner`, called from each
//! session's own task.
//!
//! A 2002 batch is admitted here, on the session's task, with the
//! session's `Taken` held: the pool work is the backpressure the brief
//! names (§2 rule 6), one batch per session in flight, and the session
//! reads its next frame when the relay task has taken the arrival into
//! the zone. A 2010 is answered here from the pool and the `Taken` drops
//! with the reply queued. Everything that touches zone state goes to the
//! task as a [`Cmd`].

use std::collections::HashSet;
use std::sync::Arc;

use shekyl_levin::{GetTxpoolComplement, NewTransactions};
use shekyl_p2p_session::{
    CloseCause, CloseKind, DialEnd, Established, Message, RelayOwner, SessionFacts, Taken,
};
use tokio::sync::{mpsc, watch};

use super::actor::{connection_id, Cmd};
use super::pool::{Admit, PoolDoor};
use crate::graph::{NodeSync, TxBlob};
use crate::stem_watch::TxId;

/// The relay owner as the session layer holds it (`Owners::relay`).
pub struct Port {
    inbox: mpsc::UnboundedSender<Cmd>,
    pool: Arc<dyn PoolDoor>,
    node_sync: watch::Receiver<NodeSync>,
}

impl std::fmt::Debug for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Port")
            .field("node_sync", &*self.node_sync.borrow())
            .finish_non_exhaustive()
    }
}

impl Port {
    pub(super) fn new(
        inbox: mpsc::UnboundedSender<Cmd>,
        pool: Arc<dyn PoolDoor>,
        node_sync: watch::Receiver<NodeSync>,
    ) -> Self {
        Self {
            inbox,
            pool,
            node_sync,
        }
    }

    fn post(&self, cmd: Cmd) {
        // The task has ended: the daemon is stopping on that end, and the
        // session layer closes with it.
        let _gone = self.inbox.send(cmd);
    }
}

impl RelayOwner for Port {
    fn new_transactions(&self, session: &Established, batch: NewTransactions, taken: Taken) {
        let id = session.id();
        let mut seen = HashSet::with_capacity(batch.txs.len());
        if !batch.txs.iter().all(|blob| seen.insert(blob.as_slice())) {
            // A batch that repeats a transaction is not a relay's; the
            // inherited handler dropped the connection for it.
            tracing::debug!(
                ?id,
                "a transaction batch repeated a blob; closing the session"
            );
            session.close(CloseCause::new(CloseKind::SessionRefused));
            return;
        }
        drop(seen);
        if *self.node_sync.borrow() == NodeSync::Unsynchronised {
            tracing::debug!(
                ?id,
                count = batch.txs.len(),
                "transactions received while unsynchronised; ignored"
            );
            return;
        }
        let fluff = batch.dandelionpp_fluff;
        let mut parsed = Vec::with_capacity(batch.txs.len());
        let mut to_stem = Vec::new();
        let mut to_fluff = Vec::new();
        let mut severs = false;
        for blob in batch.txs {
            match self.pool.admit(&blob) {
                Admit::Admitted(tx) => {
                    parsed.push(tx);
                    let blob: TxBlob = blob.into();
                    if fluff {
                        to_fluff.push((tx, blob));
                    } else {
                        to_stem.push((tx, blob));
                    }
                }
                Admit::Held(tx) | Admit::RefusedState(tx) => parsed.push(tx),
                Admit::RefusedForm => {
                    severs = true;
                    break;
                }
                Admit::Fault => {
                    tracing::error!(?id, "the pool could not judge a received transaction");
                }
            }
        }
        if severs {
            tracing::debug!(
                ?id,
                "a received transaction was malformed; closing the session"
            );
            session.close(CloseCause::new(CloseKind::SessionRefused));
        }
        if parsed.is_empty() {
            return;
        }
        let admitted: Vec<TxId> = to_stem
            .iter()
            .chain(to_fluff.iter())
            .map(|(tx, _)| *tx)
            .collect();
        tracing::debug!(
            ?id,
            fluff,
            admitted = admitted.len(),
            known = parsed.len() - admitted.len(),
            txs = %TxId::short_list(&admitted),
            "transactions received"
        );
        self.post(Cmd::Arrived {
            source: connection_id(id),
            parsed,
            stem: to_stem,
            fluff: to_fluff,
            taken,
        });
    }

    fn txpool_complement(
        &self,
        session: &Established,
        request: GetTxpoolComplement,
        _taken: Taken,
    ) {
        let known: Vec<TxId> = request.hashes.into_iter().map(TxId::from_bytes).collect();
        let txs = self.pool.complement(&known);
        // The flag is left at the inherited reply's value: the C++ handler
        // never set it, and the field zero-initialises to false (stem).
        let reply = Message::NewTransactions(NewTransactions {
            txs,
            padding: Vec::new(),
            dandelionpp_fluff: false,
        });
        if let Err(refused) = session.send(&reply) {
            tracing::debug!(id = ?session.id(), %refused, "the pool complement was not sent");
        }
    }

    fn on_established(&self, session: &Established) {
        self.post(Cmd::Established(session.clone()));
    }

    fn on_closed(&self, facts: &SessionFacts, _end: DialEnd) {
        self.post(Cmd::Closed(facts.id));
    }
}
