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

use shekyl_levin::{Command, GetTxpoolComplement, NewTransactions};
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

/// The payload bytes one complement batch may hold: the 2002 cap less
/// room for the envelope (the padding and flag keys, the array's own
/// header) and a length prefix per entry, which [`complement_batches`]
/// charges separately.
fn complement_budget() -> usize {
    usize::try_from(Command::NewTransactions.payload_cap())
        .unwrap_or(usize::MAX)
        .saturating_sub(COMPLEMENT_ENVELOPE)
}

/// Headroom for a 2002's envelope, well above what portable storage
/// writes around the array.
const COMPLEMENT_ENVELOPE: usize = 1024;

/// What one entry costs beyond its bytes: a portable-storage length
/// prefix is at most 9 bytes.
const COMPLEMENT_ENTRY: usize = 9;

/// `txs` in order, as batches whose bytes and prefixes fit `budget`; at
/// least one, so an empty complement is still answered with an empty
/// 2002. A blob too large for a batch of its own is left out: no 2002 can
/// carry it, and a transaction that size is not one consensus admits.
fn complement_batches(txs: Vec<Vec<u8>>, budget: usize) -> Vec<Vec<Vec<u8>>> {
    let mut batches = Vec::new();
    let mut batch = Vec::new();
    let mut used = 0usize;
    for tx in txs {
        let cost = tx.len().saturating_add(COMPLEMENT_ENTRY);
        if cost > budget {
            continue;
        }
        if used.saturating_add(cost) > budget {
            batches.push(std::mem::take(&mut batch));
            used = 0;
        }
        used += cost;
        batch.push(tx);
    }
    if !batch.is_empty() || batches.is_empty() {
        batches.push(batch);
    }
    batches
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
            txs = TxId::measured_list(&admitted).as_deref(),
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
        // A pool can hold more than one 2002 may carry, so the complement
        // goes as batches under the cap. The flag is left at the inherited
        // reply's value: the C++ handler never set it, and the field
        // zero-initialises to false (stem).
        for txs in complement_batches(txs, complement_budget()) {
            let reply = Message::NewTransactions(NewTransactions {
                txs,
                padding: Vec::new(),
                dandelionpp_fluff: false,
            });
            if let Err(refused) = session.send(&reply) {
                tracing::debug!(id = ?session.id(), %refused, "the pool complement was not sent");
                return;
            }
        }
    }

    fn on_established(&self, session: &Established) {
        self.post(Cmd::Established(session.clone()));
    }

    fn on_closed(&self, facts: &SessionFacts, _end: DialEnd) {
        self.post(Cmd::Closed(facts.id));
    }
}

#[cfg(test)]
mod tests {
    use super::{complement_batches, COMPLEMENT_ENTRY};

    #[test]
    fn an_empty_complement_is_one_empty_batch() {
        assert_eq!(
            complement_batches(Vec::new(), 1024),
            vec![Vec::<Vec<u8>>::new()]
        );
    }

    /// Every transaction once, in order, and no batch over the budget.
    #[test]
    fn a_complement_over_the_budget_is_split_in_order() {
        let txs: Vec<Vec<u8>> = (0..10u8).map(|n| vec![n; 100]).collect();
        let budget = 3 * (100 + COMPLEMENT_ENTRY);
        let batches = complement_batches(txs.clone(), budget);
        assert_eq!(batches.len(), 4, "3 + 3 + 3 + 1");
        for batch in &batches {
            let used: usize = batch.iter().map(|tx| tx.len() + COMPLEMENT_ENTRY).sum();
            assert!(used <= budget, "a batch of {used} bytes over {budget}");
        }
        assert_eq!(batches.concat(), txs);
    }

    #[test]
    fn a_blob_no_batch_can_carry_is_left_out() {
        let txs = vec![vec![1u8; 10], vec![2u8; 5000], vec![3u8; 10]];
        let batches = complement_batches(txs, 1000);
        assert_eq!(batches, vec![vec![vec![1u8; 10], vec![3u8; 10]]]);
    }
}
