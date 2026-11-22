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
//!
//! **A batch that arrives while the node is not synchronised is held, not
//! dropped** ([`Behind`]). A node is not synchronised from the moment it
//! hears of a block until it has connected it, so the gap opens at every
//! block. A stem dropped in it is lost with nothing to tell its sender: the
//! sender waits out its whole embargo, the wait meant for a peer that
//! black-holes. The pool cannot judge a transaction against a chain the
//! node is still catching up to, so the batch waits for the turn to
//! synchronised and is admitted then.
//!
//! The session's `Taken` is **not** kept for a held batch. The session
//! reads one frame at a time under that permit, and the block the node is
//! waiting for may be the next frame on this very session. So the hold is
//! bounded by what it keeps instead: one 2002's worth for each session
//! ([`behind_budget`]), counted as the memory a held batch takes
//! ([`held_form`]), not its transactions' bytes alone. A notice's padding
//! is not kept and a notice with no transaction is not held. A session
//! that sends more than that while the node is behind has the excess
//! ignored, as every such batch was before.
//!
//! The turn to synchronised admits one held batch at a time
//! ([`Port::next_held`]), and each is taken from the hold under the same
//! lock and the same reading of the sync state as an arrival. A node that
//! falls behind again part-way keeps the rest, in order and still counted,
//! for the next turn. A session that closes takes with it whatever of its
//! batches has not been admitted, and a held batch the pool refuses as
//! malformed ends that session's replay with the session.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use shekyl_levin::{Command, GetTxpoolComplement, NewTransactions};
use shekyl_p2p_session::{
    CloseCause, CloseKind, DialEnd, Established, Message, RelayOwner, SessionFacts, Taken,
};
use tokio::sync::{mpsc, watch};

use super::actor::{connection_id, Cmd};
use super::pool::{Admit, PoolDoor};
use crate::graph::{NodeSync, TxBlob};
use crate::stem_watch::TxId;

/// One session's batches, received while the node was not synchronised.
struct HeldSession {
    /// The session they arrived on: their source when they are admitted.
    session: Established,
    /// In arrival order, each with its own stem or fluff flag and what it
    /// is charged.
    batches: VecDeque<(NewTransactions, usize)>,
    /// The sum of the batches' charges, against [`behind_budget`].
    charge: usize,
}

/// What arrived while the node was not synchronised, by session: keyed on
/// the socket id's number, so the turn to synchronised admits it in one
/// order on every run.
type Behind = BTreeMap<u64, HeldSession>;

/// What one session may have held while the node is not synchronised: what
/// one 2002 may carry. It is the bound the session's permit gives a
/// synchronised node, one batch in flight for each session, stated as a
/// charge because a held batch does not keep the permit. It moves with the
/// 2002's cap and is as tight as that cap is.
fn behind_budget() -> usize {
    usize::try_from(Command::NewTransactions.payload_cap()).unwrap_or(usize::MAX)
}

/// What the hold keeps for one transaction beyond its bytes: the blob's own
/// vector.
const HELD_ENTRY: usize = std::mem::size_of::<Vec<u8>>();

/// What the hold keeps for one batch beyond its transactions: the batch
/// and its charge.
const HELD_BATCH: usize = std::mem::size_of::<(NewTransactions, usize)>();

/// `batch` as the hold keeps it, with what it is charged, or `None` for a
/// batch with no transaction, which there is nothing to admit from.
///
/// The padding is dropped: nothing reads it after the frame is decoded, and
/// kept it would be memory a peer fills at no charge. The charge is the
/// memory kept, each transaction's bytes and [`HELD_ENTRY`] and the batch's
/// [`HELD_BATCH`], so that many small batches of small transactions cost
/// what they hold and not only their bytes.
fn held_form(mut batch: NewTransactions) -> Option<(NewTransactions, usize)> {
    if batch.txs.is_empty() {
        return None;
    }
    batch.padding = Vec::new();
    let charge = batch.txs.iter().fold(HELD_BATCH, |charge, blob| {
        charge.saturating_add(blob.len()).saturating_add(HELD_ENTRY)
    });
    Some((batch, charge))
}

/// The charge a session holds once a batch charged `batch` joins the `held`
/// it has, or `None` when the batch is not held.
///
/// A session that holds nothing has its batch held whatever the charge: the
/// batch came in under the 2002's cap, and one message is the bound. After
/// that a batch is held only while the whole stays within `budget`.
fn held_with(held: usize, batch: usize, budget: usize) -> Option<usize> {
    if held == 0 {
        return Some(batch);
    }
    held.checked_add(batch).filter(|total| *total <= budget)
}

/// Whether a session's held batches may follow the one just offered to the
/// pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Replay {
    /// The session stands.
    Continues,
    /// The batch held a malformed transaction and the session is closing.
    Ended,
}

/// The relay owner as the session layer holds it (`Owners::relay`).
pub struct Port {
    inbox: mpsc::UnboundedSender<Cmd>,
    pool: Arc<dyn PoolDoor>,
    node_sync: watch::Receiver<NodeSync>,
    /// Read with `node_sync` under this lock, by an arrival and by the turn
    /// to synchronised alike, so a batch is never held after the turn that
    /// would have admitted it.
    behind: Mutex<Behind>,
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
            behind: Mutex::new(Behind::new()),
        }
    }

    /// Admit what was held, each time the node turns synchronised. Runs for
    /// the life of the owner, beside its task.
    ///
    /// The pool's judgment runs here, on this task, and never on the relay
    /// task's timer path.
    pub(super) async fn admit_held_on_sync(self: Arc<Self>) {
        let mut node_sync = self.node_sync.clone();
        loop {
            // The state is read in `next_held`, under the hold's lock; this
            // only marks the change seen.
            let _seen = *node_sync.borrow_and_update();
            while let Some((session, batch)) = self.next_held() {
                if self.admit(&session, batch, None) == Replay::Ended {
                    // The session is closing on a malformed transaction:
                    // nothing more of it is offered to the pool.
                    self.behind
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&session.id().get());
                }
            }
            if node_sync.changed().await.is_err() {
                // The sync owner is gone: the daemon is stopping.
                return;
            }
        }
    }

    /// The next held batch to admit, taken from the hold, or `None` when the
    /// node is not synchronised or nothing is held.
    ///
    /// One batch for each call, with the sync state read under the hold's
    /// lock: a node that falls behind while a batch is with the pool admits
    /// no further one, and what is left stays held, in order and charged.
    /// What is left also stays where a closing session's `on_closed` finds
    /// it.
    fn next_held(&self) -> Option<(Established, NewTransactions)> {
        let mut behind = self.behind.lock().unwrap_or_else(PoisonError::into_inner);
        if *self.node_sync.borrow() != NodeSync::Synchronised {
            return None;
        }
        loop {
            let mut first = behind.first_entry()?;
            let held = first.get_mut();
            let Some((batch, charge)) = held.batches.pop_front() else {
                first.remove();
                continue;
            };
            held.charge = held.charge.saturating_sub(charge);
            let session = held.session.clone();
            if held.batches.is_empty() {
                first.remove();
            }
            return Some((session, batch));
        }
    }

    /// Keep `batch` for the turn to synchronised, if the session's hold has
    /// room for it.
    fn hold(behind: &mut Behind, session: &Established, batch: NewTransactions) {
        let id = session.id();
        let Some((batch, charge)) = held_form(batch) else {
            return;
        };
        let held = behind.entry(id.get()).or_insert_with(|| HeldSession {
            session: session.clone(),
            batches: VecDeque::new(),
            charge: 0,
        });
        let Some(total) = held_with(held.charge, charge, behind_budget()) else {
            tracing::debug!(
                ?id,
                count = batch.txs.len(),
                "transactions received while unsynchronised, past the session's hold; ignored"
            );
            return;
        };
        tracing::debug!(
            ?id,
            count = batch.txs.len(),
            "transactions received while unsynchronised; held for the turn to synchronised"
        );
        held.charge = total;
        held.batches.push_back((batch, charge));
    }

    /// Offer `batch` to the pool and hand what it admits to the relay task.
    /// `taken` is the session's permit for a batch admitted as it arrives;
    /// a held batch gave its permit back when it was held. The answer is
    /// whether the session's held batches may still follow this one.
    fn admit(&self, session: &Established, batch: NewTransactions, taken: Option<Taken>) -> Replay {
        let id = session.id();
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
        let replay = if severs {
            Replay::Ended
        } else {
            Replay::Continues
        };
        if parsed.is_empty() {
            return replay;
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
        replay
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
        {
            let mut behind = self.behind.lock().unwrap_or_else(PoisonError::into_inner);
            if *self.node_sync.borrow() == NodeSync::Unsynchronised {
                Self::hold(&mut behind, session, batch);
                // The permit goes back at once: the block this node is
                // waiting for may be this session's next frame.
                drop(taken);
                return;
            }
        }
        let _replay = self.admit(session, batch, Some(taken));
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
        self.behind
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&facts.id.get());
        self.post(Cmd::Closed(facts.id));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        behind_budget, complement_batches, held_form, held_with, COMPLEMENT_ENTRY, HELD_BATCH,
        HELD_ENTRY,
    };
    use shekyl_levin::{Command, NewTransactions};

    /// A session's hold takes batches up to its budget and no further, and
    /// the budget is what one 2002 may carry.
    /// Red edit: no bound in `held_with`.
    #[test]
    fn a_sessions_hold_ends_at_one_messages_worth() {
        assert_eq!(held_with(0, 600, 1_000), Some(600));
        assert_eq!(
            held_with(0, 1_001, 1_000),
            Some(1_001),
            "a session that holds nothing has one message held, whatever it is charged"
        );
        assert_eq!(
            held_with(600, 400, 1_000),
            Some(1_000),
            "the budget itself fits"
        );
        assert_eq!(
            held_with(600, 401, 1_000),
            None,
            "one byte past it does not"
        );
        assert_eq!(held_with(usize::MAX, 1, usize::MAX), None, "no wrap");
        assert_eq!(
            u64::try_from(behind_budget()).expect("fits"),
            Command::NewTransactions.payload_cap()
        );
    }

    /// A held batch is charged what the hold keeps, not its transactions'
    /// bytes alone; its padding is not kept; a batch with no transaction is
    /// not held. Without each, a peer fills the hold of a node that is
    /// behind at no charge: padded notices with no transaction, or many
    /// batches of one small transaction.
    /// Red edit: charge the transactions' bytes alone, keep the padding, or
    /// hold the empty batch.
    #[test]
    fn a_held_batch_is_charged_what_it_keeps_and_keeps_no_padding() {
        assert!(
            held_form(NewTransactions {
                txs: Vec::new(),
                padding: vec![0; 4096],
                dandelionpp_fluff: false,
            })
            .is_none(),
            "a padded notice with no transaction is not held"
        );
        let (kept, charge) = held_form(NewTransactions {
            txs: vec![vec![1], vec![2, 3]],
            padding: vec![0; 4096],
            dandelionpp_fluff: false,
        })
        .expect("held");
        assert_eq!(kept.txs, vec![vec![1], vec![2, 3]]);
        assert!(!kept.dandelionpp_fluff, "the flag is kept");
        assert!(kept.padding.is_empty());
        assert_eq!(kept.padding.capacity(), 0, "the padding's memory is gone");
        assert_eq!(charge, HELD_BATCH + 2 * HELD_ENTRY + 3);
        // One-byte transactions, one to a batch: the budget ends them at
        // the memory they take.
        let each = HELD_BATCH + HELD_ENTRY + 1;
        let budget = 10 * each;
        let mut held = 0;
        let mut taken = 0;
        while let Some(total) = held_with(held, each, budget) {
            held = total;
            taken += 1;
        }
        assert_eq!(taken, 10);
    }

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
