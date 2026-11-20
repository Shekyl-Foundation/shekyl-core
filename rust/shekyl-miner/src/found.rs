// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The found-block mailbox.
//!
//! The miner holds [`FoundBlocks`] and delivers what a worker finds. The
//! sink holds [`FoundInbox`] and answers each block with
//! [`FoundInbox::answer_with`]: the door runs inside that call, and the
//! answer is recorded when the door returns. The service holds a
//! [`FoundClose`] for shutdown. That handle ends the inbox and is not a
//! receiver, so the sink's thread is the receiver whose exit ends a wait.
//! The last sender dropping ends the receive too, which is a miner stopping
//! on its own and disconnecting the sink. The last receiver dropping closes
//! the mailbox, so a later deliver refuses and nothing queued is kept.
//!
//! [`FoundBlocks::answered`] waits until every block delivered before the
//! call has been through `answer_with`. It also returns when that last
//! receiver drops. A closer that is still held does not keep the wait
//! parked. A caller that stopped the miner reads the chain after that
//! wait, and not while a block the miner found is still inside the door.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use shekyl_types::{BlockHeight, PowHash};
use shekyl_wire::Block;

use crate::job::Generation;

/// A block the search found: the job's block with the nonce that meets its
/// difficulty, the height it was mined for, the job's generation, and the
/// longhash the worker computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The mined block.
    pub block: Block,
    /// The height it connects at.
    pub height: BlockHeight,
    /// The job it was mined from.
    pub generation: Generation,
    /// Its longhash under the job's seed.
    pub pow: PowHash,
}

struct Mail {
    queue: VecDeque<Found>,
    /// The service has stopped. Receivers drain what was already delivered,
    /// then see the end. A later [`FoundBlocks::deliver`] refuses.
    closed: bool,
    /// Live [`FoundBlocks`] clones. Zero is the miner disconnecting: the
    /// same end as [`FoundInbox::close`], once the queue is empty.
    senders: usize,
    /// Live [`FoundInbox`] clones. Zero closes the mailbox. Nothing can
    /// receive, so the queue is dropped and a later deliver refuses.
    /// A [`FoundClose`] is not one of these: shutdown holds it and it
    /// never receives.
    receivers: usize,
    /// Blocks [`FoundBlocks::deliver`] accepted.
    delivered: u64,
    /// Blocks [`FoundInbox::answer_with`] has recorded, after the door
    /// returned. Never above `delivered`.
    answered: u64,
}

struct Shared {
    mail: Mutex<Mail>,
    arrived: Condvar,
    /// Woken when `answered` moves, and when the last receiver drops.
    settled: Condvar,
}

fn lock(shared: &Shared) -> MutexGuard<'_, Mail> {
    shared.mail.lock().unwrap_or_else(PoisonError::into_inner)
}

fn ended(mail: &Mail) -> bool {
    mail.closed || mail.senders == 0
}

/// The sending end. Cloning counts a sender. Dropping the last one ends
/// [`FoundInbox::recv`] once nothing is queued.
pub struct FoundBlocks {
    shared: Arc<Shared>,
}

impl fmt::Debug for FoundBlocks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FoundBlocks")
    }
}

impl Clone for FoundBlocks {
    fn clone(&self) -> Self {
        lock(&self.shared).senders += 1;
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl Drop for FoundBlocks {
    fn drop(&mut self) {
        let mut mail = lock(&self.shared);
        mail.senders = mail
            .senders
            .checked_sub(1)
            .expect("each sender is dropped once");
        if mail.senders == 0 {
            self.shared.arrived.notify_all();
        }
    }
}

impl FoundBlocks {
    /// Deliver `found`. `false` when the inbox is closed: the service has
    /// stopped, or the last inbox has been dropped, and nothing will
    /// connect the block.
    #[must_use]
    pub fn deliver(&self, found: Found) -> bool {
        let mut mail = lock(&self.shared);
        if mail.closed {
            return false;
        }
        mail.queue.push_back(found);
        mail.delivered += 1;
        self.shared.arrived.notify_one();
        true
    }

    /// Wait until every block delivered before this call has its answer
    /// ([`FoundInbox::answer_with`]). Returns at once when nothing is owed.
    /// Returns too when the last receiver has dropped: nothing will answer
    /// what was queued. A [`FoundClose`] still held does not keep this
    /// parked, because a closer does not receive.
    ///
    /// Blocking. A block delivered while this waits is not waited for: the
    /// caller that wants none stops the miner first, and a stopped miner
    /// delivers nothing ([`JobBoard`](crate::JobBoard)'s claim).
    pub fn answered(&self) {
        self.answered_observing(|| {});
    }

    /// [`answered`](Self::answered). When a reply is still owed, `on_park`
    /// runs once under the mailbox lock, immediately before this thread
    /// waits. The door records its reply under that same lock, so a signal
    /// sent from `on_park` is ordered before any reply that was not already
    /// recorded. `on_park` must not take the mailbox lock.
    pub fn answered_observing(&self, mut on_park: impl FnMut()) {
        let mut mail = lock(&self.shared);
        let owed = mail.delivered;
        let mut parked = false;
        while mail.answered < owed && mail.receivers > 0 {
            if !parked {
                on_park();
                parked = true;
            }
            mail = self
                .shared
                .settled
                .wait(mail)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// Ends the inbox without receiving. The service holds one so shutdown can
/// [`close`](FoundClose::close) the sink while a sender still lives.
/// Dropping it leaves the mailbox open: it is not a receiver, and it does
/// not keep [`FoundBlocks::answered`] parked.
pub struct FoundClose {
    shared: Arc<Shared>,
}

impl fmt::Debug for FoundClose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FoundClose")
    }
}

impl FoundClose {
    /// End the inbox. Receivers drain what was already delivered and then
    /// see [`FoundInbox::recv`] return `None`. A later deliver refuses.
    pub fn close(&self) {
        close_mail(&self.shared);
    }
}

fn close_mail(shared: &Shared) {
    let mut mail = lock(shared);
    mail.closed = true;
    shared.arrived.notify_all();
}

/// The receiving end. Cloning counts a receiver of the same inbox.
/// Dropping the last one closes the mailbox.
pub struct FoundInbox {
    shared: Arc<Shared>,
}

impl Clone for FoundInbox {
    fn clone(&self) -> Self {
        lock(&self.shared).receivers += 1;
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl Drop for FoundInbox {
    fn drop(&mut self) {
        let mut mail = lock(&self.shared);
        mail.receivers = mail
            .receivers
            .checked_sub(1)
            .expect("each inbox is dropped once");
        if mail.receivers == 0 {
            // No receiver remains to drain, unlike [`FoundInbox::close`].
            mail.closed = true;
            mail.queue.clear();
            self.shared.arrived.notify_all();
            self.shared.settled.notify_all();
        }
    }
}

impl fmt::Debug for FoundInbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FoundInbox")
    }
}

/// [`FoundInbox::recv_timeout`] returned no block. The wait ran out, or
/// the inbox had already ended with nothing left queued.
#[derive(Debug)]
pub struct FoundWait;

impl fmt::Display for FoundWait {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the found-block inbox has nothing queued")
    }
}

impl std::error::Error for FoundWait {}

impl FoundInbox {
    /// The next block. `None` when the inbox is closed, or every sender has
    /// dropped, and the queue is empty. Blocks already delivered are
    /// returned first.
    #[must_use]
    pub fn recv(&self) -> Option<Found> {
        let mut mail = lock(&self.shared);
        loop {
            if let Some(found) = mail.queue.pop_front() {
                return Some(found);
            }
            if ended(&mail) {
                return None;
            }
            mail = self
                .shared
                .arrived
                .wait(mail)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// [`recv`](Self::recv) bounded by `timeout`.
    ///
    /// # Errors
    ///
    /// [`FoundWait`]: the wait ran out, or the inbox ended with nothing queued.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Found, FoundWait> {
        let deadline = Instant::now() + timeout;
        let mut mail = lock(&self.shared);
        loop {
            if let Some(found) = mail.queue.pop_front() {
                return Ok(found);
            }
            if ended(&mail) {
                return Err(FoundWait);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(FoundWait);
            }
            mail = self
                .shared
                .arrived
                .wait_timeout(mail, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// A [`FoundClose`] for this inbox. Shutdown holds it and calls
    /// [`FoundClose::close`]. The handle is not a receiver.
    #[must_use]
    pub fn close_handle(&self) -> FoundClose {
        FoundClose {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Take the next block, run `reply`, then record that the door has
    /// answered. [`FoundBlocks::answered`] stays parked for this block
    /// until `reply` returns. `None` when the inbox has ended and nothing
    /// is queued: `reply` does not run, and nothing is recorded.
    ///
    /// A panic in `reply` records nothing. The receiver's drop ends the
    /// wait then. A closer still held does not keep it parked.
    ///
    /// # Panics
    ///
    /// When more blocks are recorded than were delivered.
    #[must_use]
    pub fn answer_with<T>(&self, reply: impl FnOnce(Found) -> T) -> Option<T> {
        let found = self.recv()?;
        let answered = reply(found);
        self.record_reply();
        Some(answered)
    }

    /// The door has returned for one block [`recv`](Self::recv) already
    /// took. One record per delivered block.
    fn record_reply(&self) {
        let mut mail = lock(&self.shared);
        assert!(
            mail.answered < mail.delivered,
            "a found block is answered once, after the door returns"
        );
        mail.answered += 1;
        self.shared.settled.notify_all();
    }

    /// End the inbox. Receivers drain the queue and then see [`recv`](Self::recv)
    /// return `None`, whether or not a sender still lives. A deliver after
    /// this returns `false`. [`FoundClose::close`] is this same close, on
    /// a handle that does not receive.
    pub fn close(&self) {
        close_mail(&self.shared);
    }
}

/// A found-block mailbox: the end the miner sends on, and the end the
/// ingest service receives from.
#[must_use]
pub fn found_blocks() -> (FoundBlocks, FoundInbox) {
    let shared = Arc::new(Shared {
        mail: Mutex::new(Mail {
            queue: VecDeque::new(),
            closed: false,
            senders: 1,
            receivers: 1,
            delivered: 0,
            answered: 0,
        }),
        arrived: Condvar::new(),
        settled: Condvar::new(),
    });
    (
        FoundBlocks {
            shared: Arc::clone(&shared),
        },
        FoundInbox { shared },
    )
}

#[cfg(test)]
mod tests {
    use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, PowHash, SectionRoot};
    use shekyl_wire::transaction::{Ct, CtBase, Input, TxPrefix};
    use shekyl_wire::{Block, BlockHeader, Transaction};

    use std::sync::mpsc;
    use std::time::Duration;

    use super::found_blocks;
    use crate::job::Generation;
    use crate::Found;

    fn found_at(nonce: u32) -> Found {
        Found {
            block: Block {
                header: BlockHeader {
                    major_version: 1,
                    minor_version: 0,
                    timestamp: 1,
                    previous: BlockHash::from_bytes([0x11; 32]),
                    nonce,
                    curve_tree_root: CurveTreeRoot::from_bytes([0x22; 32]),
                    section_root: SectionRoot::from_bytes([0x33; 32]),
                },
                miner_transaction: Transaction {
                    prefix: TxPrefix {
                        unlock_time: TxPrefix::NO_UNLOCK_TIME,
                        inputs: vec![Input::Gen(7)],
                        outputs: Vec::new(),
                        extra: Vec::new(),
                    },
                    ct: Ct::Null(CtBase {
                        enc_amounts: Vec::new(),
                        enc_labels: Vec::new(),
                        commitments: Vec::new(),
                    }),
                },
                transaction_hashes: Vec::new(),
            },
            height: BlockHeight::from_raw(1),
            generation: Generation::from_raw(1),
            pow: PowHash::from_bytes([0x44; 32]),
        }
    }

    #[test]
    fn close_ends_recv_while_a_sender_lives() {
        let (_sender, inbox) = found_blocks();
        inbox.close();
        assert!(inbox.recv().is_none());
    }

    #[test]
    fn the_last_sender_dropping_ends_recv() {
        let (sender, inbox) = found_blocks();
        let held = sender.clone();
        drop(sender);
        let waiting = std::thread::spawn(move || inbox.recv());
        drop(held);
        assert!(waiting.join().expect("recv").is_none());
    }

    #[test]
    fn a_remaining_inbox_receives_and_the_last_drop_refuses_delivery() {
        let (sender, inbox) = found_blocks();
        let kept = inbox.clone();
        drop(inbox);
        let found = found_at(1);
        assert!(sender.deliver(found.clone()));
        assert_eq!(kept.recv(), Some(found));
        drop(kept);
        assert!(!sender.deliver(found_at(2)));
    }

    /// [`FoundBlocks::answered`] returns at once when nothing has been
    /// delivered, and otherwise only once [`FoundInbox::answer_with`]'s
    /// closure has returned. Received is not answered.
    ///
    /// The park signal is sent under the mailbox lock, before the wait.
    /// Red edit: record the answer in `recv`, before the closure returns.
    /// The wait then never parks, and this times out on the park signal.
    #[test]
    fn the_wait_stays_parked_until_the_door_closure_returns() {
        let (sender, inbox) = found_blocks();
        sender.answered();
        assert!(sender.deliver(found_at(5)));
        assert!(sender.deliver(found_at(6)));
        let (received_tx, received) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let receiver = std::thread::spawn(move || {
            assert!(inbox
                .answer_with(|found| assert_eq!(found, found_at(5)))
                .is_some());
            assert!(inbox
                .answer_with(|found| {
                    assert_eq!(found, found_at(6));
                    received_tx.send(()).expect("the test waits");
                    release_rx.recv().expect("the test releases the door");
                })
                .is_some());
        });
        received
            .recv()
            .expect("the second block is in the door, and the door has not returned");
        let (parked_tx, parked) = mpsc::channel();
        let (done_tx, done) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            sender.answered_observing(|| {
                parked_tx.send(()).expect("the test hears the park");
            });
            done_tx.send(()).expect("the test hears the return");
        });
        parked
            .recv_timeout(Duration::from_secs(5))
            .expect("the waiter parked; an answer recorded at receive never parks");
        assert!(
            done.recv_timeout(Duration::from_millis(200)).is_err(),
            "the wait returned before the door closure returned"
        );
        release_tx.send(()).expect("the door returns");
        done.recv_timeout(Duration::from_secs(5))
            .expect("the wait returns once the door has replied");
        waiter.join().expect("the waiter returns");
        receiver.join().expect("the receiver returns");
    }

    /// The receiving inbox dropping ends the wait while a [`FoundClose`]
    /// still lives. Shutdown holds that closer for the whole service, and
    /// it is not a receiver.
    ///
    /// Red edit: count the closer as a receiver, or drop the `settled`
    /// wake from [`FoundInbox`]'s `Drop`. The bounded wait then times out
    /// instead of hanging the suite.
    #[test]
    fn the_wait_ends_when_the_receiver_drops_while_a_closer_still_lives() {
        let (sender, inbox) = found_blocks();
        let close = inbox.close_handle();
        assert!(sender.deliver(found_at(7)));
        let (parked_tx, parked) = mpsc::channel();
        let (done_tx, done) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            sender.answered_observing(|| {
                parked_tx.send(()).expect("the test hears the park");
            });
            done_tx.send(()).expect("the test hears the return");
        });
        parked
            .recv_timeout(Duration::from_secs(5))
            .expect("the waiter parked");
        drop(inbox);
        done.recv_timeout(Duration::from_secs(5))
            .expect("the last receiver dropping ends the wait");
        waiter.join().expect("the waiter returns");
        close.close();
    }

    /// Dropping the closer does not close the mailbox and does not refuse
    /// a deliver. Red edit: close the mailbox from `FoundClose`'s `Drop`.
    #[test]
    fn dropping_the_closer_leaves_the_receiver_at_work() {
        let (sender, inbox) = found_blocks();
        let close = inbox.close_handle();
        drop(close);
        let found = found_at(8);
        assert!(sender.deliver(found.clone()));
        assert_eq!(inbox.recv(), Some(found));
    }

    /// [`FoundClose::close`] ends `recv` while a sender still lives.
    /// [`FoundInbox::close`] is the same close.
    #[test]
    fn the_closer_ends_recv_while_a_sender_lives() {
        let (_sender, inbox) = found_blocks();
        let close = inbox.close_handle();
        close.close();
        assert!(inbox.recv().is_none());
    }

    /// An ended inbox does not run the door and does not record an answer.
    /// Red edit: run the closure when `recv` returns `None`.
    #[test]
    fn answer_with_does_not_run_the_door_once_the_inbox_has_ended() {
        let (_sender, inbox) = found_blocks();
        inbox.close();
        assert!(inbox
            .answer_with(|_| panic!("the door ran for no block"))
            .is_none());
    }

    #[test]
    fn close_drains_while_an_inbox_still_lives() {
        let (sender, inbox) = found_blocks();
        let kept = inbox.clone();
        let found = found_at(3);
        assert!(sender.deliver(found.clone()));
        inbox.close();
        drop(inbox);
        assert!(!sender.deliver(found_at(4)));
        assert_eq!(kept.recv(), Some(found));
        assert!(kept.recv().is_none());
    }
}
