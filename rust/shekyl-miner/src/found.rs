// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The found-block mailbox.
//!
//! The miner holds [`FoundBlocks`] and delivers what a worker finds. The
//! ingest service holds [`FoundInbox`]: it receives from it, and it closes
//! it when the service stops, so the sink ends while a sender still lives.
//! The last sender dropping ends the receive too, which is a miner stopping
//! on its own and disconnecting the sink. The last inbox dropping closes
//! the mailbox, so a later deliver refuses and nothing queued is kept.
//!
//! The mailbox counts what was delivered and what the receiver has
//! answered ([`FoundInbox::answered`]): the service calls it once the door
//! has replied to a block, connected or refused. [`FoundBlocks::answered`]
//! waits for every block delivered so far to be answered. A caller that
//! stopped the miner reads the chain after that wait, and not while a
//! block the miner found is still on its way through the door.

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
    receivers: usize,
    /// Blocks [`FoundBlocks::deliver`] accepted.
    delivered: u64,
    /// Blocks the receiver has answered ([`FoundInbox::answered`]). Never
    /// above `delivered`.
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
    /// from the receiver ([`FoundInbox::answered`]). Returns at once when
    /// nothing is owed. Returns too when the last inbox has dropped:
    /// nothing will answer what was queued, and nothing will connect it.
    ///
    /// Blocking. A block delivered while this waits is not waited for: the
    /// caller that wants none stops the miner first, and a stopped miner
    /// delivers nothing ([`JobBoard`](crate::JobBoard)'s claim).
    pub fn answered(&self) {
        let mut mail = lock(&self.shared);
        let owed = mail.delivered;
        while mail.answered < owed && mail.receivers > 0 {
            mail = self
                .shared
                .settled
                .wait(mail)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
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

    /// One received block has its answer: the door replied to it,
    /// connected or refused. The receiver calls this once per block it
    /// took, after the reply, so [`FoundBlocks::answered`] returns only
    /// when the chain shows what that block came to.
    ///
    /// # Panics
    ///
    /// When more blocks are answered than were delivered: a receiver
    /// answered a block it did not take.
    pub fn answered(&self) {
        let mut mail = lock(&self.shared);
        assert!(
            mail.answered < mail.delivered,
            "a found block is answered once, after it is received"
        );
        mail.answered += 1;
        self.shared.settled.notify_all();
    }

    /// End the inbox. Receivers drain the queue and then see [`recv`](Self::recv)
    /// return `None`, whether or not a sender still lives. A deliver after
    /// this returns `false`.
    pub fn close(&self) {
        let mut mail = lock(&self.shared);
        mail.closed = true;
        self.shared.arrived.notify_all();
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

    /// [`FoundBlocks::answered`] returns only once every block delivered
    /// before it has been answered: received is not answered. With nothing
    /// delivered it returns at once.
    ///
    /// Red edit: count a block as answered in `recv` instead of in
    /// [`FoundInbox::answered`]: the wait returns while the receiver still
    /// holds the block, before the flag below is set.
    #[test]
    fn the_wait_ends_when_each_delivered_block_is_answered_not_when_it_is_received() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let (sender, inbox) = found_blocks();
        sender.answered();
        assert!(sender.deliver(found_at(5)));
        assert!(sender.deliver(found_at(6)));
        let replied = Arc::new(AtomicBool::new(false));
        let (received_tx, received) = std::sync::mpsc::channel();
        let (reply, reply_rx) = std::sync::mpsc::channel::<()>();
        let receiver = {
            let replied = Arc::clone(&replied);
            std::thread::spawn(move || {
                let first = inbox.recv().expect("the first block");
                inbox.answered();
                let second = inbox.recv().expect("the second block");
                // Both are received. The second has no answer until the
                // test says the door replied.
                received_tx.send(()).expect("the test waits");
                reply_rx.recv().expect("the test replies");
                replied.store(true, Ordering::Release);
                inbox.answered();
                (first, second)
            })
        };
        let waiter = {
            let replied = Arc::clone(&replied);
            std::thread::spawn(move || {
                sender.answered();
                replied.load(Ordering::Acquire)
            })
        };
        received.recv().expect("both blocks are received");
        reply.send(()).expect("the receiver waits for the reply");
        assert!(
            waiter.join().expect("the wait returns"),
            "the wait returned before the second block was answered"
        );
        let (first, second) = receiver.join().expect("the receiver returns");
        assert_eq!((first, second), (found_at(5), found_at(6)));
    }

    /// The last inbox dropping ends the wait: nothing will answer what was
    /// delivered.
    ///
    /// Red edit: drop the `settled` wake from `FoundInbox`'s `Drop`: the
    /// wait never returns.
    #[test]
    fn the_wait_ends_when_the_last_inbox_drops_with_a_block_unanswered() {
        let (sender, inbox) = found_blocks();
        assert!(sender.deliver(found_at(7)));
        let waiter = std::thread::spawn(move || sender.answered());
        drop(inbox);
        waiter.join().expect("the wait returns");
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
