// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! State a live [`WriteBatch`](super::WriteBatch) shares with its store.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{RwLock, RwLockWriteGuard};

use crate::provenance::Provenance;

/// The one-live-write guard and the in-memory mirror of the provenance cell.
pub(super) struct Shared {
    write_held: AtomicBool,
    /// Mirror of the persisted `apply_policy` cell. Readers (`provenance`)
    /// take the read side; `WriteBatch::commit` holds the write side across
    /// the engine commit *and* the assignment so a concurrent reader cannot
    /// observe the file as tainted while this still says [`Provenance::FULL`].
    provenance: RwLock<Provenance>,
}

impl Shared {
    pub(super) fn new(provenance: Provenance) -> Self {
        Self {
            write_held: AtomicBool::new(false),
            provenance: RwLock::new(provenance),
        }
    }

    /// Claim the single write slot. `false` if it is already held.
    pub(super) fn try_hold_write(&self) -> bool {
        self.write_held
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Release the write slot.
    pub(super) fn release_write(&self) {
        self.write_held.store(false, Ordering::Release);
    }

    /// The provenance as this process last published it.
    pub(super) fn provenance(&self) -> Provenance {
        *self
            .provenance
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Write lock on the mirror. Held across `txn.commit()` and the
    /// assignment that follows it.
    pub(super) fn lock_publish(&self) -> RwLockWriteGuard<'_, Provenance> {
        self.provenance
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::apply_policy::ArchivalFamily;
    use crate::family_set::FamilySet;

    #[test]
    fn a_reader_blocked_on_publish_sees_the_value_assigned_under_the_lock() {
        // The protocol `commit` uses: hold the write lock, then (here
        // simulated) make the new value visible, then release. A reader
        // that arrives while the lock is held must not observe the old
        // value — that is the fail-open window of commit-then-taint
        // without a lock.
        let shared = Arc::new(Shared::new(Provenance::FULL));
        let tainted = Provenance::of(FamilySet::of(&[ArchivalFamily::Bond]));
        assert!(Provenance::FULL.is_parity_evidence());
        assert!(!tainted.is_parity_evidence());

        let (holding_tx, holding_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let publisher = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let mut guard = shared.lock_publish();
                holding_tx.send(()).expect("main is waiting");
                release_rx.recv().expect("main releases");
                *guard = tainted;
            })
        };
        holding_rx.recv().expect("publisher holds the lock");

        let (seen_tx, seen_rx) = mpsc::channel();
        let reader = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                seen_tx
                    .send(shared.provenance())
                    .expect("main is waiting for the read");
            })
        };
        assert!(
            seen_rx.recv_timeout(Duration::from_secs(1)).is_err(),
            "provenance() returned while the publish lock was held: the \
             mirror can split from the file"
        );

        release_tx.send(()).expect("publisher is waiting");
        let seen = seen_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("reader should unblock after publish");
        assert_eq!(seen, tainted, "reader must observe the published value");
        publisher.join().expect("publisher thread");
        reader.join().expect("reader thread");
    }
}
