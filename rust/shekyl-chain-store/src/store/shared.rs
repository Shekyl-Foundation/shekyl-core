// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! State a live [`WriteBatch`](super::WriteBatch) shares with its store.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{PoisonError, RwLock};

use crate::provenance::Provenance;

/// The one-live-write guard and the in-memory mirror of the provenance cell.
pub(super) struct Shared {
    write_held: AtomicBool,
    /// Mirror of the persisted `apply_policy` cell. Readers (`provenance`)
    /// take the read side; [`Self::publish`] — the only mutator — holds the
    /// write side across the engine commit *and* the assignment, so a
    /// concurrent reader cannot observe the file as tainted while this
    /// still says [`Provenance::FULL`].
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
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Run `commit` and, if it succeeds, make `provenance` the mirror's
    /// value — under one write lock, so no reader sees the file tainted
    /// while the mirror still says less. `commit`'s `Err` publishes
    /// nothing: a failed commit leaves the mirror exactly as tainted as the
    /// file it mirrors.
    ///
    /// This is the mirror's only mutator. "Assign only after the engine
    /// committed, and only under the lock" is therefore a property of this
    /// type, not an ordering the call site has to preserve.
    pub(super) fn publish<E>(
        &self,
        provenance: Provenance,
        commit: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), E> {
        let mut mirror = self
            .provenance
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        commit()?;
        // The cell only widens, and `provenance` is read from the file in
        // the transaction just committed, so it is a superset of what this
        // process last published. Loud in debug builds if a caller ever
        // hands the mirror something narrower than the file.
        debug_assert!(
            provenance.union(*mirror) == provenance,
            "the provenance mirror only widens: {} -> {provenance}",
            *mirror
        );
        *mirror = provenance;
        Ok(())
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

    fn tainted() -> Provenance {
        let tainted = Provenance::of(FamilySet::of(&[ArchivalFamily::Bond]));
        assert!(Provenance::FULL.is_parity_evidence());
        assert!(!tainted.is_parity_evidence());
        tainted
    }

    #[test]
    fn a_reader_blocked_on_publish_sees_the_value_assigned_under_the_lock() {
        // `publish` holds the write lock while `commit` runs, then assigns,
        // then releases. A reader that arrives while `commit` is in flight
        // must not observe the old value — that is the fail-open window of
        // commit-then-taint without a lock. The "engine commit" here is a
        // closure that blocks until the test lets it finish.
        let shared = Arc::new(Shared::new(Provenance::FULL));
        let tainted = tainted();

        let (committing_tx, committing_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let publisher = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                shared
                    .publish(tainted, || {
                        committing_tx.send(()).expect("main is waiting");
                        release_rx.recv().expect("main releases");
                        Ok::<(), ()>(())
                    })
                    .expect("commit succeeds");
            })
        };
        committing_rx
            .recv()
            .expect("publisher is inside commit, holding the lock");

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
            "provenance() returned while a commit was in flight: the mirror \
             can split from the file"
        );

        release_tx.send(()).expect("publisher is waiting");
        let seen = seen_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("reader should unblock after publish");
        assert_eq!(seen, tainted, "reader must observe the published value");
        publisher.join().expect("publisher thread");
        reader.join().expect("reader thread");
    }

    #[test]
    fn a_failed_commit_publishes_nothing() {
        // The other half of exactness: the mirror must not be *more*
        // tainted than the file. A commit that fails leaves the mirror
        // where it was, and the error is the caller's.
        let shared = Shared::new(Provenance::FULL);
        let result = shared.publish(tainted(), || Err("engine refused"));
        assert_eq!(result, Err("engine refused"));
        assert_eq!(shared.provenance(), Provenance::FULL);

        // And a commit that succeeds publishes exactly its value.
        shared
            .publish(tainted(), || Ok::<(), &str>(()))
            .expect("commit succeeds");
        assert_eq!(shared.provenance(), tainted());
    }
}
