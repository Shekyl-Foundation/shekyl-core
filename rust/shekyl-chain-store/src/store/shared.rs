// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! State a live [`WriteBatch`](super::WriteBatch) shares with its store.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, PoisonError, RwLock};

use crate::provenance::Provenance;

use super::error::{StoreCannot, StoreInvariant};

/// The one-live-write guard, the in-memory mirror of the provenance cell,
/// and the writer halt.
pub(super) struct Shared {
    write_held: AtomicBool,
    /// The writer halt (`DAEMON_REDB_STORE.md` §3.6.2): set once, by the
    /// first connect, pop, or branded-view batch to be poisoned, never
    /// cleared for the life of this handle. Not persisted — re-derived
    /// on restart by the check that reruns the belts, so a restart with
    /// a repaired file is not refused by a stale latch.
    halt: OnceLock<(u64, StoreInvariant)>,
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
            halt: OnceLock::new(),
            provenance: RwLock::new(provenance),
        }
    }

    /// Halt the writer at `at_height` on `row`. The first halt wins: a
    /// second poisoned batch cannot exist once `write` refuses, and if one
    /// races the latch anyway the first record stands.
    pub(super) fn halt(&self, at_height: u64, row: StoreInvariant) {
        if self.halt.set((at_height, row)).is_err() {
            // Already halted: the first record stands.
        }
    }

    /// The halt, if the writer is halted.
    pub(super) fn halted(&self) -> Option<(u64, StoreInvariant)> {
        self.halt.get().copied()
    }

    /// Claim the single write slot, or refuse.
    ///
    /// The slot is taken **before** the halt is observed, then the halt is
    /// rechecked while holding it. A load-then-CAS lets a batch halt and
    /// drop between the two, and the next caller begins a write on a
    /// halted handle; holding the slot across the look closes that
    /// window. Halt never clears, so a refusal here is permanent for this
    /// process. The slot is released on every refusal so a later
    /// `WriterHalted` is not reported as `WriteInProgress`.
    pub(super) fn admit_write(&self) -> Result<(), StoreCannot> {
        if !self.try_hold_write() {
            return Err(StoreCannot::WriteInProgress);
        }
        if let Some((at_height, row)) = self.halted() {
            self.release_write();
            return Err(StoreCannot::WriterHalted { at_height, row });
        }
        Ok(())
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
    use crate::store::error::{StoreCannot, StoreInvariant};

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
    fn admit_write_refuses_a_halt_and_leaves_the_slot_free() {
        // The window: halt is already latched, nobody holds the slot (the
        // batch that set it has dropped). Claiming first, then looking,
        // must still refuse and must not leave `write_held` set — or the
        // next call would be `WriteInProgress` instead of `WriterHalted`.
        let shared = Shared::new(Provenance::FULL);
        shared.halt(7, StoreInvariant::IdNotFresh);
        assert!(matches!(
            shared.admit_write(),
            Err(StoreCannot::WriterHalted {
                at_height: 7,
                row: StoreInvariant::IdNotFresh,
            })
        ));
        assert!(
            shared.try_hold_write(),
            "a halt refusal must release the write slot"
        );
        shared.release_write();
    }

    #[test]
    fn admit_write_is_in_progress_while_the_slot_is_held() {
        let shared = Shared::new(Provenance::FULL);
        assert!(shared.try_hold_write());
        assert!(matches!(
            shared.admit_write(),
            Err(StoreCannot::WriteInProgress)
        ));
        shared.release_write();
        shared.admit_write().expect("slot free");
        shared.release_write();
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
