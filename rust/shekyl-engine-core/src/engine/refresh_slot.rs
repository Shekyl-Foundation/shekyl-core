// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`RefreshSlot`]: the per-engine single-flight primitive.
//!
//! Carved out of `engine/refresh.rs` when a second entry point grew:
//! `Engine::start_refresh` and `Engine::start_rescan` (`engine/rescan.rs`)
//! claim the *same* slot, which is what makes "a rescan and a refresh can
//! never run concurrently" a structural fact rather than a convention two
//! modules each remember. A concurrency primitive shared by two workflows
//! belongs to neither of them.
//!
//! The slot is deliberately independent of the engine's cross-cutting
//! `RwLock`: it is its own `Arc<AtomicBool>`, so claiming it needs only a
//! brief read borrow of the engine and never contends with the producer
//! task's per-attempt read/write borrows.

// The slot is a per-Engine `Arc<AtomicBool>` kept on the engine struct. An
// entry point claims the flag (CAS false → true) under a brief read borrow
// of the engine; if the CAS fails another scan is in flight and the call
// returns `RefreshError::AlreadyRunning`. The producer task holds a
// `SlotGuard` for the duration of the scan; dropping the guard releases the
// flag (RAII), whether the task succeeded, errored, or was cancelled.

/// Per-engine single-flight slot shared by
/// [`Engine::start_refresh`](super::Engine::start_refresh) and
/// [`Engine::start_rescan`](super::Engine::start_rescan).
///
/// Cloneable; the slot itself is reference-counted, so cloning a
/// `RefreshSlot` produces another handle to the same underlying
/// flag. The engine struct owns one; the producer task's
/// [`SlotGuard`] holds another for its lifetime.
#[derive(Clone, Debug)]
pub(crate) struct RefreshSlot {
    flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl RefreshSlot {
    /// Build a fresh slot in the released state. Called once at
    /// `Engine::assemble` time.
    pub(crate) fn new() -> Self {
        Self {
            flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Attempt to claim the slot. Returns `Some(SlotGuard)` on
    /// success (the slot is now held; `Drop` will release it).
    /// Returns `None` if the slot is already held by another
    /// refresh task.
    ///
    /// Implemented as a single CAS (Acquire on success, Relaxed on
    /// failure) so claim and release pair across threads without
    /// needing a stronger fence.
    pub(crate) fn try_claim(&self) -> Option<SlotGuard> {
        match self.flag.compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::Acquire,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => Some(SlotGuard {
                flag: self.flag.clone(),
            }),
            Err(_) => None,
        }
    }

    /// Read the slot's current state without claiming it. Used by
    /// the redacted `Debug` impl on `Engine<S>` to surface "is a
    /// refresh in flight" without taking a guard.
    pub(crate) fn is_claimed(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// RAII guard for the [`RefreshSlot`] flag. Held by the producer
/// task; dropping it releases the flag.
///
/// Deliberately not `Clone`: the guard's whole purpose is to
/// uniquely own the claim, so cloning it would defeat single-
/// flight enforcement. The producer task receives the guard from
/// [`Engine::start_refresh`] and holds it through `run_refresh_task`'s
/// full lifetime; the `Drop` releases the slot whether the task
/// returned successfully, errored, or was cancelled.
#[derive(Debug)]
pub(crate) struct SlotGuard {
    flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        // Release: pair with `Acquire` on the matching `try_claim`.
        // Idempotent — if the slot was double-released somehow, the
        // store is a no-op (the second release would still write
        // `false` to a flag that's already `false`).
        self.flag.store(false, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
mod refresh_slot_tests {
    //! Unit tests for [`RefreshSlot`] — the single-flight
    //! primitive [`Engine::start_refresh`] uses to gate concurrent
    //! refreshes.
    //!
    //! These tests exercise the slot in isolation; concurrent
    //! `start_refresh` against a real `Engine<S>` (the integration
    //! surface that surfaces `RefreshError::AlreadyRunning`) is
    //! covered by commit 6.
    use super::RefreshSlot;

    /// Fresh slot is unclaimed; `try_claim` succeeds and returns
    /// a guard.
    #[test]
    fn claim_succeeds_when_unheld() {
        let slot = RefreshSlot::new();
        assert!(!slot.is_claimed());
        let guard = slot.try_claim().expect("fresh slot is claimable");
        assert!(slot.is_claimed());
        drop(guard);
    }

    /// A second `try_claim` returns `None` while the first guard
    /// is alive. This is the surface that surfaces
    /// `RefreshError::AlreadyRunning` at the `start_refresh`
    /// layer.
    #[test]
    fn claim_fails_when_held() {
        let slot = RefreshSlot::new();
        let _guard = slot.try_claim().expect("first claim succeeds");
        assert!(slot.try_claim().is_none(), "second claim fails");
        assert!(slot.is_claimed());
    }

    /// Dropping the guard releases the slot; a subsequent claim
    /// then succeeds. This is the contract that makes the
    /// `_slot_guard` discipline in `run_refresh_task` self-
    /// healing across success / error / cancellation exits.
    #[test]
    fn release_on_guard_drop() {
        let slot = RefreshSlot::new();
        {
            let _guard = slot.try_claim().expect("first claim succeeds");
            assert!(slot.is_claimed());
        }
        assert!(!slot.is_claimed(), "guard drop released the flag");
        let _second = slot
            .try_claim()
            .expect("slot reclaimable after first guard dropped");
    }

    /// Cloning the slot returns another handle to the same flag —
    /// so the engine's stored slot and the producer task's clone
    /// observe the same state. This is the property that makes
    /// the slot-claim path lock-free against the producer's read/
    /// write borrows of the engine.
    #[test]
    fn clone_shares_underlying_flag() {
        let slot_a = RefreshSlot::new();
        let slot_b = slot_a.clone();
        let _guard = slot_a.try_claim().expect("first claim succeeds");
        assert!(slot_b.is_claimed(), "clone observes the same flag");
        assert!(slot_b.try_claim().is_none(), "clone cannot re-claim");
    }
}
