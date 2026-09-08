// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Coordination gate for the pending-post family (bond posts, emission
//! claims, drains, unbonds) — one object per wallet carrying both of the
//! family's cross-writer disciplines:
//!
//! 1. **The write lock** (WI-3 §3.3): every load→modify→seal cycle over the
//!    `.wallet.pending` sibling seal serializes on the one async mutex held
//!    here, exactly as the bare `Arc<Mutex<()>>` it replaces did. The
//!    [`PendingPostStore`](super::pscan::dispatch::PendingPostStore) is the
//!    sole consumer of the lock; nothing else takes it.
//! 2. **The foreground gauge** (`ENGINE_CADENCE_DRIVER.md` §3, "user work
//!    always wins"): user-initiated pending-post operations — drain, unstake,
//!    collect-unstaked, first-stake — register themselves for their whole
//!    assemble→seal span
//!    via [`PendingPostGate::begin_foreground`]. The cadence driver's
//!    epoch-claim leg reads the gauge twice: a cheap pre-assembly skip, and
//!    the authoritative check **inside** its seal's critical section. Because
//!    snapshot reads and seals all serialize on the write lock above, that
//!    in-seal check gives the ruling exactly: a foreground operation that has
//!    begun before the leg seals forces the leg to yield; one that begins
//!    after the leg's seal reads the post-seal reservation set and selects
//!    around it. Neither direction can surface `InputRaced` to the user from
//!    a background claim.
//!
//! The gauge is deliberately **not** consulted by the WI-3 bond dispatch
//! driver: its send schedule is decorrelation-pinned (privacy over
//! convenience, `00-mission.mdc` priority 2), and moving a send to dodge a
//! foreground assembly would let wallet activity modulate the decorrelation
//! offset. Ordinary transfers (`build_pending_tx`) are structurally outside
//! this gate's domain: they select from the wallet ledger under
//! `output_locks`, while the pending-post family reserves persona funding
//! gindexes — disjoint pools, no race to arbitrate.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Per-wallet coordination for the pending-post family: the seal write lock
/// plus the foreground-operation gauge. See the module docs for both roles.
pub(crate) struct PendingPostGate {
    /// The WI-3 §3.3 writer mutex over the `.wallet.pending` seal.
    write_lock: tokio::sync::Mutex<()>,
    /// Count of user-initiated pending-post operations currently in flight
    /// (assemble→seal span). Read by the epoch-claim leg's yield rule.
    foreground_ops: AtomicUsize,
}

impl PendingPostGate {
    /// A fresh gate: lock free, gauge zero. One per wallet, minted at engine
    /// construction and cloned (as an `Arc`) into every store and facade.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            write_lock: tokio::sync::Mutex::new(()),
            foreground_ops: AtomicUsize::new(0),
        })
    }

    /// Take the pending-seal write lock (load→modify→seal critical section).
    pub(crate) async fn lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.write_lock.lock().await
    }

    /// Register a user-initiated pending-post operation for the lifetime of
    /// the returned guard. Callers hold the guard across their whole
    /// assemble→seal span, not just the seal — the point is to make the
    /// assembly (which does not hold the write lock) visible to the
    /// epoch-claim leg's yield rule.
    pub(crate) fn begin_foreground(self: &Arc<Self>) -> ForegroundPostOp {
        self.foreground_ops.fetch_add(1, Ordering::AcqRel);
        ForegroundPostOp {
            gate: Arc::clone(self),
        }
    }

    /// Whether any user-initiated pending-post operation is in flight.
    /// Advisory outside the write lock; authoritative inside it (seals
    /// serialize on the lock, so a check within a seal's critical section
    /// totally orders against every foreground registration).
    pub(crate) fn foreground_in_flight(&self) -> bool {
        self.foreground_ops.load(Ordering::Acquire) > 0
    }
}

/// RAII registration of one foreground pending-post operation
/// ([`PendingPostGate::begin_foreground`]). Dropping it (any exit path,
/// including error returns and panics) deregisters the operation.
pub(crate) struct ForegroundPostOp {
    gate: Arc<PendingPostGate>,
}

impl Drop for ForegroundPostOp {
    fn drop(&mut self) {
        self.gate.foreground_ops.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gauge_tracks_guard_lifetimes_including_nesting() {
        let gate = PendingPostGate::new();
        assert!(!gate.foreground_in_flight(), "fresh gate reads idle");

        let outer = gate.begin_foreground();
        assert!(gate.foreground_in_flight());

        // A second concurrent user operation nests; the gauge stays raised
        // until BOTH end (a count, not a flag).
        let inner = gate.begin_foreground();
        drop(outer);
        assert!(
            gate.foreground_in_flight(),
            "one live operation must keep the gauge raised"
        );
        drop(inner);
        assert!(
            !gate.foreground_in_flight(),
            "all guards dropped reads idle"
        );
    }

    #[test]
    fn guard_deregisters_on_unwind() {
        let gate = PendingPostGate::new();
        let gate_for_panic = Arc::clone(&gate);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _fg = gate_for_panic.begin_foreground();
            panic!("assembly failed mid-flight");
        }));
        assert!(result.is_err());
        assert!(
            !gate.foreground_in_flight(),
            "a panicking foreground op must not wedge the claim leg forever"
        );
    }

    /// Textual tripwire: every user-initiated pending-post facade registers
    /// on the foreground gauge (`ENGINE_CADENCE_DRIVER.md` §3, "user work
    /// always wins"). The gauge only means what it says if the enumerated
    /// set is complete — a facade that skips registration silently re-opens
    /// the background-claim-races-user-work window (the PR-648 Bugbot
    /// finding on `collect_unstaked` was exactly this omission). Each pin
    /// asserts `begin_foreground` appears inside the named function's body,
    /// bounded at the next `async fn`, so a registration in a *sibling*
    /// function cannot satisfy a missing one here.
    #[test]
    fn every_user_pending_post_facade_registers_on_the_gauge() {
        let pins: [(&str, &str, &str); 4] = [
            (
                "drain_facade.rs",
                include_str!("drain_facade.rs"),
                "pub async fn drain_to_principal",
            ),
            (
                "unstake_facade.rs",
                include_str!("unstake_facade.rs"),
                "pub async fn unstake",
            ),
            (
                "unstake_facade.rs",
                include_str!("unstake_facade.rs"),
                "pub async fn collect_unstaked",
            ),
            (
                "bond_orchestrator.rs",
                include_str!("bond_orchestrator.rs"),
                "pub async fn first_stake",
            ),
        ];
        for (file, source, decl) in pins {
            let start = source.find(decl).unwrap_or_else(|| {
                panic!("{file}: `{decl}` not found — the facade moved; move this pin with it")
            });
            let body = &source[start..];
            let end = body[decl.len()..]
                .find("async fn ")
                .map(|i| decl.len() + i)
                .unwrap_or(body.len());
            assert!(
                body[..end].contains(".begin_foreground()"),
                "{file}: `{decl}` does not register on the foreground gauge — \
                 the cadence claim leg will race this user operation \
                 (ENGINE_CADENCE_DRIVER.md §3)"
            );
        }
    }
}
