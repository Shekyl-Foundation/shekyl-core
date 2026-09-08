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
//! 2. **The foreground session** (`ENGINE_CADENCE_DRIVER.md` §3, "user work
//!    always wins"): user-initiated pending-post operations — the closed
//!    set [`UserPendingPost`] — register themselves for their whole
//!    assemble→seal span via [`ForegroundSession::enter`]. The cadence
//!    driver's epoch-claim leg reads the gauge twice: a cheap pre-assembly
//!    skip, and the authoritative check **inside** its seal's critical
//!    section. Because snapshot reads and seals all serialize on the write
//!    lock above, that in-seal check gives the ruling exactly: a foreground
//!    operation that has begun before the leg seals forces the leg to yield;
//!    one that begins after the leg's seal reads the post-seal reservation
//!    set and selects around it. Neither direction can surface `InputRaced`
//!    to the user from a background claim.
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

/// Closed set of user-initiated pending-post operations. The yield rule
/// is this set: a background claim yields while any of these is in flight.
///
/// Adding a fifth user pending-post facade is adding a variant here **and**
/// calling [`ForegroundSession::enter`] at that facade. A variant with no
/// call site fails `dead_code`; a facade that skips `enter` never raises
/// the gauge — and `enter` is the only constructor that does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserPendingPost {
    DrainToPrincipal,
    Unstake,
    CollectUnstaked,
    FirstStake,
}

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

    /// Whether any user-initiated pending-post operation is in flight.
    /// Advisory outside the write lock; authoritative inside it (seals
    /// serialize on the lock, so a check within a seal's critical section
    /// totally orders against every foreground registration).
    pub(crate) fn foreground_in_flight(&self) -> bool {
        self.foreground_ops.load(Ordering::Acquire) > 0
    }
}

/// RAII registration of one [`UserPendingPost`] on the foreground gauge.
/// Dropping it (any exit path, including error returns and panics)
/// deregisters the operation.
#[must_use = "dropping this ends the foreground yield-rule registration"]
pub(crate) struct ForegroundSession {
    gate: Arc<PendingPostGate>,
    kind: UserPendingPost,
}

impl ForegroundSession {
    /// Register `kind` on `gate` for the lifetime of the returned session.
    /// Callers hold the session across their whole assemble→seal span, not
    /// just the seal — the point is to make the assembly (which does not
    /// hold the write lock) visible to the epoch-claim leg's yield rule.
    ///
    /// This is the only constructor that raises the gauge.
    pub(crate) fn enter(kind: UserPendingPost, gate: &Arc<PendingPostGate>) -> Self {
        tracing::trace!(?kind, "foreground pending-post registered");
        gate.foreground_ops.fetch_add(1, Ordering::AcqRel);
        Self {
            gate: Arc::clone(gate),
            kind,
        }
    }
}

impl Drop for ForegroundSession {
    fn drop(&mut self) {
        tracing::trace!(kind = ?self.kind, "foreground pending-post released");
        self.gate.foreground_ops.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gauge_tracks_session_lifetimes_including_nesting() {
        let gate = PendingPostGate::new();
        assert!(!gate.foreground_in_flight(), "fresh gate reads idle");

        let outer = ForegroundSession::enter(UserPendingPost::DrainToPrincipal, &gate);
        assert!(gate.foreground_in_flight());

        // A second concurrent user operation nests; the gauge stays raised
        // until BOTH end (a count, not a flag).
        let inner = ForegroundSession::enter(UserPendingPost::Unstake, &gate);
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
    fn session_deregisters_on_unwind() {
        let gate = PendingPostGate::new();
        let gate_for_panic = Arc::clone(&gate);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _fg = ForegroundSession::enter(UserPendingPost::FirstStake, &gate_for_panic);
            panic!("assembly failed mid-flight");
        }));
        assert!(result.is_err());
        assert!(
            !gate.foreground_in_flight(),
            "a panicking foreground op must not wedge the claim leg forever"
        );
    }

    /// Exhaustiveness: every [`UserPendingPost`] variant has an
    /// [`ForegroundSession::enter`] site in its facade. Adding a variant
    /// without updating this match is a compile error; a match arm whose
    /// needle is missing from the named file is the yield-rule hole
    /// (a facade that never registers).
    #[test]
    fn each_variant_has_an_enter_site() {
        let pins = [
            (
                UserPendingPost::DrainToPrincipal,
                "drain_facade.rs",
                include_str!("drain_facade.rs"),
            ),
            (
                UserPendingPost::Unstake,
                "unstake_facade.rs",
                include_str!("unstake_facade.rs"),
            ),
            (
                UserPendingPost::CollectUnstaked,
                "unstake_facade.rs",
                include_str!("unstake_facade.rs"),
            ),
            (
                UserPendingPost::FirstStake,
                "bond_orchestrator.rs",
                include_str!("bond_orchestrator.rs"),
            ),
        ];
        for (kind, file, source) in pins {
            let token = match kind {
                UserPendingPost::DrainToPrincipal => "UserPendingPost::DrainToPrincipal",
                UserPendingPost::Unstake => "UserPendingPost::Unstake",
                UserPendingPost::CollectUnstaked => "UserPendingPost::CollectUnstaked",
                UserPendingPost::FirstStake => "UserPendingPost::FirstStake",
            };
            // Variant path only: rustfmt may wrap the `enter(` call. The
            // path is unique to this registration (docs use the type name,
            // not the variant).
            assert!(
                source.contains(token) && source.contains("ForegroundSession::enter"),
                "{file}: `{token}` has no ForegroundSession::enter site — \
                 the cadence claim leg will race this user operation \
                 (ENGINE_CADENCE_DRIVER.md §3)"
            );
        }
    }
}
