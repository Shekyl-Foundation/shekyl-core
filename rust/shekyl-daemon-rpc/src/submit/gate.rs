// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Phase-C concurrency bound (`docs/design/DAEMON_SUBMIT_VERDICT.md`
//! §3.1, F39) — a process-global async semaphore acquired at the transport
//! dispatch layer.
//!
//! Moving verification outside all locks (the F2 win) also removed the
//! *accidental* serialization the old path imposed — FCMP++ verification
//! under the pool lock bounded concurrent verification to one. This gate is
//! the **deliberate** cap replacing the accidental one: cheap-to-submit /
//! expensive-to-verify is otherwise an unbounded CPU/memory amplification.
//! Sized to available cores; listed as a multi-daemon-reopen prerequisite in
//! §11.
//!
//! Two properties the earlier in-engine `Mutex` + `Condvar` gate got wrong,
//! both corrected here:
//!
//! - **Async wait, not a parked thread.** The engine core is synchronous and
//!   the axum layer dispatches it via `spawn_blocking`. A *synchronous* wait
//!   for a permit inside that `spawn_blocking` pins a whole blocking-pool
//!   worker while it sits idle in the queue — pathological under exactly the
//!   submit flood the gate exists to bound (the pool's ~512 threads exhaust
//!   and every other RPC route starves). The permit is now a
//!   [`tokio::sync::Semaphore`] acquired in the async handler *before*
//!   `spawn_blocking`, so a queued submission is a cheap parked task. The
//!   permit *hold* still spans the synchronous verification on the blocking
//!   worker — that half was always correct; only the *wait* was at the wrong
//!   layer.
//! - **One cap per daemon, not per listener.** The daemon runs one RPC
//!   server per bind (unrestricted + restricted), each on its own runtime; an
//!   in-engine gate constructed per listener made the F39 cap per-endpoint
//!   (N × cores). The semaphore is process-global (a [`OnceLock`]), so every
//!   bind shares a single `cores`-sized cap — F39's "one instance per
//!   daemon".

use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};

use tokio::sync::Semaphore;

/// The single process-wide Phase-C admission semaphore, sized to available
/// cores. Shared across every daemon-RPC listener so the F39 verification cap
/// is per-daemon, not per-endpoint. Acquire an owned permit in the async
/// transport handler and hold it across the `spawn_blocking` submit.
pub fn phase_c_semaphore() -> Arc<Semaphore> {
    static GATE: OnceLock<Arc<Semaphore>> = OnceLock::new();
    Arc::clone(GATE.get_or_init(|| {
        let cores = std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1);
        Arc::new(Semaphore::new(cores))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semaphore_is_process_global_and_core_sized() {
        let a = phase_c_semaphore();
        let b = phase_c_semaphore();
        // Both handles point at the one `OnceLock` cell — the per-daemon cap.
        assert!(Arc::ptr_eq(&a, &b));
        let cores = std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1);
        assert_eq!(a.available_permits(), cores);
    }
}
