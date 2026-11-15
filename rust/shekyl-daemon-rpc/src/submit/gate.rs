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
//!   permit then moves into the blocking closure ([`verify_under`]), so its
//!   hold spans the synchronous verification on the blocking worker even
//!   when the handler that took it is dropped: a closed connection or a
//!   revoked channel session cancels the handler, never the verification
//!   it started, and the cap must stay taken until that verification ends.
//! - **One cap per daemon, not per listener.** The daemon runs one RPC
//!   server per bind (unrestricted + restricted), each on its own runtime; an
//!   in-engine gate constructed per listener made the F39 cap per-endpoint
//!   (N × cores). The semaphore is process-global (a [`OnceLock`]), so every
//!   bind shares a single `cores`-sized cap — F39's "one instance per
//!   daemon".

use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

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

/// Run `work` on the blocking pool under `permit`. The permit moves into
/// the blocking closure and is released when `work` returns, not when the
/// returned handle is awaited or dropped: a handler cancelled while its
/// verification runs leaves the cap taken until the verification ends.
pub fn verify_under<T: Send + 'static>(
    permit: OwnedSemaphorePermit,
    work: impl FnOnce() -> T + Send + 'static,
) -> JoinHandle<T> {
    tokio::task::spawn_blocking(move || {
        let _held = permit;
        work()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A handler dropped while its verification runs does not release the
    /// cap: the permit is held until the work returns. Red edit: drop the
    /// permit before `spawn_blocking` in `verify_under`, and the cap is free
    /// while the work still runs.
    #[tokio::test]
    async fn the_permit_is_held_until_the_work_returns_not_the_handler() {
        let gate = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&gate).acquire_owned().await.expect("a permit");
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (started, running) = std::sync::mpsc::channel::<()>();
        let work = verify_under(permit, move || {
            started.send(()).expect("the test waits");
            wait.recv().expect("the test releases the work");
        });
        let handler = tokio::spawn(work);
        tokio::task::spawn_blocking(move || running.recv().expect("the work starts"))
            .await
            .expect("the work started");
        handler.abort();
        assert!(handler.await.is_err(), "the handler was cancelled");
        assert_eq!(gate.available_permits(), 0, "the work still runs");
        release.send(()).expect("the work waits");
        let returned = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            Arc::clone(&gate).acquire_owned(),
        )
        .await
        .expect("the permit returns when the work does");
        drop(returned);
    }

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
