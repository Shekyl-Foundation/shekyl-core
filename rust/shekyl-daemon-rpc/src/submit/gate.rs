// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Phase-C concurrency bound (`docs/design/DAEMON_SUBMIT_VERDICT.md`
//! §3.1, F39).
//!
//! Moving verification outside all locks (the F2 win) also removed the
//! *accidental* serialization the old path imposed — FCMP++ verification
//! under the pool lock bounded concurrent verification to one. This gate is
//! the **deliberate** cap replacing the accidental one: cheap-to-submit /
//! expensive-to-verify is otherwise an unbounded CPU/memory amplification.
//! Sized to available cores by default; listed as a multi-daemon-reopen
//! prerequisite in §11.
//!
//! A plain `Mutex` + `Condvar` counting semaphore: the engine core is
//! synchronous (the axum layer dispatches it via `spawn_blocking`), so no
//! async runtime type belongs here.

use std::sync::{Condvar, Mutex};

/// Bounded counting semaphore for Phase-C admission.
#[derive(Debug)]
pub struct PhaseCGate {
    permits: Mutex<usize>,
    released: Condvar,
}

impl PhaseCGate {
    /// A gate with `permits` concurrent slots (normalized to ≥ 1: a
    /// zero-permit gate would deadlock every submit).
    pub fn new(permits: usize) -> Self {
        Self {
            permits: Mutex::new(permits.max(1)),
            released: Condvar::new(),
        }
    }

    /// A gate sized to available cores — the F39 default.
    pub fn sized_to_cores() -> Self {
        let cores = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);
        Self::new(cores)
    }

    /// Block until a permit is free, then hold it for the returned guard's
    /// lifetime.
    pub fn acquire(&self) -> PhaseCPermit<'_> {
        let mut permits = self
            .permits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *permits == 0 {
            permits = self
                .released
                .wait(permits)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *permits -= 1;
        PhaseCPermit { gate: self }
    }
}

/// RAII permit; releases its slot on drop.
#[derive(Debug)]
pub struct PhaseCPermit<'a> {
    gate: &'a PhaseCGate,
}

impl Drop for PhaseCPermit<'_> {
    fn drop(&mut self) {
        let mut permits = self
            .gate
            .permits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *permits += 1;
        self.gate.released.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn zero_permit_request_normalizes_to_one() {
        let gate = PhaseCGate::new(0);
        let _permit = gate.acquire(); // must not deadlock
    }

    #[test]
    fn cap_bounds_concurrent_holders() {
        let gate = Arc::new(PhaseCGate::new(2));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let gate = Arc::clone(&gate);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            handles.push(std::thread::spawn(move || {
                let _permit = gate.acquire();
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(20));
                active.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for handle in handles {
            handle.join().expect("gate thread panicked");
        }
        assert!(
            peak.load(Ordering::SeqCst) <= 2,
            "gate admitted {} concurrent holders past a 2-permit cap",
            peak.load(Ordering::SeqCst)
        );
    }
}
