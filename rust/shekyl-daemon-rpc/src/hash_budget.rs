// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The shared hash budget for bounded RPC callers (`RPC_CHANNEL.md` §6.3).
//!
//! One bucket per daemon. A bounded `pow` spends one hash, and only
//! once the seed is one RandomX will hash. A header read with `pow` reads the
//! hash recorded at validation and does not pay. The host's administrator does
//! not pay. The bucket bounds charges, not measured CPU, in the same shape
//! as the handshake budget:
//!
//! `charges ≤ share × elapsed + capacity`.
//!
//! The share is a quarter of one core, the handshake's share. One charge is
//! one hash: the thread-CPU 99th percentile of a header hash on the floor
//! device. A one-second burst of that share is 250 ms and cannot pay a
//! hash, so the bucket's capacity is one hash. A spend while the bucket is
//! empty is `OverResourceBound` and leaves the balance where the refill
//! put it.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError};

/// One RandomX hash on the floor device, thread-CPU 99th percentile
/// (RT-W10, `docs/benchmarks/rt_w10_request_cost_20261102.md`).
/// `pow` spends this once, after the seed's cache is held.
/// A header read with `pow` does not: it reads the hash recorded at
/// validation.
pub const HASH_CPU_NANOS: u64 = 1_290_885_199;

/// The share of one core the long-run charge rate allows, in thousandths.
/// The handshake budget's share.
pub const HASH_BUDGET_SHARE_PERMILLE: u64 = 250;

/// Hashes one full bucket holds. The capacity is this many charges of
/// [`HASH_CPU_NANOS`]. A `pow` spends one; there is no request that
/// spends more.
pub const HASH_BUDGET_BURST: u64 = 1;

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// How long the share takes to earn one hash, rounded up to the next
/// millisecond. Recorded next to the charge so a reader does not have to
/// divide.
pub const HASH_EARNED_EVERY: Duration = Duration::from_millis(hash_earned_every_ms());

const fn hash_earned_every_ms() -> u64 {
    let earned_per_sec = NANOS_PER_SEC * HASH_BUDGET_SHARE_PERMILLE / 1_000;
    HASH_CPU_NANOS
        .saturating_mul(1_000)
        .div_ceil(earned_per_sec)
}

struct State {
    balance_ns: u64,
    last: Instant,
}

/// One daemon's hash budget. Bounded callers share it.
pub struct HashBudget {
    capacity_ns: u64,
    state: Mutex<State>,
}

impl HashBudget {
    /// A full bucket at `now`: one hash ready.
    #[must_use]
    pub fn new(now: Instant) -> Self {
        let capacity_ns = HASH_BUDGET_BURST * HASH_CPU_NANOS;
        Self {
            capacity_ns,
            state: Mutex::new(State {
                balance_ns: capacity_ns,
                last: now,
            }),
        }
    }

    /// An empty bucket at `now`. The next hash is earned after
    /// [`HASH_EARNED_EVERY`].
    #[must_use]
    pub fn empty(now: Instant) -> Self {
        let budget = Self::new(now);
        budget
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .balance_ns = 0;
        budget
    }

    /// Spend one hash, judged at `now`. A bucket that cannot
    /// pay leaves its balance where the refill put it. `now` is the
    /// caller's clock, the same instant [`Self::new`] and [`Self::empty`]
    /// take, so a test can hold time still and a request can pass the
    /// moment it spends.
    ///
    /// # Errors
    ///
    /// [`ErrorClass::OverResourceBound`] when the bucket cannot pay one
    /// hash at `now`.
    pub fn spend(&self, now: Instant) -> Result<(), RpcError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let elapsed = nanos(now.saturating_duration_since(state.last));
        if now > state.last {
            state.last = now;
        }
        let earned = elapsed.saturating_mul(HASH_BUDGET_SHARE_PERMILLE) / 1_000;
        state.balance_ns = state
            .balance_ns
            .saturating_add(earned)
            .min(self.capacity_ns);
        if state.balance_ns >= HASH_CPU_NANOS {
            state.balance_ns -= HASH_CPU_NANOS;
            Ok(())
        } else {
            Err(budget_empty())
        }
    }

    /// Nanoseconds of hash currently held. A read that does not charge
    /// leaves this where it was.
    #[cfg(test)]
    pub(crate) fn held_ns(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .balance_ns
    }
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn budget_empty() -> RpcError {
    RpcError::new(
        ErrorClass::OverResourceBound,
        Diagnostic::new(
            crate::methods::codes::BOUND_HASH,
            format!(
                "the request needs a hash and this node's hash budget is empty; \
                 a bounded connection can spend one hash every {} ms",
                HASH_EARNED_EVERY.as_millis()
            ),
        )
        .param("bound", "1")
        .param("asked", "1"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn earned(elapsed: Duration) -> u64 {
        nanos(elapsed).saturating_mul(HASH_BUDGET_SHARE_PERMILLE) / 1_000
    }

    #[test]
    fn a_full_bucket_pays_one_hash_and_then_is_empty() {
        let now = Instant::now();
        let budget = HashBudget::new(now);
        assert!(budget.spend(now).is_ok());
        let err = budget.spend(now).expect_err("the bucket holds one hash");
        assert_eq!(err.diagnostic.code, "bound.hash");
        assert_eq!(
            budget.held_ns(),
            0,
            "no time passed, so the refusal holds nothing"
        );
    }

    #[test]
    fn an_empty_bucket_refuses_and_keeps_only_what_it_earned() {
        let start = Instant::now();
        let budget = HashBudget::empty(start);
        let err = budget.spend(start).unwrap_err();
        assert_eq!(err.diagnostic.code, "bound.hash");
        assert_eq!(
            budget.held_ns(),
            0,
            "no time passed, so the bucket stays empty"
        );

        // One millisecond short of the recorded interval earns just under a
        // hash. The refusal keeps that refill. The next millisecond crosses
        // a hash. Capacity is one hash, so the share past it does not carry.
        let short = HASH_EARNED_EVERY
            .checked_sub(Duration::from_millis(1))
            .expect("earning one hash takes longer than a millisecond");
        let short_earned = earned(short);
        assert!(short_earned < HASH_CPU_NANOS);
        assert!(budget.spend(start + short).is_err());
        assert_eq!(budget.held_ns(), short_earned);
        let at_interval = short_earned + earned(Duration::from_millis(1));
        assert!(at_interval > HASH_CPU_NANOS);
        assert!(budget.spend(start + HASH_EARNED_EVERY).is_ok());
        assert_eq!(budget.held_ns(), 0, "capacity is one hash");
    }

    #[test]
    fn one_hash_is_about_five_seconds_of_the_share() {
        assert_eq!(HASH_EARNED_EVERY, Duration::from_millis(5164));
    }
}
