// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The shared hash budget for bounded RPC callers (`RPC_CHANNEL.md` §6.3).
//!
//! One bucket per daemon. A bounded connection pays for `calc_pow` and for
//! each header it asks `fill_pow_hash` on. The host's administrator does
//! not pay. The bucket bounds charges, not measured CPU, in the same shape
//! as the handshake budget:
//!
//! `charges ≤ share × elapsed + capacity`.
//!
//! The share is a quarter of one core, the handshake's share. One charge is
//! one hash: the thread-CPU 99th percentile of a header hash on the floor
//! device. A one-second burst of that share is 250 ms and cannot pay a
//! hash, so the burst holds one hash, the smallest capacity that can. A
//! request for more than one hash is over the burst and is refused without
//! waiting. A request for one hash while the bucket is empty is refused
//! the same way. Both are `OverResourceBound`.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError};

/// One header hash on the floor device, thread-CPU 99th percentile
/// (RT-W10, `docs/benchmarks/rt_w10_request_cost_20261102.md`).
pub const HASH_CPU_NANOS: u64 = 1_290_885_199;

/// The share of one core the long-run charge rate allows, in thousandths.
/// The handshake budget's share.
pub const HASH_BUDGET_SHARE_PERMILLE: u64 = 250;

/// Hashes one full bucket can pay at once. A larger request cannot be
/// served by waiting.
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

    /// Pay for `hashes` from a bounded caller. Zero hashes is free. More
    /// than the burst is refused without spending. One hash spends when
    /// the balance can pay and otherwise leaves the balance where the
    /// refill put it.
    ///
    /// # Errors
    ///
    /// [`ErrorClass::OverResourceBound`] when the request asks for more
    /// hashes than the burst, or the bucket cannot pay one hash now.
    pub fn charge(&self, method: &str, hashes: u64) -> Result<(), RpcError> {
        if hashes == 0 {
            return Ok(());
        }
        if hashes > HASH_BUDGET_BURST {
            return Err(over_burst(method, hashes));
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
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
            Err(budget_empty(method))
        }
    }
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn over_burst(method: &str, asked: u64) -> RpcError {
    RpcError::new(
        ErrorClass::OverResourceBound,
        Diagnostic::new(
            "rpc.bound.exceeded",
            format!(
                "{method} accepts at most {HASH_BUDGET_BURST} hash from a bounded connection; \
                 this request asked for {asked}"
            ),
        )
        .param("method", method)
        .param("bound", HASH_BUDGET_BURST.to_string())
        .param("asked", asked.to_string()),
    )
}

fn budget_empty(method: &str) -> RpcError {
    RpcError::new(
        ErrorClass::OverResourceBound,
        Diagnostic::new(
            "rpc.bound.budget",
            format!(
                "{method} needs a hash and this node's hash budget is empty; \
                 a bounded connection can spend one hash every {} ms",
                HASH_EARNED_EVERY.as_millis()
            ),
        )
        .param("method", method),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_bucket_pays_one_hash_and_then_is_empty() {
        let budget = HashBudget::new(Instant::now());
        assert!(budget.charge("calc_pow", 1).is_ok());
        let err = budget
            .charge("calc_pow", 1)
            .expect_err("the burst was one hash");
        assert_eq!(err.diagnostic.code, "rpc.bound.budget");
    }

    #[test]
    fn more_than_one_hash_is_over_the_burst() {
        let budget = HashBudget::new(Instant::now());
        let err = budget.charge("get_block_headers_range", 2).unwrap_err();
        assert_eq!(err.diagnostic.code, "rpc.bound.exceeded");
        assert!(
            budget.charge("calc_pow", 1).is_ok(),
            "the burst was not spent"
        );
    }

    #[test]
    fn zero_hashes_do_not_spend() {
        let budget = HashBudget::empty(Instant::now());
        assert!(budget.charge("get_block", 0).is_ok());
    }

    #[test]
    fn one_hash_is_about_five_seconds_of_the_share() {
        assert_eq!(HASH_EARNED_EVERY, Duration::from_millis(5164));
    }
}
