// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The handshake budget (`RPC_CHANNEL.md` §4.3).
//!
//! A message 1 that carries a valid mac1 makes the daemon decapsulate with
//! its long-term ML-KEM key and agree with its long-term X25519 key, and if
//! it authenticates, the rest of the handshake follows. Each one is paid for
//! from this token bucket before either long-term key is touched. One with
//! nothing to pay with is answered "busy" (`HandshakeError::Busy`), which
//! its sender, a holder of the bundle, can verify; a bad mac1 gets nothing.
//!
//! The bucket is kept in nanoseconds of daemon CPU, so the rule it enforces
//! reads directly: **handshakes never take more than
//! [`HANDSHAKE_CPU_SHARE_PERMILLE`] thousandths of one core**, over any
//! window longer than [`HANDSHAKE_BUDGET_BURST`]. Each admission costs
//! [`HANDSHAKE_DAEMON_CPU_NANOS`], the daemon's whole handshake at the 99th
//! percentile on the floor device, because an admitted message 1 may go on
//! to a full handshake. A message 1 that fails at its tag costs less
//! (665.5 µs at that percentile), so the bound holds for every mix.
//!
//! What it cannot do: XK hides the client until message 3, so nothing
//! before then says whose attempt a message 1 is, and the budget is shared
//! by every sender. A bundle holder can spend it. The bundle goes only to
//! clients that will be enrolled (§5), and that is the remaining limit.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The daemon's CPU for one handshake, in nanoseconds: the 99th percentile
/// on the floor device, the daemon's steps summed per handshake, mac1
/// included (RT-P6 re-measured with mac1,
/// `docs/benchmarks/rt_p6_mac1_stranger_20261020.md`, 2,163.8 µs).
pub const HANDSHAKE_DAEMON_CPU_NANOS: u64 = 2_163_800;

/// The share of one core handshakes may take, in thousandths: a quarter
/// (confirmed 2026-10-20).
///
/// On the floor device that is a sixteenth of the machine, and at
/// [`HANDSHAKE_DAEMON_CPU_NANOS`] it admits 115 handshakes a second, far
/// above what an enrolled set of wallets and tunnels makes (a tunnel holds
/// its sessions open). The rest of the core, and the other three, stay with
/// the chain.
pub const HANDSHAKE_CPU_SHARE_PERMILLE: u64 = 250;

/// How much unspent budget may accumulate: one second's worth, so a burst
/// of reconnecting clients after a restart is served at once.
pub const HANDSHAKE_BUDGET_BURST: Duration = Duration::from_secs(1);

/// The token bucket. One per daemon, shared by every connection.
pub struct HandshakeBudget {
    cost_ns: u64,
    share_permille: u64,
    capacity_ns: u64,
    state: Mutex<State>,
}

struct State {
    balance_ns: u64,
    last: Instant,
}

impl HandshakeBudget {
    /// The budget §4.3 rules, full at `now`.
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self::with_share(HANDSHAKE_CPU_SHARE_PERMILLE, HANDSHAKE_BUDGET_BURST, now)
    }

    /// A budget at another share of one core, full at `now`. For
    /// measurement and tests: the daemon uses [`Self::new`].
    #[must_use]
    pub fn with_share(share_permille: u64, burst: Duration, now: Instant) -> Self {
        let capacity_ns = nanos(burst).saturating_mul(share_permille) / 1_000;
        Self {
            cost_ns: HANDSHAKE_DAEMON_CPU_NANOS,
            share_permille,
            capacity_ns,
            state: Mutex::new(State {
                balance_ns: capacity_ns,
                last: now,
            }),
        }
    }

    /// Pay for one message 1 at `now`, if the budget allows it.
    pub(crate) fn admit(&self, now: Instant) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let elapsed = nanos(now.saturating_duration_since(state.last));
        if now > state.last {
            state.last = now;
        }
        let earned = elapsed.saturating_mul(self.share_permille) / 1_000;
        state.balance_ns = state
            .balance_ns
            .saturating_add(earned)
            .min(self.capacity_ns);
        if state.balance_ns >= self.cost_ns {
            state.balance_ns -= self.cost_ns;
            true
        } else {
            false
        }
    }

    /// The most admissions the budget can make from full, at once.
    #[must_use]
    pub fn burst_admissions(&self) -> u64 {
        self.capacity_ns / self.cost_ns
    }
}

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ruled budget admits 115 at once and 115 a second after.
    #[test]
    fn the_ruled_budget_is_115_handshakes_a_second() {
        let t0 = Instant::now();
        let budget = HandshakeBudget::new(t0);
        assert_eq!(budget.burst_admissions(), 115);
        let admitted = (0..1_000).filter(|_| budget.admit(t0)).count();
        assert_eq!(admitted, 115, "the burst, then nothing");
        let later = t0 + Duration::from_secs(1);
        let admitted = (0..1_000).filter(|_| budget.admit(later)).count();
        assert_eq!(admitted, 115, "one second earns one second's share");
    }

    /// Over any window, admissions times their cost never exceed the share
    /// of the window plus the burst, however the attempts are spaced.
    #[test]
    fn admitted_cpu_never_exceeds_the_share() {
        let t0 = Instant::now();
        let budget = HandshakeBudget::new(t0);
        let window = Duration::from_secs(10);
        let mut admitted = 0u64;
        let attempts = 100_000u64;
        for i in 0..attempts {
            let now = t0 + window * u32::try_from(i).unwrap() / u32::try_from(attempts).unwrap();
            admitted += u64::from(budget.admit(now));
        }
        let spent = admitted * HANDSHAKE_DAEMON_CPU_NANOS;
        let allowed = nanos(window) * HANDSHAKE_CPU_SHARE_PERMILLE / 1_000
            + nanos(HANDSHAKE_BUDGET_BURST) * HANDSHAKE_CPU_SHARE_PERMILLE / 1_000;
        assert!(spent <= allowed, "{spent} ns admitted against {allowed}");
        assert!(
            spent + HANDSHAKE_DAEMON_CPU_NANOS * 2 > allowed,
            "and the budget is used, not withheld: {spent} of {allowed}"
        );
    }

    /// Time that runs backwards earns nothing and spends nothing extra.
    #[test]
    fn an_earlier_instant_earns_nothing() {
        let t0 = Instant::now() + Duration::from_secs(5);
        let budget = HandshakeBudget::new(t0);
        while budget.admit(t0) {}
        assert!(!budget.admit(t0.checked_sub(Duration::from_secs(1)).unwrap()));
    }
}
