// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The handshake budget (`RPC_CHANNEL.md` §4.3).
//!
//! A message 1 that carries a valid mac1 makes the daemon decapsulate with
//! its long-term ML-KEM key and agree with its long-term X25519 key, and if
//! it authenticates, the rest of the handshake follows. Each first
//! presentation of such a mac1 is paid for from this token bucket before
//! either long-term key is touched. One with nothing to pay with is answered
//! busy ([`crate::handshake::Message1Admission::Busy`]), which its sender, a
//! holder of the bundle, can verify. A bad mac1 gets nothing. A mac1 already
//! presented gets nothing either: the replay window admits each one once.
//!
//! The bucket bounds **charges**, not measured CPU. While it starts full,
//!
//! `charges ≤ share × elapsed + capacity`,
//!
//! where `capacity` is [`HANDSHAKE_BUDGET_BURST`] of the share. A window of
//! one second can therefore be charged the burst already saved plus what
//! that second earns. The long-run rate is the share,
//! [`HANDSHAKE_CPU_SHARE_PERMILLE`] thousandths of one core. Each charge is
//! [`HANDSHAKE_DAEMON_CPU_NANOS`], the daemon's whole handshake at the 99th
//! percentile on the floor device, because an admitted message 1 may go on
//! to a full handshake. That percentile is above a tag failure's, so a mix
//! of admitted attempts is priced at or above its measured p99. It is not a
//! ceiling on CPU: a handshake slower than the p99, the mac1 and key check
//! that run before any charge, and work an admission does in a later window
//! sit outside the equality. Nothing here reserves a core for the chain.
//!
//! What it cannot do: XK hides the client until message 3, so nothing
//! before then says whose attempt a message 1 is, and the budget is shared
//! by every sender. A bundle holder can spend it, and can flush the replay
//! window by presenting fresh mac1s. A path observer cannot: minting a mac1
//! takes the bundle. The bundle goes only to clients that will be enrolled
//! (§5), and that is the remaining limit.

use std::collections::{HashSet, VecDeque};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::MAC1_LEN;

/// The daemon's CPU for one handshake, in nanoseconds: the 99th percentile
/// on the floor device, the daemon's steps summed per handshake, mac1
/// included (RT-P6 re-measured with mac1,
/// `docs/benchmarks/rt_p6_mac1_stranger_20261020.md`, 2,163.8 µs).
pub const HANDSHAKE_DAEMON_CPU_NANOS: u64 = 2_163_800;

/// The share of one core the bucket's long-run charge rate allows, in
/// thousandths: a quarter (confirmed 2026-10-20).
///
/// On the floor device that is a sixteenth of the machine, and at
/// [`HANDSHAKE_DAEMON_CPU_NANOS`] it admits 115 handshakes a second, far
/// above what an enrolled set of wallets and tunnels makes (a tunnel holds
/// its sessions open).
pub const HANDSHAKE_CPU_SHARE_PERMILLE: u64 = 250;

/// The burst, in seconds. [`HANDSHAKE_BUDGET_BURST`] is this long.
const HANDSHAKE_BUDGET_BURST_SECS: u64 = 1;

/// How much unspent budget may accumulate: one second's worth, so a burst
/// of reconnecting clients after a restart is served at once.
pub const HANDSHAKE_BUDGET_BURST: Duration = Duration::from_secs(HANDSHAKE_BUDGET_BURST_SECS);

/// Nanoseconds in one second. The burst's admissions are counted from this
/// and [`HANDSHAKE_BUDGET_BURST_SECS`], which is what
/// [`HANDSHAKE_BUDGET_BURST`] is.
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// How many presented mac1s are remembered: the admissions one ruled burst
/// pays for.
///
/// A message 1 is admitted at most once while its mac1 remains here. A
/// quiet daemon never evicts, so a captured message stays dead. Eviction
/// takes this many newer presentations, and a newer presentation takes a
/// fresh mac1, which takes the bundle.
pub const HANDSHAKE_REPLAY_SLOTS: u64 = replay_slots();

const fn replay_slots() -> u64 {
    let burst_ns = HANDSHAKE_BUDGET_BURST_SECS * NANOS_PER_SEC;
    let capacity_ns = burst_ns * HANDSHAKE_CPU_SHARE_PERMILLE / 1_000;
    capacity_ns / HANDSHAKE_DAEMON_CPU_NANOS
}

fn replay_window() -> usize {
    usize::try_from(HANDSHAKE_REPLAY_SLOTS).expect("the ruled burst fits in a window length")
}

/// What a first-or-repeated presentation of one mac1 did to the bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    /// The mac1 was new, and the bucket paid for the long-term work.
    Admitted,
    /// The mac1 was new, and the bucket was empty. The sender is answered busy.
    Busy,
    /// This mac1 was presented before. Nothing is spent and nothing is answered.
    Replay,
}

/// The token bucket and the replay window. One per daemon, shared by every
/// connection. The window and the charge move under one lock, so two
/// presentations of one mac1 cannot both be admitted.
pub struct HandshakeBudget {
    cost_ns: u64,
    share_permille: u64,
    capacity_ns: u64,
    state: Mutex<State>,
}

struct State {
    balance_ns: u64,
    last: Instant,
    /// Mac1s still in the window, for the lookup.
    seen: HashSet<[u8; MAC1_LEN]>,
    /// The same mac1s, oldest first, so a full window drops the oldest.
    order: VecDeque<[u8; MAC1_LEN]>,
}

impl State {
    /// Record `mac1` when it is new. A full window drops the oldest first,
    /// so the window never holds more than [`HANDSHAKE_REPLAY_SLOTS`].
    /// Returns whether this is the first presentation.
    fn remember(&mut self, mac1: &[u8; MAC1_LEN]) -> bool {
        if self.seen.contains(mac1) {
            return false;
        }
        if self.order.len() == replay_window() {
            let oldest = self
                .order
                .pop_front()
                .expect("a full window has an oldest mac1");
            self.seen.remove(&oldest);
        }
        self.seen.insert(*mac1);
        self.order.push_back(*mac1);
        debug_assert_eq!(self.seen.len(), self.order.len());
        true
    }
}

impl HandshakeBudget {
    /// The budget §4.3 rules, full at `now`.
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self::with_share(HANDSHAKE_CPU_SHARE_PERMILLE, HANDSHAKE_BUDGET_BURST, now)
    }

    /// A budget at another share of one core, full at `now`. For
    /// measurement and tests: the daemon uses [`Self::new`]. The replay
    /// window stays [`HANDSHAKE_REPLAY_SLOTS`], the ruled burst, whatever
    /// share this budget charges at.
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
                seen: HashSet::with_capacity(replay_window()),
                order: VecDeque::with_capacity(replay_window()),
            }),
        }
    }

    /// Present `mac1` at `now`. A repeat is [`Admission::Replay`] and does
    /// not move the balance. A first presentation is charged, and remembered
    /// until a ruled burst of newer mac1s has followed it.
    pub(crate) fn present(&self, mac1: &[u8; MAC1_LEN], now: Instant) -> Admission {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        // A repeat returns before the refill, so `last` stays where the
        // previous first presentation left it and the next new mac1 still
        // earns the time that passed.
        if !state.remember(mac1) {
            return Admission::Replay;
        }
        if self.charge(&mut state, now) {
            Admission::Admitted
        } else {
            Admission::Busy
        }
    }

    /// Whether `mac1` is still in the window. The encapsulation-key check
    /// refuses before [`Self::present`], and that refusal must not be
    /// remembered; the admission tests are what can see it.
    #[cfg(test)]
    pub(crate) fn remembers(&self, mac1: &[u8; MAC1_LEN]) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .seen
            .contains(mac1)
    }

    /// Refill from elapsed time, then pay for one admission if the balance allows.
    fn charge(&self, state: &mut State, now: Instant) -> bool {
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
fn tag(n: u64) -> [u8; MAC1_LEN] {
    let mut out = [0u8; MAC1_LEN];
    out[..8].copy_from_slice(&n.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ruled budget admits 115 at once and 115 a second after, and the
    /// replay window is that same burst.
    #[test]
    fn the_ruled_budget_is_115_handshakes_a_second() {
        let t0 = Instant::now();
        let budget = HandshakeBudget::new(t0);
        assert_eq!(budget.burst_admissions(), 115);
        assert_eq!(HANDSHAKE_REPLAY_SLOTS, 115);
        let admitted = (0..1_000)
            .filter(|i| budget.present(&tag(*i), t0) == Admission::Admitted)
            .count();
        assert_eq!(admitted, 115, "the burst, then nothing");
        let later = t0 + Duration::from_secs(1);
        let admitted = (0..1_000)
            .filter(|i| budget.present(&tag(1_000 + *i), later) == Admission::Admitted)
            .count();
        assert_eq!(admitted, 115, "one second earns one second's share");
    }

    /// Over any window, admissions times their cost never exceed the share
    /// of the window plus the burst, however the attempts are spaced.
    #[test]
    fn admitted_charges_never_exceed_the_share_plus_the_burst() {
        let t0 = Instant::now();
        let budget = HandshakeBudget::new(t0);
        let window = Duration::from_secs(10);
        let mut admitted = 0u64;
        let attempts = 100_000u64;
        for i in 0..attempts {
            let now = t0 + window * u32::try_from(i).unwrap() / u32::try_from(attempts).unwrap();
            admitted += u64::from(budget.present(&tag(i), now) == Admission::Admitted);
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
        let burst = budget.burst_admissions();
        for i in 0..burst {
            assert_eq!(budget.present(&tag(i), t0), Admission::Admitted);
        }
        assert_eq!(
            budget.present(&tag(burst), t0.checked_sub(Duration::from_secs(1)).unwrap()),
            Admission::Busy,
            "time that runs backwards earns no admission"
        );
        // Nor does it move the clock back: presenting at t0 again earns
        // nothing for the second it went backwards.
        assert_eq!(
            budget.present(&tag(burst + 1), t0),
            Admission::Busy,
            "a later presentation at t0 earns nothing for the backwards step"
        );
    }

    /// A mac1 takes at most one admission. A repeat leaves the balance where
    /// it was, including after the bucket has had time to refill, and a
    /// ruled burst of newer mac1s is what lets the first be presented again.
    #[test]
    fn a_mac1_is_charged_once_until_the_window_forgets_it() {
        let t0 = Instant::now();
        let two = Duration::from_nanos(HANDSHAKE_DAEMON_CPU_NANOS * 2);
        let budget = HandshakeBudget::with_share(1_000, two, t0);
        assert_eq!(budget.burst_admissions(), 2);
        let first = [0xab; MAC1_LEN];
        assert_eq!(budget.present(&first, t0), Admission::Admitted);
        assert_eq!(budget.present(&first, t0), Admission::Replay);
        assert_eq!(
            budget.present(&first, t0 + Duration::from_secs(30)),
            Admission::Replay,
            "time passing does not make a remembered mac1 fresh"
        );
        assert_eq!(
            budget.present(&tag(1), t0),
            Admission::Admitted,
            "the replay did not spend the second admission"
        );
        assert_eq!(budget.present(&tag(2), t0), Admission::Busy);

        let wide = HandshakeBudget::with_share(1_000, Duration::from_secs(3_600), t0);
        assert_eq!(wide.present(&first, t0), Admission::Admitted);
        for n in 0..HANDSHAKE_REPLAY_SLOTS {
            assert_eq!(wide.present(&tag(n), t0), Admission::Admitted);
        }
        assert_eq!(
            wide.present(&first, t0),
            Admission::Admitted,
            "a ruled burst of newer mac1s evicted the first"
        );
    }

    /// The window is exactly the ruled burst: one newer mac1 short of it,
    /// the first is still refused as a replay.
    #[test]
    fn the_window_holds_exactly_the_ruled_burst() {
        let t0 = Instant::now();
        let wide = HandshakeBudget::with_share(1_000, Duration::from_secs(3_600), t0);
        let first = [0xcd; MAC1_LEN];
        assert_eq!(wide.present(&first, t0), Admission::Admitted);
        for n in 0..HANDSHAKE_REPLAY_SLOTS - 1 {
            assert_eq!(wide.present(&tag(n), t0), Admission::Admitted);
        }
        assert_eq!(
            wide.present(&first, t0),
            Admission::Replay,
            "{} newer mac1s are one short of the window",
            HANDSHAKE_REPLAY_SLOTS - 1
        );
    }

    /// A mac1 answered busy is remembered as well: after the bucket has
    /// refilled, the same message 1 is a replay, not a fresh admission.
    #[test]
    fn a_mac1_answered_busy_is_remembered() {
        let t0 = Instant::now();
        let none = HandshakeBudget::with_share(1_000, Duration::ZERO, t0);
        let one = Duration::from_nanos(HANDSHAKE_DAEMON_CPU_NANOS);
        let refilling = HandshakeBudget::with_share(1_000, one, t0);
        assert_eq!(refilling.present(&tag(0), t0), Admission::Admitted);
        let answered = [0xef; MAC1_LEN];
        assert_eq!(refilling.present(&answered, t0), Admission::Busy);
        assert_eq!(
            refilling.present(&answered, t0 + Duration::from_secs(1)),
            Admission::Replay,
            "the bucket refilled, and the busy-answered mac1 is still spent"
        );
        assert_eq!(none.present(&answered, t0), Admission::Busy);
        assert!(none.remembers(&answered));
    }
}
