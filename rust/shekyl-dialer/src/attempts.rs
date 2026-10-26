// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The dialer's own count of what it has open and what it is opening
//! (dialer brief, "The fill": the open test and the `Keep` count).
//!
//! One address has at most one open test. The test is in flight, which
//! holds a slot, or waiting for its next attempt, which holds none. The
//! address stays an outstanding draw on the lists from the first attempt
//! until the test's one outcome, so nothing else draws it during a wait.
//!
//! The `Keep` count is kept sessions plus in-flight `Keep` attempts. A
//! waiting test and a confirm dial do not count. The board's outbound
//! count knows nothing of an open test.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_draw_rng::{bounded_uniform, RelayRng};
use shekyl_peerlist::{DialOutcome, Host, KeptSessions, NetworkAddress, Tick};

use crate::fill::DialAim;

/// The first attempt of a test. Later attempts are this plus one.
const FIRST_ATTEMPT: u8 = 1;

/// One open test of an address.
///
/// `attempt` is counted from [`FIRST_ATTEMPT`]. On a waiting test it is
/// the attempt that will run when the tick arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Test {
    /// The attempt holds an in-flight slot.
    InFlight { aim: DialAim, attempt: u8 },
    /// The next attempt waits until `due`. No slot, and not a `Keep`.
    Waiting {
        aim: DialAim,
        attempt: u8,
        due: Tick,
    },
}

/// One connector's open tests and kept sessions.
#[derive(Debug, Default)]
pub struct Attempts {
    tests: BTreeMap<NetworkAddress, Test>,
    kept: BTreeSet<NetworkAddress>,
}

impl Attempts {
    /// Nothing open, nothing kept.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt [`FIRST_ATTEMPT`] of `address` starts, in flight.
    ///
    /// `false`, and nothing recorded, when that address already has an
    /// open test or is already a kept session: the candidate filter should
    /// not have offered it.
    pub fn begin(&mut self, address: &NetworkAddress, aim: DialAim) -> bool {
        if self.tests.contains_key(address) || self.kept.contains(address) {
            return false;
        }
        self.tests.insert(
            address.clone(),
            Test::InFlight {
                aim,
                attempt: FIRST_ATTEMPT,
            },
        );
        true
    }

    /// The in-flight test of `address` waits for its next attempt when
    /// this one is below `allowed`.
    ///
    /// `due_of` receives the next attempt number and returns the tick that
    /// attempt may start. Returns that number. The test leaves the
    /// in-flight set.
    ///
    /// `None` when `address` is not in flight, or this attempt is the last
    /// the test allows. The record stays in flight and the caller records
    /// the outcome.
    pub fn defer_retry(
        &mut self,
        address: &NetworkAddress,
        allowed: u8,
        due_of: impl FnOnce(u8) -> Tick,
    ) -> Option<u8> {
        let Some(Test::InFlight { aim, attempt }) = self.tests.get(address).copied() else {
            return None;
        };
        // The next attempt is one past this one, and only while the test
        // still allows it. A counter that cannot advance is the last attempt.
        let next = attempt.checked_add(1).filter(|next| *next <= allowed)?;
        let due = due_of(next);
        self.tests.insert(
            address.clone(),
            Test::Waiting {
                aim,
                attempt: next,
                due,
            },
        );
        Some(next)
    }

    /// The earliest waiting test whose tick has arrived, moved back to
    /// in flight. `None` when none is due. Equal ticks break by address,
    /// so the choice does not depend on the order the waits were stored.
    pub fn take_due(&mut self, now: Tick) -> Option<(NetworkAddress, DialAim)> {
        let due = self
            .tests
            .iter()
            .filter_map(|(address, test)| match *test {
                Test::Waiting { aim, attempt, due } if due.get() <= now.get() => {
                    Some((due.get(), address.clone(), aim, attempt))
                }
                _ => None,
            })
            .min_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        let (_, address, aim, attempt) = due?;
        self.tests
            .insert(address.clone(), Test::InFlight { aim, attempt });
        Some((address, aim))
    }

    /// The test ended with `outcome`. The open test goes on every outcome.
    /// `SessionAccepted` leaves a kept session; nothing else does, a
    /// `Confirmed` included.
    pub fn finish(&mut self, outcome: &DialOutcome) {
        let address = outcome.address();
        self.tests.remove(address);
        if matches!(outcome, DialOutcome::SessionAccepted(_)) {
            self.kept.insert(address.clone());
        }
    }

    /// A kept session closed.
    pub fn session_closed(&mut self, address: &NetworkAddress) {
        self.kept.remove(address);
    }

    /// An open test of `address` was cancelled (the dialer stopped): it
    /// leaves the open tests with no outcome, whether it was in flight or
    /// waiting, and nothing is recorded on the lists. A kept session is
    /// not touched.
    pub fn cancel(&mut self, address: &NetworkAddress) {
        self.tests.remove(address);
    }

    /// The addresses expiry skips, and whose close moves the white clock.
    #[must_use]
    pub fn kept_addresses(&self) -> &BTreeSet<NetworkAddress> {
        &self.kept
    }

    /// The `Keep` count: kept sessions plus in-flight `Keep` attempts. A
    /// waiting test and a pending `Confirm` do not count.
    #[must_use]
    pub fn kept_count(&self) -> usize {
        self.kept.len()
            + self
                .tests
                .values()
                .filter(|test| {
                    matches!(
                        test,
                        Test::InFlight {
                            aim: DialAim::Keep,
                            ..
                        }
                    )
                })
                .count()
    }

    /// Tests in flight, of either aim. A waiting test holds no slot.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.tests
            .values()
            .filter(|test| matches!(test, Test::InFlight { .. }))
            .count()
    }

    /// Whether a test is waiting for its next attempt.
    #[must_use]
    pub fn has_waiting(&self) -> bool {
        self.tests
            .values()
            .any(|test| matches!(test, Test::Waiting { .. }))
    }

    /// Whether `address` is in flight or a kept session.
    ///
    /// A waiting test is neither: it holds no slot, and the outstanding
    /// draw is what keeps the address from being drawn again.
    #[must_use]
    pub fn holds(&self, address: &NetworkAddress) -> bool {
        matches!(self.tests.get(address), Some(Test::InFlight { .. }))
            || self.kept.contains(address)
    }

    /// Whether an in-flight test or a kept session is to `host`, on any
    /// port. One outbound session per host: an in-flight test's host is
    /// not a candidate either. A waiting test does not hold the host.
    #[must_use]
    pub fn holds_host(&self, host: &Host) -> bool {
        self.tests
            .iter()
            .filter(|(_, test)| matches!(test, Test::InFlight { .. }))
            .map(|(address, _)| address)
            .chain(self.kept.iter())
            .any(|address| address.host() == *host)
    }

    /// The kept sessions to close so that no more than `target` remain,
    /// chosen uniformly. Lowering the cap closes `Keep` rows only: an
    /// open test is never what the cap closes. The caller closes each and
    /// reports it with [`Self::session_closed`].
    pub fn over_target<R: RelayRng + ?Sized>(
        &self,
        target: usize,
        rng: &mut R,
    ) -> Vec<NetworkAddress> {
        let excess = self.kept.len().saturating_sub(target);
        let mut pool: Vec<&NetworkAddress> = self.kept.iter().collect();
        let mut out = Vec::with_capacity(excess);
        for _ in 0..excess {
            let Some(last) = pool.len().checked_sub(1) else {
                break;
            };
            let at = usize::try_from(bounded_uniform(rng, last as u64)).unwrap_or(0);
            out.push(pool.swap_remove(at).clone());
        }
        out
    }
}

impl KeptSessions for Attempts {
    fn is_kept(&mut self, address: &NetworkAddress) -> bool {
        self.kept.contains(address)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn peer(n: u8) -> NetworkAddress {
        NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(11, 15, 0, n),
            port: 18080,
        }
    }

    fn at(nanos: u64) -> Tick {
        Tick::new(nanos)
    }

    #[test]
    fn a_retry_waits_without_a_slot_and_the_earliest_due_resumes() {
        let mut attempts = Attempts::new();
        let first = peer(1);
        let second = peer(2);
        assert!(attempts.begin(&first, DialAim::Keep));
        assert!(attempts.begin(&second, DialAim::Confirm));
        assert_eq!(attempts.in_flight(), 2);
        assert_eq!(attempts.kept_count(), 1);

        let resumed = attempts.defer_retry(&first, 3, |_| at(20));
        assert_eq!(resumed, Some(2));
        assert!(attempts.has_waiting());
        assert!(!attempts.holds(&first));
        assert_eq!(attempts.in_flight(), 1);
        assert_eq!(attempts.kept_count(), 0);
        assert!(attempts.take_due(at(19)).is_none());

        let resumed = attempts.defer_retry(&second, 3, |_| at(10));
        assert_eq!(resumed, Some(2));
        assert_eq!(attempts.in_flight(), 0);

        let (address, aim) = attempts.take_due(at(10)).expect("the earlier wait");
        assert_eq!(address, second);
        assert_eq!(aim, DialAim::Confirm);
        assert_eq!(attempts.in_flight(), 1);
        assert!(attempts.has_waiting());

        // The cap refuses another wait and leaves the test in flight.
        assert!(attempts.defer_retry(&second, 2, |_| at(30)).is_none());
        assert_eq!(attempts.in_flight(), 1);

        attempts.finish(&DialOutcome::Confirmed(second));
        assert_eq!(attempts.in_flight(), 0);
        assert!(attempts.kept_addresses().is_empty());

        let (address, aim) = attempts.take_due(at(20)).expect("the later wait");
        assert_eq!((address, aim), (first.clone(), DialAim::Keep));
        attempts.finish(&DialOutcome::SessionAccepted(first.clone()));
        assert!(attempts.kept_addresses().contains(&first));
        assert!(!attempts.has_waiting());
        assert!(attempts.is_kept(&first));
    }

    #[test]
    fn a_cancel_drops_the_open_test_and_leaves_a_kept_session() {
        let mut attempts = Attempts::new();
        let kept = peer(1);
        let flying = peer(2);
        let waiting = peer(3);
        assert!(attempts.begin(&kept, DialAim::Keep));
        attempts.finish(&DialOutcome::SessionAccepted(kept.clone()));
        assert!(attempts.begin(&flying, DialAim::Keep));
        assert!(attempts.begin(&waiting, DialAim::Confirm));
        assert_eq!(attempts.defer_retry(&waiting, 3, |_| at(10)), Some(2));

        attempts.cancel(&flying);
        attempts.cancel(&waiting);
        // A kept session is not an open test. Cancelling its address
        // removes nothing.
        attempts.cancel(&kept);

        assert_eq!(attempts.in_flight(), 0);
        assert!(!attempts.has_waiting());
        assert!(attempts.kept_addresses().contains(&kept));
        assert_eq!(attempts.kept_count(), 1);
    }
}
