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

    /// Waiting tests whose tick has arrived, earliest first.
    ///
    /// Equal ticks break by address, so the order does not depend on the
    /// order the waits were stored. Listing them does not move them: the
    /// caller resumes the one it will dial. A wait whose host is occupied
    /// stays here, with the same due, until a later wake.
    #[must_use]
    pub fn due(&self, now: Tick) -> Vec<(NetworkAddress, DialAim)> {
        let mut due: Vec<(u64, NetworkAddress, DialAim)> = self
            .tests
            .iter()
            .filter_map(|(address, test)| match *test {
                Test::Waiting { aim, due, .. } if due.get() <= now.get() => {
                    Some((due.get(), address.clone(), aim))
                }
                _ => None,
            })
            .collect();
        due.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        due.into_iter()
            .map(|(_, address, aim)| (address, aim))
            .collect()
    }

    /// Move `address`'s waiting test back to in flight.
    ///
    /// `None` when `address` has no waiting test. The attempt number and
    /// the aim are the ones the wait stored.
    pub fn resume(&mut self, address: &NetworkAddress) -> Option<DialAim> {
        let Test::Waiting { aim, attempt, .. } = self.tests.get(address).copied()? else {
            return None;
        };
        self.tests
            .insert(address.clone(), Test::InFlight { aim, attempt });
        Some(aim)
    }

    /// The earliest waiting test whose tick has arrived, moved back to
    /// in flight. `None` when none is due.
    pub fn take_due(&mut self, now: Tick) -> Option<(NetworkAddress, DialAim)> {
        let (address, _) = self.due(now).into_iter().next()?;
        let aim = self.resume(&address)?;
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

    /// Sessions held now, without the dials still in a test.
    #[must_use]
    pub fn held(&self) -> usize {
        self.kept.len()
    }

    /// The addresses expiry skips, and whose close moves the white clock.
    #[must_use]
    pub fn kept_addresses(&self) -> &BTreeSet<NetworkAddress> {
        &self.kept
    }

    /// The `Keep` count: kept sessions plus every open `Keep` test, in
    /// flight or waiting for its next attempt. A `Keep` test holds its
    /// target slot from its draw to its outcome, waits included, so a retry
    /// that comes due can never keep past the target. A pending `Confirm`
    /// does not count. *Records-was (2026-10-24 to 2026-10-26): a waiting
    /// test did not count, and a due `Keep` retry could keep one session
    /// past the target.*
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
                        } | Test::Waiting {
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

    /// Whether an in-flight test or a kept session names `host`, on any
    /// port.
    ///
    /// A waiting test does not. The outstanding draw already keeps that
    /// address from being drawn again, and the wait must not block its
    /// own resumption. A live session is not in this set: the candidate
    /// filter reads the board beside it ([`crate::candidate::host_occupied`]).
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
        assert_eq!(
            attempts.kept_count(),
            1,
            "the waiting keep holds no slot but still holds its target place"
        );
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

    /// Listing the due retries does not move them, and resuming one
    /// leaves the others waiting. A waiting test does not hold its host,
    /// so the wait cannot block its own resumption.
    #[test]
    fn listing_due_retries_leaves_them_waiting_until_one_is_resumed() {
        let mut attempts = Attempts::new();
        let earlier = peer(1);
        let later = peer(2);
        assert!(attempts.begin(&earlier, DialAim::Keep));
        assert!(attempts.begin(&later, DialAim::Confirm));
        assert_eq!(attempts.defer_retry(&earlier, 3, |_| at(10)), Some(2));
        assert_eq!(attempts.defer_retry(&later, 3, |_| at(20)), Some(2));

        let listed = attempts.due(at(20));
        assert_eq!(
            listed,
            vec![
                (earlier.clone(), DialAim::Keep),
                (later.clone(), DialAim::Confirm),
            ]
        );
        assert_eq!(attempts.in_flight(), 0, "listing does not resume");
        assert!(!attempts.holds_host(&earlier.host()));
        assert!(!attempts.holds_host(&later.host()));

        assert_eq!(attempts.resume(&later), Some(DialAim::Confirm));
        assert_eq!(attempts.in_flight(), 1);
        assert_eq!(attempts.due(at(20)), vec![(earlier.clone(), DialAim::Keep)]);
        assert!(attempts.resume(&earlier).is_some());
        assert!(attempts.resume(&earlier).is_none(), "already in flight");
    }
}
