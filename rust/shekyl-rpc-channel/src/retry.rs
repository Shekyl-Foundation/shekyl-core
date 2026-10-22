// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a client does when a handshake does not finish (`RPC_CHANNEL.md`
//! §4.3, ruled 2026-10-20).
//!
//! - **The deadline expired.** The client retries once, without telling the
//!   user, with a fresh ephemeral: a new [`Client::start`](crate::handshake::Client::start),
//!   never the old message 1 again. The retry has a whole deadline of its
//!   own. If it too runs out, the client reports that the node did not
//!   complete the handshake in time.
//! - **The daemon answered busy** (a reply [`is_busy`](crate::handshake::ClientAwaitingMessage2::is_busy)
//!   recognised). The client backs off and starts again, and reports "node
//!   busy" only when the current attempt's deadline would pass before it
//!   could start again.
//! - **Each wait is drawn uniformly from `[b/2, b]`** (D2, confirmed
//!   2026-10-22), where `b` is the back-off: 250 ms, doubling to 2 s.
//!   Without the draw, clients answered busy together retry together.
//!
//! [`HandshakeRetry`] decides; the caller dials, times and starts. It reads
//! no clock and no randomness of its own: the instants are arguments, and
//! the random source is a parameter (`OsRng` in a client), so a test drives
//! it with the instants and the draws it chooses.

use std::time::{Duration, Instant};

use rand_core::RngCore;

use crate::deadline::HANDSHAKE_DEADLINE;

/// The first wait after a busy reply. The budget earns one handshake every
/// 8.7 ms at its ruled 115 a second and holds a second's worth, so a short
/// wait usually finds room; a quarter of a second spreads out the clients
/// that a restart sends back together.
pub const BUSY_BACKOFF_INITIAL: Duration = Duration::from_millis(250);

/// The longest back-off between busy retries: it doubles up to this. With
/// every wait at its top and a busy reply that comes at once, seven retries
/// fit in one handshake deadline; a draw lower in the range, or a reply
/// that takes a round trip, changes the count.
pub const BUSY_BACKOFF_MAX: Duration = Duration::from_secs(2);

/// How an attempt ended without a session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptEnd {
    /// The handshake deadline expired.
    TimedOut,
    /// The daemon answered with its busy reply.
    Busy,
}

/// What the client tells its user, once there is nothing left to try.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeFailure {
    /// "The node did not complete the handshake in time."
    TimedOut,
    /// "The node is busy and did not accept the connection in time."
    Busy,
}

/// The next step after an attempt ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Next {
    /// Start a new attempt, from a new [`Client::start`](crate::handshake::Client::start),
    /// at this instant. Its own deadline is [`HandshakeRetry::deadline_at`].
    StartAt(Instant),
    /// Stop and report.
    Report(HandshakeFailure),
}

/// The retry policy for one connection's handshake, drawing its waits
/// from `R`.
#[derive(Debug)]
pub struct HandshakeRetry<R> {
    /// When the current attempt's deadline expires.
    deadline_at: Instant,
    /// Whether the one retry after a timeout has been spent.
    timeout_retried: bool,
    /// The back-off `b`: the next wait after a busy reply is drawn from
    /// `[b/2, b]`.
    backoff: Duration,
    rng: R,
}

/// A wait drawn uniformly from `[b/2, b]`, at nanosecond grain, from one
/// 64-bit draw scaled by multiply-high rather than reduced modulo. A draw
/// of 0 gives `b/2` and a draw of `u64::MAX` gives `b`.
fn jittered(backoff: Duration, draw: u64) -> Duration {
    let b = u64::try_from(backoff.as_nanos()).unwrap_or(u64::MAX);
    let half = b / 2;
    let span = u128::from(b - half) + 1;
    let offset = (u128::from(draw) * span) >> 64;
    Duration::from_nanos(half + u64::try_from(offset).expect("the offset is at most b - b/2"))
}

impl<R: RngCore> HandshakeRetry<R> {
    /// The policy for a handshake whose first attempt starts at `now`,
    /// drawing its waits from `rng`.
    #[must_use]
    pub fn new(now: Instant, rng: R) -> Self {
        Self {
            deadline_at: now + HANDSHAKE_DEADLINE,
            timeout_retried: false,
            backoff: BUSY_BACKOFF_INITIAL,
            rng,
        }
    }

    /// When the current attempt's deadline expires.
    #[must_use]
    pub fn deadline_at(&self) -> Instant {
        self.deadline_at
    }

    /// The attempt ended as `end`, at `now`: what next.
    pub fn after(&mut self, end: AttemptEnd, now: Instant) -> Next {
        match end {
            AttemptEnd::TimedOut => {
                if self.timeout_retried {
                    return Next::Report(HandshakeFailure::TimedOut);
                }
                self.timeout_retried = true;
                self.deadline_at = now + HANDSHAKE_DEADLINE;
                self.backoff = BUSY_BACKOFF_INITIAL;
                Next::StartAt(now)
            }
            AttemptEnd::Busy => {
                let at = now + jittered(self.backoff, self.rng.next_u64());
                if at >= self.deadline_at {
                    return Next::Report(HandshakeFailure::Busy);
                }
                self.backoff = (self.backoff * 2).min(BUSY_BACKOFF_MAX);
                Next::StartAt(at)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A random source that always draws the same value: `TOP` makes every
    /// wait the whole back-off, `BOTTOM` half of it.
    struct Constant(u64);

    const TOP: u64 = u64::MAX;
    const BOTTOM: u64 = 0;

    impl RngCore for Constant {
        fn next_u32(&mut self) -> u32 {
            u32::try_from(self.0 >> 32).unwrap()
        }
        fn next_u64(&mut self) -> u64 {
            self.0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            dest.fill(0);
            Ok(())
        }
    }

    fn retry(now: Instant, draw: u64) -> HandshakeRetry<Constant> {
        HandshakeRetry::new(now, Constant(draw))
    }

    /// A timeout is retried once, at once, with a whole deadline; a second
    /// timeout is reported.
    #[test]
    fn a_timeout_is_retried_once_then_reported() {
        let t0 = Instant::now();
        let mut retry = retry(t0, TOP);
        assert_eq!(retry.deadline_at(), t0 + HANDSHAKE_DEADLINE);
        let t1 = t0 + HANDSHAKE_DEADLINE;
        assert_eq!(retry.after(AttemptEnd::TimedOut, t1), Next::StartAt(t1));
        assert_eq!(retry.deadline_at(), t1 + HANDSHAKE_DEADLINE);
        let t2 = t1 + HANDSHAKE_DEADLINE;
        assert_eq!(
            retry.after(AttemptEnd::TimedOut, t2),
            Next::Report(HandshakeFailure::TimedOut)
        );
    }

    /// Busy replies are retried after a wait that doubles to its cap, and
    /// "busy" is reported only when the next start would fall at or after
    /// the deadline.
    #[test]
    fn busy_backs_off_and_reports_only_at_the_deadline() {
        let t0 = Instant::now();
        let mut retry = retry(t0, TOP);
        let mut now = t0;
        let mut waits = Vec::new();
        loop {
            match retry.after(AttemptEnd::Busy, now) {
                Next::StartAt(at) => {
                    assert!(at < retry.deadline_at(), "never starts past the deadline");
                    waits.push(at - now);
                    now = at;
                }
                Next::Report(failure) => {
                    assert_eq!(failure, HandshakeFailure::Busy);
                    assert!(
                        now + BUSY_BACKOFF_MAX >= retry.deadline_at(),
                        "reported with time still left for a retry"
                    );
                    break;
                }
            }
        }
        let ms: Vec<u128> = waits.iter().map(Duration::as_millis).collect();
        assert_eq!(&ms[..4], &[250, 500, 1_000, 2_000]);
        assert!(ms[4..].iter().all(|&w| w == 2_000), "capped: {ms:?}");
        assert_eq!(ms.len(), 7, "seven retries at the top of every range");
    }

    /// D2: each wait is drawn from `[b/2, b]`. The bottom of every range is
    /// half the top schedule, and draws in between land in between.
    #[test]
    fn each_wait_is_drawn_from_half_the_backoff_to_all_of_it() {
        let t0 = Instant::now();
        let mut low = retry(t0, BOTTOM);
        let mut waits = Vec::new();
        let mut now = t0;
        while let Next::StartAt(at) = low.after(AttemptEnd::Busy, now) {
            waits.push((at - now).as_millis());
            now = at;
        }
        assert_eq!(&waits[..5], &[125, 250, 500, 1_000, 1_000]);
        for (draw, expected) in [(u64::MAX / 2, 187), (u64::MAX / 4, 156)] {
            let mut mid = retry(t0, draw);
            let Next::StartAt(at) = mid.after(AttemptEnd::Busy, t0) else {
                panic!("retried");
            };
            assert_eq!((at - t0).as_millis(), expected);
        }
        assert_eq!(
            jittered(Duration::from_nanos(1), TOP),
            Duration::from_nanos(1)
        );
        assert_eq!(jittered(Duration::ZERO, TOP), Duration::ZERO);
    }

    /// The boundary is "at or after": a start that would fall exactly on
    /// the deadline is reported, and one a nanosecond sooner is retried.
    #[test]
    fn a_start_exactly_at_the_deadline_is_reported() {
        let t0 = Instant::now();
        let at_cap = |r: &mut HandshakeRetry<Constant>| {
            for _ in 0..4 {
                assert!(matches!(r.after(AttemptEnd::Busy, t0), Next::StartAt(_)));
            }
        };
        let mut exact = retry(t0, TOP);
        at_cap(&mut exact);
        let deadline = exact.deadline_at();
        assert_eq!(
            exact.after(AttemptEnd::Busy, deadline - BUSY_BACKOFF_MAX),
            Next::Report(HandshakeFailure::Busy),
            "a start exactly at the deadline"
        );
        let mut early = retry(t0, TOP);
        at_cap(&mut early);
        let now = deadline - BUSY_BACKOFF_MAX - Duration::from_nanos(1);
        assert_eq!(
            early.after(AttemptEnd::Busy, now),
            Next::StartAt(deadline - Duration::from_nanos(1))
        );
    }

    /// After a timeout the back-off starts again from its first value.
    #[test]
    fn a_timeout_resets_the_backoff() {
        let t0 = Instant::now();
        let mut r = retry(t0, TOP);
        for _ in 0..4 {
            r.after(AttemptEnd::Busy, t0);
        }
        let t1 = t0 + HANDSHAKE_DEADLINE;
        assert_eq!(r.after(AttemptEnd::TimedOut, t1), Next::StartAt(t1));
        assert_eq!(
            r.after(AttemptEnd::Busy, t1),
            Next::StartAt(t1 + BUSY_BACKOFF_INITIAL)
        );
    }

    /// A timeout's retry gets a whole deadline for its own busy replies.
    #[test]
    fn the_retry_after_a_timeout_has_a_deadline_of_its_own() {
        let t0 = Instant::now();
        let mut retry = retry(t0, TOP);
        let t1 = t0 + HANDSHAKE_DEADLINE;
        assert_eq!(retry.after(AttemptEnd::TimedOut, t1), Next::StartAt(t1));
        let near_first_deadline = t1 + Duration::from_millis(100);
        assert_eq!(
            retry.after(AttemptEnd::Busy, near_first_deadline),
            Next::StartAt(near_first_deadline + BUSY_BACKOFF_INITIAL),
            "busy right after the retry starts is retried, from a fresh backoff"
        );
    }

    /// The loop end to end on the real handshake: an empty budget answers
    /// busy, the client recognises it, the policy says start again, and the
    /// new attempt, from a new `Client::start` and so a fresh ephemeral,
    /// completes once the budget has earned a handshake.
    #[test]
    fn busy_then_a_fresh_attempt_completes() {
        use crate::budget::{HandshakeBudget, HANDSHAKE_DAEMON_CPU_NANOS};
        use crate::handshake::{Client, Daemon, Message1Admission, StaticKeypair, MESSAGE1_LEN};

        let network = [0x29u8; 16];
        let daemon = StaticKeypair::generate().unwrap();
        let client = StaticKeypair::generate().unwrap();
        let t0 = Instant::now();
        // A whole core and room for one handshake, which another client
        // spends at t0; the next is earned HANDSHAKE_DAEMON_CPU_NANOS later.
        let budget = HandshakeBudget::with_share(
            1_000,
            Duration::from_nanos(HANDSHAKE_DAEMON_CPU_NANOS),
            t0,
        );
        let other = StaticKeypair::generate().unwrap();
        let (_, spends) = Client::start(&network, &other, daemon.public()).unwrap();
        assert!(
            matches!(
                Daemon::new(&network, &daemon).read_message1(&spends, &budget, t0),
                Ok(Message1Admission::Continue(_))
            ),
            "the one admission is spent on another client"
        );
        let mut retry = retry(t0, TOP);

        let (first, m1) = Client::start(&network, &client, daemon.public()).unwrap();
        let Ok(Message1Admission::Busy(reply)) =
            Daemon::new(&network, &daemon).read_message1(&m1, &budget, t0)
        else {
            panic!("an empty budget answers busy");
        };
        assert!(first.is_busy(&reply));
        let Next::StartAt(at) = retry.after(AttemptEnd::Busy, t0) else {
            panic!("busy before the deadline is retried");
        };
        assert!(at >= t0 + Duration::from_nanos(HANDSHAKE_DAEMON_CPU_NANOS));

        let (second, m1_again) = Client::start(&network, &client, daemon.public()).unwrap();
        assert_ne!(
            m1[..MESSAGE1_LEN],
            m1_again[..MESSAGE1_LEN],
            "a fresh attempt is a fresh message 1"
        );
        assert!(
            !second.is_busy(&reply),
            "the first attempt's busy reply is not the second's"
        );
        let Ok(Message1Admission::Continue(daemon_side)) =
            Daemon::new(&network, &daemon).read_message1(&m1_again, &budget, at)
        else {
            panic!("the budget earned a handshake by then");
        };
        let (_, m2) = daemon_side.write_message2().unwrap();
        second.read_message2(&m2).unwrap();
    }

    /// The deadline the policy holds is the measured one.
    #[test]
    fn the_policy_runs_on_the_measured_deadline() {
        assert_eq!(HANDSHAKE_DEADLINE, Duration::from_secs(11));
    }
}
