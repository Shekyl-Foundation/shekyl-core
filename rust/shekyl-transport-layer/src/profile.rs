// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Each connector's dial profile (Rick, 2026-10-27): its stand-off and pace
//! parameters, declared as data beside its [`crate::Declaration`] (D7:
//! capabilities are data).
//!
//! The dialer's mechanisms, the retry ladder, the cooldown ladder, the
//! in-flight bound, the fill's target and the wake spacing, are single
//! mechanisms that read their numbers from the dialing connector's profile.
//! A connector supplies numbers, never logic: one that needs a different
//! shape, not different numbers, is a design round, not a plug-in.
//!
//! [`dial_profile`] holds the only per-connector match for these values.
//! Adding a connector is one row, and the compiler refuses a connector
//! without one. Every value is protocol data, the same on every node for
//! that connector (rule 71); none is an operator setting. The one runtime
//! input is a connector's window when it is [`WindowSource::Published`].

use shekyl_relay_privacy::params::{MIN_PROVISIONED_OUT_PEERS, P2P_DEFAULT_OUT_PEERS};

use crate::declaration::ConnectorId;
use crate::spans::{CLEARNET_DIAL_WITHIN_NANOS, TOR_DIAL_WITHIN_NANOS};

/// Nanoseconds in one second.
const SECOND_NANOS: u64 = 1_000_000_000;

/// A span drawn as `base_nanos` plus a uniform draw over
/// `[0, jitter_nanos]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JitteredSpan {
    /// The fixed part, in nanoseconds.
    pub base_nanos: u64,
    /// The width of the uniform part, in nanoseconds.
    pub jitter_nanos: u64,
}

/// How many attempts one test of an address makes, by the list the address
/// is drawn from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptsPerTest {
    /// A gray address: unconfirmed.
    pub gray: u8,
    /// A white address: known-working, so a failed test demotes it, and the
    /// test may give it a redial first (Rick, 2026-10-26).
    pub white: u8,
}

/// The waits between a test's attempts. An attempt after the first follows
/// its wait, and a wait holds no in-flight slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryWaits {
    /// Before the second attempt.
    pub before_second: JitteredSpan,
    /// Before the third attempt, and any later one.
    pub before_third: JitteredSpan,
}

/// The cooldown ladder's ends. The ladder doubles from the first step to the
/// cap, and jitters each step; that shape is the peer list's mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cooldown {
    /// After the first failed test, in nanoseconds.
    pub first_nanos: u64,
    /// The longest, in nanoseconds.
    pub cap_nanos: u64,
}

/// Where a connector's dial window comes from: the span after which a
/// failed attempt has used the connector's whole window, so its test makes
/// no further attempt (the full-window rule, Rick 2026-10-26).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowSource {
    /// The connector's own dial deadline, in nanoseconds.
    DialDeadline(u64),
    /// Published by the connector when its route is published: the managed
    /// Tor's `SocksTimeout`, read from its earliest expiry. A proxy whose
    /// timeout this node does not know publishes none, and every timeout
    /// through it keeps its retries.
    Published,
}

/// The quiet threshold: the evidence that a connector reaches nothing. The
/// dialer's quiet guard holds while the connector holds no session,
/// outbound or inbound, its last `attempts` attempts all ended without
/// opening a stream, and at least `span_nanos` has passed since a stream
/// last opened there; any opened stream resets both. Then a failed test
/// cools at the first step and does not climb, and a white address is not
/// demoted (Rick, 2026-10-26 and 2026-10-27).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuietThreshold {
    /// K: the smallest k with `p_fail^k < 10⁻³` on a working link at the
    /// half-dead fraction, `p_fail` measured on the floor device.
    pub attempts: u32,
    /// S: at least one full window, and at least the time K attempts take
    /// at the connector's bound and pace, in nanoseconds. Computed by
    /// [`QuietThreshold::derive`], never written as a literal.
    pub span_nanos: u64,
}

impl QuietThreshold {
    /// The threshold for `attempts` (K), with S computed from the values it
    /// depends on: the connector's in-flight bound, its dial deadline and
    /// its wake spacing.
    ///
    /// K attempts at bound B are `ceil(K / B)` rounds: each slot runs its
    /// share in turn. An attempt in a round waits at most one wake gap
    /// (`wake.base_nanos + wake.jitter_nanos`) for its launch and holds its
    /// slot at most the dial deadline, which no attempt outlasts. So S is
    /// `ceil(K / B) × (deadline + the longest wake gap)`. It is at least one
    /// full window: a round is at least the deadline, and the deadline is at
    /// least the window. If K, the bound, the deadline or the wake moves, S
    /// follows.
    #[must_use]
    pub const fn derive(
        attempts: u32,
        in_flight_bound: usize,
        dial_deadline_nanos: u64,
        wake: JitteredSpan,
    ) -> Self {
        let rounds = (attempts as u64).div_ceil(in_flight_bound as u64);
        Self {
            attempts,
            span_nanos: rounds * (dial_deadline_nanos + wake.base_nanos + wake.jitter_nanos),
        }
    }
}

/// One connector's dial profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialProfile {
    /// The outbound target: the sessions the fill aims to keep.
    pub target: u32,
    /// The most dials in flight at once, of either aim.
    pub in_flight_bound: usize,
    /// Attempts per test.
    pub attempts: AttemptsPerTest,
    /// The waits between a test's attempts.
    pub retry_waits: RetryWaits,
    /// The cooldown ladder's ends.
    pub cooldown: Cooldown,
    /// Where the dial window comes from.
    pub window: WindowSource,
    /// The gap between the dialer's wakes (R3): one wake, one dial.
    pub wake: JitteredSpan,
    /// The quiet guard's evidence threshold.
    pub quiet: QuietThreshold,
}

/// The retry waits every connector starts from: 5 s + U(0, 5 s) before the
/// second attempt, 20 s + U(0, 10 s) before the third.
///
/// **Assumption** (`DAEMON_RELAY_PRIVACY.md` §97, "Tor dial retry waits"):
/// starting values, re-derived from testnet runs.
const RETRY_WAITS: RetryWaits = RetryWaits {
    before_second: JitteredSpan {
        base_nanos: 5 * SECOND_NANOS,
        jitter_nanos: 5 * SECOND_NANOS,
    },
    before_third: JitteredSpan {
        base_nanos: 20 * SECOND_NANOS,
        jitter_nanos: 10 * SECOND_NANOS,
    },
};

/// The cooldown ladder every connector starts from: two minutes after the
/// first failed test, doubling to one hour (the gray lifecycle, Rick
/// 2026-10-24). What the cap means: a dead address costs each node at most
/// about 24 failed tests a day once it reaches the cap.
///
/// **Assumption** (§97, "Gray cooldown"): starting values, re-derived from
/// testnet runs.
const COOLDOWN: Cooldown = Cooldown {
    first_nanos: 2 * 60 * SECOND_NANOS,
    cap_nanos: 60 * 60 * SECOND_NANOS,
};

/// The wake spacing every connector starts from (R3, Rick 2026-10-12):
/// 0.5 s + U(0, 1.0 s), mean 1 s, drawn per dial.
///
/// **Assumption** (§97, "Dial wake spacing"): re-measured on the Rust dialer
/// after PR-3.
const WAKE: JitteredSpan = JitteredSpan {
    base_nanos: 500_000_000,
    jitter_nanos: SECOND_NANOS,
};

/// Clearnet's in-flight bound, named because its quiet span is derived
/// from it.
const CLEARNET_IN_FLIGHT_BOUND: usize = 1;

/// Tor's in-flight bound, named because its quiet span is derived from it.
const TOR_IN_FLIGHT_BOUND: usize = 5;

/// `connector`'s dial profile: the only per-connector match for these
/// values.
#[must_use]
pub const fn dial_profile(connector: ConnectorId) -> DialProfile {
    match connector {
        // Clearnet: a dial ends within 1.4 s, so one at a time costs a wake
        // or two (the 2026-10-08 interim, an Assumption in §97); one attempt
        // per gray test, and one redial before a white address demotes.
        ConnectorId::Clearnet => DialProfile {
            target: P2P_DEFAULT_OUT_PEERS,
            in_flight_bound: CLEARNET_IN_FLIGHT_BOUND,
            attempts: AttemptsPerTest { gray: 1, white: 2 },
            retry_waits: RETRY_WAITS,
            cooldown: COOLDOWN,
            window: WindowSource::DialDeadline(CLEARNET_DIAL_WITHIN_NANOS),
            wake: WAKE,
            // **Derived** (§97, "Gray cooldown"; shekyl-dev data
            // `dial-profile/2026-10-27-clearnet-pfail`, the floor device):
            // 0 of 283 attempts to live peers failed. With none observed,
            // the estimate is read at its bound: the 95 % upper bound of the
            // live-failure rate, about 1.1 %, gives `p_fail` 0.505 at half
            // dead and K = 11 (the point estimate gives 10). S is derived:
            // eleven rounds at bound 1, each up to the 1.415 s deadline and a
            // 1.5 s wake, 32.065 s.
            quiet: QuietThreshold::derive(
                11,
                CLEARNET_IN_FLIGHT_BOUND,
                CLEARNET_DIAL_WITHIN_NANOS,
                WAKE,
            ),
        },
        // Tor: the bound is Measured on the floor device (§97, "In-flight
        // dial bound"); three attempts per test, since a failed dial is
        // often a descriptor that has not propagated against a peer that is
        // up; the window is the managed Tor's, published with its route.
        ConnectorId::Tor => DialProfile {
            target: MIN_PROVISIONED_OUT_PEERS,
            in_flight_bound: TOR_IN_FLIGHT_BOUND,
            attempts: AttemptsPerTest { gray: 3, white: 3 },
            retry_waits: RETRY_WAITS,
            cooldown: COOLDOWN,
            window: WindowSource::Published,
            wake: WAKE,
            // **Derived** (§97, "Gray cooldown"; shekyl-dev data
            // `inflight-bound/2026-10-26-final-head`, the floor device): 189
            // of 336 attempts failed at half dead, `p_fail` 0.5625, so K = 13.
            // S is derived: three rounds at bound 5, each up to the 120 s
            // deadline and a 1.5 s wake, 364.5 s. Every full-window reply
            // seen (104 to 113 s) is inside the deadline.
            quiet: QuietThreshold::derive(13, TOR_IN_FLIGHT_BOUND, TOR_DIAL_WITHIN_NANOS, WAKE),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{dial_profile, WindowSource};
    use crate::declaration::ConnectorId;
    use crate::spans::{CLEARNET_DIAL_WITHIN_NANOS, TOR_DIAL_WITHIN_NANOS};
    use shekyl_relay_privacy::params::{MIN_PROVISIONED_OUT_PEERS, P2P_DEFAULT_OUT_PEERS};

    /// The profile table moves today's values unchanged (the dial profile
    /// brief, test 2): every connector has a row, the target is the
    /// relay-privacy constant it names, and the bound, attempts, waits,
    /// cooldown, window and wake equal what the dialer and the peer list
    /// held before.
    #[test]
    fn the_profile_table_moves_todays_values() {
        let clearnet = dial_profile(ConnectorId::Clearnet);
        let tor = dial_profile(ConnectorId::Tor);
        assert_eq!(clearnet.target, P2P_DEFAULT_OUT_PEERS);
        assert_eq!(tor.target, MIN_PROVISIONED_OUT_PEERS);
        assert_eq!((clearnet.in_flight_bound, tor.in_flight_bound), (1, 5));
        assert_eq!((clearnet.attempts.gray, clearnet.attempts.white), (1, 2));
        assert_eq!((tor.attempts.gray, tor.attempts.white), (3, 3));
        assert_eq!(
            clearnet.window,
            WindowSource::DialDeadline(CLEARNET_DIAL_WITHIN_NANOS)
        );
        assert_eq!(tor.window, WindowSource::Published);
        assert_eq!((clearnet.quiet.attempts, tor.quiet.attempts), (11, 13));
        for connector in ConnectorId::ALL {
            let profile = dial_profile(*connector);
            let second = profile.retry_waits.before_second;
            let third = profile.retry_waits.before_third;
            assert_eq!(
                (second.base_nanos, second.jitter_nanos),
                (5_000_000_000, 5_000_000_000)
            );
            assert_eq!(
                (third.base_nanos, third.jitter_nanos),
                (20_000_000_000, 10_000_000_000)
            );
            assert_eq!(profile.cooldown.first_nanos, 120_000_000_000);
            assert_eq!(profile.cooldown.cap_nanos, 3_600_000_000_000);
            assert_eq!(
                (profile.wake.base_nanos, profile.wake.jitter_nanos),
                (500_000_000, 1_000_000_000)
            );
            assert!(profile.in_flight_bound as u64 <= u64::from(profile.target));
            assert!(profile.attempts.gray >= 1 && profile.attempts.white >= profile.attempts.gray);
        }
    }

    /// Each connector's quiet span S is derived, not written (the Tor
    /// lane's review of item 6): `ceil(K / bound)` rounds, each up to the
    /// connector's dial deadline and its longest wake gap, computed here from
    /// the named constants, and S covers at least one full window. Those two
    /// are the properties. The last two assertions are a record of today's
    /// values, 32.065 s on clearnet and 364.5 s on Tor, as §97, the slice 3
    /// brief and `TOR_SUPERVISOR.md` §4.2 cite them: if an honest change to K,
    /// a bound, a deadline or the wake turns only those red, the derivation
    /// still holds, so update the record here and in those documents.
    #[test]
    fn the_quiet_span_is_derived_from_the_bound_the_deadline_and_the_wake() {
        for (connector, deadline) in [
            (ConnectorId::Clearnet, CLEARNET_DIAL_WITHIN_NANOS),
            (ConnectorId::Tor, TOR_DIAL_WITHIN_NANOS),
        ] {
            let profile = dial_profile(connector);
            let attempts = u64::from(profile.quiet.attempts);
            let bound = profile.in_flight_bound as u64;
            let rounds = attempts.div_ceil(bound);
            let wake = profile.wake.base_nanos + profile.wake.jitter_nanos;
            assert_eq!(
                profile.quiet.span_nanos,
                rounds * (deadline + wake),
                "{connector:?}"
            );
            assert!(profile.quiet.span_nanos >= deadline, "{connector:?}");
            if let WindowSource::DialDeadline(window) = profile.window {
                assert!(profile.quiet.span_nanos >= window, "{connector:?}");
            }
        }
        assert_eq!(
            dial_profile(ConnectorId::Clearnet).quiet.span_nanos,
            32_065_000_000
        );
        assert_eq!(
            dial_profile(ConnectorId::Tor).quiet.span_nanos,
            364_500_000_000
        );
    }
}
