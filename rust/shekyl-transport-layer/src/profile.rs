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
//! input is a published retry window, and only a connector whose
//! [`WindowSource`] is [`WindowSource::Published`] reads it.

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

/// Where a connector's retry cutoff comes from. An attempt that times out
/// at or after the cutoff has used the connector's whole window, so its
/// test makes no further attempt (the full-window rule, Rick 2026-10-26).
///
/// The cutoff is not the dial deadline. Every connector has a dial deadline
/// ([`DialProfile::dial_deadline_nanos`]): how long one attempt may run.
/// The retry cutoff is that deadline, or a window published with the route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowSource {
    /// The retry cutoff is the connector's dial deadline. Protocol data.
    Deadline,
    /// Published with the route. The managed Tor publishes its
    /// `SocksTimeout`, read from its earliest expiry. A proxy whose timeout
    /// this node does not know publishes none, and every timeout through it
    /// keeps its retries.
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
    /// S, in nanoseconds. The approved upper bound
    /// `ceil(K / bound) × (dial deadline + the longest wake gap)`, computed
    /// by [`QuietThreshold::derive`] from the row's K, its in-flight bound,
    /// its dial deadline and its wake. Never written as a literal.
    pub span_nanos: u64,
}

impl QuietThreshold {
    /// S for `attempts` (K), from the connector's in-flight bound, its dial
    /// deadline and its wake spacing.
    ///
    /// The product is `ceil(K / bound) × (deadline + the longest wake gap)`.
    /// It is an approved upper bound for the rows in [`dial_profile`], not a
    /// trace of the owner loop: that loop launches one dial per wake and
    /// skips a wake already at the bound. For those rows the product still
    /// sits above the time K such launches take, and it is at least one dial
    /// deadline. A published retry window sits below that deadline. If K,
    /// the bound, the deadline or the wake moves, S follows.
    ///
    /// # Panics
    ///
    /// When `attempts` is zero or `in_flight_bound` is zero. A row with
    /// nothing to count, or no slot to count it in, is not a threshold.
    /// Every row in [`dial_profile`] is evaluated in a constant at build
    /// time (the unnamed constant after the table), so a bad row is a compile
    /// error, never a panic in the dialer.
    #[must_use]
    pub const fn derive(
        attempts: u32,
        in_flight_bound: usize,
        dial_deadline_nanos: u64,
        wake: JitteredSpan,
    ) -> Self {
        assert!(attempts >= 1, "the quiet guard counts at least one attempt");
        assert!(in_flight_bound >= 1, "the in-flight bound is at least one");
        let rounds = (attempts as u64).div_ceil(in_flight_bound as u64);
        Self {
            attempts,
            span_nanos: rounds * (dial_deadline_nanos + wake.base_nanos + wake.jitter_nanos),
        }
    }
}

/// Whether an attempt that opened a stream on this connector shows the
/// link working (`DIALER_OUTAGE_EVIDENCE.md` §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamOpens {
    /// A stream opened on this connector shows its link works.
    Corroborate,
    /// It does not: on this connector a stream to one destination says
    /// nothing about the path to another.
    Ignore,
}

/// Which held sessions' received bytes show the link working. A session
/// merely held never does: a byte must arrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionTraffic {
    /// Bytes received on any session, inbound included. Right where every
    /// session crosses one link an observer cannot split by destination.
    AnySession,
    /// Bytes received on outbound sessions only. An inbound peer chose this
    /// node, and a party that blocks this node's outbound connects can let
    /// established inbound flows continue.
    OutboundOnly,
}

/// What shows this connector's link working around an uncertain failure:
/// the connector's input to the judge. A closed list the dialer can
/// observe; never the probe of this node's own onion, and never anything
/// Tor says about its network (`TSR-Q14`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Corroboration {
    /// Whether a stream that opened counts.
    pub stream_opens: StreamOpens,
    /// Whose received bytes count.
    pub session_traffic: SessionTraffic,
}

/// How the judge reads this connector's failures (Rick, 2026-10-31): its
/// corroboration and its two values. Each value is the connector's own,
/// an `Assumption` with its basis in `DAEMON_RELAY_PRIVACY.md` §97. The
/// mapping of each failure to its evidence is the connector's own stamping
/// into [`crate::DialFailure`], not a field here, so there is one source.
/// Clearing is the judge's behaviour, not a field: a per-connector clearing
/// rule is rejected (rule 21; reopen when a connector shows signs of life
/// while its dials still cannot succeed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailureJudging {
    /// What shows the link working.
    pub corroboration: Corroboration,
    /// δ: an uncertain failure counts only when the link was shown working
    /// within this span before it and within this span after it (the
    /// bracket, `OE-D5`). In nanoseconds.
    pub bracket_nanos: u64,
    /// How long an excused address with no counted failure waits before it
    /// can be drawn again. An address with counted failures cools at its
    /// current rung instead (hold the rung, `OE-D6`).
    pub outage_retry: JitteredSpan,
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
    /// How long one attempt may run, in nanoseconds. The quiet span is
    /// derived from this, the bound, K and the wake.
    pub dial_deadline_nanos: u64,
    /// Where the retry cutoff comes from.
    pub window: WindowSource,
    /// The gap between the dialer's wakes (R3): one wake, one dial.
    pub wake: JitteredSpan,
    /// K: how many unopened attempts the quiet guard counts. The span S is
    /// [`Self::quiet`], derived from this, the bound, the dial deadline and
    /// the wake. Storing K and computing S means a row cannot pair K with
    /// another row's deadline.
    pub quiet_attempts: u32,
    /// How the judge reads this connector's failures.
    pub judging: FailureJudging,
}

impl DialProfile {
    /// The quiet threshold for this row: K as stored, and S derived from
    /// this row's bound, dial deadline and wake.
    #[must_use]
    pub const fn quiet(self) -> QuietThreshold {
        QuietThreshold::derive(
            self.quiet_attempts,
            self.in_flight_bound,
            self.dial_deadline_nanos,
            self.wake,
        )
    }

    /// The retry cutoff in force, in nanoseconds.
    ///
    /// A [`WindowSource::Deadline`] connector answers from its dial deadline
    /// and ignores `published`. A [`WindowSource::Published`] connector
    /// answers with the window its route published, or `None` while that
    /// is unknown.
    #[must_use]
    pub const fn retry_cutoff_nanos(self, published: Option<u64>) -> Option<u64> {
        match self.window {
            WindowSource::Deadline => Some(self.dial_deadline_nanos),
            WindowSource::Published => published,
        }
    }
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

/// Clearnet's in-flight bound. Its quiet span is derived from it.
const CLEARNET_IN_FLIGHT_BOUND: usize = 1;

/// Tor's in-flight bound. Its quiet span is derived from it.
const TOR_IN_FLIGHT_BOUND: usize = 5;

/// Attempts in one clearnet test of a gray address: one. A clearnet dial
/// ends within its deadline, so a second attempt is a redial, and gray has
/// not earned one.
const CLEARNET_GRAY_ATTEMPTS: u8 = 1;

/// Attempts in one clearnet test of a white address: the first, and one
/// redial before a known-working address demotes (Rick, 2026-10-26).
const CLEARNET_WHITE_ATTEMPTS: u8 = 2;

/// Attempts in one Tor test, gray or white. A failed dial is often a
/// descriptor that has not propagated against a peer that is up.
const TOR_ATTEMPTS_PER_TEST: u8 = 3;

/// Clearnet's K. The 2026-10-27 floor series saw 0 failures in 283 attempts
/// to live peers (`dial-profile/2026-10-27-clearnet-pfail`). With none
/// observed, K is read at the 95 % upper bound of the live-failure rate,
/// about 1.1 %: `p_fail` 0.505 at half dead, so K is 11. The point estimate
/// would give 10.
const CLEARNET_QUIET_ATTEMPTS: u32 = 11;

/// Tor's K. The 2026-10-26 short series (`inflight-bound/2026-10-26-final-head`):
/// 189 of 336 attempts failed at half dead, `p_fail` 0.5625, so K is 13.
const TOR_QUIET_ATTEMPTS: u32 = 13;

/// Tor's δ, 15 s. **Assumption** (§97, "Tor failure bracket"). Basis: the
/// 60 s timed sync (`P2P_DEFAULT_HANDSHAKE_INTERVAL`) gives each session
/// about two received messages a minute, and every Tor stream crosses the
/// one guard link, so with `n` sessions a healthy link shows nothing in δ
/// with probability `exp(−n · δ / 30 s)`. Re-derived if that interval moves.
const TOR_BRACKET_NANOS: u64 = 15 * SECOND_NANOS;

/// Tor's outage retry, 10 s + U(0, 5 s). **Assumption** (§97, "Tor outage
/// retry"). Basis: it stays under the slot turnover, `window / bound`, so
/// an excused address is drawable again before a slot comes free and the
/// outage cooldown never holds a slot idle. Checked at build time against
/// the row's dial deadline.
const TOR_OUTAGE_RETRY: JitteredSpan = JitteredSpan {
    base_nanos: 10 * SECOND_NANOS,
    jitter_nanos: 5 * SECOND_NANOS,
};

/// Clearnet's δ, 15 s. **Assumption** (§97, "Clearnet failure bracket").
/// Basis: the 60 s timed sync, on outbound sessions only (clearnet's
/// corroboration excludes inbound). Re-derived if that interval moves.
const CLEARNET_BRACKET_NANOS: u64 = 15 * SECOND_NANOS;

/// Clearnet's outage retry, 10 s + U(0, 5 s). **Assumption** (§97,
/// "Clearnet outage retry"). Basis: it caps redials of an unproven
/// address: with one dial in flight and a deadline of about 1.4 s, at most
/// one redial of such an address per 10–15 s, fewer than one per fill
/// round. Checked at build time against the row's deadline and wake.
const CLEARNET_OUTAGE_RETRY: JitteredSpan = JitteredSpan {
    base_nanos: 10 * SECOND_NANOS,
    jitter_nanos: 5 * SECOND_NANOS,
};

/// `connector`'s dial profile: the only per-connector match for these
/// values.
#[must_use]
pub const fn dial_profile(connector: ConnectorId) -> DialProfile {
    match connector {
        // Clearnet: a dial ends within its deadline, so one at a time costs
        // a wake or two (the 2026-10-08 interim, an Assumption in §97). The
        // retry cutoff is that deadline. S is the row's: eleven rounds at
        // bound 1, each up to the 1.415 s deadline and a 1.5 s wake, 32.065 s.
        ConnectorId::Clearnet => DialProfile {
            target: P2P_DEFAULT_OUT_PEERS,
            in_flight_bound: CLEARNET_IN_FLIGHT_BOUND,
            attempts: AttemptsPerTest {
                gray: CLEARNET_GRAY_ATTEMPTS,
                white: CLEARNET_WHITE_ATTEMPTS,
            },
            retry_waits: RETRY_WAITS,
            cooldown: COOLDOWN,
            dial_deadline_nanos: CLEARNET_DIAL_WITHIN_NANOS,
            window: WindowSource::Deadline,
            wake: WAKE,
            quiet_attempts: CLEARNET_QUIET_ATTEMPTS,
            // A clearnet path is per destination: an on-path party can pass
            // one session and drop the rest, so a stream to one address says
            // nothing about another, and an inbound peer chose this node.
            judging: FailureJudging {
                corroboration: Corroboration {
                    stream_opens: StreamOpens::Ignore,
                    session_traffic: SessionTraffic::OutboundOnly,
                },
                bracket_nanos: CLEARNET_BRACKET_NANOS,
                outage_retry: CLEARNET_OUTAGE_RETRY,
            },
        },
        // Tor: the bound is Measured on the floor device (§97, "In-flight
        // dial bound"). The retry cutoff is the managed Tor's window,
        // published with its route; the dial deadline stays on the row, and
        // S is derived from it. Three rounds at bound 5, each up to the
        // 120 s deadline and a 1.5 s wake, 364.5 s. Every full-window reply
        // seen (104 to 113 s) is inside the deadline.
        ConnectorId::Tor => DialProfile {
            target: MIN_PROVISIONED_OUT_PEERS,
            in_flight_bound: TOR_IN_FLIGHT_BOUND,
            attempts: AttemptsPerTest {
                gray: TOR_ATTEMPTS_PER_TEST,
                white: TOR_ATTEMPTS_PER_TEST,
            },
            retry_waits: RETRY_WAITS,
            cooldown: COOLDOWN,
            dial_deadline_nanos: TOR_DIAL_WITHIN_NANOS,
            window: WindowSource::Published,
            wake: WAKE,
            quiet_attempts: TOR_QUIET_ATTEMPTS,
            // Every Tor stream crosses the one guard link, and an observer
            // on it cannot tell streams apart: it passes all or none.
            judging: FailureJudging {
                corroboration: Corroboration {
                    stream_opens: StreamOpens::Corroborate,
                    session_traffic: SessionTraffic::AnySession,
                },
                bracket_nanos: TOR_BRACKET_NANOS,
                outage_retry: TOR_OUTAGE_RETRY,
            },
        },
    }
}

/// Every row's quiet threshold, evaluated at build time. A row with K or
/// its in-flight bound at zero fails [`QuietThreshold::derive`]'s assertion
/// here, and a row whose S falls short of one dial deadline fails the one
/// below: both are compile errors.
const _: () = {
    let mut index = 0;
    while index < ConnectorId::ALL.len() {
        let profile = dial_profile(ConnectorId::ALL[index]);
        assert!(
            profile.quiet().span_nanos >= profile.dial_deadline_nanos,
            "a quiet span covers at least one dial deadline"
        );
        index += 1;
    }
};

/// The outage-retry bases Rick ruled (2026-10-31), held at build time.
/// Tor's stays under the slot turnover, `deadline / bound` (the published
/// window, shorter than the deadline, only widens the margin it is checked
/// against here, so the managed Tor's 105 s gives 21 s against 15 s).
/// Clearnet's longest redial gap, its base, exceeds one fill round (a
/// deadline and the longest wake), so an excused address is redialed at
/// most once per outage retry.
const _: () = {
    let tor = dial_profile(ConnectorId::Tor);
    let tor_retry = tor.judging.outage_retry;
    assert!(
        tor_retry.base_nanos + tor_retry.jitter_nanos
            < tor.dial_deadline_nanos / tor.in_flight_bound as u64,
        "Tor's outage retry stays under the slot turnover"
    );
    let clearnet = dial_profile(ConnectorId::Clearnet);
    assert!(
        clearnet.judging.outage_retry.base_nanos
            > clearnet.dial_deadline_nanos + clearnet.wake.base_nanos + clearnet.wake.jitter_nanos,
        "clearnet's outage retry caps redials below one per fill round"
    );
    let mut index = 0;
    while index < ConnectorId::ALL.len() {
        assert!(
            dial_profile(ConnectorId::ALL[index]).judging.bracket_nanos > 0,
            "every connector declares a bracket"
        );
        index += 1;
    }
};

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
        assert_eq!(clearnet.dial_deadline_nanos, CLEARNET_DIAL_WITHIN_NANOS);
        assert_eq!(tor.dial_deadline_nanos, TOR_DIAL_WITHIN_NANOS);
        assert_eq!(clearnet.window, WindowSource::Deadline);
        assert_eq!(tor.window, WindowSource::Published);
        assert_eq!((clearnet.quiet().attempts, tor.quiet().attempts), (11, 13));
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

    /// Each connector's quiet span S is derived from its own row (the Tor
    /// lane's review of item 6): `ceil(K / bound)` times the row's dial
    /// deadline plus its longest wake gap, and S covers at least that
    /// deadline. Those two are the properties. The last two assertions are
    /// a record of today's values, 32.065 s on clearnet and 364.5 s on Tor,
    /// as §97, the slice 3 brief and `TOR_SUPERVISOR.md` §4.2 cite them: if
    /// an honest change to K, a bound, a deadline or the wake turns only
    /// those red, the derivation still holds, so update the record here and
    /// in those documents.
    #[test]
    fn the_quiet_span_is_derived_from_the_row() {
        for connector in ConnectorId::ALL {
            let profile = dial_profile(*connector);
            let quiet = profile.quiet();
            let attempts = u64::from(quiet.attempts);
            let bound = profile.in_flight_bound as u64;
            let rounds = attempts.div_ceil(bound);
            let wake = profile.wake.base_nanos + profile.wake.jitter_nanos;
            assert_eq!(
                quiet.span_nanos,
                rounds * (profile.dial_deadline_nanos + wake),
                "{connector:?}"
            );
            assert!(
                quiet.span_nanos >= profile.dial_deadline_nanos,
                "{connector:?}"
            );
        }
        assert_eq!(
            dial_profile(ConnectorId::Clearnet).quiet().span_nanos,
            32_065_000_000
        );
        assert_eq!(
            dial_profile(ConnectorId::Tor).quiet().span_nanos,
            364_500_000_000
        );
    }

    /// The retry cutoff is the row's deadline, or the window the route
    /// published. A publish does not move a deadline connector.
    #[test]
    fn the_retry_cutoff_is_the_deadline_or_what_was_published() {
        let clearnet = dial_profile(ConnectorId::Clearnet);
        let published = Some(1);
        assert_eq!(
            clearnet.retry_cutoff_nanos(published),
            Some(clearnet.dial_deadline_nanos)
        );
        assert_ne!(clearnet.retry_cutoff_nanos(published), published);
        let tor = dial_profile(ConnectorId::Tor);
        assert_eq!(tor.retry_cutoff_nanos(None), None);
        assert_eq!(tor.retry_cutoff_nanos(published), published);
    }
}
