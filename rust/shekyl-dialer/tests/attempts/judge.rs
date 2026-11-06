// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The judge (`DIALER_OUTAGE_EVIDENCE.md` §4, `OE-D8`) against the brief's
//! tests (`DIALER_OUTAGE_EVIDENCE_BRIEF.md` §6), on the real dialer over
//! the attempt rig. The judge reads its own clock ([`Life::install_own`]):
//! a dial the rig refuses moves the engine's clock by the time it took, and
//! the test moves the judge's, so five tests can fail inside one bracket.
//! Each test names the edit that makes it fail.

use std::sync::Arc;
use std::time::Duration;

use shekyl_dialer::{Dialer, Launch};
use shekyl_draw_rng::SplitMix64;
use shekyl_p2p_session::harness::Wire;
use shekyl_p2p_session::Endpoint;
use shekyl_peerlist::{dial_profile, ConnectorId, NetworkAddress, Tick};
use shekyl_timing_engine::{Clock, ManualClock};
use shekyl_transport_layer::{DialEnd, SocketId};

use super::life::Life;
use super::rig::{Answer, Rig};
use super::{onions, peer, reply, CLEARNET, NETWORK, TOR, TOR_WINDOW};

/// The judge's clock at the start, in milliseconds.
const START_MS: u64 = 1_000_000;

/// Far enough on the judge's clock that nothing before it is inside a
/// bracket.
const PAST_THE_BRACKET_MS: u64 = 60_000;

struct JudgeRig {
    rig: Rig,
    clock: ManualClock,
    dialer: Arc<Dialer<ManualClock>>,
    connector: ConnectorId,
    life: Life,
    rng: SplitMix64,
    /// The far sides of the inbound sessions this rig accepted, open for
    /// the test.
    inbound: Vec<Wire>,
}

impl JudgeRig {
    fn new(connector: ConnectorId, seed: u64) -> Self {
        let clock = ManualClock::new(Tick::new(1_000_000_000));
        let rig = Rig::on(&clock);
        let dialer = Arc::clone(&rig.dialer);
        dialer.set_window(TOR, Some(TOR_WINDOW));
        let life = Life::install_own(&dialer, START_MS);
        Self {
            rig,
            clock,
            dialer,
            connector,
            life,
            rng: SplitMix64::new(seed),
            inbound: Vec::new(),
        }
    }

    /// Accept an inbound Tor connection and, with `established`, run its
    /// handshake from the far side. The far side is held for the test.
    fn accept_tor(&mut self, established: bool) -> SocketId {
        let mut wire = self.rig.accept(Endpoint::TorInbound);
        if established {
            self.rig.establish_inbound(&mut wire);
        }
        let id = wire.id;
        self.inbound.push(wire);
        id
    }

    /// `count` addresses on the rig's connector, numbered from `from`.
    fn addresses(&self, from: usize, count: usize) -> Vec<NetworkAddress> {
        match self.connector {
            ConnectorId::Tor => onions(from + count).split_off(from),
            ConnectorId::Clearnet => (from..from + count)
                .map(|n| peer(800 + u16::try_from(n).expect("small")))
                .collect(),
        }
    }

    /// Admit `addresses` as gray.
    fn admit(&mut self, addresses: &[NetworkAddress]) {
        for address in addresses {
            self.dialer
                .admit_operator(address, self.clock.now(), &mut self.rng)
                .expect("admitted");
        }
    }

    /// Dial one drawable address and let it answer: a stream that opens,
    /// kept or confirmed as the plan aims. Returns the sessions it left
    /// held.
    fn open_one(&mut self) -> Vec<SocketId> {
        let before = self.rig.opened();
        self.rig.peer.answer_next(Answer::Answered(reply(NETWORK)));
        assert!(self.dialer.wake(self.connector, &mut self.rng), "a dial");
        self.rig
            .opened()
            .into_iter()
            .filter(|id| !before.contains(id))
            .collect()
    }

    /// A session held through the test, whose bytes are what it shows the
    /// judge: an inbound Tor session (Tor counts inbound), an outbound
    /// clearnet one (clearnet counts outbound only). Call it before any
    /// other address is admitted.
    fn hold(&mut self, from: usize) -> SocketId {
        match self.connector {
            ConnectorId::Tor => self.accept_tor(true),
            ConnectorId::Clearnet => {
                let address = self.addresses(from, 1);
                self.admit(&address);
                let held = self.open_one();
                assert_eq!(held.len(), 1, "the first dial keeps");
                held[0]
            }
        }
    }

    /// `count` white addresses numbered from `from`, each kept and then
    /// closed by its peer, so none is held. The judge's clock then moves
    /// past the keeps' streams.
    fn whites(&mut self, from: usize, count: usize) -> Vec<NetworkAddress> {
        let addresses = self.addresses(from, count);
        self.admit(&addresses);
        let ids: Vec<SocketId> = (0..count).flat_map(|_| self.open_one()).collect();
        for id in ids {
            self.rig.close_as_peer(id);
        }
        for address in &addresses {
            assert!(self.lists_white(address), "{address:?} white");
        }
        self.later(PAST_THE_BRACKET_MS);
        addresses
    }

    /// Move the judge's clock on by `ms`.
    fn later(&self, ms: u64) {
        self.life.set_ms(self.life.now_ms() + ms);
    }

    /// Move the engine's clock on by `by`.
    fn advance(&self, by: Duration) {
        let by = u64::try_from(by.as_nanos()).expect("a short span");
        self.clock.set(Tick::new(self.clock.now().get() + by));
    }

    /// One attempt at a drawable address, failing with `cause` after
    /// `took` on the engine's clock.
    fn fail(&mut self, cause: DialEnd, took: Duration) {
        self.rig.peer.refuse_after(cause, took);
        assert!(self.dialer.wake(self.connector, &mut self.rng), "a draw");
    }

    /// A test that ends on its one attempt with uncertain evidence: Tor's
    /// general failure (`0x01`), final at once; clearnet's dial deadline,
    /// which is its whole window.
    fn fail_uncertain(&mut self) {
        let (cause, took) = match self.connector {
            ConnectorId::Tor => (shekyl_tor::reply_end(0x01), Duration::from_secs(1)),
            ConnectorId::Clearnet => (
                shekyl_clearnet::Observed::Deadline.end(),
                Duration::from_nanos(dial_profile(CLEARNET).dial_deadline_nanos),
            ),
        };
        self.fail(cause, took);
    }

    /// Past the last failure's bracket on the judge's clock, and the
    /// verdicts due performed.
    fn close_bracket(&mut self) {
        let bracket = dial_profile(self.connector).judging.bracket_nanos / 1_000_000;
        self.later(bracket + 1);
        self.dialer.apply_verdicts(&mut self.rng);
    }

    fn pending(&self) -> usize {
        self.dialer.pending_verdicts(self.connector)
    }

    fn lists_white(&self, address: &NetworkAddress) -> bool {
        self.dialer.shared().lists.is_white(address)
    }

    fn cooling(&self, address: &NetworkAddress) -> bool {
        self.dialer.shared().lists.is_cooling(address)
    }

    fn excused(&self, address: &NetworkAddress) -> bool {
        self.dialer.shared().lists.is_excused(address)
    }

    fn failures(&self, address: &NetworkAddress) -> u32 {
        self.dialer.shared().lists.failed_tests(address)
    }

    fn demoted(&self, address: &NetworkAddress) -> bool {
        !self.lists_white(address) && self.cooling(address)
    }
}

/// A Tor block in progress: a held inbound session, five white addresses,
/// and a gray `climbed` with one counted failure. The session's last byte
/// was the onset; the five white tests failed inside the bracket after it,
/// and their verdicts wait.
struct Block {
    rig: JudgeRig,
    whites: Vec<NetworkAddress>,
    climbed: NetworkAddress,
}

fn tor_block(seed: u64) -> Block {
    let mut rig = JudgeRig::new(TOR, seed);
    let held = rig.hold(0);
    // `climbed` takes one counted failure while the link works.
    let climbed = rig.addresses(10, 1).remove(0);
    rig.admit(std::slice::from_ref(&climbed));
    rig.life.received_now(held);
    rig.fail_uncertain();
    rig.later(1_000);
    rig.life.received_now(held);
    rig.close_bracket();
    assert_eq!(rig.failures(&climbed), 1, "counted while the link worked");

    let whites = rig.whites(0, 5);
    // The onset: the held session's last byte.
    rig.life.received_now(held);
    for _ in 0..5 {
        rig.later(1_000);
        rig.fail_uncertain();
    }
    Block {
        rig,
        whites,
        climbed,
    }
}

impl Block {
    /// The block holds: past the onset's bracket the five verdicts are
    /// performed; then, with nothing showing the link worked, `climbed`
    /// (its rung's cooldown over) and a fresh gray address each fail a
    /// test. The whites' outage retries are over too, so a wake may draw
    /// one of them first: it fails and is excused again. Returns the fresh
    /// address.
    fn hold_the_block(&mut self) -> NetworkAddress {
        let rig = &mut self.rig;
        rig.close_bracket();
        rig.later(PAST_THE_BRACKET_MS);
        rig.advance(Duration::from_secs(200));
        let unproven = rig.addresses(11, 1).remove(0);
        rig.admit(std::slice::from_ref(&unproven));
        for _ in 0..20 {
            if rig.excused(&self.climbed) && rig.excused(&unproven) {
                break;
            }
            rig.fail_uncertain();
        }
        assert!(rig.excused(&self.climbed) && rig.excused(&unproven));
        unproven
    }
}

/// **The onset of a Tor silent-drop block** (the brief's test 1 and
/// invariant 7): five white tests fail inside the bracket after the last
/// byte. Their verdicts wait without holding a slot: the dialer still
/// dials, and nothing in flight or kept counts them, and an address whose
/// verdict waits is not dialed again. With nothing after the failures, all
/// five are excused and white keeps every entry. The edits that make this
/// red: counting at the bracket's end on the before side alone, or drawing
/// an address whose verdict waits.
#[test]
fn an_outages_onset_excuses_the_tests_in_flight() {
    let Block {
        mut rig, whites, ..
    } = tor_block(201);
    assert_eq!(rig.pending(), 5, "the bound's worth of verdicts waits");
    assert_eq!(rig.dialer.in_flight(TOR), 0, "and holds no in-flight slot");
    assert_eq!(rig.dialer.kept_sessions(TOR), 0, "nor a target place");
    for address in &whites {
        assert!(rig.lists_white(address) && !rig.cooling(address));
    }
    let connects = rig.rig.peer.connects();
    let fresh = rig.addresses(12, 1);
    rig.admit(&fresh);
    rig.fail(shekyl_tor::reply_end(0x08), Duration::ZERO);
    assert_eq!(
        rig.rig.peer.connects(),
        connects + 1,
        "the dialer dials while the verdicts wait"
    );

    rig.close_bracket();
    assert_eq!(rig.pending(), 0);
    for address in &whites {
        assert!(
            rig.lists_white(address) && !rig.cooling(address),
            "{address:?}: an outage's onset demotes nothing"
        );
        assert_eq!(rig.failures(address), 0);
        assert!(rig.excused(address), "{address:?} waits its outage retry");
    }
}

/// **The block itself** (the brief's test 1, continued): a gray address
/// with counted failures that fails in the block cools at its current
/// rung, and one with none takes the outage retry. Nothing climbs. The
/// edit that makes this red: counting an uncorroborated failure.
#[test]
fn in_a_block_nothing_climbs_and_white_stays() {
    let mut block = tor_block(202);
    let unproven = block.hold_the_block();
    let rig = &block.rig;
    assert_eq!(
        rig.pending(),
        0,
        "nothing before the failures: excused at once"
    );
    assert_eq!(rig.failures(&block.climbed), 1, "it holds its rung");
    assert!(rig.cooling(&block.climbed) && rig.excused(&block.climbed));
    assert_eq!(rig.failures(&unproven), 0);
    assert!(rig.cooling(&unproven) && rig.excused(&unproven));
    for address in &block.whites {
        assert!(rig.lists_white(address), "{address:?} stays white");
    }
}

/// **After the block, the first sign of life** (the brief's test 3,
/// `OE-D6` clearing): a stream that opens clears the excusals of addresses
/// with no counted failure, white and gray, which are drawable at once;
/// the address with a counted failure keeps its rung. The edit that makes
/// this red: clearing every excused seat, or clearing none.
#[test]
fn the_first_sign_of_life_clears_only_the_excusals_with_no_counted_failure() {
    let mut block = tor_block(203);
    let unproven = block.hold_the_block();
    let fresh = block.rig.addresses(13, 1);
    block.rig.admit(&fresh);
    block.rig.open_one();
    let rig = &block.rig;
    for address in &block.whites {
        assert!(
            rig.lists_white(address) && !rig.excused(address),
            "{address:?}: white is drawable again"
        );
    }
    assert!(
        !rig.cooling(&unproven) && !rig.excused(&unproven),
        "a gray address with no counted failure is drawable again"
    );
    assert!(
        rig.cooling(&block.climbed),
        "the address with a counted failure keeps its rung"
    );
    assert_eq!(rig.failures(&block.climbed), 1);
}

/// **The bracket needs the link shown working on both sides** (the brief's
/// test 2), both connectors: a sign of life within δ before the failure,
/// other than the failing attempt (on Tor, another attempt's stream
/// opening, or a byte on a session), and one within δ after. With both the
/// white address is demoted when the bracket closes; with one side only it
/// is excused. The edits that make this red: dropping the after side, or
/// dropping the before side.
#[test]
fn a_failure_counts_only_with_life_on_both_sides_of_it() {
    for connector in [TOR, CLEARNET] {
        for (case, before, after) in [
            ("both sides", true, true),
            ("before only", true, false),
            ("after only", false, true),
        ] {
            let mut rig = JudgeRig::new(connector, 210);
            let held = rig.hold(20);
            let white = rig.whites(0, 1).remove(0);
            if before {
                if connector == TOR && after {
                    // Another attempt's stream opens, just before.
                    let other = rig.addresses(30, 1);
                    rig.admit(&other);
                    rig.open_one();
                } else {
                    rig.life.received_now(held);
                }
            }
            rig.later(1_000);
            rig.fail_uncertain();
            assert_eq!(
                rig.pending(),
                usize::from(before),
                "{connector:?} {case}: the verdict waits only with life before"
            );
            if after {
                rig.later(1_000);
                rig.life.received_now(held);
            }
            rig.close_bracket();
            assert_eq!(rig.demoted(&white), before && after, "{connector:?} {case}");
            assert_eq!(rig.lists_white(&white), !(before && after));
        }
    }
}

/// **A Destination failure with no corroboration counts** (the brief's
/// test 4), both connectors: a refusal is the destination's answer, never
/// excused as an outage. The edit that makes this red: sending Destination
/// evidence through the bracket.
#[test]
fn a_destination_failure_counts_without_corroboration() {
    for (connector, cause) in [
        (TOR, shekyl_tor::reply_end(0x05)),
        (
            CLEARNET,
            shekyl_clearnet::Observed::HandshakeUnverified.end(),
        ),
    ] {
        let mut rig = JudgeRig::new(connector, 220);
        let gray = rig.addresses(0, 1);
        rig.admit(&gray);
        rig.fail(cause, Duration::ZERO);
        assert_eq!(rig.pending(), 0, "{connector:?}: no wait");
        assert_eq!(rig.failures(&gray[0]), 1, "{connector:?}: counted");
        assert!(!rig.excused(&gray[0]));
    }
}

/// **A Local failure never counts** (the brief's test 5), both connectors,
/// even with the link shown working throughout (which also clears the
/// excusal at the next look). The edit that makes this red: judging Local
/// evidence by the bracket.
#[test]
fn a_local_failure_never_counts() {
    for (connector, cause) in [
        (TOR, shekyl_tor::reply_end(0x08)),
        (
            CLEARNET,
            shekyl_clearnet::Observed::ProxyConnectFailed.end(),
        ),
    ] {
        let mut rig = JudgeRig::new(connector, 230);
        rig.hold(20);
        rig.life.keep_alive();
        let gray = rig.addresses(0, 1);
        rig.admit(&gray);
        rig.fail(cause, Duration::ZERO);
        assert_eq!(rig.pending(), 0, "{connector:?}: no wait");
        rig.close_bracket();
        assert_eq!(rig.failures(&gray[0]), 0, "{connector:?}: never counted");
        assert!(
            !rig.cooling(&gray[0]),
            "{connector:?}: the link's next sign of life cleared the excusal"
        );
    }
}

/// **Boot with the network down** (the brief's test 6), both connectors:
/// white and gray addresses from before the boot, no session, every test
/// failing. No demotion, no climb, and no verdict waits. The edit that
/// makes this red: counting an uncorroborated failure.
#[test]
fn boot_with_the_network_down_demotes_and_climbs_nothing() {
    for connector in [TOR, CLEARNET] {
        let mut rig = JudgeRig::new(connector, 240);
        let whites = rig.whites(0, 3);
        let grays = rig.addresses(10, 3);
        rig.admit(&grays);
        for _ in 0..6 {
            rig.later(1_000);
            rig.fail_uncertain();
        }
        assert_eq!(rig.pending(), 0, "{connector:?}");
        for address in &whites {
            assert!(rig.lists_white(address), "{connector:?} {address:?}");
        }
        for address in whites.iter().chain(&grays) {
            assert_eq!(rig.failures(address), 0, "{connector:?} {address:?}");
        }
    }
}

/// **The probe never corroborates** (the brief's test 7, `DIALER_OUTAGE_
/// EVIDENCE.md` §3.3). The probe of this node's own onion arrives as an
/// inbound Tor connection, and Tor's corroboration counts inbound sessions;
/// but the probe is dropped in its handshake, before its row is
/// established, so its bytes are never read. A byte on that row leaves the
/// failure excused at once; the same byte on an established row defers it.
/// The edit that makes this red: reading the board's rows without the
/// established check.
#[test]
fn the_probe_never_corroborates() {
    let mut rig = JudgeRig::new(TOR, 250);
    let probe = rig.accept_tor(false);
    let white = rig.whites(0, 1).remove(0);
    rig.life.received_now(probe);
    rig.later(1_000);
    rig.fail_uncertain();
    assert_eq!(rig.pending(), 0, "the probe's byte is not a sign of life");
    assert!(rig.lists_white(&white) && rig.excused(&white));

    let mut rig = JudgeRig::new(TOR, 251);
    let session = rig.accept_tor(true);
    rig.whites(0, 1);
    rig.life.received_now(session);
    rig.later(1_000);
    rig.fail_uncertain();
    assert_eq!(rig.pending(), 1, "an established session's byte is");
}

/// **The judge's last sign of life on Tor** is published on the tally, as
/// a tick on the process clock, for the posture line (§6): a stream that
/// opens moves it, and so does a byte a session receives; a failure does
/// not. The edit that makes this red: not publishing a sign of life.
#[test]
fn the_tally_carries_the_judges_last_sign_of_life() {
    let mut rig = JudgeRig::new(TOR, 260);
    assert_eq!(rig.dialer.tor_link_tally().last_sign_of_life, None);
    let held = rig.hold(0);
    rig.whites(0, 1);
    let opened = rig.dialer.tor_link_tally().last_sign_of_life;
    assert!(opened.is_some(), "the keeps' streams opened");

    rig.advance(Duration::from_secs(5));
    rig.fail_uncertain();
    assert_eq!(
        rig.dialer.tor_link_tally().last_sign_of_life,
        opened,
        "a failure is not a sign of life"
    );

    rig.later(1_000);
    rig.life.received_now(held);
    let now = rig.clock.now();
    rig.dialer.apply_verdicts(&mut rig.rng);
    assert_eq!(rig.dialer.tor_link_tally().last_sign_of_life, Some(now));
}

/// **The after side is bounded** (#1235 review, F1), both connectors. A
/// verdict resolved late, past its deadline: a sign of life at the
/// deadline plus one, the link coming back after an outage, does not count
/// a failure from inside it; a sign of life just after the failure does,
/// however late it is read. The edit that makes this red: dropping the
/// deadline from `closes_the_bracket`, or reading the after side when the
/// verdict is performed.
#[test]
fn a_late_resolution_counts_only_life_inside_the_bracket() {
    for connector in [TOR, CLEARNET] {
        for (case, life_after_ms, demoted) in [
            ("just after the failure", 1, true),
            ("past the deadline", 1, false),
        ] {
            let mut rig = JudgeRig::new(connector, 270);
            let held = rig.hold(20);
            let white = rig.whites(0, 1).remove(0);
            rig.life.received_now(held);
            rig.later(1_000);
            rig.fail_uncertain();
            assert_eq!(rig.pending(), 1, "{connector:?} {case}");
            let failed = rig.life.now_ms();
            let bracket = dial_profile(connector).judging.bracket_nanos / 1_000_000;
            let life = if demoted {
                failed + life_after_ms
            } else {
                failed + bracket + life_after_ms
            };
            rig.life.received(held, life);
            // Resolved late: nothing looks until well past the deadline.
            rig.later(bracket + 5_000);
            rig.dialer.apply_verdicts(&mut rig.rng);
            assert_eq!(rig.pending(), 0, "{connector:?} {case}");
            assert_eq!(rig.demoted(&white), demoted, "{connector:?} {case}");
        }
    }
}

/// **The verdict's wake reads the byte clock** (#1235 review, F2). The
/// deadline is on the byte-stamp clock, so the owner's wake is derived from
/// it: the engine's now plus what the byte clock still has to run, and now
/// once that clock has reached the deadline. A wake set on the engine clock
/// when the verdict was deferred fails this: here the byte clock runs ahead
/// of the engine's, and such a wake would come late, or, the other way,
/// before the deadline and re-arm for a due already past.
#[test]
fn the_verdicts_wake_reads_the_byte_clock() {
    let mut rig = JudgeRig::new(TOR, 280);
    let held = rig.hold(20);
    rig.whites(0, 1);
    rig.life.received_now(held);
    rig.later(1_000);
    rig.fail_uncertain();
    assert_eq!(rig.pending(), 1);
    let bracket = dial_profile(TOR).judging.bracket_nanos / 1_000_000;
    let engine = rig.clock.now().get();
    rig.later(bracket - 1_000);
    assert_eq!(
        rig.dialer.next_verdict_due(TOR),
        Some(Tick::new(engine + 1_000_000_000)),
        "the byte clock has one second to run"
    );
    rig.later(1_000);
    assert_eq!(
        rig.dialer.next_verdict_due(TOR),
        Some(Tick::new(engine)),
        "the deadline is reached: due now, not in the past"
    );
    rig.dialer.apply_verdicts(&mut rig.rng);
    assert_eq!(rig.pending(), 0, "and the wake finds it due");
    assert_eq!(rig.dialer.next_verdict_due(TOR), None);
}

/// **The failing attempt's own stream never vouches for its failure**
/// (#1235 review R2-1), on a byte clock that advances 1 ms at every read,
/// so no two reads are the same instant. A Tor white test whose every
/// attempt opens a stream that the peer then closes: the earlier attempts'
/// streams are life before the final failure, so its verdict waits; the
/// final attempt's own stream comes before its own failure, so nothing is
/// after it, and the failure is excused. The edit that makes this red:
/// stamping the stream from a second reading of the clock, after the
/// failure was judged.
#[test]
fn the_failing_attempts_own_stream_never_vouches_for_it() {
    let mut rig = JudgeRig::new(TOR, 290);
    let white = rig.whites(0, 1).remove(0);
    rig.life.advance_per_read(1);
    rig.rig.peer.close_on_open();
    let attempts = usize::from(dial_profile(TOR).attempts.white);
    for attempt in 1..=attempts {
        assert!(rig.dialer.wake(TOR, &mut rig.rng), "attempt {attempt}");
        if attempt < attempts {
            assert_eq!(rig.pending(), 0, "attempt {attempt} retries");
            rig.advance(Duration::from_secs(31));
        }
    }
    assert_eq!(
        rig.pending(),
        1,
        "the earlier attempts' streams are life before the failure"
    );
    rig.close_bracket();
    assert_eq!(rig.pending(), 0);
    assert!(
        rig.lists_white(&white) && !rig.demoted(&white),
        "nothing after the failure vouched for it"
    );
}

/// **A stream is dated when it opened** (#1235 review R2-2), not when its
/// attempt ended: a failed attempt's life is not dated up to one handshake
/// span late. A pending failure's bracket closes while another attempt's
/// stream is open: the stream opened inside the bracket and the attempt
/// ended after it. On a byte clock that steps one second per read, the
/// reads during that attempt are the span between its open and its end.
/// Dated at the open, the stream counts the pending failure. The edit that
/// makes this red: dating the stream when its attempt ended.
#[test]
fn a_stream_is_dated_when_it_opened() {
    let mut rig = JudgeRig::new(TOR, 300);
    let held = rig.hold(20);
    let whites = rig.whites(0, 2);
    rig.life.received_now(held);
    rig.later(1_000);
    rig.fail_uncertain();
    assert_eq!(rig.pending(), 1, "the first white's verdict waits");
    let failed = rig.life.now_ms();
    let bracket = dial_profile(TOR).judging.bracket_nanos / 1_000_000;
    // One read at the wake's start, the stream's open the next, the
    // attempt's end the one after: the deadline falls between the last two.
    rig.life.set_ms(failed + bracket - 1_500);
    rig.life.advance_per_read(1_000);
    rig.rig.peer.close_on_open();
    assert!(
        rig.dialer.wake(TOR, &mut rig.rng),
        "the other white's attempt"
    );
    rig.life.advance_per_read(0);
    rig.later(bracket);
    rig.dialer.apply_verdicts(&mut rig.rng);
    let demoted = whites.iter().filter(|white| rig.demoted(white)).count();
    assert_eq!(demoted, 1, "the stream opened inside the bracket counts it");
}

/// **A queued failure is dated when the attempt ended** (#1235 review).
/// The result waits in the completion queue. Recovery traffic strictly
/// between that end and the moment the owner applies it, and traffic just
/// after the apply, must not form a bracket around the apply. Dated at the
/// apply, the earlier byte is the before side and the later byte the after
/// side, and white is demoted. Dated at the attempt's end, both are after
/// the bracket and the failure is excused.
#[test]
fn a_queued_failure_is_dated_when_the_attempt_ended() {
    let mut rig = JudgeRig::new(TOR, 310);
    let held = rig.hold(0);
    let white = rig.whites(0, 1).remove(0);
    let ended = rig.life.now_ms();
    rig.rig
        .peer
        .refuse_after(shekyl_tor::reply_end(0x01), Duration::from_secs(1));
    let Launch::Running(id) = rig.dialer.launch(TOR, &mut rig.rng) else {
        panic!("a draw");
    };
    rig.dialer.wait_posted(id);
    // Outside the attempt's own bracket, and inside δ before an apply that
    // late: the before side of a failure dated at the apply.
    let bracket = dial_profile(TOR).judging.bracket_nanos / 1_000_000;
    let between = ended.saturating_add(bracket).saturating_add(5_000);
    let applied = between.saturating_add(bracket);
    let after = applied.saturating_add(1_000);
    rig.life.received(held, between);
    rig.life.set_ms(applied);
    rig.dialer.apply_completions(TOR, &mut rig.rng);
    rig.life.received(held, after);
    rig.dialer.apply_verdicts(&mut rig.rng);
    assert_eq!(rig.pending(), 0, "the bracket has closed");
    assert!(
        rig.lists_white(&white) && !rig.demoted(&white),
        "traffic during the wait does not corroborate the failure"
    );
}

/// **Recovery inside δ is not the before side of a queued failure.**
/// The result waits in the completion queue. A byte after the attempt
/// ended, still inside δ, is noted before the owner applies the result,
/// and another byte still inside δ arrives after the apply. Both are
/// after the failure. The latest stamp is the only one kept, so the byte
/// already noted is not the before side and the failure is excused at
/// once. Treating that byte as the before side defers the verdict, and
/// the later byte counts it.
#[test]
fn recovery_inside_the_bracket_does_not_corroborate_a_queued_failure() {
    let mut rig = JudgeRig::new(TOR, 311);
    let held = rig.hold(0);
    let white = rig.whites(0, 1).remove(0);
    let ended = rig.life.now_ms();
    rig.rig
        .peer
        .refuse_after(shekyl_tor::reply_end(0x01), Duration::from_secs(1));
    let Launch::Running(id) = rig.dialer.launch(TOR, &mut rig.rng) else {
        panic!("a draw");
    };
    rig.dialer.wait_posted(id);
    let bracket = dial_profile(TOR).judging.bracket_nanos / 1_000_000;
    let during = ended.saturating_add(5_000);
    let applied = during.saturating_add(1_000);
    let after = applied.saturating_add(1_000);
    assert!(
        after < ended.saturating_add(bracket),
        "both bytes are inside δ"
    );
    rig.life.received(held, during);
    rig.life.set_ms(applied);
    rig.dialer.apply_completions(TOR, &mut rig.rng);
    assert_eq!(
        rig.pending(),
        0,
        "nothing before the failure, so the verdict does not wait"
    );
    rig.life.received(held, after);
    rig.dialer.apply_verdicts(&mut rig.rng);
    assert!(
        rig.lists_white(&white) && !rig.demoted(&white),
        "recovery after the failure does not demote white"
    );
}
