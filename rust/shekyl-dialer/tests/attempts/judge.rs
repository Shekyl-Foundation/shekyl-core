// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The judge (`DIALER_OUTAGE_EVIDENCE.md` §4, `OE-D8`; §3.3 as ruled
//! 2026-11-15) on the real dialer over the attempt rig. An uncertain
//! failure asks the dialing connector for a path reading taken after it:
//! the connector's source here is [`ScriptedPath`], the test's stand-in for
//! a connector's own. The failures are the connectors' own stamping, from
//! their reply tables. Each test names the edit that makes it fail.

use std::sync::Arc;
use std::time::Duration;

use shekyl_dialer::Dialer;
use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{dial_profile, ConnectorId, NetworkAddress, Tick};
use shekyl_timing_engine::{Clock, ManualClock};
use shekyl_transport_layer::{DialEnd, PathReading};

use super::path::ScriptedPath;
use super::rig::{Answer, Rig};
use super::{onions, peer, reply, CLEARNET, NETWORK, TOR, TOR_WINDOW};

/// A connector's wait for a reading in these tests: a minute.
const WAIT: Duration = Duration::from_secs(60);

struct JudgeRig {
    rig: Rig,
    clock: ManualClock,
    dialer: Arc<Dialer<ManualClock>>,
    connector: ConnectorId,
    path: ScriptedPath,
    rng: SplitMix64,
}

impl JudgeRig {
    fn new(connector: ConnectorId, seed: u64) -> Self {
        let clock = ManualClock::new(Tick::new(1_000_000_000));
        let rig = Rig::on(&clock);
        let dialer = Arc::clone(&rig.dialer);
        dialer.set_window(TOR, Some(TOR_WINDOW));
        let wait = u64::try_from(WAIT.as_nanos()).expect("a minute");
        let path = ScriptedPath::install(&dialer, connector, wait);
        Self {
            rig,
            clock,
            dialer,
            connector,
            path,
            rng: SplitMix64::new(seed),
        }
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

    /// `count` white addresses numbered from `from`, each kept and then
    /// closed by its peer, so none is held.
    fn whites(&mut self, from: usize, count: usize) -> Vec<NetworkAddress> {
        let addresses = self.addresses(from, count);
        self.admit(&addresses);
        let mut ids = Vec::new();
        for _ in 0..count {
            let before = self.rig.opened();
            self.rig.peer.answer_next(Answer::Answered(reply(NETWORK)));
            assert!(self.dialer.wake(self.connector, &mut self.rng), "a dial");
            ids.extend(
                self.rig
                    .opened()
                    .into_iter()
                    .filter(|id| !before.contains(id)),
            );
        }
        for id in ids {
            self.rig.close_as_peer(id);
        }
        for address in &addresses {
            assert!(self.lists_white(address), "{address:?} white");
        }
        addresses
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

    /// The path reads `reading` now, and the verdicts it decides are
    /// performed.
    fn read(&mut self, reading: PathReading) {
        self.advance(Duration::from_millis(1));
        self.path.read_now(&self.clock, reading);
        self.dialer.apply_verdicts(&mut self.rng);
    }

    /// Past the connector's wait, and the verdicts due performed.
    fn wait_out(&mut self) {
        self.advance(WAIT + Duration::from_millis(1));
        self.dialer.apply_verdicts(&mut self.rng);
    }

    fn pending(&self) -> usize {
        self.dialer.pending_verdicts(self.connector)
    }

    fn lists_white(&self, address: &NetworkAddress) -> bool {
        self.dialer.shared().lists.is_white(address)
    }

    fn excused(&self, address: &NetworkAddress) -> bool {
        self.dialer.shared().lists.is_excused(address)
    }

    fn failures(&self, address: &NetworkAddress) -> u32 {
        self.dialer.shared().lists.failed_tests(address)
    }
}

/// **An uncertain failure asks, and waits without a slot** (both
/// connectors): the judge asks the dialing connector for a reading after
/// the failure, at the failure's own instant; the verdict waits, holding
/// no in-flight slot, and the address is not drawn again meanwhile. The
/// edits that make this red: deciding without asking, asking about an
/// instant other than the failure's, or drawing an address whose verdict
/// waits.
#[test]
fn an_uncertain_failure_asks_and_waits_without_a_slot() {
    for connector in [TOR, CLEARNET] {
        let mut rig = JudgeRig::new(connector, 11);
        let address = rig.addresses(0, 1);
        rig.admit(&address);
        let before = rig.clock.stamp();
        rig.fail_uncertain();
        assert_eq!(rig.pending(), 1, "{connector:?}: the verdict waits");
        assert_eq!(rig.path.asks(), 1, "{connector:?}: asked at the failure");
        assert!(
            rig.path.asked_after()[0] > before,
            "{connector:?}: asked about the failure's own instant"
        );
        assert_eq!(rig.dialer.in_flight(connector), 0, "no slot held");
        assert!(
            !rig.dialer.wake(connector, &mut rig.rng),
            "{connector:?}: the waiting address is not drawn again"
        );
        assert_eq!(rig.failures(&address[0]), 0, "nothing counted yet");
    }
}

/// **One reading after the failure decides** (both connectors): working
/// counts the failure, impaired excuses it, and a white address excused
/// stays white. The edits that make this red: counting on an impaired
/// reading, or excusing on a working one.
#[test]
fn one_reading_after_the_failure_decides() {
    for connector in [TOR, CLEARNET] {
        let mut rig = JudgeRig::new(connector, 12);
        let gray = rig.addresses(0, 1);
        rig.admit(&gray);
        rig.fail_uncertain();
        rig.read(PathReading::Working);
        assert_eq!(rig.pending(), 0);
        assert_eq!(rig.failures(&gray[0]), 1, "{connector:?}: working counts");

        let white = rig.whites(10, 1);
        rig.advance(Duration::from_secs(4 * 3600));
        rig.fail_uncertain();
        rig.read(PathReading::Impaired);
        assert_eq!(rig.pending(), 0);
        assert!(
            rig.lists_white(&white[0]),
            "{connector:?}: impaired excuses"
        );
        assert_eq!(rig.failures(&white[0]), 0);
    }
}

/// **A reading from before the failure decides nothing**: the path worked
/// before the failure, and nothing after it; the failure waits, then is
/// excused when the wait runs out. The before side of the old bracket is
/// gone (Rick, 2026-11-15). The edits that make this red: answering from a
/// reading at or before the failure, or counting when the wait runs out.
#[test]
fn a_reading_before_the_failure_decides_nothing_and_the_wait_excuses() {
    let mut rig = JudgeRig::new(TOR, 13);
    let address = rig.addresses(0, 1);
    rig.admit(&address);
    rig.path.read_now(&rig.clock, PathReading::Working);
    rig.fail_uncertain();
    rig.dialer.apply_verdicts(&mut rig.rng);
    assert_eq!(
        rig.pending(),
        1,
        "a reading before the failure does not decide"
    );
    rig.wait_out();
    assert_eq!(rig.pending(), 0);
    assert!(
        rig.excused(&address[0]),
        "no reading within the wait excuses"
    );
    assert_eq!(rig.failures(&address[0]), 0);
}

/// **Destination counts and Local is excused without asking**: neither
/// depends on the path, so the connector is never asked. The edit that
/// makes this red is asking the path for either.
#[test]
fn destination_and_local_never_ask_the_path() {
    let mut rig = JudgeRig::new(TOR, 14);
    let addresses = rig.addresses(0, 2);
    rig.admit(&addresses);
    // The service's own refusal (`0x05`) is Destination evidence; this
    // node's proxy being down is Local.
    rig.fail(shekyl_tor::reply_end(0x05), Duration::from_secs(1));
    rig.fail(
        shekyl_tor::Observed::ProxyUnavailable.end(),
        Duration::from_millis(5),
    );
    assert_eq!(rig.path.asks(), 0, "the path was never asked");
    assert_eq!(rig.pending(), 0);
    let counted: u32 = addresses.iter().map(|address| rig.failures(address)).sum();
    assert_eq!(
        counted, 1,
        "the destination failure counted, the local one not"
    );
}

/// **A working reading clears the excusals with no counted failure**
/// (`OE-D6`'s clearing, now on a reading): an address excused while the
/// path was impaired is drawable again once a later failure reads
/// working, and an address with a counted failure keeps its rung. The edit
/// that makes this red is clearing on an impaired reading, or never.
#[test]
fn a_working_reading_clears_the_excusals_with_no_counted_failure() {
    let mut rig = JudgeRig::new(TOR, 15);
    let addresses = rig.addresses(0, 2);
    rig.admit(&addresses);
    rig.fail_uncertain();
    rig.read(PathReading::Impaired);
    let excused: Vec<_> = addresses
        .iter()
        .filter(|address| rig.excused(address))
        .cloned()
        .collect();
    assert_eq!(excused.len(), 1, "one excused while impaired");
    rig.fail_uncertain();
    rig.read(PathReading::Working);
    assert!(
        !rig.excused(&excused[0]),
        "the working reading lifted the excusal"
    );
}

/// **A connector with no source excuses at once**: until the network
/// supplies a connector's source, an uncertain failure on it has no
/// reading to wait for. The edit that makes this red is a default source
/// that counts, or one that holds the verdict.
#[test]
fn a_connector_with_no_source_excuses_at_once() {
    let clock = ManualClock::new(Tick::new(1_000_000_000));
    let rig = Rig::on(&clock);
    let dialer = Arc::clone(&rig.dialer);
    let mut rng = SplitMix64::new(16);
    let address = peer(900);
    dialer
        .admit_operator(&address, clock.now(), &mut rng)
        .expect("admitted");
    rig.peer.refuse_after(
        shekyl_clearnet::Observed::Deadline.end(),
        Duration::from_nanos(dial_profile(CLEARNET).dial_deadline_nanos),
    );
    assert!(dialer.wake(CLEARNET, &mut rng), "a draw");
    assert_eq!(dialer.pending_verdicts(CLEARNET), 0, "nothing to wait for");
    assert!(dialer.shared().lists.is_excused(&address));
}

/// **A dead onion address on a settled node climbs on its first verdict**
/// (Rick, 2026-11-15). The node holds its sessions; a dead onion fails its
/// test with an uncertain answer, the Tor connector is asked, and the
/// reading after the failure is working (the Tor Manager's check, or a
/// completed dial, answered the want). The address counts one failed test
/// and cools at the ladder's first rung, on that first verdict; it is not
/// excused and redialed first. The manager's half, a want answered working
/// by its check, is `shekyl-tor-control-client`'s
/// `a_want_with_no_reading_starts_a_check` and the directory check's
/// working fact. The edits that make this red: excusing a failure whose
/// reading is working, or waiting for a second test before counting.
#[test]
fn a_dead_onion_on_a_settled_node_climbs_on_its_first_verdict() {
    let mut rig = JudgeRig::new(TOR, 17);
    let dead = rig.addresses(0, 1);
    rig.admit(&dead);
    rig.fail_uncertain();
    assert_eq!(rig.path.asks(), 1, "the Tor connector was asked");
    rig.read(PathReading::Working);
    assert_eq!(rig.failures(&dead[0]), 1, "counted on its first verdict");
    assert!(!rig.excused(&dead[0]), "not excused");
    assert!(
        rig.dialer.shared().lists.is_cooling(&dead[0]),
        "it cools at the first rung"
    );
}
