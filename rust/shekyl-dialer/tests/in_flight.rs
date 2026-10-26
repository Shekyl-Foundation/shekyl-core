// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The in-flight dial bound, per connector (Rick, 2026-10-25; dialer brief,
//! "The fill"). The bound limits concurrency; the target still caps the
//! `Keep` dials; the filters see every attempt in flight; and the draw
//! distribution does not move with the bound.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use shekyl_dialer::{in_flight_bound, plan, Attempts, CandidateFilter, Census, DialAim, DrawList};
use shekyl_draw_rng::{RelayRng, SplitMix64};
use shekyl_peerlist::{
    white_diversity_floor, ConnectorId, DialOutcome, Host, KeptSessions, NetworkAddress, NoBans,
    Peerlist, RefusedSet, Source, Tick, WHITE_REFILL_LINE,
};

/// The kept sessions expiry must see, copied out so a filter can borrow
/// the attempts at the same time.
struct KeptNow<'a>(&'a BTreeSet<NetworkAddress>);

impl KeptSessions for KeptNow<'_> {
    fn is_kept(&mut self, address: &NetworkAddress) -> bool {
        self.0.contains(address)
    }
}

const CLEARNET: ConnectorId = ConnectorId::Clearnet;
const TARGET: usize = 12;

fn at(seconds: u64) -> Tick {
    Tick::new(seconds * 1_000_000_000)
}

/// Host `n`, on `port`: many ports per host test the one-per-host rule.
fn address(n: u16, port: u16) -> NetworkAddress {
    let [hi, lo] = n.to_be_bytes();
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 9, hi, lo),
        port,
    }
}

fn census(attempts: &Attempts, white: usize, gray: usize) -> Census {
    Census {
        kept: attempts.kept_count(),
        in_flight: attempts.in_flight(),
        target: TARGET,
        white,
        white_candidates: white,
        gray,
        gray_candidates: gray,
    }
}

/// The bounds as derived (2026-10-25; on the full-window-final lifecycle,
/// Rick 2026-10-26): Tor five, the smallest bound that fills the Tor
/// target within one stem epoch with half the draws dead; clearnet stays at
/// one, so its behaviour is unchanged (the brief's test 5). Never more than
/// the connector's target.
#[test]
fn the_bounds_are_tor_five_and_clearnet_one_and_never_past_the_target() {
    assert_eq!(in_flight_bound(ConnectorId::Clearnet), 1);
    assert_eq!(in_flight_bound(ConnectorId::Tor), 5);
    assert!(in_flight_bound(ConnectorId::Tor) <= TARGET);
}

/// **The target is the ceiling at any bound** (the brief's test 2). With
/// one kept session short of the target and a bound of four, the wakes
/// launch exactly one `Keep` dial; the slots it leaves go to `Confirm`
/// dials, which the target does not count. The `Keep` count includes
/// pending `Keep` attempts, so `kept < target` is already kept sessions
/// plus in-flight keeps under the target.
#[test]
fn one_short_of_the_target_launches_exactly_one_keep_at_a_bound_above_one() {
    const BOUND: usize = 4;
    let mut attempts = Attempts::new();
    for n in 0..u16::try_from(TARGET - 1).expect("small") {
        let kept = address(n, 18080);
        assert!(attempts.begin(&kept, DialAim::Keep));
        attempts.finish(&DialOutcome::SessionAccepted(kept));
    }
    assert_eq!(attempts.kept_count(), TARGET - 1);
    // White below the refill line and gray far over the floor: rule (b)
    // keeps from gray while under target, rule (c) confirms otherwise.
    let gray = white_diversity_floor() * 4;
    let mut keeps = 0;
    let mut confirms = 0;
    for n in 0..u16::try_from(BOUND * 2).expect("small") {
        let Some(chosen) = plan(
            &census(&attempts, 0, gray),
            white_diversity_floor(),
            WHITE_REFILL_LINE,
            BOUND,
        ) else {
            break;
        };
        assert_eq!(chosen.list, DrawList::Gray);
        match chosen.aim {
            DialAim::Keep => keeps += 1,
            DialAim::Confirm => confirms += 1,
        }
        assert!(attempts.begin(&address(1_000 + n, 18080), chosen.aim));
    }
    assert_eq!(keeps, 1, "exactly one keep: the target is the ceiling");
    assert_eq!(confirms, BOUND - 1, "the other slots confirm");
    assert_eq!(attempts.in_flight(), BOUND, "and the bound stops the wakes");
    assert!(attempts.kept_count() <= TARGET);
}

/// **The filters see every attempt in flight** (the brief's test 3). With
/// many hosts, several ports each, and up to eight dials in flight, no two
/// in-flight dials share an address or, on clearnet, a host, and a draw
/// never returns an address already in flight.
#[test]
fn concurrent_dials_never_share_an_address_or_a_clearnet_host() {
    const IN_FLIGHT: usize = 8;
    for seed in 0..50 {
        let mut rng = SplitMix64::new(seed);
        let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
        // Twelve hosts, three ports each: thirty-six addresses, so eight
        // draws must find eight distinct hosts among twelve.
        for host in 0..12 {
            for port in [18080, 18081, 28080] {
                list.admit_gray(
                    &address(host, port),
                    Source::Operator,
                    at(0),
                    &mut NoBans,
                    &mut rng,
                )
                .expect("admitted");
            }
        }
        let mut attempts = Attempts::new();
        let empty_sessions = BTreeSet::new();
        let empty_hosts: BTreeSet<Host> = BTreeSet::new();
        let mut drawn: Vec<NetworkAddress> = Vec::new();
        for _ in 0..IN_FLIGHT {
            let mut bans = NoBans;
            let mut filter = CandidateFilter {
                own: &[],
                sessions: &empty_sessions,
                outbound_hosts: &empty_hosts,
                attempts: &attempts,
                bans: &mut bans,
                now: at(1),
            };
            let pick = list
                .draw_gray_where(CLEARNET, at(1), &mut |a| filter.admits(a), &mut rng)
                .expect("a candidate remains");
            assert!(
                !drawn.contains(&pick),
                "seed {seed}: {pick:?} is already in flight"
            );
            assert!(attempts.begin(&pick, DialAim::Keep), "seed {seed}");
            drawn.push(pick);
        }
        let hosts: BTreeSet<Host> = drawn.iter().map(NetworkAddress::host).collect();
        assert_eq!(hosts.len(), IN_FLIGHT, "seed {seed}: one dial per host");
        assert_eq!(attempts.in_flight(), IN_FLIGHT);
    }
}

/// One node's fill over the real lists, with dials that take time: up to
/// `bound` dials outstanding, one wake per second, one dial per wake.
/// Every dial succeeds; an attacker address answers in one second and an
/// honest one in twenty, so a fast answer would win any race the fill
/// allowed. Returns the attacker's share of the kept sessions at target.
fn fill_share(bound: usize, attacker_share: f64, seed: u64) -> f64 {
    const GRAY: u16 = 400;
    let mut rng = SplitMix64::new(seed);
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    let mut attacker = BTreeSet::new();
    for n in 0..GRAY {
        let a = address(n, 18080);
        list.admit_gray(&a, Source::Operator, at(0), &mut NoBans, &mut rng)
            .expect("admitted");
        #[allow(clippy::cast_precision_loss)]
        let roll = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        if roll < attacker_share {
            attacker.insert(a);
        }
    }
    let mut attempts = Attempts::new();
    let empty_sessions = BTreeSet::new();
    let empty_hosts: BTreeSet<Host> = BTreeSet::new();
    // Completion second -> the dials that end then.
    let mut ending: BTreeMap<u64, Vec<(NetworkAddress, DialAim)>> = BTreeMap::new();
    let mut kept: Vec<NetworkAddress> = Vec::new();
    for now in 1..100_000u64 {
        for (a, aim) in ending.remove(&now).unwrap_or_default() {
            let outcome = match aim {
                DialAim::Keep => {
                    kept.push(a.clone());
                    DialOutcome::SessionAccepted(a)
                }
                DialAim::Confirm => DialOutcome::Confirmed(a),
            };
            attempts.finish(&outcome);
            list.apply(&outcome, at(now), &mut rng);
        }
        if kept.len() >= TARGET {
            break;
        }
        let live = attempts.kept_addresses().clone();
        let white = list.white_count(
            CLEARNET,
            at(now),
            &mut NoBans,
            &mut KeptNow(&live),
            &mut rng,
        );
        let live_white = kept.iter().filter(|a| list.is_white(a)).count();
        let gray = list.gray_count(CLEARNET);
        let mut bans = NoBans;
        let mut filter = CandidateFilter {
            own: &[],
            sessions: &empty_sessions,
            outbound_hosts: &empty_hosts,
            attempts: &attempts,
            bans: &mut bans,
            now: at(now),
        };
        let gray_candidates = list.gray_candidates(CLEARNET, &mut |a| filter.admits(a));
        let census = Census {
            kept: attempts.kept_count(),
            in_flight: attempts.in_flight(),
            target: TARGET,
            white,
            white_candidates: white.saturating_sub(live_white),
            gray,
            gray_candidates,
        };
        let Some(chosen) = plan(&census, white_diversity_floor(), WHITE_REFILL_LINE, bound) else {
            continue;
        };
        let pick = match chosen.list {
            DrawList::Gray => {
                list.draw_gray_where(CLEARNET, at(now), &mut |a| filter.admits(a), &mut rng)
            }
            DrawList::White => list.draw_white_where(
                CLEARNET,
                at(now),
                &mut NoBans,
                &mut KeptNow(&live),
                &mut |a| filter.admits(a) && !kept.contains(a),
                &mut rng,
            ),
        };
        let Some(pick) = pick else { continue };
        assert!(attempts.begin(&pick, chosen.aim));
        let seconds = if attacker.contains(&pick) { 1 } else { 20 };
        ending
            .entry(now + seconds)
            .or_default()
            .push((pick, chosen.aim));
    }
    assert_eq!(kept.len(), TARGET, "seed {seed}: the target filled");
    #[allow(clippy::cast_precision_loss)]
    let share = kept.iter().filter(|a| attacker.contains(a)).count() as f64 / TARGET as f64;
    share
}

/// **Eclipse: the attacker's expected share does not move with the bound**
/// (the brief's wargame). Gray is 90% attacker, and the attacker's
/// addresses answer twenty times faster than honest ones. At bound one and
/// at bound eight the mean attacker share of the kept sessions is the same
/// within sampling noise, and both sit at the gray share: a pending `Keep`
/// takes its target slot when it is drawn, not when it answers, so a fast
/// answer wins nothing.
#[test]
fn the_attacker_share_of_kept_sessions_does_not_move_with_the_bound() {
    const RUNS: u64 = 300;
    let mean = |bound: usize| {
        (0..RUNS)
            .map(|seed| fill_share(bound, 0.9, seed))
            .sum::<f64>()
            / 300.0
    };
    let one = mean(1);
    let eight = mean(8);
    // The standard error of a mean of 300 runs of 12 draws at p = 0.9 is
    // about 0.005; a difference of 0.03 is six of them.
    assert!(
        (one - eight).abs() < 0.03,
        "bound 1: {one:.3}, bound 8: {eight:.3}"
    );
    assert!(
        (one - 0.9).abs() < 0.03,
        "bound 1 sits at the gray share: {one:.3}"
    );
    assert!(
        (eight - 0.9).abs() < 0.03,
        "bound 8 sits at the gray share: {eight:.3}"
    );
}
