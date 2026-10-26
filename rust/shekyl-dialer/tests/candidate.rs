// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The candidate filter's kept rows, one test each, and the dialer's own
//! count of pending attempts and kept sessions.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use shekyl_dialer::{Attempts, CandidateFilter, DialAim, Skip};
use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{
    BanQuery, CloseCause, CloseKind, DialOutcome, Host, NetworkAddress, NoBans, Tick,
};

fn peer(n: u8, port: u16) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 11, 0, n),
        port,
    }
}

fn onion(n: u8) -> NetworkAddress {
    NetworkAddress::Tor {
        host: format!("{n:0>56}.onion"),
        port: 18080,
    }
}

/// An outcome constructor that takes only the address.
type MakeOutcome = fn(NetworkAddress) -> DialOutcome;

fn at(nanos: u64) -> Tick {
    Tick::new(nanos)
}

/// Bans exactly one host.
struct OneBan(IpAddr);

impl BanQuery for OneBan {
    fn is_banned(&mut self, host: IpAddr, _now: Tick) -> bool {
        host == self.0
    }
}

/// Everything the filter reads, empty unless a test fills it.
#[derive(Default)]
struct World {
    own: Vec<NetworkAddress>,
    sessions: BTreeSet<NetworkAddress>,
    outbound_hosts: BTreeSet<Host>,
    attempts: Attempts,
}

impl World {
    fn check(
        &self,
        address: &NetworkAddress,
        bans: &mut dyn BanQuery,
        now: Tick,
    ) -> Result<(), Skip> {
        CandidateFilter {
            own: &self.own,
            sessions: &self.sessions,
            outbound_hosts: &self.outbound_hosts,
            attempts: &self.attempts,
            bans,
            now,
        }
        .check(address)
    }
}

#[test]
fn an_address_nothing_names_is_a_candidate() {
    let world = World::default();
    assert_eq!(world.check(&peer(1, 18080), &mut NoBans, at(0)), Ok(()));
    assert_eq!(world.check(&onion(1), &mut NoBans, at(0)), Ok(()));
}

#[test]
fn our_own_address_is_not_a_candidate() {
    let world = World {
        own: vec![peer(1, 18080), onion(1)],
        ..World::default()
    };
    assert_eq!(
        world.check(&peer(1, 18080), &mut NoBans, at(0)),
        Err(Skip::OwnAddress)
    );
    assert_eq!(
        world.check(&onion(1), &mut NoBans, at(0)),
        Err(Skip::OwnAddress)
    );
    assert_eq!(world.check(&peer(2, 18080), &mut NoBans, at(0)), Ok(()));
}

#[test]
fn an_address_already_in_use_is_not_a_candidate() {
    let mut world = World::default();
    world.sessions.insert(peer(3, 18080));
    assert_eq!(
        world.check(&peer(3, 18080), &mut NoBans, at(0)),
        Err(Skip::InUse)
    );
}

#[test]
fn a_host_with_an_outbound_session_is_not_a_candidate_on_another_port() {
    let mut world = World::default();
    world.outbound_hosts.insert(peer(4, 18080).host());
    assert_eq!(
        world.check(&peer(4, 28080), &mut NoBans, at(0)),
        Err(Skip::HostHasOutbound)
    );
    assert_eq!(world.check(&peer(5, 28080), &mut NoBans, at(0)), Ok(()));
}

#[test]
fn a_pending_attempt_and_its_host_are_not_candidates() {
    let mut world = World::default();
    assert!(world.attempts.begin(&peer(6, 18080), DialAim::Confirm));
    assert_eq!(
        world.check(&peer(6, 18080), &mut NoBans, at(0)),
        Err(Skip::Pending)
    );
    assert_eq!(
        world.check(&peer(6, 28080), &mut NoBans, at(0)),
        Err(Skip::HostHasOutbound),
        "the pending attempt's host, on another port"
    );

    // Once the attempt ends without a kept session, both are candidates.
    world
        .attempts
        .finish(&DialOutcome::Confirmed(peer(6, 18080)));
    assert_eq!(world.check(&peer(6, 18080), &mut NoBans, at(0)), Ok(()));
    assert_eq!(world.check(&peer(6, 28080), &mut NoBans, at(0)), Ok(()));
}

#[test]
fn a_banned_host_is_not_a_candidate() {
    let world = World::default();
    let mut bans = OneBan(IpAddr::V4(Ipv4Addr::new(11, 11, 0, 7)));
    assert_eq!(
        world.check(&peer(7, 18080), &mut bans, at(0)),
        Err(Skip::Banned)
    );
    assert_eq!(world.check(&peer(8, 18080), &mut bans, at(0)), Ok(()));
    assert_eq!(
        world.check(&onion(7), &mut bans, at(0)),
        Ok(()),
        "an onion has no IP to ban"
    );
}

// ---- the dialer's own counts --------------------------------------------

#[test]
fn a_pending_keep_counts_toward_the_target_and_a_pending_confirm_does_not() {
    let mut attempts = Attempts::new();
    assert!(attempts.begin(&peer(1, 18080), DialAim::Keep));
    assert!(attempts.begin(&peer(2, 18080), DialAim::Confirm));
    assert_eq!(attempts.kept_count(), 1);
    assert_eq!(attempts.in_flight(), 2);
    assert!(
        !attempts.begin(&peer(1, 18080), DialAim::Confirm),
        "already pending"
    );
}

#[test]
fn only_session_accepted_leaves_a_kept_session_and_every_outcome_ends_the_attempt() {
    let cause = CloseCause::new(CloseKind::LevinHandshakeTimeout);
    let outcomes: [(MakeOutcome, usize); 4] = [
        (DialOutcome::SessionAccepted, 1),
        (DialOutcome::Confirmed, 0),
        (
            (|a| {
                DialOutcome::PeerlistRefused(a, CloseCause::new(CloseKind::LevinHandshakeRejected))
            }) as MakeOutcome,
            0,
        ),
        (DialOutcome::PayloadRefused, 0),
    ];
    for (make, kept) in outcomes {
        for aim in [DialAim::Keep, DialAim::Confirm] {
            let mut attempts = Attempts::new();
            assert!(attempts.begin(&peer(1, 18080), aim));
            attempts.finish(&make(peer(1, 18080)));
            assert_eq!(
                attempts.in_flight(),
                0,
                "the pending set is empty after the outcome"
            );
            assert_eq!(attempts.kept_count(), kept);
        }
    }
    let mut attempts = Attempts::new();
    assert!(attempts.begin(&peer(1, 18080), DialAim::Keep));
    attempts.finish(&DialOutcome::DialFailed(peer(1, 18080), cause));
    assert_eq!((attempts.in_flight(), attempts.kept_count()), (0, 0));

    let mut attempts = Attempts::new();
    assert!(attempts.begin(&peer(1, 18080), DialAim::Keep));
    attempts.finish(&DialOutcome::SessionAccepted(peer(1, 18080)));
    assert!(attempts.holds(&peer(1, 18080)));
    assert!(
        !attempts.begin(&peer(1, 18080), DialAim::Keep),
        "already a kept session"
    );
    attempts.session_closed(&peer(1, 18080));
    assert_eq!(attempts.kept_count(), 0);
}

#[test]
fn lowering_the_cap_closes_kept_sessions_only_and_only_the_excess() {
    let mut rng = SplitMix64::new(1);
    let mut attempts = Attempts::new();
    for n in 1..=6 {
        assert!(attempts.begin(&peer(n, 18080), DialAim::Keep));
        attempts.finish(&DialOutcome::SessionAccepted(peer(n, 18080)));
    }
    assert!(attempts.begin(&peer(20, 18080), DialAim::Keep));
    assert!(attempts.begin(&peer(21, 18080), DialAim::Confirm));

    assert!(attempts.over_target(6, &mut rng).is_empty());
    assert!(attempts.over_target(60, &mut rng).is_empty());
    let closing = attempts.over_target(4, &mut rng);
    assert_eq!(closing.len(), 2);
    let distinct: BTreeSet<_> = closing.iter().collect();
    assert_eq!(distinct.len(), 2);
    for address in &closing {
        assert_ne!(
            *address,
            peer(20, 18080),
            "a pending attempt is not what the cap closes"
        );
        assert_ne!(*address, peer(21, 18080));
        attempts.session_closed(address);
    }
    assert_eq!(
        attempts.kept_count(),
        4 + 1,
        "four kept and the pending keep"
    );
    assert_eq!(
        attempts.over_target(0, &mut rng).len(),
        4,
        "a cap of zero closes every kept session"
    );
}

#[test]
fn the_sessions_the_cap_closes_are_chosen_uniformly() {
    let mut attempts = Attempts::new();
    for n in 1..=8 {
        assert!(attempts.begin(&peer(n, 18080), DialAim::Keep));
        attempts.finish(&DialOutcome::SessionAccepted(peer(n, 18080)));
    }
    let mut rng = SplitMix64::new(2);
    let mut counts = [0u32; 8];
    let rounds = 16_000;
    for _ in 0..rounds {
        for address in attempts.over_target(7, &mut rng) {
            let NetworkAddress::Ipv4 { ip, .. } = address else {
                panic!("clearnet");
            };
            counts[usize::from(ip.octets()[3]) - 1] += 1;
        }
    }
    // 2000 each; five standard deviations is about 210.
    for (n, count) in counts.iter().enumerate() {
        assert!((1790..=2210).contains(count), "session {n}: {count}");
    }
}
