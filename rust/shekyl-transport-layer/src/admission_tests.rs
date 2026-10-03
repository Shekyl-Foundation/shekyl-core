// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::{CloseResult, ObservedEndpoint, OpenError};
pub(super) use super::{Direction, Sockets};
use crate::ban::Ipv4Subnet;
pub(super) use crate::declaration::ConnectorId;
use crate::{CloseCause, CloseKind};
use shekyl_net_address::NetworkAddress;
use shekyl_onion_v3::v3_onion_hostname;
use shekyl_peer_policy::{InboundCeiling, UnboundedReason};
use shekyl_timing_engine::Tick;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::thread;

fn now() -> Tick {
    Tick::new(1_000)
}

fn ip(octets: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(octets))
}

fn refused(error: OpenError) -> CloseKind {
    match error {
        OpenError::Refused(cause) => cause.kind(),
        OpenError::Exhausted => panic!("exhausted"),
    }
}

#[test]
fn a_ceiling_of_zero_admits_nothing_and_an_unbounded_ceiling_does() {
    let sockets = Sockets::new();
    let error = sockets
        .accept_clearnet(ip([10, 0, 0, 1]), InboundCeiling::Bounded(0), now())
        .expect_err("none");
    assert_eq!(refused(error), CloseKind::InboundNotAccepted);
    assert_eq!(sockets.live(), 0);
    let _open = sockets
        .accept_tor(InboundCeiling::Unbounded(
            shekyl_peer_policy::UnboundedReason::Unlimited,
        ))
        .expect("admitted");
    assert_eq!(
        sockets.socket_count(ConnectorId::Tor, Direction::Inbound),
        1
    );
}

#[test]
fn a_banned_accept_does_not_take_a_slot() {
    let sockets = Sockets::new();
    let host = ip([10, 0, 0, 1]);
    assert_eq!(sockets.ban_host(host, Tick::new(2_000), now()).len(), 0);
    let error = sockets
        .accept_clearnet(host, InboundCeiling::Bounded(4), now())
        .expect_err("banned");
    assert_eq!(refused(error), CloseKind::AdmissionRefused);
    assert_eq!(sockets.live(), 0);
    assert!(!sockets.is_banned(host, Tick::new(2_000)));
    let _open = sockets
        .accept_clearnet(host, InboundCeiling::Bounded(4), Tick::new(2_000))
        .expect("expired");
    assert_eq!(sockets.live(), 1);
}

#[test]
fn inbound_held_sums_inbound_rows_and_leaves_outbound_out() {
    let sockets = Sockets::new();
    let ceiling = InboundCeiling::Bounded(4);
    let _clearnet = sockets
        .accept_clearnet(ip([10, 0, 0, 1]), ceiling, now())
        .expect("clearnet inbound");
    let _tor = sockets.accept_tor(ceiling).expect("tor inbound");
    let _outbound = sockets
        .open_clearnet(ip([10, 0, 0, 2]), now())
        .expect("clearnet outbound");
    assert_eq!(sockets.inbound_held(), 2);
    assert_eq!(sockets.live(), 3);
    assert_eq!(
        sockets.socket_count(ConnectorId::Clearnet, Direction::Outbound),
        1
    );
}

#[test]
fn close_releases_once_and_drop_does_not_release_again() {
    let sockets = Sockets::new();
    let open = sockets
        .accept_tor(InboundCeiling::Bounded(2))
        .expect("open");
    let id = open.id();
    assert_eq!(
        open.close(CloseCause::new(CloseKind::TransportHandshakeFailed)),
        CloseResult::Recorded(CloseCause::new(CloseKind::TransportHandshakeFailed))
    );
    assert_eq!(
        sockets.close(id, CloseCause::new(CloseKind::PeerClosed)),
        CloseResult::AlreadyClosed
    );
    assert_eq!(sockets.live(), 0);
    assert_eq!(
        sockets.socket_count(ConnectorId::Tor, Direction::Inbound),
        0
    );
}

#[test]
fn drop_releases_a_socket_that_failed_before_the_channel_existed() {
    let sockets = Sockets::new();
    let open = sockets
        .accept_clearnet(ip([10, 0, 0, 1]), InboundCeiling::Bounded(2), now())
        .expect("open");
    drop(open);
    assert_eq!(sockets.live(), 0);
}

#[test]
fn an_explicit_zone_cap_bounds_that_connector_when_the_process_ceiling_is_unbounded() {
    let sockets = Sockets::new();
    sockets.set_zone_cap(ConnectorId::Clearnet, Some(1));
    let ceiling = InboundCeiling::Unbounded(UnboundedReason::Unlimited);
    let _first = sockets
        .accept_clearnet(ip([10, 0, 0, 1]), ceiling, now())
        .expect("under the cap");
    let error = sockets
        .accept_clearnet(ip([10, 0, 0, 2]), ceiling, now())
        .expect_err("over the cap");
    assert_eq!(refused(error), CloseKind::AdmissionRefused);
    let _tor = sockets.accept_tor(ceiling).expect("tor has no zone cap");
}

#[test]
fn a_zone_cap_of_zero_never_accepts_that_connector() {
    let sockets = Sockets::new();
    sockets.set_zone_cap(ConnectorId::Clearnet, Some(0));
    let ceiling = InboundCeiling::Unbounded(UnboundedReason::Unlimited);
    let error = sockets
        .accept_clearnet(ip([10, 0, 0, 1]), ceiling, now())
        .expect_err("cap is zero");
    assert_eq!(refused(error), CloseKind::InboundNotAccepted);
    assert_eq!(sockets.live(), 0);
    let _tor = sockets.accept_tor(ceiling).expect("tor has no zone cap");
}

#[test]
fn a_zone_cap_does_not_raise_the_process_ceiling() {
    let sockets = Sockets::new();
    sockets.set_zone_cap(ConnectorId::Clearnet, Some(2));
    sockets.set_zone_cap(ConnectorId::Tor, Some(2));
    let ceiling = InboundCeiling::Bounded(2);
    let _tor = sockets.accept_tor(ceiling).expect("tor under both bounds");
    let _clearnet = sockets
        .accept_clearnet(ip([10, 0, 0, 1]), ceiling, now())
        .expect("clearnet under both bounds");
    let clearnet = sockets
        .accept_clearnet(ip([10, 0, 0, 2]), ceiling, now())
        .expect_err("the sum is the ceiling");
    assert_eq!(refused(clearnet), CloseKind::AdmissionRefused);
    let tor = sockets
        .accept_tor(ceiling)
        .expect_err("the sum is the ceiling");
    assert_eq!(refused(tor), CloseKind::AdmissionRefused);
}

#[test]
fn outbound_does_not_consume_the_inbound_ceiling() {
    let sockets = Sockets::new();
    let ceiling = InboundCeiling::Bounded(1);
    let _inbound = sockets
        .accept_clearnet(ip([10, 0, 0, 1]), ceiling, now())
        .expect("one inbound");
    let error = sockets
        .accept_clearnet(ip([10, 0, 0, 2]), ceiling, now())
        .expect_err("full");
    assert_eq!(refused(error), CloseKind::AdmissionRefused);
    let _outbound = sockets
        .open_clearnet(ip([10, 0, 0, 3]), now())
        .expect("outbound");
    assert_eq!(
        sockets.socket_count(ConnectorId::Clearnet, Direction::Outbound),
        1
    );
    assert_eq!(
        sockets.socket_count(ConnectorId::Clearnet, Direction::Inbound),
        1
    );
}

#[test]
fn clearnet_and_tor_inbound_share_the_process_ceiling() {
    let sockets = Sockets::new();
    let ceiling = InboundCeiling::Bounded(1);
    let clearnet = sockets
        .accept_clearnet(ip([10, 0, 0, 1]), ceiling, now())
        .expect("clearnet");
    let error = sockets.accept_tor(ceiling).expect_err("process full");
    assert_eq!(refused(error), CloseKind::AdmissionRefused);
    assert_eq!(
        sockets.socket_count(ConnectorId::Clearnet, Direction::Inbound),
        1
    );
    assert_eq!(
        sockets.socket_count(ConnectorId::Tor, Direction::Inbound),
        0
    );
    assert_eq!(
        sockets.endpoint(clearnet.id()),
        Some(ObservedEndpoint::Host(ip([10, 0, 0, 1])))
    );
    let tor = sockets
        .accept_tor(InboundCeiling::Bounded(2))
        .expect("room");
    assert_eq!(sockets.endpoint(tor.id()), Some(ObservedEndpoint::Zone));
}

#[test]
fn a_tor_dial_that_is_not_an_onion_reserves_nothing() {
    let sockets = Sockets::new();
    let error = sockets
        .open_tor(&NetworkAddress::Ipv4 {
            ip: Ipv4Addr::LOCALHOST,
            port: 18080,
        })
        .expect_err("not an onion");
    assert_eq!(refused(error), CloseKind::DialFailed);
    assert_eq!(sockets.live(), 0);
    let host = v3_onion_hostname(&[0x22; 32]);
    let _open = sockets
        .open_tor(&NetworkAddress::Tor { host, port: 18080 })
        .expect("onion");
    assert_eq!(
        sockets.socket_count(ConnectorId::Tor, Direction::Outbound),
        1
    );
}

#[test]
fn a_new_ban_closes_matching_sockets_once() {
    let sockets = Sockets::new();
    let banned = ip([10, 1, 2, 5]);
    let other = ip([10, 9, 0, 1]);
    let inside = sockets
        .accept_clearnet(banned, InboundCeiling::Bounded(8), now())
        .expect("in");
    let outbound = sockets.open_clearnet(banned, now()).expect("out");
    let kept = sockets
        .accept_clearnet(other, InboundCeiling::Bounded(8), now())
        .expect("other");
    let tor = sockets.accept_tor(InboundCeiling::Bounded(8)).expect("tor");
    let v6 = sockets
        .accept_clearnet(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            InboundCeiling::Bounded(8),
            now(),
        )
        .expect("v6");
    let closed = sockets.ban_host(banned, Tick::new(5_000), now());
    assert_eq!(closed.len(), 2);
    assert!(!sockets.is_live(inside.id()));
    assert!(!sockets.is_live(outbound.id()));
    assert!(sockets.is_live(kept.id()));
    assert!(sockets.is_live(tor.id()));
    assert!(sockets.is_live(v6.id()));
    assert_eq!(
        sockets.close(inside.id(), CloseCause::new(CloseKind::LocalClose)),
        CloseResult::AlreadyClosed
    );
    assert_eq!(sockets.live(), 3);
    drop(inside);
    drop(outbound);
    assert_eq!(sockets.live(), 3);

    let subnet = Ipv4Subnet::new(Ipv4Addr::new(10, 9, 0, 9), 24).expect("prefix");
    let closed = sockets.ban_subnet(subnet, Tick::new(5_000), now());
    assert_eq!(closed, vec![kept.id()]);
    assert!(sockets.is_live(v6.id()));
    assert_eq!(sockets.live(), 2);
    drop(kept);
    drop(tor);
    drop(v6);
    assert_eq!(sockets.live(), 0);
}

#[test]
fn lift_does_not_close_and_a_later_accept_is_admitted() {
    let sockets = Sockets::new();
    let host = ip([10, 0, 0, 8]);
    sockets.ban_host(host, Tick::new(5_000), now());
    assert!(sockets.lift_host(host));
    let _open = sockets
        .accept_clearnet(host, InboundCeiling::Bounded(2), now())
        .expect("lifted");
}

#[test]
fn racing_accepts_do_not_pass_the_ceiling() {
    let sockets = Sockets::new();
    let held = Arc::new(Mutex::new(Vec::new()));
    thread::scope(|scope| {
        for _ in 0..8 {
            let sockets = sockets.clone();
            let held = Arc::clone(&held);
            scope.spawn(move || {
                for _ in 0..20 {
                    if let Ok(open) = sockets.accept_tor(InboundCeiling::Bounded(5)) {
                        held.lock().expect("held").push(open);
                    }
                }
            });
        }
    });
    let guard = held.lock().expect("held");
    assert_eq!(guard.len(), 5);
    assert_eq!(sockets.live(), 5);
    assert_eq!(
        sockets.socket_count(ConnectorId::Tor, Direction::Inbound),
        5
    );
    drop(guard);
    drop(held);
    assert_eq!(sockets.live(), 0);
}

#[test]
fn simultaneous_closes_release_the_slot_once() {
    let sockets = Sockets::new();
    let open = sockets
        .accept_clearnet(ip([10, 0, 0, 1]), InboundCeiling::Bounded(2), now())
        .expect("open");
    let id = open.id();
    let results = thread::scope(|scope| {
        let first = scope.spawn(|| sockets.close(id, CloseCause::new(CloseKind::PeerClosed)));
        let second = scope.spawn(|| sockets.close(id, CloseCause::new(CloseKind::LocalClose)));
        (first.join().expect("join"), second.join().expect("join"))
    });
    let recorded = [results.0, results.1]
        .into_iter()
        .filter(|result| matches!(result, CloseResult::Recorded(_)))
        .count();
    assert_eq!(recorded, 1);
    assert_eq!(sockets.live(), 0);
    drop(open);
    assert_eq!(sockets.live(), 0);
}

#[test]
fn churn_of_accepts_and_closes_returns_to_zero() {
    let sockets = Sockets::new();
    thread::scope(|scope| {
        for n in 0..8u8 {
            let sockets = sockets.clone();
            scope.spawn(move || {
                let host = ip([10, 0, 0, n]);
                for i in 0..40 {
                    if let Ok(open) =
                        sockets.accept_clearnet(host, InboundCeiling::Bounded(64), now())
                    {
                        assert_eq!(
                            open.close(CloseCause::new(CloseKind::LocalClose)),
                            CloseResult::Recorded(CloseCause::new(CloseKind::LocalClose))
                        );
                    }
                    if i % 2 == 0 {
                        if let Ok(open) = sockets.accept_tor(InboundCeiling::Bounded(64)) {
                            drop(open);
                        }
                    }
                }
            });
        }
    });
    assert_eq!(sockets.live(), 0);
    assert_eq!(
        sockets.socket_count(ConnectorId::Clearnet, Direction::Inbound),
        0
    );
    assert_eq!(
        sockets.socket_count(ConnectorId::Tor, Direction::Inbound),
        0
    );
}

#[test]
fn dropping_a_clone_keeps_the_reservation_until_the_last_clone_drops() {
    let sockets = Sockets::new();
    let open = sockets
        .open_clearnet(ip([10, 0, 0, 8]), now())
        .expect("open");
    let id = open.id();
    let kept = open.clone();
    drop(open);
    assert_eq!(sockets.live(), 1);
    assert!(sockets.is_live(id));
    drop(kept);
    assert_eq!(sockets.live(), 0);
    assert!(!sockets.is_live(id));
}

#[test]
fn close_on_one_clone_makes_the_other_drop_a_no_op() {
    let sockets = Sockets::new();
    let open = sockets
        .open_clearnet(ip([10, 0, 0, 9]), now())
        .expect("open");
    let id = open.id();
    let other = open.clone();
    assert_eq!(
        open.close(CloseCause::new(CloseKind::LocalClose)),
        CloseResult::Recorded(CloseCause::new(CloseKind::LocalClose))
    );
    assert_eq!(sockets.live(), 0);
    drop(other);
    assert_eq!(sockets.live(), 0);
    assert!(!sockets.is_live(id));
    assert_eq!(
        sockets.close(id, CloseCause::new(CloseKind::IoError)),
        CloseResult::AlreadyClosed
    );
}

fn cases_from_env() -> u32 {
    match std::env::var("PROPTEST_CASES") {
        Ok(raw) => raw
            .parse()
            .unwrap_or_else(|_| panic!("PROPTEST_CASES must be a u32, got {raw}")),
        Err(std::env::VarError::NotPresent) => 64,
        Err(std::env::VarError::NotUnicode(_)) => panic!("PROPTEST_CASES is not Unicode"),
    }
}

pub(super) fn proptest_config() -> proptest::test_runner::Config {
    proptest::test_runner::Config {
        cases: cases_from_env(),
        ..proptest::test_runner::Config::default()
    }
}

pub(super) fn apply(sockets: &Sockets, open: &mut Vec<super::OpenSocket>, byte: u8) {
    let hosts = [
        ip([10, 0, 0, 1]),
        ip([10, 0, 0, 2]),
        ip([10, 1, 0, 1]),
        ip([192, 168, 0, 1]),
    ];
    let ceiling = InboundCeiling::Bounded(4);
    match byte % 6 {
        0 => {
            if let Ok(sock) =
                sockets.accept_clearnet(hosts[usize::from(byte) % hosts.len()], ceiling, now())
            {
                open.push(sock);
            }
        }
        1 => {
            if let Ok(sock) = sockets.accept_tor(ceiling) {
                open.push(sock);
            }
        }
        2 => {
            if let Ok(sock) = sockets.open_clearnet(hosts[usize::from(byte) % hosts.len()], now()) {
                open.push(sock);
            }
        }
        3 => {
            let host = v3_onion_hostname(&[0x33; 32]);
            if let Ok(sock) = sockets.open_tor(&NetworkAddress::Tor { host, port: 18080 }) {
                open.push(sock);
            }
        }
        4 => {
            if !open.is_empty() {
                let index = usize::from(byte) % open.len();
                let sock = open.swap_remove(index);
                let id = sock.id();
                assert!(matches!(
                    sockets.close(id, CloseCause::new(CloseKind::PeerClosed)),
                    CloseResult::Recorded(_)
                ));
                assert_eq!(
                    sockets.close(id, CloseCause::new(CloseKind::IoError)),
                    CloseResult::AlreadyClosed
                );
                drop(sock);
            }
        }
        _ => {
            if let Ok(sock) = sockets.accept_clearnet(hosts[0], ceiling, now()) {
                assert_eq!(
                    sock.close(CloseCause::new(CloseKind::TransportHandshakeFailed)),
                    CloseResult::Recorded(CloseCause::new(CloseKind::TransportHandshakeFailed))
                );
            }
        }
    }
}
