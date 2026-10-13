// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The candidate draw (dialer brief, "The fill" and "The candidate
//! filter"): uniform over the hosts that have an eligible address, then
//! uniform over that host's eligible ports.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{
    ConnectorId, DialOutcome, NetworkAddress, NoBans, Peerlist, RefusedSet, Source, Tick, GRAY_CAP,
};

const C: ConnectorId = ConnectorId::Clearnet;

fn now() -> Tick {
    Tick::new(0)
}

fn host(n: u16, port: u16) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 10, (n >> 8) as u8, (n & 0xff) as u8),
        port,
    }
}

fn gray_list(addresses: &[NetworkAddress], rng: &mut SplitMix64) -> Peerlist {
    let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
    for address in addresses {
        list.admit_gray(address, Source::Operator, now(), &mut NoBans, rng)
            .expect("admitted");
    }
    list
}

/// Draw once and put the draw back, so one list serves many draws.
fn draw_and_return(
    list: &mut Peerlist,
    eligible: &mut dyn FnMut(&NetworkAddress) -> bool,
    rng: &mut SplitMix64,
) -> Option<NetworkAddress> {
    let drawn = list.draw_gray_where(C, eligible, rng)?;
    list.apply(&DialOutcome::PayloadRefused(drawn.clone()), now(), rng);
    Some(drawn)
}

/// Every count within `sigmas` standard deviations of `draws / cells`.
fn assert_uniform(counts: &[u32], draws: u32, sigmas: f64, what: &str) {
    let cells = f64::from(u32::try_from(counts.len()).expect("few cells"));
    let mean = f64::from(draws) / cells;
    let sd = (f64::from(draws) * (1.0 / cells) * (1.0 - 1.0 / cells)).sqrt();
    for (cell, count) in counts.iter().enumerate() {
        let off = (f64::from(*count) - mean).abs();
        assert!(
            off <= sigmas * sd,
            "{what}: cell {cell} has {count}, expected {mean:.0} within {:.0}",
            sigmas * sd
        );
    }
}

#[test]
fn the_gray_draw_is_uniform_over_eligible_hosts() {
    let mut rng = SplitMix64::new(1);
    let hosts: Vec<NetworkAddress> = (0..20).map(|n| host(n, 18080)).collect();
    let mut list = gray_list(&hosts, &mut rng);
    let draws = 40_000;
    let mut counts = vec![0u32; hosts.len()];
    for _ in 0..draws {
        let drawn = draw_and_return(&mut list, &mut |_| true, &mut rng).expect("drawable");
        counts[hosts.iter().position(|a| *a == drawn).expect("ours")] += 1;
    }
    assert_uniform(&counts, draws, 5.0, "20 hosts");
}

#[test]
fn the_gray_draw_is_uniform_over_a_full_gray_list() {
    let mut rng = SplitMix64::new(2);
    let full = u16::try_from(GRAY_CAP).expect("fits");
    let hosts: Vec<NetworkAddress> = (0..full).map(|n| host(n, 18080)).collect();
    let mut list = gray_list(&hosts, &mut rng);
    assert_eq!(list.gray_count(C), GRAY_CAP);
    assert_eq!(list.gray_candidates(C, &mut |_| true), GRAY_CAP);

    // Ten cells by position in the admission order: an order-biased draw
    // would favour the early cells or the late ones.
    let index: BTreeMap<&NetworkAddress, usize> =
        hosts.iter().enumerate().map(|(i, a)| (a, i)).collect();
    let draws = 4_000;
    let mut counts = vec![0u32; 10];
    for _ in 0..draws {
        let drawn = draw_and_return(&mut list, &mut |_| true, &mut rng).expect("drawable");
        counts[index[&drawn] * 10 / GRAY_CAP] += 1;
    }
    assert_uniform(&counts, draws, 5.0, "a full gray list, by admission decile");
}

#[test]
fn a_host_with_many_ports_is_drawn_no_more_often_and_its_port_is_uniform() {
    let mut rng = SplitMix64::new(3);
    // Host 0 advertises ten ports. Hosts 1 to 9 advertise one each.
    let mut addresses: Vec<NetworkAddress> = (0..10).map(|p| host(0, 18080 + p)).collect();
    addresses.extend((1..10).map(|n| host(n, 18080)));
    let mut list = gray_list(&addresses, &mut rng);
    assert_eq!(list.gray_count(C), 19);
    assert_eq!(
        list.gray_candidates(C, &mut |_| true),
        10,
        "ten hosts, not nineteen"
    );

    let draws = 30_000;
    let mut by_host = vec![0u32; 10];
    let mut by_port = vec![0u32; 10];
    for _ in 0..draws {
        let drawn = draw_and_return(&mut list, &mut |_| true, &mut rng).expect("drawable");
        let NetworkAddress::Ipv4 { ip, port } = drawn else {
            panic!("clearnet");
        };
        let n = usize::from(ip.octets()[3]);
        by_host[n] += 1;
        if n == 0 {
            by_port[usize::from(port - 18080)] += 1;
        }
    }
    // One in ten, where a draw over addresses would give ten in nineteen.
    assert_uniform(&by_host, draws, 5.0, "ten hosts");
    assert_uniform(&by_port, by_host[0], 5.0, "host 0's ten ports");
}

#[test]
fn only_an_eligible_address_is_drawn_and_none_eligible_draws_nothing() {
    let mut rng = SplitMix64::new(4);
    let hosts: Vec<NetworkAddress> = (0..10).map(|n| host(n, 18080)).collect();
    let mut list = gray_list(&hosts, &mut rng);
    let allowed = [hosts[2].clone(), hosts[7].clone()];
    let mut seen = [0u32; 2];
    for _ in 0..400 {
        let drawn = draw_and_return(&mut list, &mut |a| allowed.contains(a), &mut rng)
            .expect("two are eligible");
        seen[allowed
            .iter()
            .position(|a| *a == drawn)
            .expect("an allowed one")] += 1;
    }
    assert!(
        seen[0] > 100 && seen[1] > 100,
        "both eligible hosts are drawn: {seen:?}"
    );
    assert_eq!(list.gray_candidates(C, &mut |a| allowed.contains(a)), 2);

    assert_eq!(list.draw_gray_where(C, &mut |_| false, &mut rng), None);
    assert_eq!(
        list.gray_candidates(C, &mut |_| true),
        10,
        "a draw that found nothing left no outstanding draw behind"
    );
}

#[test]
fn a_drawn_address_is_outstanding_and_is_not_drawn_again() {
    let mut rng = SplitMix64::new(5);
    let hosts: Vec<NetworkAddress> = (0..6).map(|n| host(n, 18080)).collect();
    let mut list = gray_list(&hosts, &mut rng);
    let mut drawn = Vec::new();
    while let Some(address) = list.draw_gray_where(C, &mut |_| true, &mut rng) {
        assert!(!drawn.contains(&address), "{address:?} drawn twice");
        drawn.push(address);
    }
    assert_eq!(drawn.len(), 6, "each address once, then nothing");
    assert_eq!(list.gray_candidates(C, &mut |_| true), 0);
    assert_eq!(
        list.gray_count(C),
        6,
        "an outstanding draw is still gray to a reader"
    );
}

#[test]
fn the_white_draw_takes_white_only_and_counts_hosts() {
    let mut rng = SplitMix64::new(6);
    let hosts: Vec<NetworkAddress> = (0..8).map(|n| host(n, 18080)).collect();
    let mut list = gray_list(&hosts, &mut rng);
    // Four reach white, the only way there is.
    let mut white = Vec::new();
    for _ in 0..4 {
        let address = list
            .draw_gray_where(C, &mut |_| true, &mut rng)
            .expect("gray");
        list.apply(&DialOutcome::Confirmed(address.clone()), now(), &mut rng);
        white.push(address);
    }
    assert_eq!(
        list.white_candidates(C, now(), &mut NoBans, &mut |_| true, &mut rng),
        4
    );
    assert_eq!(list.gray_candidates(C, &mut |_| true), 4);
    for _ in 0..200 {
        let drawn = list
            .draw_white_where(C, now(), &mut NoBans, &mut |_| true, &mut rng)
            .expect("white");
        assert!(
            white.contains(&drawn),
            "a white draw returned a gray address"
        );
    }
    // A white address that is already a session is not eligible.
    let live = white[0].clone();
    for _ in 0..200 {
        let drawn = list
            .draw_white_where(C, now(), &mut NoBans, &mut |a| *a != live, &mut rng)
            .expect("three remain");
        assert_ne!(drawn, live);
    }
    assert_eq!(
        list.draw_white_where(C, now(), &mut NoBans, &mut |_| false, &mut rng),
        None
    );
}
