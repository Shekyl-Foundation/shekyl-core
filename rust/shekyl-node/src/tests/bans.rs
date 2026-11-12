// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bans on the node's socket table.

use super::*;

/// A finite ban on a node with no connectors ends when its time is up. A
/// lookup does not end a ban, so the network's expiry timer has to run
/// with no connector up. Red edit: start the timer only with a connector.
#[test]
fn a_finite_ban_on_an_offline_node_ends_when_its_time_is_up() {
    let dir = tempfile::tempdir().expect("temp");
    let node = open_at(dir.path(), Arc::new(|| {}));
    let host = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
    let target = shekyl_daemon_rpc::handles::BanTargetFacts::Host(host);
    assert!(node.handles().bans.ban(target, Some(1)).expect("ban"));
    assert!(
        node.handles().bans.remaining(host).expect("read").is_some(),
        "the ban is in force"
    );
    let give_up = std::time::Instant::now() + Duration::from_secs(10);
    while node.handles().bans.remaining(host).expect("read").is_some() {
        assert!(
            std::time::Instant::now() < give_up,
            "the ban stayed in force past its second"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    node.stop();
}

/// A ban through the node is on the socket table every connector admits
/// through, and the network's ban verbs read the same table. Red edit:
/// ban on a table the node does not hold.
#[test]
fn a_ban_through_the_node_is_on_the_node_socket_table() {
    let dir = tempfile::tempdir().expect("temp");
    let node = open_at(dir.path(), Arc::new(|| {}));
    let host = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    let target = shekyl_daemon_rpc::handles::BanTargetFacts::Host(host);
    assert!(node.handles().bans.ban(target, None).expect("ban"));
    assert!(
        node.sockets().is_banned(host),
        "the admission table holds the node's ban"
    );
    assert!(
        node.network().bans().is_banned(host),
        "the network's ban verbs read the node's table"
    );
    assert_eq!(
        node.handles().bans.remaining(host).expect("banned"),
        Some(shekyl_daemon_rpc::handles::BanLeftFacts::Permanent)
    );
    node.stop();
}
/// The ban methods over the node's table (DX-Q3, Q11): `ban_add` bans a
/// host for a time and a subnet until lifted; `ban_list` lists both with
/// their time left; `ban_show` answers for a host inside the subnet;
/// `ban_remove` lifts; a malformed host changes nothing. Red edit: apply
/// the ban before the host parses.
#[test]
fn add_list_show_and_remove_round_trip_over_the_nodes_table() {
    use shekyl_daemon_rpc::ban_methods::{ban_add, ban_list, ban_remove, ban_show, codes};
    use shekyl_rpc_types::kinds::{Duration, Text};
    use shekyl_rpc_types::wire::node::{BanAdd, BanHost};
    let dir = tempfile::tempdir().expect("temp");
    let node = open_at(dir.path(), Arc::new(|| {}));
    let bans = node.handles().bans;
    let add = |host: &str, seconds: Option<u64>| BanAdd {
        host: Text(host.to_owned()),
        duration: seconds.map(Duration),
    };
    let host = |host: &str| BanHost {
        host: Text(host.to_owned()),
    };
    let refused = ban_add(&*bans, &add("not-a-host", None)).expect_err("malformed");
    assert_eq!(refused.diagnostic.code, codes::BAD_HOST);
    assert!(
        ban_list(&*bans).expect("list").is_empty(),
        "nothing applied"
    );
    ban_add(&*bans, &add("198.51.100.4", Some(600))).expect("banned");
    ban_add(&*bans, &add("192.0.2.0/24", None)).expect("banned");
    let mut listed = ban_list(&*bans).expect("list");
    listed.sort_by(|a, b| a.host.0.cmp(&b.host.0));
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].host.0, "192.0.2.0/24");
    assert!(listed[0].permanent && listed[0].duration.0.is_none());
    assert_eq!(listed[1].host.0, "198.51.100.4");
    let left = listed[1].duration.0.expect("a timed ban has time left").0;
    assert!(!listed[1].permanent && left > 590 && left <= 600);
    let inside = ban_show(&*bans, &host("192.0.2.77"))
        .expect("answered")
        .0
        .expect("the subnet covers its hosts");
    assert!(inside.permanent);
    ban_remove(&*bans, &host("192.0.2.0/24")).expect("lifted");
    let lifted = ban_show(&*bans, &host("192.0.2.77")).expect("answered");
    assert!(lifted.0.is_none(), "not banned once lifted");
    node.stop();
}
