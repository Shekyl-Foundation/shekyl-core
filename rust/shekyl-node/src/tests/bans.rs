// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bans on the node's socket table.

use super::*;

/// A ban through the node is on the table `process_sockets` reads.
/// Red edit: install a second table, or ban on a table the node does
/// not hold.
#[test]
fn a_ban_through_the_node_is_on_the_process_socket_table() {
    let dir = tempfile::tempdir().expect("temp");
    let node = open_at(dir.path(), Arc::new(|| {}));
    assert!(
        shekyl_ffi::seam_ffi::install_process_sockets(node.sockets()),
        "the table is installed once, before any reader"
    );
    let host = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    let target = shekyl_daemon_rpc::handles::BanTargetFacts::Host(host);
    assert!(node.handles().bans.ban(target, None).expect("ban"));
    assert!(
        shekyl_ffi::seam_ffi::process_sockets().is_banned(host, Tick::new(0)),
        "the FFI reader sees the node's table"
    );
    assert_eq!(
        node.handles().bans.remaining(host).expect("banned"),
        Some(shekyl_daemon_rpc::handles::BanLeftFacts::Permanent)
    );
    node.stop();
}
/// The ban methods over the node's table (DX-Q3, Q11): `set_bans` bans
/// a host for a time, a subnet until lifted, and lifts; `get_bans` lists
/// both with their time left; `banned` answers for a host inside the
/// subnet; a malformed entry changes nothing. Red edit: apply entries
/// as they are read.
#[test]
fn set_get_and_banned_round_trip_over_the_nodes_table() {
    use shekyl_daemon_rpc::ban_methods::{banned, codes, get_bans, set_bans};
    use shekyl_rpc_types::bans::{BannedRequest, SetBan, SetBansRequest};
    let dir = tempfile::tempdir().expect("temp");
    let node = open_at(dir.path(), Arc::new(|| {}));
    let bans = node.handles().bans;
    let entry = |host: &str, ban: bool, seconds: Option<u64>| SetBan {
        host: host.to_owned(),
        ban,
        seconds,
    };
    let refused = set_bans(
        &*bans,
        &SetBansRequest {
            bans: vec![
                entry("198.51.100.4", true, Some(600)),
                entry("not-a-host", true, None),
            ],
        },
    )
    .expect_err("malformed");
    assert_eq!(refused.diagnostic.code, codes::BAD_HOST);
    assert!(
        get_bans(&*bans).expect("list").bans.is_empty(),
        "nothing applied"
    );
    set_bans(
        &*bans,
        &SetBansRequest {
            bans: vec![
                entry("198.51.100.4", true, Some(600)),
                entry("192.0.2.0/24", true, None),
            ],
        },
    )
    .expect("banned");
    let mut listed = get_bans(&*bans).expect("list").bans;
    listed.sort_by(|a, b| a.host.cmp(&b.host));
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].host, "192.0.2.0/24");
    assert!(listed[0].permanent);
    assert_eq!(listed[1].host, "198.51.100.4");
    assert!(!listed[1].permanent && listed[1].seconds > 590 && listed[1].seconds <= 600);
    let inside = banned(
        &*bans,
        &BannedRequest {
            address: "192.0.2.77".to_owned(),
        },
    )
    .expect("banned");
    assert!(
        inside.banned && inside.permanent,
        "the subnet covers its hosts"
    );
    set_bans(
        &*bans,
        &SetBansRequest {
            bans: vec![entry("192.0.2.0/24", false, None)],
        },
    )
    .expect("lifted");
    let lifted = banned(
        &*bans,
        &BannedRequest {
            address: "192.0.2.77".to_owned(),
        },
    )
    .expect("answered");
    assert!(!lifted.banned);
    node.stop();
}
