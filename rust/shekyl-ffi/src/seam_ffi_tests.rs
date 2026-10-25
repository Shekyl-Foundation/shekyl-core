// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use shekyl_seam::CloseCause;
use shekyl_timing_engine::Tick;

use super::{
    bans::host_is_banned, install_process_sockets, process_sockets, seam_bind_lock,
    shekyl_seam_bind, ShekylSeamObserved,
};

/// A hub whose posts go nowhere.
unsafe extern "C" fn no_post(
    _ctx: *mut c_void,
    _id: u64,
    _kind: u32,
    _observed: *const ShekylSeamObserved,
    _bytes: *const u8,
    _len: usize,
    _cause: *const CloseCause,
) {
}

fn unbind() {
    assert_eq!(unsafe { shekyl_seam_bind(std::ptr::null_mut(), None) }, 0);
    assert!(super::hub().is_none());
}

fn bind() {
    let mut ctx = 0u8;
    assert_eq!(
        unsafe { shekyl_seam_bind((&raw mut ctx).cast::<c_void>(), Some(no_post)) },
        0
    );
}

/// The ban path (DX-Q3, Q11) under a bound hub: a ban closes a live
/// session and refuses the next dial; `remaining`, the listing and
/// `lift` read and change the hub's table; a subnet ban covers a host
/// inside it; a timed ban expires at the process clock. Red edit: lift
/// through the path's own table while a hub is bound.
#[test]
fn the_ban_path_goes_through_a_bound_hub() {
    use std::time::Duration;

    use shekyl_seam::{BanLeft, CloseKind, Direction, Endpoint, Ipv4Subnet, ListedBan};

    use super::bans::{BanPath, BanSpan, BanTarget};
    let _gate = seam_bind_lock().lock();
    unbind();
    bind();
    let hub = super::hub().expect("bound");
    hub.install_loopback(32);
    let host = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
    let endpoint = Endpoint::Clearnet {
        ip: host,
        port: 18080,
        direction: Direction::Outbound,
    };
    let live = hub.connect(&endpoint).expect("open");
    // A path over a table of its own: under a bound hub it is the hub's
    // table the verbs change.
    let path = BanPath::over(shekyl_seam::Sockets::new());
    assert!(path.ban(BanTarget::Host(host), BanSpan::Permanent));
    assert!(hub.cause(live.id).is_some(), "the live session was closed");
    drop(live);
    let Err(refused) = hub.connect(&endpoint) else {
        panic!("a banned host was dialled");
    };
    assert_eq!(refused.kind(), CloseKind::AdmissionRefused);
    assert_eq!(path.remaining(host), Some(BanLeft::Permanent));
    assert!(path
        .listed()
        .iter()
        .any(|row| matches!(row, ListedBan::Host { host: listed, .. } if *listed == host)));
    assert!(path.lift(BanTarget::Host(host)));
    assert_eq!(path.remaining(host), None);
    drop(hub.connect(&endpoint).expect("lifted, dialled"));
    let subnet = Ipv4Subnet::new(Ipv4Addr::new(203, 0, 113, 0), 24).expect("a /24");
    assert!(path.ban(
        BanTarget::Subnet(subnet),
        BanSpan::For(Duration::from_millis(1))
    ));
    assert!(path.is_banned(host), "a host inside the subnet");
    std::thread::sleep(Duration::from_millis(20));
    assert!(!path.is_banned(host), "expired at the process clock");
    let _lifted = path.lift(BanTarget::Subnet(subnet));
    unbind();
}

/// The peer and session counts get_info reads (DX-Q3, b9) are the
/// bound hub's: its sockets by connector and direction and its board's
/// handshaken sessions; with no hub bound there are none to report,
/// which is not zero. Red edit: count the outbound socket as inbound.
#[test]
fn the_peer_counts_are_the_bound_hubs() {
    use shekyl_seam::{Direction, Endpoint};
    let _gate = seam_bind_lock().lock();
    unbind();
    assert_eq!(crate::rpc_peerlist_ffi::peer_counts(), None);
    assert_eq!(crate::rpc_peerlist_ffi::session_counts(), None);
    bind();
    let hub = super::hub().expect("bound");
    hub.install_loopback(32);
    let endpoint = Endpoint::Clearnet {
        ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88)),
        port: 18080,
        direction: Direction::Outbound,
    };
    let open = hub.connect(&endpoint).expect("open");
    let counts = crate::rpc_peerlist_ffi::peer_counts().expect("a hub and a dialer");
    assert_eq!(counts.clearnet_out, 1);
    assert_eq!(counts.clearnet_in, 0);
    assert_eq!(
        counts.clearnet_out,
        hub.socket_count(shekyl_seam::ConnectorId::Clearnet, Direction::Outbound)
    );
    let board = hub.board();
    assert_eq!(
        crate::rpc_peerlist_ffi::session_counts(),
        Some((
            u64::try_from(board.established_count(Direction::Outbound)).expect("fits"),
            u64::try_from(board.established_count(Direction::Inbound)).expect("fits"),
        ))
    );
    drop(open);
    unbind();
}

/// Install, then bind: the hub is built on the table that was installed.
/// A ban on that table is the hub's ban. Red edit: build the hub on a
/// table of its own.
#[test]
fn an_install_then_a_bind_shares_the_installed_table() {
    let _gate = seam_bind_lock().lock();
    unbind();
    let installed = shekyl_seam::Sockets::new();
    assert!(install_process_sockets(installed.clone()));
    bind();
    let host = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let _closed = installed.ban_host_permanent(host);
    assert!(
        super::hub().expect("bound").is_banned(host),
        "the hub reads the table install published"
    );
    installed.lift_host(host);
    unbind();
}

/// Bind, then install: the install refuses, and the hub keeps the table
/// it was built with. A ban on the refused table is not the hub's. Red
/// edit: replace the table under a bound hub.
#[test]
fn a_bind_then_an_install_keeps_the_hubs_table() {
    let _gate = seam_bind_lock().lock();
    unbind();
    bind();
    let refused = shekyl_seam::Sockets::new();
    assert!(
        !install_process_sockets(refused.clone()),
        "a bound hub refuses the install"
    );
    let host = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    let _closed = refused.ban_host_permanent(host);
    assert!(
        !super::hub().expect("bound").is_banned(host),
        "the refused table is not the hub's"
    );
    let _closed = process_sockets().ban_host_permanent(host);
    assert!(
        super::hub().expect("bound").is_banned(host),
        "the hub still reads the table it was built with"
    );
    process_sockets().lift_host(host);
    unbind();
}

/// One millisecond, then long enough that the process clock is past it.
const ONE_MILLISECOND: Duration = Duration::from_millis(1);
const PAST_THE_DEADLINE: Duration = Duration::from_millis(20);

/// A deadline that has passed is not a ban on the process clock. Reading
/// it at tick zero still says it is: that tick is before the deadline.
/// Red edit: answer `banned` from tick zero.
#[test]
fn a_passed_deadline_is_not_a_ban_and_tick_zero_still_says_it_is() {
    let _gate = seam_bind_lock().lock();
    unbind();
    let host = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
    let now = super::ban_now();
    let until = Tick::new(
        now.get()
            .saturating_add(u64::try_from(ONE_MILLISECOND.as_nanos()).expect("one millisecond")),
    );
    let _closed = process_sockets().ban_host(host, until, now);
    std::thread::sleep(PAST_THE_DEADLINE);
    assert!(
        process_sockets().is_banned(host, Tick::new(0)),
        "tick zero is before the deadline, so the ban still reads as live"
    );
    assert!(
        !host_is_banned(host),
        "the process clock is past the deadline"
    );
}
