// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Zone host tests.

use std::ffi::c_void;

use shekyl_timing_engine::OwnerClass;

use shekyl_seam::Outbound;

use super::*;
use crate::inbound_ceiling_ffi::ShekylInboundCeiling;
use crate::inbound_ceiling_ffi::SHEKYL_INBOUND_CEILING_UNLIMITED;
use crate::seam_ffi::{shekyl_seam_bind, shekyl_seam_set_ceiling, ShekylSeamObserved};

unsafe extern "C" fn discard(
    _ctx: *mut c_void,
    _id: u64,
    _kind: u32,
    _observed: *const ShekylSeamObserved,
    _bytes: *const u8,
    _len: usize,
    _cause: *const CloseCause,
) {
}

/// The connectors arm every transport deadline on the host's engine
/// handle. `ensure` once stored the handle and dropped the service, so
/// the engine closed the moment `ensure` returned and every NNhfs and
/// Tor connection failed with `TransportHandshakeFailed`. The option-off
/// path arms nothing and never saw it.
#[test]
fn the_engine_outlives_ensure() {
    let _bind = crate::seam_ffi::seam_bind_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut executor = 0u8;
    let ceiling = ShekylInboundCeiling {
        kind: SHEKYL_INBOUND_CEILING_UNLIMITED,
        ceiling: 0,
        soft_limit: 0,
        held: 0,
    };
    let bound = unsafe {
        shekyl_seam_bind(
            std::ptr::addr_of_mut!(executor).cast::<c_void>(),
            Some(discard),
        )
    };
    assert_eq!(bound, 0);
    assert_eq!(unsafe { shekyl_seam_set_ceiling(&raw const ceiling) }, 0);
    let network_id = [7u8; 16];
    let host = ensure(network_id).expect("zone host");

    let owner = host.engine.register(OwnerClass::Transport);
    assert!(
        owner.is_ok(),
        "a transport deadline must be armable after ensure returns"
    );
    drop(owner);

    // An outbound-only tor zone installs its proxy without listening: the
    // Tor link (TSR-F1) is usable through it, and dial_tor reads its route.
    assert_eq!(host.hub.links().get(ConnectorId::Tor).route, None);
    dial_through_tor(
        shekyl_socks::Proxy::unauthenticated(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9050,
        )),
        network_id,
    )
    .expect("the proxy install");
    let link = host.hub.links().get(ConnectorId::Tor);
    assert_eq!(
        link.route,
        Some(Route::Socks(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9050
        ))),
        "dial_tor reads this route; none is DialFailed before the network"
    );
    assert!(
        link.is_usable(),
        "nothing watches an operator's Tor, so its link stays usable"
    );

    shutdown();
    assert_eq!(
        host.hub.links().get(ConnectorId::Tor).route,
        None,
        "the zone's routes leave with it"
    );
    assert!(
        host.engine.register(OwnerClass::Transport).is_err(),
        "shutdown closes the engine"
    );
    unsafe {
        shekyl_seam_bind(std::ptr::null_mut(), None);
    }
}

/// One process clock (Rick, 2026-10-14): the zone host's engine reads
/// the hub's origin, so an engine `now` read between two hub reads lies
/// between them. *Records-was:* the host started its own clock, and the
/// two origins differed by the time between the seam's first clock read
/// and the host's start (0.49 ms on the measurement host; unbounded in
/// general, since a ban can be written long before the host starts).
#[test]
fn the_engine_reads_the_process_clock() {
    let _bind = crate::seam_ffi::seam_bind_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut executor = 0u8;
    let ceiling = ShekylInboundCeiling {
        kind: SHEKYL_INBOUND_CEILING_UNLIMITED,
        ceiling: 0,
        soft_limit: 0,
        held: 0,
    };
    let bound = unsafe {
        shekyl_seam_bind(
            std::ptr::addr_of_mut!(executor).cast::<c_void>(),
            Some(discard),
        )
    };
    assert_eq!(bound, 0);
    assert_eq!(unsafe { shekyl_seam_set_ceiling(&raw const ceiling) }, 0);
    let network_id = [7u8; 16];
    let host = ensure(network_id).expect("zone host");
    let owner = host
        .engine
        .register(OwnerClass::Transport)
        .expect("transport owner");
    for _ in 0..1_000 {
        let before = host.hub.now();
        let engine_now = owner.clock().now();
        let after = host.hub.now();
        assert!(
            before <= engine_now && engine_now <= after,
            "the engine's clock ({}) is not the hub's ({} to {})",
            engine_now.get(),
            before.get(),
            after.get()
        );
    }
    drop(owner);
    shutdown();
    unsafe {
        shekyl_seam_bind(std::ptr::null_mut(), None);
    }
}

/// One owner loop per connector (the §4 run, 2026-10-13): the
/// ephemeral-tor listen started Tor's loop, then the zone loop's
/// proxy-only branch called `shekyl_zone_set_tor_proxy` and started it
/// again, so two `p2p-dial-tor` threads ran. The second start now finds
/// the loop claimed and starts nothing; the proxy install still answers
/// 0, since the proxy it writes is the same.
#[test]
fn a_second_start_of_a_connectors_loop_starts_nothing() {
    let _bind = crate::seam_ffi::seam_bind_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut executor = 0u8;
    let ceiling = ShekylInboundCeiling {
        kind: SHEKYL_INBOUND_CEILING_UNLIMITED,
        ceiling: 0,
        soft_limit: 0,
        held: 0,
    };
    let bound = unsafe {
        shekyl_seam_bind(
            std::ptr::addr_of_mut!(executor).cast::<c_void>(),
            Some(discard),
        )
    };
    assert_eq!(bound, 0);
    assert_eq!(unsafe { shekyl_seam_set_ceiling(&raw const ceiling) }, 0);
    let network_id = [9u8; 16];
    let host = ensure(network_id).expect("zone host");

    assert!(
        crate::dialer_ffi::start_connector(ConnectorId::Tor, &host.engine),
        "the first start takes the loop"
    );
    assert!(
        !crate::dialer_ffi::start_connector(ConnectorId::Tor, &host.engine),
        "a second start finds it taken and starts nothing"
    );
    dial_through_tor(
        shekyl_socks::Proxy::unauthenticated(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9050,
        )),
        network_id,
    )
    .expect("the proxy install is not refused by the claimed loop");

    shutdown();
    unsafe {
        shekyl_seam_bind(std::ptr::null_mut(), None);
    }
}

/// Shutdown stops and drops the dialer while the seam stays bound, so
/// a zone host built after it (a daemon re-initialised in one process,
/// as the unit tests do) had no dialer: every push was held for a
/// build that never came, and the listing export refused.
#[test]
fn a_zone_host_built_after_shutdown_has_a_dialer() {
    let _bind = crate::seam_ffi::seam_bind_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut executor = 0u8;
    let ceiling = crate::inbound_ceiling_ffi::ShekylInboundCeiling {
        kind: SHEKYL_INBOUND_CEILING_UNLIMITED,
        ceiling: 0,
        soft_limit: 0,
        held: 0,
    };
    unsafe {
        shekyl_seam_bind(std::ptr::null_mut(), None);
    }
    let bound = unsafe {
        shekyl_seam_bind(
            std::ptr::addr_of_mut!(executor).cast::<c_void>(),
            Some(discard),
        )
    };
    assert_eq!(bound, 0);
    assert_eq!(unsafe { shekyl_seam_set_ceiling(&raw const ceiling) }, 0);
    assert!(crate::dialer_ffi::dialer().is_some(), "built at the bind");
    let network_id = [7u8; 16];
    let first = ensure(network_id).expect("zone host");
    shutdown();
    assert!(
        crate::dialer_ffi::dialer().is_none(),
        "shutdown drops the dialer"
    );
    assert!(crate::seam_ffi::hub().is_some(), "and the seam stays bound");
    drop(first);
    let second = ensure(network_id).expect("a second zone host");
    assert!(
        crate::dialer_ffi::dialer().is_some(),
        "the second host builds the dialer again"
    );
    shutdown();
    drop(second);
    unsafe {
        shekyl_seam_bind(std::ptr::null_mut(), None);
    }
}

#[test]
fn a_closed_admission_keeps_the_dial_cause() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let (tx, rx) = mpsc::unbounded_channel::<u8>();
        let (fail_tx, fail_rx) = oneshot::channel();
        fail_tx
            .send(CloseCause::new(CloseKind::DialFailed))
            .expect("cause");
        drop(tx);
        let err = recv_admitted(rx, fail_rx).await.expect_err("dial failed");
        assert_eq!(err.kind(), CloseKind::DialFailed);
    });
}

/// A listener that cannot bind is a refusal naming the endpoint, and
/// nothing of that start survives: the endpoint already taken by one host's
/// clearnet is refused to a second start (the C++ `bind_same_p2p_port`
/// test's subject, now the zone host's).
#[test]
fn a_clearnet_endpoint_already_bound_is_refused_with_its_address() {
    let _bind = crate::seam_ffi::seam_bind_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut executor = 0u8;
    let ceiling = ShekylInboundCeiling {
        kind: SHEKYL_INBOUND_CEILING_UNLIMITED,
        ceiling: 0,
        soft_limit: 0,
        held: 0,
    };
    let bound = unsafe {
        shekyl_seam_bind(
            std::ptr::addr_of_mut!(executor).cast::<c_void>(),
            Some(discard),
        )
    };
    assert_eq!(bound, 0);
    assert_eq!(unsafe { shekyl_seam_set_ceiling(&raw const ceiling) }, 0);
    let network_id = [11u8; 16];
    let first = start_clearnet(
        &[SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
        None,
        false,
        network_id,
    )
    .expect("the first start binds");
    assert_eq!(first.len(), 1);
    let taken = first[0];
    assert_ne!(taken.port(), 0, "the OS chose a port");
    // Another listener on the taken endpoint: refused, naming it. (The
    // host is one per process, so this is a second listener set on the
    // same host, which is what a second start would bind.)
    let again = start_clearnet(&[taken], None, false, network_id);
    match again {
        Err(ZoneStart::Bind { addr, .. }) => assert_eq!(addr, taken),
        other => panic!("a taken endpoint must be refused as a bind error: {other:?}"),
    }
    // A free endpoint beside the taken one still binds.
    let another = start_clearnet(
        &[SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
        None,
        false,
        network_id,
    )
    .expect("a free endpoint binds");
    assert_ne!(another[0], taken);
    shutdown();
    unsafe {
        shekyl_seam_bind(std::ptr::null_mut(), None);
    }
}

/// The managed Tor's death takes the Tor link down, naming the incarnation
/// installed when the watch began (`TSR-F1`). A death that arrives after
/// another route was installed leaves that route usable. Publishing the
/// down without the incarnation check fails the second half.
#[test]
fn a_managed_tor_death_takes_its_own_incarnation_down_and_no_later_one() {
    let _bind = crate::seam_ffi::seam_bind_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut executor = 0u8;
    let ceiling = ShekylInboundCeiling {
        kind: SHEKYL_INBOUND_CEILING_UNLIMITED,
        ceiling: 0,
        soft_limit: 0,
        held: 0,
    };
    let bound = unsafe {
        shekyl_seam_bind(
            std::ptr::addr_of_mut!(executor).cast::<c_void>(),
            Some(discard),
        )
    };
    assert_eq!(bound, 0);
    assert_eq!(unsafe { shekyl_seam_set_ceiling(&raw const ceiling) }, 0);
    let network_id = [12u8; 16];
    let socks =
        |port| Proxy::unauthenticated(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    let fell_within = |host: &Host, wanted: bool| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if host.hub.links().get(ConnectorId::Tor).is_usable() != wanted {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        false
    };
    assert!(
        !watch_managed_tor(std::future::pending()),
        "no zone host, no watch"
    );

    dial_through_tor(socks(9050), network_id).expect("the proxy install");
    let host = ensure(network_id).expect("zone host");
    let (died, death) = tokio::sync::oneshot::channel();
    assert!(watch_managed_tor(async move {
        death.await.unwrap_or(DownCause::ProcessStopped)
    }));
    died.send(DownCause::ProcessExited)
        .expect("the watch waits");
    assert!(fell_within(&host, true), "the death took the link down");
    assert!(matches!(
        host.hub.links().get(ConnectorId::Tor).outbound,
        Outbound::Down {
            cause: DownCause::ProcessExited,
            ..
        }
    ));

    let (died, death) = tokio::sync::oneshot::channel();
    assert!(watch_managed_tor(async move {
        death.await.unwrap_or(DownCause::ProcessStopped)
    }));
    dial_through_tor(socks(9051), network_id).expect("a later route");
    died.send(DownCause::ProcessExited)
        .expect("the watch waits");
    assert!(
        !fell_within(&host, true),
        "the later route is not the dead Tor's"
    );

    shutdown();
    unsafe {
        shekyl_seam_bind(std::ptr::null_mut(), None);
    }
}

/// A pair is presented to the proxy it was given for and to no other
/// (DC-Q7): a route at another address, such as a managed Tor's port, dials
/// unauthenticated.
#[test]
fn a_pair_is_presented_only_at_its_own_proxy() {
    let at = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9050);
    let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9150);
    let pair = shekyl_socks::SocksUsername::new(b"op", b"pw").expect("a pair");
    let configured = Proxy::authenticated(at, pair);
    let here = presented(at, Some(&configured));
    assert_eq!(here.at(), at);
    assert!(here.authenticates(), "its own proxy gets the pair");
    let elsewhere = presented(other, Some(&configured));
    assert_eq!(elsewhere.at(), other);
    assert!(!elsewhere.authenticates(), "another proxy gets no pair");
    assert!(!presented(at, None).authenticates());
}
