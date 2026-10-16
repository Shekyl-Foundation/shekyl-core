// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Zone host tests.

use std::ffi::c_void;

use shekyl_peer_policy::UnboundedReason;
use shekyl_timing_engine::OwnerClass;

use super::*;
use crate::inbound_ceiling_ffi::SHEKYL_INBOUND_CEILING_UNLIMITED;
use crate::seam_ffi::{shekyl_seam_bind, ShekylSeamObserved};

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
            &raw const ceiling,
        )
    };
    assert_eq!(bound, 0);
    let network_id = [7u8; 16];
    let host = ensure(
        network_id.as_ptr(),
        InboundCeiling::Unbounded(UnboundedReason::Unlimited),
    )
    .expect("zone host");

    let owner = host.engine.register(OwnerClass::Transport);
    assert!(
        owner.is_ok(),
        "a transport deadline must be armable after ensure returns"
    );
    drop(owner);

    // An outbound-only tor zone installs its proxy without listening: the
    // Tor link (TSR-F1) is usable through it, and dial_tor reads its route.
    assert_eq!(host.hub.links().get(ConnectorId::Tor).route, None);
    let socks = std::ffi::CString::new("127.0.0.1").expect("socks host");
    let rc = unsafe {
        shekyl_zone_set_tor_proxy(
            socks.as_ptr(),
            9050,
            network_id.as_ptr(),
            &raw const ceiling,
        )
    };
    assert_eq!(rc, 0);
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
        "no managed Tor holds this port, so no death edge takes it down"
    );

    shekyl_zone_shutdown();
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
        shekyl_seam_bind(std::ptr::null_mut(), None, std::ptr::null());
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
            &raw const ceiling,
        )
    };
    assert_eq!(bound, 0);
    let network_id = [7u8; 16];
    let host = ensure(
        network_id.as_ptr(),
        InboundCeiling::Unbounded(UnboundedReason::Unlimited),
    )
    .expect("zone host");
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
    shekyl_zone_shutdown();
    unsafe {
        shekyl_seam_bind(std::ptr::null_mut(), None, std::ptr::null());
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
            &raw const ceiling,
        )
    };
    assert_eq!(bound, 0);
    let network_id = [9u8; 16];
    let host = ensure(
        network_id.as_ptr(),
        InboundCeiling::Unbounded(UnboundedReason::Unlimited),
    )
    .expect("zone host");

    assert!(
        crate::dialer_ffi::start_connector(ConnectorId::Tor, &host.engine),
        "the first start takes the loop"
    );
    assert!(
        !crate::dialer_ffi::start_connector(ConnectorId::Tor, &host.engine),
        "a second start finds it taken and starts nothing"
    );
    let socks = std::ffi::CString::new("127.0.0.1").expect("socks host");
    let rc = unsafe {
        shekyl_zone_set_tor_proxy(
            socks.as_ptr(),
            9050,
            network_id.as_ptr(),
            &raw const ceiling,
        )
    };
    assert_eq!(
        rc, 0,
        "the proxy install is not refused by the claimed loop"
    );

    shekyl_zone_shutdown();
    unsafe {
        shekyl_seam_bind(std::ptr::null_mut(), None, std::ptr::null());
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
        shekyl_seam_bind(std::ptr::null_mut(), None, std::ptr::null());
    }
    let bound = unsafe {
        shekyl_seam_bind(
            std::ptr::addr_of_mut!(executor).cast::<c_void>(),
            Some(discard),
            &raw const ceiling,
        )
    };
    assert_eq!(bound, 0);
    assert!(crate::dialer_ffi::dialer().is_some(), "built at the bind");
    let network_id = [7u8; 16];
    let first = ensure(
        network_id.as_ptr(),
        InboundCeiling::Unbounded(UnboundedReason::Unlimited),
    )
    .expect("zone host");
    shekyl_zone_shutdown();
    assert!(
        crate::dialer_ffi::dialer().is_none(),
        "shutdown drops the dialer"
    );
    assert!(crate::seam_ffi::hub().is_some(), "and the seam stays bound");
    drop(first);
    let second = ensure(
        network_id.as_ptr(),
        InboundCeiling::Unbounded(UnboundedReason::Unlimited),
    )
    .expect("a second zone host");
    assert!(
        crate::dialer_ffi::dialer().is_some(),
        "the second host builds the dialer again"
    );
    shekyl_zone_shutdown();
    drop(second);
    unsafe {
        shekyl_seam_bind(std::ptr::null_mut(), None, std::ptr::null());
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

/// The watch follows the incarnation just published. Returning before the
/// plan on [`RoutePublish::Unchanged`] fails the first assert: that publish
/// is how a route installed before the managed Tor existed gets its watch.
#[test]
fn the_watch_follows_a_managed_route_whether_or_not_the_publish_changed_it() {
    assert_eq!(
        plan_tor_death_watch(
            RoutePublish::Unchanged { incarnation: 4 },
            None,
            ManagedListener::This,
        ),
        TorDeathWatch::Arm { incarnation: 4 },
    );
    assert_eq!(
        plan_tor_death_watch(
            RoutePublish::Unchanged { incarnation: 4 },
            Some(4),
            ManagedListener::This,
        ),
        TorDeathWatch::Keep,
    );
    assert_eq!(
        plan_tor_death_watch(
            RoutePublish::Installed { incarnation: 4 },
            Some(4),
            ManagedListener::This,
        ),
        TorDeathWatch::Keep,
    );
    assert_eq!(
        plan_tor_death_watch(
            RoutePublish::Installed { incarnation: 5 },
            Some(4),
            ManagedListener::This,
        ),
        TorDeathWatch::Arm { incarnation: 5 },
    );
    assert_eq!(
        plan_tor_death_watch(
            RoutePublish::Installed { incarnation: 1 },
            None,
            ManagedListener::This,
        ),
        TorDeathWatch::Arm { incarnation: 1 },
    );
}

/// A route that is not the managed Tor's drops a watch, including when the
/// publish itself did not change. An early keep on an unchanged publish
/// leaves that watch held. Nothing held stays nothing.
#[test]
fn a_route_that_is_not_the_managed_tor_drops_a_held_watch_and_only_that() {
    assert_eq!(
        plan_tor_death_watch(
            RoutePublish::Unchanged { incarnation: 4 },
            Some(3),
            ManagedListener::NotThis,
        ),
        TorDeathWatch::Clear,
    );
    assert_eq!(
        plan_tor_death_watch(
            RoutePublish::Installed { incarnation: 2 },
            None,
            ManagedListener::NotThis,
        ),
        TorDeathWatch::Keep,
    );
}

/// An exit and a stop both take the link down, and they are not the same
/// cause. Swapping the arms fails this.
#[test]
fn an_exit_and_a_stop_record_different_causes() {
    assert_eq!(down_cause(TorDeath::Exited), DownCause::ProcessExited);
    assert_eq!(down_cause(TorDeath::Stopped), DownCause::ProcessStopped);
}
