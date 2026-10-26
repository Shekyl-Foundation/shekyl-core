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
    let _bind = crate::seam_ffi::seam_bind_lock().lock();
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
    let _bind = crate::seam_ffi::seam_bind_lock().lock();
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
    let _bind = crate::seam_ffi::seam_bind_lock().lock();
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

/// Every p2p thread is on the thread ledger (decision B, Rick 2026-10-25;
/// the in-flight bound, revision 4, item 4). Each connector's owner loop is
/// a dedicated row named for it, and shutdown joins it: a row leaves the
/// ledger only after its thread is joined. The lateness report is a task
/// on the transport runtime, so no thread or row of its own exists.
#[test]
fn the_owner_loops_are_ledger_rows_joined_at_shutdown_and_lateness_is_no_thread() {
    let _bind = crate::seam_ffi::seam_bind_lock().lock();
    let rows = |name: &str| {
        shekyl_thread_ledger::ledger()
            .into_iter()
            .filter(|row| {
                row.name.as_str() == name
                    && row.kind == shekyl_thread_ledger::RowKind::DedicatedThread
            })
            .count()
    };
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
    let host = ensure([9u8; 16]).expect("zone host");
    assert!(crate::dialer_ffi::start_connector(
        ConnectorId::Clearnet,
        &host.engine
    ));
    assert!(crate::dialer_ffi::start_connector(
        ConnectorId::Tor,
        &host.engine
    ));
    drop(host);
    assert_eq!(rows("p2p-dial-clearnet"), 1);
    assert_eq!(rows("p2p-dial-tor"), 1);
    assert_eq!(rows("p2p-lateness"), 0, "the report is a task, not a row");
    #[cfg(target_os = "linux")]
    {
        let threads = std::fs::read_dir("/proc/self/task")
            .expect("this process's threads")
            .filter_map(|task| std::fs::read_to_string(task.ok()?.path().join("comm")).ok())
            .filter(|comm| comm.trim_end() == "p2p-lateness")
            .count();
        assert_eq!(threads, 0, "no thread named p2p-lateness");
    }

    shutdown();
    assert_eq!(rows("p2p-dial-clearnet"), 0, "joined at shutdown");
    assert_eq!(rows("p2p-dial-tor"), 0, "joined at shutdown");
    unsafe {
        shekyl_seam_bind(std::ptr::null_mut(), None);
    }
}

/// The Tor window follows the route (revision 4 of the in-flight bound,
/// Rick 2026-10-26; the Tor lane's review). The managed Tor's route gives
/// the dialer the earliest that Tor's launch timeout can expire; an
/// operator's Tor
/// sets its own `SocksTimeout`, so its route leaves the dialer none.
#[test]
fn the_tor_window_is_the_managed_tors_and_an_operators_tor_has_none() {
    let _bind = crate::seam_ffi::seam_bind_lock().lock();
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
    let _host = ensure(network_id).expect("zone host");
    let dialer = crate::dialer_ffi::dialer().expect("the bound dialer");
    assert_eq!(dialer.tor_window(), None, "no route yet");

    let managed = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9150);
    assert!(publish_managed_socks(managed).is_some());
    assert_eq!(
        dialer.tor_window(),
        crate::tor_link::TOR_SOCKS_TIMEOUT.earliest_expiry(),
        "the managed Tor's window"
    );
    assert_eq!(
        dialer.tor_window(),
        Some(Duration::from_secs(104)),
        "105 s, less Tor's whole-second clock"
    );

    dial_through_tor(
        shekyl_socks::Proxy::unauthenticated(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9050,
        )),
        network_id,
    )
    .expect("the operator's proxy");
    assert_eq!(
        dialer.tor_window(),
        None,
        "an operator's Tor has no known window"
    );

    shutdown();
    unsafe {
        shekyl_seam_bind(std::ptr::null_mut(), None);
    }
}

/// A Tor-only start admits the compiled onion seeds and not the clearnet
/// ones. Admission used to run only inside the clearnet branch, so a node
/// with clearnet off never received the onion list.
#[test]
fn a_tor_only_start_admits_the_compiled_onion_seeds() {
    let _bind = crate::seam_ffi::seam_bind_lock().lock();
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::dialer_ffi::note_network(shekyl_rpc_types::DaemonNetwork::Stagenet);
        }
    }
    let _restore = Restore;

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
    crate::dialer_ffi::note_network(shekyl_rpc_types::DaemonNetwork::Testnet);

    assert!(
        crate::dialer_ffi::start_connector(ConnectorId::Tor, &host.engine),
        "the Tor loop starts without a clearnet connector"
    );

    let dialer = crate::dialer_ffi::dialer().expect("the dialer exists");
    let shared = dialer.shared();
    let onions: Vec<_> = shekyl_dialer::seeds(shekyl_dialer::SeedNetwork::Testnet)
        .into_iter()
        .filter(|address| {
            shekyl_peerlist::Peerlist::connector_of(address) == Some(ConnectorId::Tor)
        })
        .collect();
    assert_eq!(onions.len(), 6);
    for onion in &onions {
        assert!(
            shared.lists.is_gray(onion),
            "the onion seed is gray on a Tor-only start: {onion:?}"
        );
    }
    assert_eq!(
        shared.lists.gray_count(ConnectorId::Clearnet),
        0,
        "clearnet seeds are not admitted until that connector starts"
    );
    drop(shared);

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
    let _bind = crate::seam_ffi::seam_bind_lock().lock();
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
    let _bind = crate::seam_ffi::seam_bind_lock().lock();
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
    let _bind = crate::seam_ffi::seam_bind_lock().lock();
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
    assert!(
        !publish_tor_down(1, DownCause::ProcessExited),
        "no zone host, no route"
    );

    dial_through_tor(socks(9050), network_id).expect("the proxy install");
    let host = ensure(network_id).expect("zone host");
    let first = host.hub.links().get(ConnectorId::Tor).incarnation;
    assert!(publish_tor_down(first, DownCause::ProcessExited));
    assert!(
        !host.hub.links().get(ConnectorId::Tor).is_usable(),
        "the death took the link down"
    );
    assert!(matches!(
        host.hub.links().get(ConnectorId::Tor).outbound,
        Outbound::Down {
            cause: DownCause::ProcessExited,
            ..
        }
    ));

    dial_through_tor(socks(9051), network_id).expect("a later route");
    assert!(
        !publish_tor_down(first, DownCause::ProcessExited),
        "the later route is not the dead Tor's"
    );
    assert!(host.hub.links().get(ConnectorId::Tor).is_usable());

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
