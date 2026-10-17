// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Dialer FFI tests.

use std::ffi::{c_void, CString};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, PoisonError};
use std::thread;
use std::time::Duration;

use shekyl_dialer::DialAim;
use shekyl_levin::{
    response, BasicNodeData, CoreSyncData, HandshakeResponse, PortableMap, SupportFlags,
    COMMAND_HANDSHAKE,
};
use shekyl_timing_engine::Tick;

use super::*;
use crate::inbound_ceiling_ffi::{ShekylInboundCeiling, SHEKYL_INBOUND_CEILING_UNLIMITED};
use crate::seam_ffi::{
    seam_bind_lock, shekyl_seam_bind, shekyl_seam_install_loopback, ShekylSeamObserved, ADDR_IPV4,
};

/// A hub whose posts go nowhere: these tests never open a session.
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

fn v4(n: u8) -> ShekylSeamAddress {
    let mut entry = ShekylSeamAddress {
        connector: 0,
        address_type: ADDR_IPV4,
        zone_only: 0,
        _pad: 0,
        port: 18080,
        len: 4,
        bytes: [0; TOR_HOST_MAX],
    };
    entry.bytes[..4].copy_from_slice(&[11, 16, 0, n]);
    entry
}

fn address(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 16, 0, n),
        port: 18080,
    }
}

/// Unbind the seam: the dialer, if any, is stopped and dropped.
fn unbind() {
    unsafe { shekyl_seam_bind(std::ptr::null_mut(), None, std::ptr::null()) };
    assert!(dialer().is_none());
}

/// Make the built dialer ready to draw (`TSR-F1`): a published tip,
/// the network id, and a usable clearnet link.
fn ready(dialer: &Dialer) {
    let top = [1u8; 32];
    unsafe { shekyl_core_publish_tip(1, 1, 0, top.as_ptr()) };
    dialer.set_network_id([7; 16]);
    assert!(
        matches!(
            dialer.hub().links().publish_usable(
                ConnectorId::Clearnet,
                shekyl_seam::Route::Direct,
                dialer.hub().now(),
            ),
            shekyl_seam::RoutePublish::Installed { .. }
        ),
        "ready installs the clearnet route"
    );
    assert_eq!(dialer.readiness(ConnectorId::Clearnet), Ok(()));
}

/// Bind a hub, which builds the dialer and applies what was held.
fn bind() {
    let ceiling = ShekylInboundCeiling {
        kind: SHEKYL_INBOUND_CEILING_UNLIMITED,
        ceiling: 0,
        soft_limit: 0,
        held: 0,
    };
    let mut ctx = 0u8;
    let bound = unsafe {
        shekyl_seam_bind(
            (&raw mut ctx).cast::<c_void>(),
            Some(no_post),
            &raw const ceiling,
        )
    };
    assert_eq!(bound, 0);
}

/// On a clearnet-only start the command line is parsed before the
/// seam binds, so the file, `--add-peer` and the own address arrive
/// before the dialer exists. Each is held and applied at the build.
#[test]
fn pushes_before_the_dialer_exists_are_applied_when_it_is_built() {
    let _bind = seam_bind_lock()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    unbind();
    let dir = tempfile::tempdir().expect("a directory");
    let file = dir.path().join("p2pstate.bin");
    std::fs::write(&file, shekyl_peerlist::address_file::encode(&[address(1)])).expect("written");
    let path = CString::new(file.to_str().expect("utf-8")).expect("no NUL");
    assert_eq!(
        unsafe { shekyl_dialer_open_address_file(path.as_ptr()) },
        SHEKYL_DIALER_DEFERRED
    );
    let named = v4(2);
    assert_eq!(
        unsafe { shekyl_peerlist_admit_operator(&raw const named) },
        SHEKYL_DIALER_DEFERRED
    );
    bind();
    let dialer = dialer().expect("built at the bind");
    {
        let shared = dialer.shared();
        assert!(shared.lists.is_gray(&address(1)), "from the file");
        assert!(shared.lists.is_gray(&address(2)), "from --add-peer");
        assert!(!shared.lists.is_white(&address(1)));
        assert!(!shared.lists.is_white(&address(2)));
    }
    // The dialer exists now: a push applies at once.
    let later = v4(3);
    assert_eq!(
        unsafe { shekyl_peerlist_admit_operator(&raw const later) },
        1
    );
    assert!(dialer.shared().lists.is_gray(&address(3)));
    unbind();
}

#[test]
fn an_own_address_held_for_the_build_is_never_a_candidate() {
    let _bind = seam_bind_lock()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    unbind();
    let own = v4(4);
    assert_eq!(
        unsafe { shekyl_peerlist_set_own_address(0, &raw const own) },
        0
    );
    assert_eq!(
        unsafe { shekyl_peerlist_admit_operator(&raw const own) },
        SHEKYL_DIALER_DEFERRED
    );
    bind();
    let dialer = dialer().expect("built at the bind");
    ready(&dialer);
    assert!(dialer.shared().lists.is_gray(&address(4)));
    assert!(
        dialer
            .choose(ConnectorId::Clearnet, &mut SecureRelayRng)
            .is_none(),
        "the one gray address is our own, so nothing is drawn"
    );
    unbind();
}

/// The C++ declares the closed network on every boot, with an empty
/// list when no exclusive node was named. Empty is no declaration: an
/// operator-named address is still drawn (the §4 run, 2026-10-13).
#[test]
fn an_empty_declaration_before_the_build_declares_no_closed_network() {
    let _bind = seam_bind_lock()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    unbind();
    let named = v4(7);
    assert_eq!(
        unsafe { shekyl_peerlist_admit_operator(&raw const named) },
        SHEKYL_DIALER_DEFERRED
    );
    assert_eq!(
        unsafe { shekyl_dialer_set_exclusive(std::ptr::null(), 0) },
        SHEKYL_DIALER_DEFERRED
    );
    bind();
    let dialer = dialer().expect("built at the bind");
    ready(&dialer);
    let drawn = dialer
        .choose(ConnectorId::Clearnet, &mut SecureRelayRng)
        .map(|(address, _aim, _nonce)| address);
    assert_eq!(drawn, Some(address(7)), "nothing is held back");
    assert_eq!(
        unsafe { shekyl_dialer_set_exclusive(std::ptr::null(), 0) },
        0
    );
    unbind();
}

/// `--p2p-disclose-early` is parsed before the seam binds, like every
/// config push: held for the build, then the flag runs on every
/// connector from the build's clock.
#[test]
fn the_disclose_early_flag_held_for_the_build_runs_from_the_build() {
    let _bind = seam_bind_lock()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    unbind();
    assert_eq!(shekyl_peerlist_disclose_early(), SHEKYL_DIALER_DEFERRED);
    bind();
    let dialer = dialer().expect("built at the bind");
    for connector in ConnectorId::ALL {
        assert!(
            matches!(
                dialer.shared().lists.disclose_early(*connector),
                Some(shekyl_peerlist::DiscloseEarly::Running { .. })
            ),
            "{connector:?} runs the flag from the build"
        );
    }
    assert_eq!(
        shekyl_peerlist_disclose_early(),
        0,
        "after the build the push acts at once"
    );
    unbind();
}

#[test]
fn a_closed_network_held_for_the_build_is_the_population() {
    let _bind = seam_bind_lock()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    unbind();
    let other = v4(5);
    assert_eq!(
        unsafe { shekyl_peerlist_admit_operator(&raw const other) },
        SHEKYL_DIALER_DEFERRED
    );
    let declared = [v4(6)];
    assert_eq!(
        unsafe { shekyl_dialer_set_exclusive(declared.as_ptr(), declared.len()) },
        SHEKYL_DIALER_DEFERRED
    );
    bind();
    let dialer = dialer().expect("built at the bind");
    ready(&dialer);
    let drawn = dialer
        .choose(ConnectorId::Clearnet, &mut SecureRelayRng)
        .map(|(address, _aim, _nonce)| address);
    assert_eq!(drawn, Some(address(6)));
    unbind();
}

/// `get_config` builds the mainnet, testnet, and stagenet ids, in that
/// order, on first use. Those derivations must leave the noted seed
/// network where the daemon put it. Fakechain shares mainnet's id and
/// still admits no seeds. An unrecognized code does not move a record.
#[test]
fn a_noted_network_survives_every_id_derivation() {
    const DERIVATION_ORDER: [DaemonNetwork; 3] = [
        DaemonNetwork::Mainnet,
        DaemonNetwork::Testnet,
        DaemonNetwork::Stagenet,
    ];
    /// The first byte past `cryptonote::FAKECHAIN`.
    const UNRECOGNIZED_NETTYPE: u8 = DaemonNetwork::Fakechain.to_cryptonote() + 1;

    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            note_network(DaemonNetwork::Stagenet);
        }
    }
    let _restore = Restore;
    let recorded = || *NETWORK.lock().expect("network");

    assert_eq!(recorded(), SeedNetwork::None);

    let derive_each_static = || {
        for network in DERIVATION_ORDER {
            let mut out = [0u8; 16];
            assert_eq!(
                crate::network_id_ffi::shekyl_network_id(network.to_cryptonote(), out.as_mut_ptr()),
                0
            );
        }
    };

    assert_eq!(
        shekyl_dialer_note_network(DaemonNetwork::Mainnet.to_cryptonote()),
        0
    );
    derive_each_static();
    assert_eq!(recorded(), SeedNetwork::Mainnet);
    assert_eq!(seeds(recorded()), seeds(SeedNetwork::Mainnet));

    assert_eq!(
        shekyl_dialer_note_network(DaemonNetwork::Testnet.to_cryptonote()),
        0
    );
    derive_each_static();
    assert_eq!(recorded(), SeedNetwork::Testnet);
    assert_eq!(seeds(recorded()), seeds(SeedNetwork::Testnet));

    assert_eq!(
        shekyl_dialer_note_network(DaemonNetwork::Stagenet.to_cryptonote()),
        0
    );
    derive_each_static();
    assert_eq!(recorded(), SeedNetwork::None);
    assert!(seeds(recorded()).is_empty());

    assert_eq!(
        shekyl_dialer_note_network(DaemonNetwork::Fakechain.to_cryptonote()),
        0
    );
    let mut mainnet_id = [0u8; 16];
    let mut fakechain_id = [0u8; 16];
    assert_eq!(
        crate::network_id_ffi::shekyl_network_id(
            DaemonNetwork::Mainnet.to_cryptonote(),
            mainnet_id.as_mut_ptr()
        ),
        0
    );
    assert_eq!(
        crate::network_id_ffi::shekyl_network_id(
            DaemonNetwork::Fakechain.to_cryptonote(),
            fakechain_id.as_mut_ptr()
        ),
        0
    );
    assert_eq!(mainnet_id, fakechain_id);
    assert_eq!(recorded(), SeedNetwork::None);

    assert_eq!(
        shekyl_dialer_note_network(DaemonNetwork::Mainnet.to_cryptonote()),
        0
    );
    assert_eq!(shekyl_dialer_note_network(UNRECOGNIZED_NETTYPE), -1);
    assert_eq!(recorded(), SeedNetwork::Mainnet);
}

/// One handshake response and an empty peerlist, so admit is not a ban.
fn handshake_frame() -> Vec<u8> {
    let body = HandshakeResponse {
        node_data: BasicNodeData {
            network_id: [7; 16],
            support_flags: SupportFlags::ADVERTISED,
        },
        payload_data: CoreSyncData {
            current_height: 20,
            cumulative_difficulty: 200,
            cumulative_difficulty_top64: 0,
            top_id: [2; 32],
        },
        local_peerlist_new: Vec::new(),
    };
    response(COMMAND_HANDSHAKE, &body.store().expect("encode"))
}

/// Unbind on the way out, including a panic. A timed-out deadlock exits
/// the process instead, so the suite does not wait on a non-daemon thread.
struct UnbindOnDrop;

impl Drop for UnbindOnDrop {
    fn drop(&mut self) {
        unbind();
    }
}

/// The three list paths — a wake, a confirm dial's received list, and the
/// RPC listing — run together with closes and bans. Each takes its ban
/// snapshot before the dialer's lock. A close poster that ran under the
/// hub's lock and then took the dialer's would not return.
#[test]
fn the_list_paths_and_closes_do_not_deadlock() {
    let _bind = seam_bind_lock()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    unbind();
    let _unbind = UnbindOnDrop;
    bind();
    assert_eq!(shekyl_seam_install_loopback(), 0);
    let dialer = dialer().expect("built at the bind");
    ready(&dialer);

    let peer = address(1);
    let named = v4(1);
    assert_eq!(
        unsafe { shekyl_peerlist_admit_operator(&raw const named) },
        1,
        "the address entered gray"
    );
    assert_eq!(
        unsafe { shekyl_peerlist_set_own_address(0, &raw const named) },
        0,
        "the wake's filter skips the only address; a named dial does not"
    );

    let stop = Arc::new(AtomicBool::new(false));
    let dial_done = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = mpsc::channel();
    let frame = handshake_frame();
    let hub = dialer.hub().clone();

    let wake = {
        let dialer = Arc::clone(&dialer);
        let stop = Arc::clone(&stop);
        let done = done_tx.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                dialer.wake(ConnectorId::Clearnet, &mut SecureRelayRng);
                thread::sleep(Duration::from_millis(1));
            }
            let _sent = done.send(());
        })
    };
    let dial = {
        let dialer = Arc::clone(&dialer);
        let stop = Arc::clone(&stop);
        let dial_done = Arc::clone(&dial_done);
        let done = done_tx.clone();
        let peer = peer.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                // None is a dial that lost the race with a close. The next
                // loop tries again.
                let _id = dialer.dial(
                    ConnectorId::Clearnet,
                    &peer,
                    DialAim::Confirm,
                    &mut SecureRelayRng,
                );
            }
            dial_done.store(true, Ordering::Release);
            let _sent = done.send(());
        })
    };
    let inject = {
        let hub = hub.clone();
        let dial_done = Arc::clone(&dial_done);
        let done = done_tx.clone();
        thread::spawn(move || {
            let mut next = 1u64;
            while !dial_done.load(Ordering::Acquire) {
                let Some(id) = SocketId::from_ffi(next) else {
                    break;
                };
                if hub.inject(id, frame.clone()) {
                    next = next.saturating_add(1);
                    continue;
                }
                // A finished confirm drops the session, so inject fails on
                // that id while the next dial has already opened the one
                // after it.
                if let Some(ahead) = SocketId::from_ffi(next.saturating_add(1)) {
                    if hub.inject(ahead, frame.clone()) {
                        next = next.saturating_add(2);
                        continue;
                    }
                }
                thread::sleep(Duration::from_millis(1));
            }
            let _sent = done.send(());
        })
    };
    let list = {
        let stop = Arc::clone(&stop);
        let done = done_tx.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let mut out: *const crate::rpc_peerlist_ffi::ShekylRpcPeerFacts = std::ptr::null();
                let mut len = 0usize;
                let mut owner: *mut c_void = std::ptr::null_mut();
                let rc = unsafe {
                    crate::rpc_peerlist_ffi::shekyl_rpc_peer_list(
                        1,
                        &raw mut out,
                        &raw mut len,
                        &raw mut owner,
                    )
                };
                if rc == 0 {
                    unsafe { crate::rpc_peerlist_ffi::shekyl_rpc_peer_list_free(owner) };
                }
                let mut white = 0u64;
                let mut gray = 0u64;
                let _ = unsafe {
                    crate::rpc_peerlist_ffi::shekyl_rpc_peerlist_sizes(
                        &raw mut white,
                        &raw mut gray,
                    )
                };
                thread::sleep(Duration::from_millis(1));
            }
            let _sent = done.send(());
        })
    };
    let close = {
        let stop = Arc::clone(&stop);
        let done = done_tx.clone();
        thread::spawn(move || {
            let banned = IpAddr::V4(Ipv4Addr::new(11, 16, 9, 9));
            let mut id = 1u64;
            while !stop.load(Ordering::Acquire) {
                if let Some(socket) = SocketId::from_ffi(id) {
                    hub.close(socket);
                }
                let until = Tick::new(hub.now().get().saturating_add(60_000_000_000));
                hub.ban_host(banned, until);
                id = id.saturating_add(1);
                thread::sleep(Duration::from_millis(1));
            }
            let _sent = done.send(());
        })
    };

    thread::sleep(Duration::from_secs(10));
    stop.store(true, Ordering::Release);
    for _ in 0..5 {
        if done_rx.recv_timeout(Duration::from_secs(5)).is_err() {
            eprintln!("the list paths and closes did not finish within 5s of stop");
            std::process::exit(1);
        }
    }
    wake.join().expect("wake");
    dial.join().expect("dial");
    inject.join().expect("inject");
    list.join().expect("list");
    close.join().expect("close");
}
