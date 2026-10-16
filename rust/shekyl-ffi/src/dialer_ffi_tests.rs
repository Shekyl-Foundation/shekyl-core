// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Dialer FFI tests.

use std::ffi::{c_void, CString};
use std::net::Ipv4Addr;
use std::sync::PoisonError;

use shekyl_seam::CloseCause;

use super::*;
use crate::inbound_ceiling_ffi::{ShekylInboundCeiling, SHEKYL_INBOUND_CEILING_UNLIMITED};
use crate::seam_ffi::{seam_bind_lock, shekyl_seam_bind, ShekylSeamObserved, ADDR_IPV4};

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
