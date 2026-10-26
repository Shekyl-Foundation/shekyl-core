// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Dialer FFI tests.

// Whole-file test module: the parent already gates it with
// `#[cfg(test)] mod tests;`, and this inner marker is how the file declares
// the same thing to `build.yml`'s debug-macro lint, whose scan keys on the
// first `#[cfg(test)]` / `#![cfg(test)]` in the file. The watchdogs'
// `eprintln!` are test-only output and must not read as production.
#![cfg(test)]

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use shekyl_dialer::DialAim;
use shekyl_levin::{
    response, BasicNodeData, CoreSyncData, HandshakeResponse, PortableMap, COMMAND_HANDSHAKE,
};
use shekyl_seam::{Channel, CloseCause, Dial, Loopback};
use shekyl_timing_engine::Tick;

use super::*;
use crate::inbound_ceiling_ffi::{ShekylInboundCeiling, SHEKYL_INBOUND_CEILING_UNLIMITED};
use crate::seam_ffi::{
    seam_bind_lock, shekyl_seam_bind, shekyl_seam_set_ceiling, ShekylSeamObserved,
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

fn address(n: u8) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 16, 0, n),
        port: 18080,
    }
}

/// Unbind the seam: the dialer, if any, is stopped and dropped.
fn unbind() {
    unsafe { shekyl_seam_bind(std::ptr::null_mut(), None) };
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
    let bound = unsafe { shekyl_seam_bind((&raw mut ctx).cast::<c_void>(), Some(no_post)) };
    assert_eq!(bound, 0);
    assert_eq!(unsafe { shekyl_seam_set_ceiling(&raw const ceiling) }, 0);
}

/// On a clearnet-only start the command line is parsed before the
/// seam binds, so the file, `--add-peer` and the own address arrive
/// before the dialer exists. Each is held and applied at the build.
fn peer(n: u8) -> PeerEndpoint {
    PeerEndpoint::Ip(SocketAddr::from(([11, 16, 0, n], 18080)))
}

fn section(peers: &[u8], closed: &[u8], disclose_early: bool) -> P2p {
    P2p {
        peers: peers.iter().copied().map(peer).collect(),
        closed_peers: closed.iter().copied().map(peer).collect(),
        local: false,
        disclose_early,
        bans: Vec::new(),
        upload_max: None,
        download_max: None,
    }
}

/// The section is applied once the dialer exists; before that it is a
/// refusal the caller sees, not a push held for a build.
#[test]
fn a_push_before_the_dialer_exists_is_refused_not_held() {
    let _bind = seam_bind_lock().lock();
    unbind();
    let dir = tempfile::tempdir().expect("a directory");
    assert_eq!(
        apply_p2p(&section(&[2], &[], false), &dir.path().join("p2pstate.bin")),
        Err(NoDialer)
    );
    assert_eq!(
        set_own_addresses(ConnectorId::Clearnet, vec![address(4)]),
        Err(NoDialer)
    );
}

/// The built dialer reads the window the managed Tor is launched with: a
/// Tor attempt that fails at or after it is final within its test.
#[test]
fn the_dialer_reads_the_managed_tors_window() {
    let _bind = seam_bind_lock().lock();
    unbind();
    bind();
    let window = dialer().expect("bound").tor_window();
    assert_eq!(window, crate::tor_link::TOR_SOCKS_TIMEOUT.window());
    assert!(window.is_some(), "the daemon sets a window");
    unbind();
}

/// The address file's entries and the operator's peers enter gray, never
/// white: a named address has not been dialled, and white is disclosed.
#[test]
fn the_section_enters_the_file_and_the_operators_peers_as_gray() {
    let _bind = seam_bind_lock().lock();
    unbind();
    let dir = tempfile::tempdir().expect("a directory");
    let file = dir.path().join("p2pstate.bin");
    std::fs::write(&file, shekyl_peerlist::address_file::encode(&[address(1)])).expect("written");
    bind();
    apply_p2p(&section(&[2], &[], false), &file).expect("the dialer exists");
    let dialer = dialer().expect("built at the bind");
    let shared = dialer.shared();
    assert!(shared.lists.is_gray(&address(1)), "from the file");
    assert!(shared.lists.is_gray(&address(2)), "from p2p-peer");
    assert!(!shared.lists.is_white(&address(1)));
    assert!(!shared.lists.is_white(&address(2)));
    drop(shared);
    unbind();
}

#[test]
fn an_own_address_is_never_a_candidate() {
    let _bind = seam_bind_lock().lock();
    unbind();
    bind();
    let dir = tempfile::tempdir().expect("a directory");
    set_own_addresses(ConnectorId::Clearnet, vec![address(4)]).expect("the dialer exists");
    apply_p2p(&section(&[4], &[], false), &dir.path().join("p2pstate.bin")).expect("applied");
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

/// An empty closed-network declaration is no declaration: the
/// population stays open (the §4 run, 2026-10-13).
#[test]
fn an_empty_declaration_declares_no_closed_network() {
    let _bind = seam_bind_lock().lock();
    unbind();
    bind();
    let dir = tempfile::tempdir().expect("a directory");
    apply_p2p(&section(&[7], &[], false), &dir.path().join("p2pstate.bin")).expect("applied");
    let dialer = dialer().expect("built at the bind");
    ready(&dialer);
    let drawn = dialer
        .choose(ConnectorId::Clearnet, &mut SecureRelayRng)
        .map(|(address, _aim, _nonce)| address);
    assert_eq!(drawn, Some(address(7)), "nothing is held back");
    unbind();
}

#[test]
fn disclose_early_runs_from_the_section() {
    let _bind = seam_bind_lock().lock();
    unbind();
    bind();
    let dir = tempfile::tempdir().expect("a directory");
    apply_p2p(&section(&[], &[], true), &dir.path().join("p2pstate.bin")).expect("applied");
    let dialer = dialer().expect("built at the bind");
    for connector in ConnectorId::ALL {
        assert!(
            matches!(
                dialer.shared().lists.disclose_early(*connector),
                Some(shekyl_peerlist::DiscloseEarly::Running { .. })
            ),
            "{connector:?} runs the flag"
        );
    }
    unbind();
}

#[test]
fn a_closed_network_is_the_population() {
    let _bind = seam_bind_lock().lock();
    unbind();
    bind();
    let dir = tempfile::tempdir().expect("a directory");
    apply_p2p(
        &section(&[5], &[6], false),
        &dir.path().join("p2pstate.bin"),
    )
    .expect("applied");
    let dialer = dialer().expect("built at the bind");
    ready(&dialer);
    let drawn = dialer
        .choose(ConnectorId::Clearnet, &mut SecureRelayRng)
        .map(|(address, _aim, _nonce)| address);
    assert_eq!(drawn, Some(address(6)));
    unbind();
}

#[test]
fn a_noted_network_survives_every_id_derivation() {
    const DERIVATION_ORDER: [DaemonNetwork; 3] = [
        DaemonNetwork::Mainnet,
        DaemonNetwork::Testnet,
        DaemonNetwork::Stagenet,
    ];
    /// The first byte past `cryptonote::FAKECHAIN`.
    const UNRECOGNIZED_NETTYPE: u8 = DaemonNetwork::Fakechain.to_cryptonote() + 1;

    // `NETWORK` is process-wide. The Tor seed test writes it under this
    // same lock; restoration stays inside the lock so a parallel test
    // cannot observe the value mid-restore.
    let _bind = seam_bind_lock().lock();
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

/// A closed Tor population is the only address `choose` returns after the
/// compiled onions have been admitted. The daemon applies the section
/// before the owner loop; this is that order without the thread.
#[test]
fn a_closed_tor_network_draws_its_declaration_not_a_compiled_onion() {
    let _bind = seam_bind_lock().lock();
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            note_network(DaemonNetwork::Stagenet);
        }
    }
    let _restore = Restore;

    unbind();
    bind();
    note_network(DaemonNetwork::Testnet);
    let port = shekyl_daemon_config::Network::Testnet.p2p_port();
    let host = shekyl_onion_v3::v3_onion_hostname(&[0x11; 32]);
    let declared = NetworkAddress::Tor {
        host: host.clone(),
        port,
    };
    let compiled: Vec<_> = seeds(SeedNetwork::Testnet)
        .into_iter()
        .filter(|address| Peerlist::connector_of(address) == Some(ConnectorId::Tor))
        .collect();
    assert!(
        !compiled.contains(&declared),
        "the declaration is not one of the compiled onions"
    );
    let dir = tempfile::tempdir().expect("a directory");
    apply_p2p(
        &P2p {
            peers: Vec::new(),
            closed_peers: vec![PeerEndpoint::Onion { host, port }],
            local: false,
            disclose_early: false,
            bans: Vec::new(),
            upload_max: None,
            download_max: None,
        },
        &dir.path().join("p2pstate.bin"),
    )
    .expect("applied");
    let dialer = dialer().expect("built at the bind");
    admit_compiled_seeds(&dialer, ConnectorId::Tor);
    ready(&dialer);
    assert!(matches!(
        dialer.hub().links().publish_usable(
            ConnectorId::Tor,
            shekyl_seam::Route::Socks(SocketAddr::from((Ipv4Addr::LOCALHOST, 9050))),
            dialer.hub().now(),
        ),
        shekyl_seam::RoutePublish::Installed { .. }
    ));
    let mut drawn = Vec::new();
    for _ in 0..=compiled.len() {
        if let Some((address, _aim, _nonce)) = dialer.choose(ConnectorId::Tor, &mut SecureRelayRng)
        {
            drawn.push(address);
        }
    }
    assert_eq!(
        drawn,
        vec![declared],
        "the compiled onions are gray and not eligible"
    );
    unbind();
}

/// The ports in the compiled list are the daemon network's P2P ports.
#[test]
fn compiled_seed_ports_match_the_daemon_network() {
    use shekyl_daemon_config::Network;
    let port = |address: &NetworkAddress| match address {
        NetworkAddress::Ipv4 { port, .. }
        | NetworkAddress::Ipv6 { port, .. }
        | NetworkAddress::Tor { port, .. } => *port,
    };
    assert!(seeds(SeedNetwork::Mainnet)
        .iter()
        .all(|address| port(address) == Network::Mainnet.p2p_port()));
    assert!(seeds(SeedNetwork::Testnet)
        .iter()
        .all(|address| port(address) == Network::Testnet.p2p_port()));
    assert!(seeds(SeedNetwork::None).is_empty());
}

/// One handshake response and an empty peerlist, so admit is not a ban.
fn handshake_frame() -> Vec<u8> {
    let body = HandshakeResponse {
        node_data: BasicNodeData {
            network_id: [7; 16],
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

/// The harness loopback, answering each channel it opens with the
/// handshake response the way the peer would. A test that guessed a dial's
/// socket id to answer it could miss: ids are the process's, and a dial the
/// loopback does not answer waits for good, since it has no gap.
struct AnsweringLoopback {
    inner: Loopback,
    frame: Vec<u8>,
}

impl Dial for AnsweringLoopback {
    fn connect(
        &self,
        endpoint: &shekyl_seam::Endpoint,
        ceiling: shekyl_peer_policy::InboundCeiling,
        now: Tick,
    ) -> Result<Channel, CloseCause> {
        let channel = self.inner.connect(endpoint, ceiling, now)?;
        assert!(
            self.inner.inject(channel.open.id(), self.frame.clone()),
            "a channel the loopback just opened takes its answer"
        );
        Ok(channel)
    }

    fn inject(&self, id: SocketId, frame: Vec<u8>) -> bool {
        self.inner.inject(id, frame)
    }

    fn reader_stopped(&self, id: SocketId) {
        self.inner.reader_stopped(id);
    }

    fn retired(&self, id: SocketId) {
        self.inner.retired(id);
    }

    fn drive(&self, hub: &Hub, id: SocketId, session: shekyl_capped_stream::Session) {
        self.inner.drive(hub, id, session);
    }
}

/// Install [`AnsweringLoopback`] on the bound hub.
fn install_answering_loopback(hub: &Hub) {
    hub.install_dial(Arc::new(AnsweringLoopback {
        inner: Loopback::new(crate::seam_ffi::process_sockets(), 64 * 1024),
        frame: handshake_frame(),
    }));
}

/// Unbind on the way out, including a panic. A timed-out deadlock exits
/// the process instead, so the suite does not wait on a non-daemon thread.
struct UnbindOnDrop;

impl Drop for UnbindOnDrop {
    fn drop(&mut self) {
        unbind();
    }
}

/// **A kept session closed from C++ returns, and leaves the kept count.**
/// The alpha.10 fleet's freeze, as three nodes showed it: an ordinary close
/// from C++ (`drop_connection`, or a Levin callback) reaches
/// `shekyl_seam_close`, then `Hub::finish`. At the release tag `finish` ran
/// its close poster with the hub's lock held. The poster ran
/// `Dialer::session_closed`, which asked `Hub::cause` for the cause, which
/// waited on that same lock, and p2p and RPC froze for good. The close now
/// carries its cause, and the poster runs after the lock is released. A
/// close that does not return in five seconds ends the process, so the
/// suite fails instead of waiting.
#[test]
fn a_kept_session_closed_from_cxx_returns_and_leaves_the_kept_count() {
    let _bind = seam_bind_lock().lock();
    unbind();
    let _unbind = UnbindOnDrop;
    bind();
    let dialer = dialer().expect("built at the bind");
    install_answering_loopback(dialer.hub());
    ready(&dialer);
    let dir = tempfile::tempdir().expect("a directory");
    apply_p2p(&section(&[2], &[], false), &dir.path().join("p2pstate.bin")).expect("applied");
    assert!(
        dialer.shared().lists.is_gray(&address(2)),
        "the address entered gray"
    );

    let id = dialer
        .dial(
            ConnectorId::Clearnet,
            &address(2),
            DialAim::Keep,
            &mut SecureRelayRng,
        )
        .expect("a kept dial");
    assert_eq!(dialer.kept_sessions(ConnectorId::Clearnet), 1);

    let (closed_tx, closed) = mpsc::channel();
    let closing = thread::spawn(move || {
        crate::seam_ffi::shekyl_seam_close(id.get());
        let _sent = closed_tx.send(());
    });
    if closed.recv_timeout(Duration::from_secs(5)).is_err() {
        eprintln!("a kept session closed from C++ did not return within 5s");
        std::process::exit(1);
    }
    closing.join().expect("closed");
    assert_eq!(
        dialer.kept_sessions(ConnectorId::Clearnet),
        0,
        "the close reached the dialer, and the kept row went"
    );
}

/// The three list paths (a wake, a dial's received list, and the RPC
/// listing) run together with bans and with closes of kept sessions from
/// C++. Each list path takes its ban snapshot before the dialer's lock. A
/// close goes through `shekyl_seam_close`, the entry the alpha.10 fleet
/// froze on, to the dialer's close callback, while the list paths hold and
/// release the dialer's lock around it. A close poster that ran under the
/// hub's lock and then took the dialer's would not return. The closer reads
/// the kept sessions' ids off the hub's board, so it closes what exists.
#[test]
fn the_list_paths_and_closes_do_not_deadlock() {
    let _bind = seam_bind_lock().lock();
    unbind();
    let _unbind = UnbindOnDrop;
    bind();
    let dialer = dialer().expect("built at the bind");
    install_answering_loopback(dialer.hub());
    ready(&dialer);

    // Address 1 is confirmed by name only: it is this node's own, so the
    // wake skips it. Addresses 20 to 23 are kept, by name and by the wake.
    const KEPT: [u8; 4] = [20, 21, 22, 23];
    let dir = tempfile::tempdir().expect("a directory");
    let mut named = vec![1];
    named.extend(KEPT);
    apply_p2p(
        &section(&named, &[], false),
        &dir.path().join("p2pstate.bin"),
    )
    .expect("applied");
    set_own_addresses(ConnectorId::Clearnet, vec![address(1)]).expect("the dialer exists");

    let stop = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = mpsc::channel();
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
        let done = done_tx.clone();
        thread::spawn(move || {
            let mut turn = 0usize;
            while !stop.load(Ordering::Acquire) {
                // None is a dial that lost a race: a close, or an address
                // still kept from the last turn. The next turn tries again.
                let _confirmed = dialer.dial(
                    ConnectorId::Clearnet,
                    &address(1),
                    DialAim::Confirm,
                    &mut SecureRelayRng,
                );
                let _kept = dialer.dial(
                    ConnectorId::Clearnet,
                    &address(KEPT[turn % KEPT.len()]),
                    DialAim::Keep,
                    &mut SecureRelayRng,
                );
                turn = turn.wrapping_add(1);
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
    let closed = Arc::new(AtomicU64::new(0));
    let close = {
        let stop = Arc::clone(&stop);
        let done = done_tx.clone();
        let hub = hub.clone();
        let closed = Arc::clone(&closed);
        thread::spawn(move || {
            let banned = IpAddr::V4(Ipv4Addr::new(11, 16, 9, 9));
            while !stop.load(Ordering::Acquire) {
                for row in hub.board().rows().iter().filter(|row| row.established()) {
                    crate::seam_ffi::shekyl_seam_close(row.id().get());
                    closed.fetch_add(1, Ordering::Relaxed);
                }
                let until = Tick::new(hub.now().get().saturating_add(60_000_000_000));
                hub.ban_host(banned, until);
                thread::sleep(Duration::from_millis(1));
            }
            let _sent = done.send(());
        })
    };

    thread::sleep(Duration::from_secs(10));
    stop.store(true, Ordering::Release);
    for _ in 0..4 {
        if done_rx.recv_timeout(Duration::from_secs(5)).is_err() {
            eprintln!("the list paths and closes did not finish within 5s of stop");
            std::process::exit(1);
        }
    }
    wake.join().expect("wake");
    dial.join().expect("dial");
    list.join().expect("list");
    close.join().expect("close");

    assert!(
        closed.load(Ordering::Relaxed) > 0,
        "kept sessions were closed from C++ while the list paths ran"
    );
    // What the last turns kept is closed the same way, and every close
    // reaches the dialer.
    for row in hub.board().rows().iter().filter(|row| row.established()) {
        crate::seam_ffi::shekyl_seam_close(row.id().get());
    }
    assert_eq!(
        dialer.kept_sessions(ConnectorId::Clearnet),
        0,
        "every close reached the dialer's callback"
    );
}
