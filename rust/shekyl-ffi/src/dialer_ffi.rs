// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The outbound dialer, as the C++ reaches it (`P2P_3_SLICE_3_DIALER_BRIEF.md`).
//!
//! The dialer is `shekyl-dialer`'s, built over the seam hub when the zone
//! host starts, and its owner loops start when each connector is ready.
//! Nothing here is a dial. The C++ asks this file for what the dialer
//! already decided, and tells it what changed.
//!
//! Asked: the self-connection nonce query the inbound handshake makes
//! ([`shekyl_dial_take_handshake_nonce`]); the disclosure sample for the
//! two responses the C++ still sends ([`shekyl_peerlist_disclose`]).
//!
//! Told: the core's tip ([`shekyl_core_publish_tip`]); the network the
//! daemon chose ([`shekyl_dialer_note_network`]), which selects the
//! compiled seeds.
//!
//! The configuration is not told from C++. The daemon's Rust `main()`
//! applies the p2p section ([`apply_p2p`]) and this node's own addresses
//! ([`set_own_addresses`]) once the dialer exists, which is from the seam's
//! bind in the remnant's `init` (`DAEMON_CONFIG_CUTOVER.md` §2.2 step 8).

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use shekyl_daemon_config::sections::P2p;
use shekyl_dialer::{seeds, BanSnapshot, Dialer, LoadError, SeedNetwork, Shared};
use shekyl_options::PeerEndpoint;
use shekyl_peerlist::Peerlist;
use std::net::SocketAddr;

pub use shekyl_peerlist::{ConnectorId, NetworkAddress};
use shekyl_relay_privacy::params::{MIN_PROVISIONED_OUT_PEERS, P2P_DEFAULT_OUT_PEERS};
use shekyl_rpc_types::DaemonNetwork;
use shekyl_seam::{connector_from_index, CloseCause, Hub, SocketId, SyncPayload};
use shekyl_timing_engine::{EngineError, Handle, MonotonicClock, OwnerClass};

use crate::legacy_util::slice_from_typed_ptr;
use crate::peerlist_ffi::refused_set;
use crate::seam_ffi::ShekylSeamAddress;
use crate::secure_relay_rng::SecureRelayRng;
use shekyl_seam::TOR_HOST_MAX;

/// The process's dialer, from the zone host's start to its shutdown.
static DIALER: Mutex<Option<Arc<Dialer>>> = Mutex::new(None);

/// The core's latest published tip. `None` until the first publish.
static TIP: Mutex<Option<SyncPayload>> = Mutex::new(None);

/// Which network's seeds to admit. `None` until
/// [`shekyl_dialer_note_network`], and `None` for stagenet and fakechain,
/// which have no compiled seeds.
static NETWORK: Mutex<SeedNetwork> = Mutex::new(SeedNetwork::None);

pub(crate) fn dialer() -> Option<Arc<Dialer>> {
    DIALER.lock().expect("dialer").clone()
}

/// The dialer's shared state, for the peerlist entries that read or
/// write the lists. `None` before the zone host starts.
pub(crate) fn shared() -> Option<Arc<Dialer>> {
    dialer()
}

/// Build the dialer over `hub`, once. Called when the seam binds its hub,
/// so the lists exist for every call that reaches them; the zone host
/// names the network when it starts.
pub(crate) fn ensure_dialer(hub: &Hub) -> Arc<Dialer> {
    let mut slot = DIALER.lock().expect("dialer");
    if let Some(dialer) = slot.as_ref() {
        return Arc::clone(dialer);
    }
    let dialer = Arc::new(Dialer::new(
        hub.clone(),
        refused_set(),
        Arc::new(|| *TIP.lock().expect("tip")),
    ));
    dialer.report_tor_link(crate::tor_link::sink());
    *slot = Some(Arc::clone(&dialer));
    dialer
}

/// Name and load the address file, logging what happened to it.
fn open_file(dialer: &Dialer, path: &Path) {
    match dialer.open_address_file(path.to_path_buf(), &mut SecureRelayRng) {
        Ok(count) => tracing::info!("{count} address(es) from {} entered gray", path.display()),
        Err(LoadError::Dropped(why)) => tracing::warn!(
            "{} is not an address file this build reads ({why:?}); dropped whole, replaced at the next store",
            path.display()
        ),
        Err(LoadError::Io(err)) => tracing::warn!(
            "{} could not be read ({err}); the lists start empty",
            path.display()
        ),
    }
}

/// This node's own addresses on `connector`, now or when the dialer is
/// built.
fn set_own(connector: ConnectorId, own: Vec<NetworkAddress>) -> Result<(), NoDialer> {
    let dialer = dialer().ok_or(NoDialer)?;
    dialer.set_own_addresses(connector, own);
    Ok(())
}

/// The zone host started: the dialer learns the network it dials.
pub(crate) fn set_network_id(network_id: [u8; 16]) {
    if let Some(dialer) = dialer() {
        dialer.set_network_id(network_id);
    }
}

/// The daemon's chosen network, mapped onto the seed list that network
/// admits. Stagenet and fakechain admit none. An id derivation must not
/// call this: [`crate::network_id_ffi::shekyl_network_id`] is pure.
pub(crate) fn note_network(network: DaemonNetwork) {
    let seeds_of = match network {
        DaemonNetwork::Mainnet => SeedNetwork::Mainnet,
        DaemonNetwork::Testnet => SeedNetwork::Testnet,
        DaemonNetwork::Stagenet | DaemonNetwork::Fakechain => SeedNetwork::None,
    };
    *NETWORK.lock().expect("network") = seeds_of;
}

/// Records the network this process dials. `nettype` is
/// `cryptonote::network_type`. Returns 0, or -1 when `nettype` is not one
/// of the four networks, leaving the record unchanged.
///
/// `shekyl_network_id` does not call this. `cryptonote::get_config`
/// initializes the mainnet, testnet, and stagenet ids on first use,
/// whichever network was asked for, so a record taken there would always
/// end on stagenet and clearnet would admit no seeds.
#[no_mangle]
pub extern "C" fn shekyl_dialer_note_network(nettype: u8) -> i32 {
    let Some(net) = DaemonNetwork::from_cryptonote(nettype) else {
        return -1;
    };
    note_network(net);
    0
}

/// Start the owner loop for `connector` on a thread of its own, as an
/// owner of the daemon's timing engine. The compiled seeds of this
/// connector enter gray first, as operator-named addresses (slice 1
/// brief §3): clearnet admits the IPv4 seeds, Tor admits the onion
/// seeds. A connector that is not started admits nothing of the other
/// connector's list. The daemon applies the p2p section, including a
/// closed network, before this loop exists, so the first wake already
/// draws inside that population. Once per connector: a second call finds
/// the loop claimed and starts nothing (the ephemeral-tor listen and the
/// proxy-only zone branch both reach here for Tor, 2026-10-13: two loops
/// ran). Returns whether this call started the loop.
pub(crate) fn start_connector(connector: ConnectorId, engine: &Handle<MonotonicClock>) -> bool {
    let Some(dialer) = dialer() else {
        return false;
    };
    if !dialer.claim_owner(connector) {
        tracing::debug!("{connector:?} already has its owner loop; not started again");
        return false;
    }
    let owner = match engine.register(OwnerClass::Discovery) {
        Ok(owner) => owner,
        Err(err) => {
            tracing::error!("the dialer's wake for {connector:?} could not register: {err:?}");
            dialer.release_owner(connector);
            return false;
        }
    };
    if connector == ConnectorId::Clearnet {
        // The node does not know its own public host, and a host-0 address
        // is non-global, so nothing about this node is disclosed on
        // clearnet. The option that names a public address comes with the
        // daemon-config slice (Rick, 2026-10-13); no C++ option is added.
        tracing::info!(
            "clearnet is dial-only: this node discloses no address of its own until a public address is configured"
        );
    }
    admit_compiled_seeds(&dialer, connector);
    let name = format!("p2p-dial-{connector:?}").to_lowercase();
    let running = Arc::clone(&dialer);
    let spawned = std::thread::Builder::new().name(name).spawn(move || {
        running.run(connector, &owner, &mut SecureRelayRng);
        if let Err(err) = owner.deregister() {
            // The engine closes at shutdown and drops every owner. That is
            // the loop's expected end, not a failure of the deregister.
            if err == EngineError::Closed {
                tracing::debug!("{connector:?}: the dialer's wake ended because the engine closed");
            } else {
                tracing::warn!("{connector:?}: the dialer's wake did not deregister: {err:?}");
            }
        }
    });
    if let Err(err) = spawned {
        tracing::error!("the dialer's thread for {connector:?} could not start: {err}");
        dialer.release_owner(connector);
        return false;
    }
    true
}

/// Admit the compiled seeds that belong to `connector`.
///
/// The other connector's rows stay out: a clearnet start does not put
/// onions in gray, and a Tor start does not put the IPv4 seeds there.
/// Called from the owner-loop start, after the p2p section is applied.
fn admit_compiled_seeds(dialer: &Dialer, connector: ConnectorId) {
    let network = *NETWORK.lock().expect("network");
    let now = dialer.hub().now();
    for seed in seeds(network) {
        if Peerlist::connector_of(&seed) != Some(connector) {
            continue;
        }
        if let Err(refusal) = dialer.admit_operator(&seed, now, &mut SecureRelayRng) {
            tracing::warn!("{connector:?}: seed {seed:?} was not admitted: {refusal:?}");
        }
    }
}

/// The per-boot onion `shekyl-tor` published, as this node's own address
/// on the Tor connector. `service_id` is the 56-character id, no suffix.
/// The onion this daemon published is its own Tor address.
pub fn note_own_onion(service_id: &str, virtual_port: u16) {
    let own = NetworkAddress::Tor {
        host: format!("{service_id}.onion"),
        port: virtual_port,
    };
    if set_own(ConnectorId::Tor, vec![own]).is_err() {
        tracing::error!(
            "the onion was published before the dialer existed; it is not this node's own address"
        );
    }
}

/// Stop every owner loop. Called at zone shutdown.
pub(crate) fn stop() {
    if let Some(dialer) = DIALER.lock().expect("dialer").take() {
        dialer.stop();
    }
}

/// A session closed. A kept session leaves the dialer's count. A
/// `SessionRefused` cause is the lists' `PayloadRefused`. The row is
/// already off the board, and this poster does not hold the table lock,
/// so an inbound Tor session leaves the held count here.
pub(crate) fn on_closed(id: SocketId, cause: CloseCause) {
    if let Some(dialer) = dialer() {
        dialer.session_closed_from_seam(id, cause, &mut SecureRelayRng);
    }
}

/// An inbound Tor session was accepted. The board already carries the row.
pub(crate) fn note_inbound_tor() {
    if let Some(dialer) = dialer() {
        dialer.note_inbound_tor();
    }
}

fn with_shared<T>(f: impl FnOnce(MutexGuard<'_, Shared>) -> T) -> Option<T> {
    dialer().map(|dialer| f(dialer.shared()))
}

/// The inbound handshake's self-connection check: 1 when `nonce` is one
/// this node put in flight on `connector`, erasing it; 0 otherwise. The
/// connector is the inbound session's, not one the request names.
///
/// # Safety
///
/// `nonce` points to 32 readable bytes, or is null (answered 0).
#[no_mangle]
pub unsafe extern "C" fn shekyl_dial_take_handshake_nonce(connector: u32, nonce: *const u8) -> i32 {
    let Some(connector) = connector_from_index(connector) else {
        return 0;
    };
    let Some(bytes) = (unsafe { slice_from_typed_ptr(nonce, 32) }) else {
        return 0;
    };
    let Ok(nonce) = <[u8; 32]>::try_from(bytes) else {
        return 0;
    };
    match dialer() {
        Some(dialer) => i32::from(dialer.take_nonce(connector, &nonce)),
        None => 0,
    }
}

/// The core's tip: height, cumulative difficulty (low and high 64 bits)
/// and top block id. The dialer's next handshake carries this snapshot.
/// Called wherever the tip changes, and once at start.
///
/// # Safety
///
/// `top_id` points to 32 readable bytes, or is null (ignored).
#[no_mangle]
pub unsafe extern "C" fn shekyl_core_publish_tip(
    height: u64,
    cumulative_difficulty: u64,
    cumulative_difficulty_top64: u64,
    top_id: *const u8,
) {
    let Some(bytes) = (unsafe { slice_from_typed_ptr(top_id, 32) }) else {
        return;
    };
    let Ok(top_id) = <[u8; 32]>::try_from(bytes) else {
        return;
    };
    *TIP.lock().expect("tip") = Some(SyncPayload {
        current_height: height,
        cumulative_difficulty,
        cumulative_difficulty_top64,
        top_id,
    });
    if let Some(dialer) = dialer() {
        dialer.tip_published();
    }
}

/// The tip the core last published: 1 and the fields written, or 0 and
/// nothing written when no tip has been published yet. What the dialer's
/// next handshake carries, so a test of the publish reads it here.
///
/// # Safety
///
/// Each out pointer is writable, or null (then not written).
#[no_mangle]
pub unsafe extern "C" fn shekyl_core_published_tip(
    out_height: *mut u64,
    out_cumulative_difficulty: *mut u64,
    out_cumulative_difficulty_top64: *mut u64,
    out_top_id: *mut u8,
) -> i32 {
    let Some(tip) = *TIP.lock().expect("tip") else {
        return 0;
    };
    unsafe {
        if !out_height.is_null() {
            out_height.write(tip.current_height);
        }
        if !out_cumulative_difficulty.is_null() {
            out_cumulative_difficulty.write(tip.cumulative_difficulty);
        }
        if !out_cumulative_difficulty_top64.is_null() {
            out_cumulative_difficulty_top64.write(tip.cumulative_difficulty_top64);
        }
        if !out_top_id.is_null() {
            for (i, byte) in tip.top_id.iter().enumerate() {
                out_top_id.add(i).write(*byte);
            }
        }
    }
    1
}

/// The outbound target a connector is provisioned at: the protocol
/// constants (`shekyl-relay-privacy`), one source for the dialer and for
/// the reservation the daemon records before the seam binds.
#[must_use]
pub fn default_target(connector: ConnectorId) -> u32 {
    match connector {
        ConnectorId::Clearnet => P2P_DEFAULT_OUT_PEERS,
        ConnectorId::Tor => MIN_PROVISIONED_OUT_PEERS,
    }
}

/// The dialer does not exist: the seam is not bound, so the remnant has
/// not constructed `net_node` yet, or the zone host was shut down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoDialer;

impl std::fmt::Display for NoDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the dialer does not exist (the seam is not bound)")
    }
}

impl std::error::Error for NoDialer {}

/// A peer endpoint as the lists address it.
fn network_address(peer: &PeerEndpoint) -> NetworkAddress {
    match peer {
        PeerEndpoint::Ip(SocketAddr::V4(a)) => NetworkAddress::Ipv4 {
            ip: *a.ip(),
            port: a.port(),
        },
        PeerEndpoint::Ip(SocketAddr::V6(a)) => NetworkAddress::Ipv6 {
            ip: *a.ip(),
            port: a.port(),
        },
        PeerEndpoint::Onion { host, port } => NetworkAddress::Tor {
            host: host.clone(),
            port: *port,
        },
    }
}

/// Applies the p2p section to the dialer: the address file first, so an
/// operator address already in it is not re-seated; then the operator's
/// peers, which enter gray as candidates (slice 1 §3: seeds are ordinary
/// peers); the closed-network declaration when it is non-empty (an empty
/// one is no declaration); and early disclosure.
///
/// # Errors
/// [`NoDialer`] before the seam binds.
pub fn apply_p2p(section: &P2p, address_file: &Path) -> Result<(), NoDialer> {
    let dialer = dialer().ok_or(NoDialer)?;
    open_file(&dialer, address_file);
    let now = dialer.hub().now();
    for peer in &section.peers {
        let address = network_address(peer);
        if let Err(refusal) = dialer.admit_operator(&address, now, &mut SecureRelayRng) {
            tracing::warn!("operator address {address:?} was not admitted: {refusal:?}");
        }
    }
    if !section.closed_peers.is_empty() {
        let closed: Vec<NetworkAddress> =
            section.closed_peers.iter().map(network_address).collect();
        dialer.set_exclusive(closed, now, &mut SecureRelayRng);
    }
    if section.disclose_early {
        dialer.set_disclose_early(now);
    }
    Ok(())
}

/// This node's own addresses on `connector`: never dial candidates, and
/// the disclosure population's own member. `clearnet-advertise` for the
/// clearnet connector (§2.8); the onion for Tor.
///
/// # Errors
/// [`NoDialer`] before the seam binds.
pub fn set_own_addresses(
    connector: ConnectorId,
    addresses: Vec<NetworkAddress>,
) -> Result<(), NoDialer> {
    set_own(connector, addresses)
}

/// The disclosure sample for a response on `session` (the socket id):
/// writes up to `cap` entries into `out` and returns how many. Zero when
/// the connector's white list is below the diversity floor, when there
/// is no such session, or when there is no dialer.
///
/// # Safety
///
/// `out` points to `cap` writable [`ShekylSeamAddress`] slots, or `cap`
/// is zero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_peerlist_disclose(
    session: u64,
    out: *mut ShekylSeamAddress,
    cap: usize,
) -> usize {
    if cap == 0 || out.is_null() {
        return 0;
    }
    let Some(dialer) = dialer() else {
        return 0;
    };
    let Some(id) = SocketId::from_ffi(session) else {
        return 0;
    };
    let hub = dialer.hub();
    let Some(connector) = hub.board().get(id).map(|row| row.connector()) else {
        return 0;
    };
    let now = hub.now();
    let mut bans = BanSnapshot::take(hub);
    let sample = with_shared(|mut shared| {
        let mut kept = shared.kept_addresses(connector);
        shared
            .lists
            .disclose(connector, now, &mut bans, &mut kept, &mut SecureRelayRng)
    })
    .unwrap_or_default();
    let mut written = 0;
    for address in sample.iter().take(cap) {
        if let Some(entry) = entry_of(address) {
            // SAFETY: the caller's contract, stated above; `written < cap`.
            unsafe { out.add(written).write(entry) };
            written += 1;
        }
    }
    written
}

/// One list address, encoded for the adapter. `None` for an onion host
/// longer than the entry holds, which the lists never admit.
fn entry_of(address: &NetworkAddress) -> Option<ShekylSeamAddress> {
    let mut entry = ShekylSeamAddress {
        connector: 0,
        address_type: 0,
        zone_only: 0,
        _pad: 0,
        port: 0,
        len: 0,
        bytes: [0; TOR_HOST_MAX],
    };
    match address {
        NetworkAddress::Ipv4 { ip, port } => {
            entry.address_type = crate::seam_ffi::ADDR_IPV4;
            entry.port = *port;
            entry.len = 4;
            entry.bytes[..4].copy_from_slice(&ip.octets());
        }
        NetworkAddress::Ipv6 { ip, port } => {
            entry.address_type = crate::seam_ffi::ADDR_IPV6;
            entry.port = *port;
            entry.len = 16;
            entry.bytes[..16].copy_from_slice(&ip.octets());
        }
        NetworkAddress::Tor { host, port } => {
            let bytes = host.as_bytes();
            if bytes.len() > TOR_HOST_MAX {
                return None;
            }
            entry.connector = 1;
            entry.address_type = crate::seam_ffi::ADDR_TOR;
            entry.port = *port;
            entry.len = u16::try_from(bytes.len()).ok()?;
            entry.bytes[..bytes.len()].copy_from_slice(bytes);
        }
    }
    Some(entry)
}

#[cfg(test)]
#[path = "dialer_ffi_tests.rs"]
mod tests;
