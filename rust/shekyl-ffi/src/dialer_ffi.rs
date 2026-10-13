// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The outbound dialer, as the C++ reaches it (`P2P_3_SLICE_3_DIALER_BRIEF.md`).
//!
//! The dialer is `shekyl-dialer`'s, built over the seam hub when the zone
//! host starts, and its owner loops start when each connector is ready.
//! Nothing here is a dial: the C++ asks four things of this file and
//! tells it three.
//!
//! Asked: the self-connection nonce query the inbound handshake makes
//! ([`shekyl_dial_take_handshake_nonce`]); the disclosure sample for the
//! two responses the C++ still sends ([`shekyl_peerlist_disclose`]).
//!
//! Told: the strand's verdict on a posted handshake
//! ([`shekyl_dialer_handshake_verdict`]); the core's tip
//! ([`shekyl_core_publish_tip`]); `--out-peers`
//! ([`shekyl_dialer_set_out_peers`]); an operator-named address
//! ([`shekyl_peerlist_admit_operator`]); this node's own address on a
//! connector ([`shekyl_peerlist_set_own_address`]).

use std::sync::{Arc, Mutex, MutexGuard};

use shekyl_dialer::{seeds, Dialer, SeedNetwork, Shared};
use shekyl_levin::SupportFlags;
use shekyl_peerlist::{ConnectorId, NetworkAddress, Tick};
use shekyl_relay_privacy::params::MIN_PROVISIONED_OUT_PEERS;
use shekyl_rpc_types::DaemonNetwork;
use shekyl_seam::{connector_from_index, Hub, SocketId, SyncPayload};
use shekyl_timing_engine::{Handle, MonotonicClock, OwnerClass};

use crate::legacy_util::slice_from_typed_ptr;
use crate::peerlist_ffi::{address_of, refused_set};
use crate::seam_ffi::ShekylSeamAddress;
use crate::secure_relay_rng::SecureRelayRng;
use shekyl_seam::TOR_HOST_MAX;

/// The process's dialer, from the zone host's start to its shutdown.
static DIALER: Mutex<Option<Arc<Dialer>>> = Mutex::new(None);

/// The core's latest published tip. `None` until the first publish.
static TIP: Mutex<Option<SyncPayload>> = Mutex::new(None);

/// Which network's seeds to admit, from the network-id derivation.
static NETWORK: Mutex<SeedNetwork> = Mutex::new(SeedNetwork::None);

/// The outbound caps the C++ set before the dialer existed: the command
/// line is parsed before the seam binds. Applied when the dialer is built.
static CAPS: Mutex<[Option<u32>; ConnectorId::COUNT]> = Mutex::new([None; ConnectorId::COUNT]);

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
        SupportFlags::ADVERTISED.bits(),
        Arc::new(|| *TIP.lock().expect("tip")),
    ));
    for (index, cap) in CAPS.lock().expect("caps").iter().enumerate() {
        if let (Some(cap), Some(connector)) = (cap, ConnectorId::ALL.get(index)) {
            let _closed = dialer.set_target(*connector, *cap as usize, &mut SecureRelayRng);
        }
    }
    *slot = Some(Arc::clone(&dialer));
    dialer
}

/// The zone host started: the dialer learns the network it dials.
pub(crate) fn set_network_id(network_id: [u8; 16]) {
    if let Some(dialer) = dialer() {
        dialer.set_network_id(network_id);
    }
}

/// The derived network, recorded where the C++ asks for its network id.
pub(crate) fn note_network(network: DaemonNetwork) {
    let seeds_of = match network {
        DaemonNetwork::Mainnet => SeedNetwork::Mainnet,
        DaemonNetwork::Testnet => SeedNetwork::Testnet,
        DaemonNetwork::Stagenet | DaemonNetwork::Fakechain => SeedNetwork::None,
    };
    *NETWORK.lock().expect("network") = seeds_of;
}

/// Start the owner loop for `connector` on a thread of its own, as an
/// owner of the daemon's timing engine. The compiled seeds enter gray
/// first, as operator-named addresses (slice 1 brief §3). Called once per
/// connector, when it is ready to dial.
pub(crate) fn start_connector(connector: ConnectorId, engine: &Handle<MonotonicClock>) {
    let Some(dialer) = dialer() else {
        return;
    };
    let owner = match engine.register(OwnerClass::Discovery) {
        Ok(owner) => owner,
        Err(err) => {
            tracing::error!("the dialer's wake for {connector:?} could not register: {err:?}");
            return;
        }
    };
    if connector == ConnectorId::Clearnet {
        let network = *NETWORK.lock().expect("network");
        let now = dialer.hub().now();
        for seed in seeds(network) {
            match dialer.admit_operator(&seed, now, &mut SecureRelayRng) {
                Ok(_) | Err(_) => {}
            }
        }
    }
    let name = format!("p2p-dial-{connector:?}").to_lowercase();
    let spawned = std::thread::Builder::new().name(name).spawn(move || {
        dialer.run(connector, &owner, &mut SecureRelayRng);
        match owner.deregister() {
            Ok(()) | Err(_) => {}
        }
    });
    if spawned.is_err() {
        tracing::error!("the dialer's thread for {connector:?} could not start");
    }
}

/// Stop every owner loop. Called at zone shutdown.
pub(crate) fn stop() {
    if let Some(dialer) = DIALER.lock().expect("dialer").take() {
        dialer.stop();
    }
}

/// A session closed. A kept session leaves the dialer's count; a dial
/// awaiting its verdict fails with the cause the connector stored.
pub(crate) fn on_closed(id: SocketId) {
    if let Some(dialer) = dialer() {
        dialer.session_closed(id, &mut SecureRelayRng);
    }
}

fn with_shared<T>(f: impl FnOnce(MutexGuard<'_, Shared>) -> T) -> Option<T> {
    dialer().map(|dialer| f(dialer.shared()))
}

/// The strand accepted (1) or refused (0) the sync payload of the
/// handshake posted for `id`. The dialer closes a confirm dial and a
/// refused dial here; a kept and accepted dial stays.
#[no_mangle]
pub extern "C" fn shekyl_dialer_handshake_verdict(id: u64, accepted: i32) {
    let Some(id) = SocketId::from_ffi(id) else {
        return;
    };
    if let Some(dialer) = dialer() {
        dialer.verdict(id, accepted != 0, &mut SecureRelayRng);
    }
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

/// `--out-peers`, and the anonymity zones' cap: the connector's outbound
/// target. A cap of 0 is legal and stops outbound entirely. A positive cap
/// below the F-8b floor (`MIN_PROVISIONED_OUT_PEERS`) is refused with -1,
/// because the relay embargo derivation assumes that degree. Lowering a
/// cap at runtime closes kept sessions only. Returns 0 when set, which
/// includes a cap set before the seam binds: it is kept and applied when
/// the dialer is built.
#[no_mangle]
pub extern "C" fn shekyl_dialer_set_out_peers(connector: u32, cap: u32) -> i32 {
    let Some(connector) = connector_from_index(connector) else {
        return -1;
    };
    if cap > 0 && cap < MIN_PROVISIONED_OUT_PEERS {
        return -1;
    }
    CAPS.lock().expect("caps")[connector.index()] = Some(cap);
    if let Some(dialer) = dialer() {
        let _closed = dialer.set_target(connector, cap as usize, &mut SecureRelayRng);
    }
    0
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
}

/// An operator-named address (`--add-peer`): into gray, whatever its
/// range. Returns 1 when it newly entered gray, 0 when it already sat or
/// was refused, -1 when the entry is not an address or there is no
/// dialer yet.
///
/// # Safety
///
/// `entry` points to one initialized [`ShekylSeamAddress`], or is null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_peerlist_admit_operator(entry: *const ShekylSeamAddress) -> i32 {
    if entry.is_null() {
        return -1;
    }
    let Some(address) = address_of(unsafe { &*entry }) else {
        return -1;
    };
    let Some(dialer) = dialer() else {
        return -1;
    };
    let now = dialer.hub().now();
    match dialer.admit_operator(&address, now, &mut SecureRelayRng) {
        Ok(true) => 1,
        Ok(false) | Err(_) => 0,
    }
}

/// This node's own dialable address on `connector`: never a dial
/// candidate, and one uniform member of the disclosure population. An
/// entry that is not an address clears it. Returns 0, or -1 with no
/// dialer.
///
/// # Safety
///
/// `entry` points to one initialized [`ShekylSeamAddress`], or is null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_peerlist_set_own_address(
    connector: u32,
    entry: *const ShekylSeamAddress,
) -> i32 {
    let Some(connector) = connector_from_index(connector) else {
        return -1;
    };
    let Some(dialer) = dialer() else {
        return -1;
    };
    let own = if entry.is_null() {
        Vec::new()
    } else {
        address_of(unsafe { &*entry }).into_iter().collect()
    };
    dialer.set_own_addresses(connector, own);
    0
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
    let mut bans = HubBans(hub);
    let sample = with_shared(|mut shared| {
        shared
            .lists
            .disclose(connector, now, &mut bans, &mut SecureRelayRng)
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

/// The transport layer's bans, asked through the hub.
struct HubBans<'a>(&'a Hub);

impl shekyl_peerlist::BanQuery for HubBans<'_> {
    fn is_banned(&mut self, host: std::net::IpAddr, _now: Tick) -> bool {
        self.0.is_banned(host)
    }
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
