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

use std::ffi::{c_char, CStr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use shekyl_dialer::{seeds, Dialer, HubBans, LoadError, SeedNetwork, Shared};
use shekyl_levin::SupportFlags;
use shekyl_peerlist::{ConnectorId, NetworkAddress};
use shekyl_relay_privacy::params::{MIN_PROVISIONED_OUT_PEERS, P2P_DEFAULT_OUT_PEERS};
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

/// Pushes made before the dialer exists, held for its build. What that
/// means, plainly: the daemon's `init()` parses the command line and names
/// the address file (`shekyl_dialer_open_address_file`, `--add-peer` through
/// `shekyl_peerlist_admit_operator`, `--add-exclusive-node` through
/// `shekyl_dialer_set_exclusive`, `--anonymous-inbound` through
/// `shekyl_peerlist_set_own_address`) before its first listen binds the
/// seam, and the dialer is built at that bind (and again with every zone
/// host, [`ensure_dialer`]). On a start where the managed Tor does not
/// listen first, every one of those calls therefore arrives with no dialer
/// to act on. Each such call records its argument here and answers
/// [`SHEKYL_DIALER_DEFERRED`]; the build drains this slot into the new
/// dialer in the order below (the file first, so an operator address
/// already in it is not re-seated; then the operator addresses, the closed
/// network, the own addresses), and the call has the same effect it would
/// have had after the build. A call after the build acts at once.
struct Deferred {
    address_file: Option<PathBuf>,
    operator: Vec<NetworkAddress>,
    exclusive: Option<Vec<NetworkAddress>>,
    own: Vec<(ConnectorId, Vec<NetworkAddress>)>,
    disclose_early: bool,
}

static DEFERRED: Mutex<Deferred> = Mutex::new(Deferred {
    address_file: None,
    operator: Vec::new(),
    exclusive: None,
    own: Vec::new(),
    disclose_early: false,
});

/// Recorded for the dialer's build: the entry's effect follows when the
/// seam binds.
pub const SHEKYL_DIALER_DEFERRED: i32 = 2;

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
    let deferred = {
        let mut held = DEFERRED.lock().expect("deferred");
        std::mem::replace(
            &mut *held,
            Deferred {
                address_file: None,
                operator: Vec::new(),
                exclusive: None,
                own: Vec::new(),
                disclose_early: false,
            },
        )
    };
    let now = hub.now();
    if deferred.disclose_early {
        dialer.set_disclose_early(now);
    }
    if let Some(path) = deferred.address_file {
        open_file(&dialer, &path);
    }
    for address in &deferred.operator {
        if let Err(refusal) = dialer.admit_operator(address, now, &mut SecureRelayRng) {
            tracing::warn!("operator address {address:?} was not admitted: {refusal:?}");
        }
    }
    if let Some(list) = deferred.exclusive {
        dialer.set_exclusive(list, now, &mut SecureRelayRng);
    }
    for (connector, own) in deferred.own {
        dialer.set_own_addresses(connector, own);
    }
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
fn set_own(connector: ConnectorId, own: Vec<NetworkAddress>) {
    match dialer() {
        Some(dialer) => dialer.set_own_addresses(connector, own),
        None => DEFERRED
            .lock()
            .expect("deferred")
            .own
            .push((connector, own)),
    }
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
/// first, as operator-named addresses (slice 1 brief §3). Once per
/// connector: a second call finds the loop claimed and starts nothing
/// (the ephemeral-tor listen and the proxy-only zone branch both reach
/// here for Tor, 2026-10-13: two loops ran). Returns whether this call
/// started the loop.
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
        let network = *NETWORK.lock().expect("network");
        let now = dialer.hub().now();
        for seed in seeds(network) {
            if let Err(refusal) = dialer.admit_operator(&seed, now, &mut SecureRelayRng) {
                tracing::warn!("{connector:?}: seed {seed:?} was not admitted: {refusal:?}");
            }
        }
    }
    let name = format!("p2p-dial-{connector:?}").to_lowercase();
    let running = Arc::clone(&dialer);
    let spawned = std::thread::Builder::new().name(name).spawn(move || {
        running.run(connector, &owner, &mut SecureRelayRng);
        if let Err(err) = owner.deregister() {
            tracing::warn!("{connector:?}: the dialer's wake did not deregister: {err:?}");
        }
    });
    if let Err(err) = spawned {
        tracing::error!("the dialer's thread for {connector:?} could not start: {err}");
        dialer.release_owner(connector);
        return false;
    }
    true
}

/// The per-boot onion `shekyl-tor` published, as this node's own address
/// on the Tor connector. `service_id` is the 56-character id, no suffix.
pub(crate) fn note_own_onion(service_id: &str, virtual_port: u16) {
    let own = NetworkAddress::Tor {
        host: format!("{service_id}.onion"),
        port: virtual_port,
    };
    set_own(ConnectorId::Tor, vec![own]);
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
        tracing::error!(
            "outbound cap {cap} for {connector:?} is below the floor of {MIN_PROVISIONED_OUT_PEERS} that the relay embargo derivation assumes (F-8b); refused. Omit the option for the default ({P2P_DEFAULT_OUT_PEERS}) or give a value >= {MIN_PROVISIONED_OUT_PEERS}"
        );
        return -1;
    }
    CAPS.lock().expect("caps")[connector.index()] = Some(cap);
    if let Some(dialer) = dialer() {
        let _closed = dialer.set_target(connector, cap as usize, &mut SecureRelayRng);
    }
    0
}

/// The connector's outbound target as the dialer holds it: the cap the
/// C++ pushed, or the compiled default before any push (`--out-peers`'s
/// default on clearnet, the hidden-cap floor on Tor). Read for the
/// descriptor reservation and the operator's `out_peers` readback. An
/// unknown connector is 0.
#[no_mangle]
pub extern "C" fn shekyl_dialer_out_target(connector: u32) -> u32 {
    let Some(connector) = connector_from_index(connector) else {
        return 0;
    };
    if let Some(dialer) = dialer() {
        return u32::try_from(dialer.target(connector)).unwrap_or(u32::MAX);
    }
    match CAPS.lock().expect("caps")[connector.index()] {
        Some(cap) => cap,
        None => match connector {
            ConnectorId::Clearnet => P2P_DEFAULT_OUT_PEERS,
            ConnectorId::Tor => MIN_PROVISIONED_OUT_PEERS,
        },
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

/// An operator-named address (`--add-peer`): into gray,
/// whatever its range. Returns 1 when it newly entered gray, 0 when it
/// already sat or was refused, [`SHEKYL_DIALER_DEFERRED`] when the dialer
/// is not built yet and the address is held for its build, -1 when the
/// entry is not an address.
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
        DEFERRED.lock().expect("deferred").operator.push(address);
        return SHEKYL_DIALER_DEFERRED;
    };
    let now = dialer.hub().now();
    match dialer.admit_operator(&address, now, &mut SecureRelayRng) {
        Ok(true) => 1,
        Ok(false) | Err(_) => 0,
    }
}

/// `--p2p-disclose-early` (brief revision 3 §2.6): the lists disclose below
/// the white diversity floor, fresh per request, until the span or the
/// floor ends it per connector. Returns 0, or [`SHEKYL_DIALER_DEFERRED`]
/// when held for the dialer's build. The C++ option that pushes this is
/// the one exception to "no new daemon option in C++"; the daemon-config
/// slice deletes it and moves the option to the Rust option table.
#[no_mangle]
pub extern "C" fn shekyl_peerlist_disclose_early() -> i32 {
    let Some(dialer) = dialer() else {
        DEFERRED.lock().expect("deferred").disclose_early = true;
        return SHEKYL_DIALER_DEFERRED;
    };
    let now = dialer.hub().now();
    dialer.set_disclose_early(now);
    0
}

/// A closed network (`--add-exclusive-node`): the candidate population is
/// exactly these entries, admitted as operator-named. An entry that is
/// not an address is left out. A count of zero declares no closed
/// network (the C++ passes one on every boot without the option). Returns
/// 0, [`SHEKYL_DIALER_DEFERRED`] when the list is held for the dialer's
/// build, or -1 for a null pointer with a non-zero count.
///
/// # Safety
///
/// `entries` points to `count` initialized [`ShekylSeamAddress`] values,
/// or `count` is zero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_dialer_set_exclusive(
    entries: *const ShekylSeamAddress,
    count: usize,
) -> i32 {
    let Some(entries) = (unsafe { slice_from_typed_ptr(entries, count) }) else {
        return -1;
    };
    let addresses: Vec<NetworkAddress> = entries.iter().filter_map(address_of).collect();
    let Some(dialer) = dialer() else {
        DEFERRED.lock().expect("deferred").exclusive = Some(addresses);
        return SHEKYL_DIALER_DEFERRED;
    };
    let now = dialer.hub().now();
    dialer.set_exclusive(addresses, now, &mut SecureRelayRng);
    0
}

/// The address file (`<data dir>/p2pstate.bin`): named once, at start.
/// Its addresses enter gray when the dialer is built, or now if it is;
/// the dialer writes it every thirty minutes and at stop. Returns 0, or
/// [`SHEKYL_DIALER_DEFERRED`] when held for the build, or -1 for a null
/// or non-UTF-8 path.
///
/// # Safety
///
/// `path` points to a NUL-terminated string, or is null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_dialer_open_address_file(path: *const c_char) -> i32 {
    if path.is_null() {
        return -1;
    }
    let Ok(path) = (unsafe { CStr::from_ptr(path) }).to_str() else {
        return -1;
    };
    let path = PathBuf::from(path);
    let Some(dialer) = dialer() else {
        DEFERRED.lock().expect("deferred").address_file = Some(path);
        return SHEKYL_DIALER_DEFERRED;
    };
    open_file(&dialer, &path);
    0
}

/// This node's own dialable address on `connector`: never a dial
/// candidate, and one uniform member of the disclosure population. An
/// entry that is not an address clears it. Returns 0, or -1 for an
/// unknown connector; held for the dialer's build when it is not built.
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
    let own = if entry.is_null() {
        Vec::new()
    } else {
        address_of(unsafe { &*entry }).into_iter().collect()
    };
    set_own(connector, own);
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
mod tests {
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
        std::fs::write(&file, shekyl_peerlist::address_file::encode(&[address(1)]))
            .expect("written");
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
        let drawn = dialer
            .choose(ConnectorId::Clearnet, &mut SecureRelayRng)
            .map(|(address, _aim, _nonce)| address);
        assert_eq!(drawn, Some(address(6)));
        unbind();
    }
}
