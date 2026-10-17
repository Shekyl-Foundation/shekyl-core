// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The RPC's view of the peer lists: `get_peer_list` and `get_info`'s two
//! list sizes, read from the Rust lists (RK-5a's two exports, moved here
//! from C++ with the C++ peerlist's deletion, 2026-10-13).
//!
//! The entries carry no clock: the lists hold none (slice 1 brief §4).
//! `blocked` is the transport layer's ban on the address's host, asked
//! through the hub. Nothing here changes the lists.
//!
//! Offline is not a result of these exports. The RPC answers it from the
//! bit `configure` recorded, before it calls here. An online daemon with
//! no dialer is a fault (`FACTS_ERR_NULL`), and says so: absence of a
//! dialer is not a way to infer offline.

use std::ffi::c_void;

use shekyl_dialer::HubBans;
use shekyl_peerlist::{ConnectorId, ListName, NetworkAddress, Peerlist};

use crate::dialer_ffi::dialer;

/// The facts codes the RPC's exports share (`rpc_facts_ffi.h`).
const FACTS_OK: i32 = 0;
/// A null out pointer, or an online daemon with no peer lists.
const FACTS_ERR_NULL: i32 = -1;

/// One peerlist entry, as `get_peer_list` renders it. Twin of
/// `shekyl_rpc_peer_facts` (C++) and `shekyl-daemon-rpc`'s `PeerFactsFfi`,
/// pinned by size on each side.
///
/// `host` is the ip string for IPv4, the bare host for IPv6, and the whole
/// `host:port` for Tor, with `port` zero there; `ip` is the IPv4 address
/// with its four octets in network order, zero for every other arm.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ShekylRpcPeerFacts {
    pub host: *const u8,
    pub host_len: usize,
    pub ip: u32,
    pub port: u16,
    /// 1 white, 0 gray.
    pub white: u8,
    /// 1 when the transport layer bans the host now. The request's
    /// `include_blocked` is the caller's to apply.
    pub blocked: u8,
}

const _: () = assert!(std::mem::size_of::<ShekylRpcPeerFacts>() == 24);

/// What `shekyl_rpc_peer_list` hands out and `shekyl_rpc_peer_list_free`
/// takes back: the host strings and the entries that point into them.
struct PeerListOwner {
    hosts: Vec<String>,
    entries: Vec<ShekylRpcPeerFacts>,
}

/// The host string and the numeric fields of one address.
fn render(address: &NetworkAddress) -> (String, u32, u16) {
    match address {
        NetworkAddress::Ipv4 { ip, port } => {
            (ip.to_string(), u32::from_le_bytes(ip.octets()), *port)
        }
        NetworkAddress::Ipv6 { ip, port } => (ip.to_string(), 0, *port),
        NetworkAddress::Tor { host, port } => (format!("{host}:{port}"), 0, 0),
    }
}

/// The entries, white then gray, for every connector or clearnet only.
/// `None` when there are no peer lists to read.
fn entries(public_only: bool) -> Option<PeerListOwner> {
    let dialer = dialer()?;
    let hub = dialer.hub();
    let snapshot = dialer.shared().lists.snapshot();
    let mut rows: Vec<(NetworkAddress, ListName)> = snapshot
        .into_iter()
        .filter(|(address, _)| {
            !public_only || Peerlist::connector_of(address) == Some(ConnectorId::Clearnet)
        })
        .collect();
    rows.sort_by_key(|(_, list)| matches!(list, ListName::Gray));
    let mut hosts = Vec::new();
    let mut facts = Vec::new();
    for (address, list) in &rows {
        let (host, ip, port) = render(address);
        let blocked = match address {
            NetworkAddress::Ipv4 { ip, .. } => hub.is_banned((*ip).into()),
            NetworkAddress::Ipv6 { ip, .. } => hub.is_banned((*ip).into()),
            NetworkAddress::Tor { .. } => false,
        };
        facts.push(ShekylRpcPeerFacts {
            host: std::ptr::null(),
            host_len: host.len(),
            ip,
            port,
            white: u8::from(matches!(list, ListName::White)),
            blocked: u8::from(blocked),
        });
        hosts.push(host);
    }
    let mut owner = PeerListOwner {
        hosts,
        entries: facts,
    };
    for (entry, host) in owner.entries.iter_mut().zip(&owner.hosts) {
        entry.host = host.as_ptr();
    }
    Some(owner)
}

/// White then gray peerlist entries in one array, discriminated by
/// `white`; `public_only` nonzero lists the clearnet lists alone. Returns
/// 0 with `*out`, `*out_len` and `*out_owner` written, or -1 for a null
/// out pointer or an online daemon with no peer lists. Release
/// `*out_owner` with
/// [`shekyl_rpc_peer_list_free`]; the entries point into it.
///
/// # Safety
///
/// Each out pointer is writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_peer_list(
    public_only: u8,
    out: *mut *const ShekylRpcPeerFacts,
    out_len: *mut usize,
    out_owner: *mut *mut c_void,
) -> i32 {
    if out.is_null() || out_len.is_null() || out_owner.is_null() {
        return FACTS_ERR_NULL;
    }
    unsafe { out_owner.write(std::ptr::null_mut()) };
    let Some(owner) = entries(public_only != 0) else {
        return FACTS_ERR_NULL;
    };
    let owner = Box::new(owner);
    let first = if owner.entries.is_empty() {
        std::ptr::null()
    } else {
        owner.entries.as_ptr()
    };
    let len = owner.entries.len();
    unsafe {
        out.write(first);
        out_len.write(len);
        out_owner.write(Box::into_raw(owner).cast::<c_void>());
    }
    FACTS_OK
}

/// Release what [`shekyl_rpc_peer_list`] handed out. Null is a no-op.
///
/// # Safety
///
/// `owner` came from [`shekyl_rpc_peer_list`] and is released once.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_peer_list_free(owner: *mut c_void) {
    if owner.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(owner.cast::<PeerListOwner>()) });
}

/// How many addresses the clearnet white and gray lists hold, for
/// `get_info`. Returns 0 with both written, or -1 for a null out pointer
/// or an online daemon with no peer lists.
///
/// # Safety
///
/// Both out pointers are writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_peerlist_sizes(out_white: *mut u64, out_gray: *mut u64) -> i32 {
    if out_white.is_null() || out_gray.is_null() {
        return FACTS_ERR_NULL;
    }
    let Some(dialer) = dialer() else {
        return FACTS_ERR_NULL;
    };
    let (white, gray) = {
        let mut shared = dialer.shared();
        let hub = dialer.hub();
        let now = hub.now();
        let white = shared.lists.white_count(
            ConnectorId::Clearnet,
            now,
            &mut HubBans(hub),
            &mut crate::secure_relay_rng::SecureRelayRng,
        );
        let gray = shared.lists.gray_count(ConnectorId::Clearnet);
        (white, gray)
    };
    unsafe {
        out_white.write(white as u64);
        out_gray.write(gray as u64);
    }
    FACTS_OK
}

#[cfg(test)]
mod tests {
    use crate::seam_ffi::shekyl_seam_set_ceiling;
    use std::ffi::c_void;
    use std::net::Ipv4Addr;
    use std::sync::PoisonError;

    use shekyl_peerlist::Tick;
    use shekyl_seam::CloseCause;

    use super::*;
    use crate::inbound_ceiling_ffi::{ShekylInboundCeiling, SHEKYL_INBOUND_CEILING_UNLIMITED};
    use crate::legacy_util::slice_from_typed_ptr;
    use crate::seam_ffi::{seam_bind_lock, shekyl_seam_bind, ShekylSeamObserved};
    use crate::secure_relay_rng::SecureRelayRng;

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

    fn unbind() {
        unsafe { shekyl_seam_bind(std::ptr::null_mut(), None) };
    }

    fn v4(n: u8) -> NetworkAddress {
        NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(11, 17, 0, n),
            port: 18080,
        }
    }

    fn onion() -> NetworkAddress {
        NetworkAddress::Tor {
            host: format!("{:0>56}.onion", 7),
            port: 18080,
        }
    }

    /// Every row the export hands out, copied, then the owner released.
    fn listed(public_only: bool) -> Vec<(String, u32, u16, bool, bool)> {
        let mut rows: *const ShekylRpcPeerFacts = std::ptr::null();
        let mut len = 0usize;
        let mut owner: *mut c_void = std::ptr::null_mut();
        let rc = unsafe {
            shekyl_rpc_peer_list(
                u8::from(public_only),
                &raw mut rows,
                &raw mut len,
                &raw mut owner,
            )
        };
        assert_eq!(rc, FACTS_OK);
        let mut out = Vec::new();
        for i in 0..len {
            let e = unsafe { rows.add(i).read() };
            let host = unsafe { slice_from_typed_ptr(e.host, e.host_len) }.expect("a host");
            out.push((
                String::from_utf8(host.to_vec()).expect("utf-8"),
                e.ip,
                e.port,
                e.white != 0,
                e.blocked != 0,
            ));
        }
        unsafe { shekyl_rpc_peer_list_free(owner) };
        out
    }

    /// An online daemon with no peer lists is a fault on both exports, not
    /// an empty answer: it is not a state any configuration asked for.
    /// Offline is answered by the RPC before these exports are called.
    #[test]
    fn an_online_daemon_with_no_dialer_is_a_fault() {
        let _bind = seam_bind_lock()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        unbind();
        let mut rows: *const ShekylRpcPeerFacts = std::ptr::null();
        let mut len = 0usize;
        let mut owner: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            unsafe { shekyl_rpc_peer_list(0, &raw mut rows, &raw mut len, &raw mut owner) },
            FACTS_ERR_NULL
        );
        assert!(owner.is_null());
        let mut white = 0u64;
        let mut gray = 0u64;
        assert_eq!(
            unsafe { shekyl_rpc_peerlist_sizes(&raw mut white, &raw mut gray) },
            FACTS_ERR_NULL
        );
    }

    /// The three address arms render as the wire contract says, every entry
    /// names its list, `public_only` leaves the Tor list out, and the sizes
    /// agree with the listing.
    #[test]
    fn the_listing_renders_each_arm_and_public_only_is_clearnet_alone() {
        let _bind = seam_bind_lock()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        unbind();
        bind();
        let dialer = dialer().expect("built at the bind");
        let now = Tick::new(1);
        for address in [v4(1), v4(2), onion()] {
            dialer
                .admit_operator(&address, now, &mut SecureRelayRng)
                .expect("admitted");
        }
        let v6 = NetworkAddress::Ipv6 {
            ip: "2001:db8::1".parse().expect("v6"),
            port: 18081,
        };
        dialer
            .admit_operator(&v6, now, &mut SecureRelayRng)
            .expect("admitted");

        let all = listed(false);
        assert_eq!(all.len(), 4);
        assert!(all
            .iter()
            .all(|(_, _, _, white, blocked)| !white && !blocked));
        let host = |want: &str| all.iter().find(|(h, ..)| h == want).expect(want).clone();
        assert_eq!(
            host("11.17.0.1"),
            ("11.17.0.1".to_owned(), 0x0100_110b, 18080, false, false)
        );
        assert_eq!(host("2001:db8::1").2, 18081);
        assert_eq!(host("2001:db8::1").1, 0);
        let tor = host(&format!("{:0>56}.onion:18080", 7));
        assert_eq!((tor.1, tor.2), (0, 0), "Tor carries the port in the host");

        let public = listed(true);
        assert_eq!(public.len(), 3, "the onion is left out");
        assert!(public
            .iter()
            .all(|(h, ..)| !h.ends_with(":18080") || h.starts_with("11.")));

        let mut white = 0u64;
        let mut gray = 0u64;
        assert_eq!(
            unsafe { shekyl_rpc_peerlist_sizes(&raw mut white, &raw mut gray) },
            FACTS_OK
        );
        assert_eq!(
            (white, gray),
            (0, 3),
            "clearnet only: two v4 and one v6, all gray"
        );
        unbind();
    }

    #[test]
    fn a_null_out_pointer_is_refused_and_writes_nothing() {
        let mut len = 0usize;
        let mut owner: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            unsafe { shekyl_rpc_peer_list(0, std::ptr::null_mut(), &raw mut len, &raw mut owner) },
            FACTS_ERR_NULL
        );
        assert!(owner.is_null());
        unsafe { shekyl_rpc_peer_list_free(std::ptr::null_mut()) };
    }
}
