// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The peer lists, as the C++ reaches them.
//!
//! The C++ receives a peerlist in a handshake or timed-sync response and
//! hands it here as it arrived, with the session it arrived on.
//! [`shekyl_peerlist_admit_received`] answers accept or refuse, and the
//! C++ closes the session only on refuse. Every rule is on this side:
//! the receiver limit (D3), the per-session intake cap (D-S1), address
//! validity and its whole-list refusal (R4) and the foreign-connector
//! rule, on inbound and outbound sessions alike (every exchange is an
//! exchange, Rick 2026-10-13; *records-was* PWD-I2's direction rule).
//!
//! The session's connector is read from the seam board by the session id.
//! The C++ passes neither it nor the direction.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use shekyl_peerlist::{
    BanQuery, ConnectionId, ConnectorId, NetworkAddress, Peerlist, RefusedSet, SessionRow, Tick,
};
use shekyl_seam::{Hub, SocketId};

use crate::legacy_util::slice_from_typed_ptr;
use crate::seam_ffi::{hub, ShekylSeamAddress, ADDR_IPV4, ADDR_IPV6, ADDR_TOR};
use crate::secure_relay_rng::SecureRelayRng;

/// The list is refused. The C++ closes the session. No other answer
/// closes it.
pub const SHEKYL_PEERLIST_REFUSE: i32 = 0;
/// The list arrived on a session this node opened and passed every rule.
/// Its new addresses are in gray.
pub const SHEKYL_PEERLIST_ADMITTED: i32 = 1;
// 2 was SHEKYL_PEERLIST_INBOUND, retired 2026-10-13 with the direction
// rule (§2.5): an inbound list is admitted or refused like any other. The
// number is not reused.
/// The board holds no session with this id, so its direction is not
/// known. Nothing was admitted.
pub const SHEKYL_PEERLIST_NO_SESSION: i32 = 3;
/// No hub is bound: there are no sessions. Nothing was admitted.
pub const SHEKYL_PEERLIST_NO_HUB: i32 = 4;
/// The entries pointer is null with a non-zero count. That is the
/// caller's fault, not the peer's. Nothing was admitted.
pub const SHEKYL_PEERLIST_BAD_ARGUMENT: i32 = 5;

/// The refused set the lists are built with, from `--allow-local-ip`.
/// The lists themselves are the dialer's (`crate::dialer_ffi`).
static REFUSED: Mutex<RefusedSet> = Mutex::new(RefusedSet::NON_GLOBAL);

/// The set the lists are built with.
pub(crate) fn refused_set() -> RefusedSet {
    *REFUSED.lock().expect("refused set")
}

/// `--allow-local-ip`, as the peer lists' constructor input. Returns
/// `allow`, so the C++ line that read the flag reads it through this call.
///
/// `true` builds the lists over [`RefusedSet::EMPTY`]: a private test
/// network whose nodes find each other by peerlist exchange. The set is
/// fixed for the life of the lists, so a call after they exist that would
/// change it is logged and ignored.
#[no_mangle]
pub extern "C" fn shekyl_peerlist_allow_local_ip(allow: bool) -> bool {
    let wanted = if allow {
        RefusedSet::EMPTY
    } else {
        RefusedSet::NON_GLOBAL
    };
    let built = crate::dialer_ffi::shared().is_some();
    let mut refused = REFUSED.lock().expect("refused set");
    if built && *refused != wanted {
        tracing::error!("allow-local-ip changed after the peer lists were built; ignored");
    } else {
        *refused = wanted;
    }
    allow
}

/// The bans the transport layer holds, asked through the hub.
struct HubBans(Hub);

impl BanQuery for HubBans {
    fn is_banned(&mut self, host: IpAddr, _now: Tick) -> bool {
        self.0.is_banned(host)
    }
}

/// The peerlist's name for a seam session. The board's id is the socket
/// id; the lists key a session's intake by it.
fn session_of(id: SocketId) -> ConnectionId {
    shekyl_dialer::session_of(id)
}

/// One entry as the C++ encoded it, or `None` for an entry that is not an
/// address: an unknown type, a length that does not fit its type, or a
/// host that is not UTF-8. The adapter writes an empty entry for an
/// address it cannot encode, and that is `None` here too.
pub(crate) fn address_of(entry: &ShekylSeamAddress) -> Option<NetworkAddress> {
    let len = usize::from(entry.len);
    match entry.address_type {
        ADDR_IPV4 if len == 4 => Some(NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(
                entry.bytes[0],
                entry.bytes[1],
                entry.bytes[2],
                entry.bytes[3],
            ),
            port: entry.port,
        }),
        ADDR_IPV6 if len == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&entry.bytes[..16]);
            Some(NetworkAddress::Ipv6 {
                ip: Ipv6Addr::from(octets),
                port: entry.port,
            })
        }
        ADDR_TOR if len > 0 && len <= entry.bytes.len() => {
            let host = std::str::from_utf8(&entry.bytes[..len]).ok()?;
            Some(NetworkAddress::Tor {
                host: host.to_owned(),
                port: entry.port,
            })
        }
        _ => None,
    }
}

/// Decide one received list. Everything the FFI entry does, without the
/// process statics.
///
/// `row` is the session's connector from the board, or `None` when the
/// board has none. A session the board does not hold has no known
/// connector, so its list admits nothing and is not refused.
///
/// Each situation has its own code (rule 43): "nothing was admitted
/// because there is no such session" is not the same answer as "the list
/// was admitted", and neither is a refusal.
fn receive(
    list: &mut Peerlist,
    row: Option<ConnectorId>,
    session: ConnectionId,
    entries: &[ShekylSeamAddress],
    now: Tick,
    bans: &mut dyn BanQuery,
) -> i32 {
    let Some(connector) = row else {
        return SHEKYL_PEERLIST_NO_SESSION;
    };
    let Some(addresses) = entries
        .iter()
        .map(address_of)
        .collect::<Option<Vec<NetworkAddress>>>()
    else {
        return SHEKYL_PEERLIST_REFUSE;
    };
    let session = SessionRow {
        id: session,
        connector,
    };
    match list.admit_received_list(&addresses, session, now, bans, &mut SecureRelayRng) {
        Ok(_) => SHEKYL_PEERLIST_ADMITTED,
        Err(refusal) => {
            tracing::debug!(?refusal, "received peerlist refused");
            SHEKYL_PEERLIST_REFUSE
        }
    }
}

/// A peerlist a peer sent over session `session`, as it arrived.
///
/// Returns one of the `SHEKYL_PEERLIST_*` codes. The caller closes the
/// session on [`SHEKYL_PEERLIST_REFUSE`] and on nothing else.
///
/// # Safety
///
/// `entries` points to `count` initialized [`ShekylSeamAddress`] values,
/// or `count` is zero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_peerlist_admit_received(
    session: u64,
    entries: *const ShekylSeamAddress,
    count: usize,
) -> i32 {
    // SAFETY: the caller's contract, stated above. A null pointer with a
    // non-zero count is not a list; it is accepted and admits nothing, so a
    // caller's bug never closes a peer's session.
    let Some(entries) = (unsafe { slice_from_typed_ptr(entries, count) }) else {
        return SHEKYL_PEERLIST_BAD_ARGUMENT;
    };
    let Some(hub) = hub() else {
        return SHEKYL_PEERLIST_NO_HUB;
    };
    let Some(id) = SocketId::from_ffi(session) else {
        return SHEKYL_PEERLIST_NO_SESSION;
    };
    let row = hub.board().get(id).map(|row| row.connector());
    let now = hub.now();
    let Some(dialer) = crate::dialer_ffi::shared() else {
        return SHEKYL_PEERLIST_NO_HUB;
    };
    let mut shared = dialer.shared();
    receive(
        &mut shared.lists,
        row,
        session_of(id),
        entries,
        now,
        &mut HubBans(hub),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_peerlist::NoBans;

    fn v4(n: u8) -> ShekylSeamAddress {
        let mut entry = empty();
        entry.address_type = ADDR_IPV4;
        entry.port = 18080;
        entry.len = 4;
        entry.bytes[..4].copy_from_slice(&[11, 6, 0, n]);
        entry
    }

    fn empty() -> ShekylSeamAddress {
        ShekylSeamAddress {
            connector: 0,
            address_type: 0,
            zone_only: 0,
            _pad: 0,
            port: 0,
            len: 0,
            bytes: [0; shekyl_seam::TOR_HOST_MAX],
        }
    }

    fn session() -> ConnectionId {
        ConnectionId([9; 16])
    }

    fn decide(list: &mut Peerlist, row: Option<ConnectorId>, entries: &[ShekylSeamAddress]) -> i32 {
        receive(list, row, session(), entries, Tick::new(0), &mut NoBans)
    }

    const OUTBOUND: Option<ConnectorId> = Some(ConnectorId::Clearnet);

    #[test]
    fn an_outbound_list_is_admitted() {
        let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
        let entries: Vec<_> = (1..=5).map(v4).collect();
        assert_eq!(
            decide(&mut list, OUTBOUND, &entries),
            SHEKYL_PEERLIST_ADMITTED
        );
        assert_eq!(list.gray_count(ConnectorId::Clearnet), 5);
    }

    /// Every exchange is an exchange (§2.5): the boundary reads the
    /// session's connector and not its direction, so an inbound list is
    /// admitted or refused by the same rules as an outbound one. There is
    /// no inbound answer code any more.
    #[test]
    fn the_boundary_reads_no_direction() {
        let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
        let entries: Vec<_> = (1..=5).map(v4).collect();
        assert_eq!(
            decide(&mut list, OUTBOUND, &entries),
            SHEKYL_PEERLIST_ADMITTED
        );
        assert_eq!(list.gray_count(ConnectorId::Clearnet), 5);
        let too_many: Vec<_> = (0..40).map(v4).collect();
        assert_eq!(
            decide(&mut list, OUTBOUND, &too_many),
            SHEKYL_PEERLIST_REFUSE
        );
        assert_eq!(
            decide(&mut list, OUTBOUND, &[empty()]),
            SHEKYL_PEERLIST_REFUSE
        );
        assert_eq!(list.gray_count(ConnectorId::Clearnet), 5);
    }

    #[test]
    fn a_session_the_board_does_not_hold_admits_nothing_and_is_not_refused() {
        let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
        let entries: Vec<_> = (1..=5).map(v4).collect();
        assert_eq!(
            decide(&mut list, None, &entries),
            SHEKYL_PEERLIST_NO_SESSION
        );
        assert_eq!(list.gray_count(ConnectorId::Clearnet), 0);
    }

    /// Each rule the C++ used to hold, refused from here: the count (D3),
    /// a non-global entry (address validity, R4), a foreign-connector
    /// entry, and an entry that is not an address.
    #[test]
    fn each_refusal_reaches_the_caller_and_admits_nothing() {
        let mut private = v4(1);
        private.bytes[..4].copy_from_slice(&[192, 168, 1, 1]);
        let mut port_zero = v4(2);
        port_zero.port = 0;
        let mut onion = empty();
        onion.address_type = ADDR_TOR;
        onion.port = 18080;
        let host = format!("{:0>56}.onion", 1);
        onion.len = u16::try_from(host.len()).expect("fits");
        onion.bytes[..host.len()].copy_from_slice(host.as_bytes());
        let mut short_v4 = v4(3);
        short_v4.len = 3;

        for (bad, why) in [
            (private, "private address"),
            (port_zero, "port 0"),
            (onion, "onion entry on a clearnet session"),
            (empty(), "an entry the adapter could not encode"),
            (short_v4, "an IPv4 entry of the wrong length"),
        ] {
            let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
            assert_eq!(
                decide(&mut list, OUTBOUND, &[v4(10), bad, v4(11)]),
                SHEKYL_PEERLIST_REFUSE,
                "{why}"
            );
            assert_eq!(list.gray_count(ConnectorId::Clearnet), 0, "{why}");
        }
        let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
        let too_many: Vec<_> = (0..13).map(v4).collect();
        assert_eq!(
            decide(&mut list, OUTBOUND, &too_many),
            SHEKYL_PEERLIST_REFUSE
        );
        let exact: Vec<_> = (0..12).map(v4).collect();
        assert_eq!(
            decide(&mut list, OUTBOUND, &exact),
            SHEKYL_PEERLIST_ADMITTED
        );
    }

    #[test]
    fn the_empty_set_admits_a_private_address_from_a_session() {
        let mut private = v4(1);
        private.bytes[..4].copy_from_slice(&[192, 168, 1, 1]);
        let mut list = Peerlist::new(RefusedSet::EMPTY);
        assert_eq!(
            decide(&mut list, OUTBOUND, &[private]),
            SHEKYL_PEERLIST_ADMITTED
        );
        assert_eq!(list.gray_count(ConnectorId::Clearnet), 1);
    }

    /// The entries reach the lists unaltered and in full: every address
    /// the C++ encoded is the address admitted, all three types.
    #[test]
    fn every_encoded_address_is_the_address_admitted() {
        let mut v6 = empty();
        v6.address_type = ADDR_IPV6;
        v6.port = 28080;
        v6.len = 16;
        let octets = "2a00:1450::7".parse::<Ipv6Addr>().expect("v6").octets();
        v6.bytes[..16].copy_from_slice(&octets);
        assert_eq!(
            address_of(&v6),
            Some(NetworkAddress::Ipv6 {
                ip: Ipv6Addr::from(octets),
                port: 28080
            })
        );
        assert_eq!(
            address_of(&v4(7)),
            Some(NetworkAddress::Ipv4 {
                ip: Ipv4Addr::new(11, 6, 0, 7),
                port: 18080
            })
        );
        let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
        assert_eq!(
            decide(&mut list, OUTBOUND, &[v4(7), v6]),
            SHEKYL_PEERLIST_ADMITTED
        );
        assert!(list.is_gray(&address_of(&v4(7)).expect("v4")));
        assert!(list.is_gray(&address_of(&v6).expect("v6")));
    }

    #[test]
    fn allow_local_ip_returns_what_it_was_given() {
        // The process statics are shared; this test only reads the return.
        let before = refused_set();
        assert!(!shekyl_peerlist_allow_local_ip(false));
        *REFUSED.lock().expect("refused set") = before;
    }
}
