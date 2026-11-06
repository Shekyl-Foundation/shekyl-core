// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the node reads about the network: the session board, one socket's
//! traffic, the link totals, and the peer-list addresses. Nothing here is
//! an RPC document. The node renders those
//! (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1, "RPC facts").

use shekyl_capped_stream::node_gate;
use shekyl_dialer::Dialer;
use shekyl_p2p_session::Board;
use shekyl_peerlist::{ListName, NetworkAddress, Peerlist};
use shekyl_timing_engine::MonotonicClock;
use shekyl_transport_layer::{ConnectorId, Direction, Sockets};

/// Bytes and times the link gate has observed on one socket.
///
/// Times are unix milliseconds. Speeds are whole bytes per second.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketTraffic {
    /// Unix milliseconds of the last byte sent. Zero before any.
    pub last_send_ms: u64,
    /// Unix milliseconds of the last byte received. Zero before any.
    pub last_recv_ms: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub speed_up: u64,
    pub speed_down: u64,
}

/// The link totals since the gate was installed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkTotals {
    pub packets_in: u64,
    pub bytes_in: u64,
    pub packets_out: u64,
    pub bytes_out: u64,
}

/// One peer-list address, which list it sits on, and whether it is banned.
///
/// The address is the list's own value. The RPC's host string and packed
/// IPv4 are the node's rendering of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedAddress {
    pub address: NetworkAddress,
    /// White list. Otherwise gray.
    pub white: bool,
    /// The transport layer bans this host now.
    pub blocked: bool,
}

/// The sockets per connector and direction, and the clearnet list sizes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerCounts {
    pub clearnet_in: u64,
    pub clearnet_out: u64,
    pub tor_in: u64,
    pub tor_out: u64,
    pub white: u64,
    pub gray: u64,
}

/// A count that does not fit the `u64` the RPC reports.
const COUNT_DOES_NOT_FIT: u64 = u64::MAX;

fn count_width(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(COUNT_DOES_NOT_FIT)
}

/// Traffic the link gate holds for `id`.
pub(crate) fn socket_traffic(id: u64) -> SocketTraffic {
    let gate = node_gate();
    let (last_send_ms, last_recv_ms) = gate.activity_unix(id);
    let observed = gate.connection(id);
    let (speed_up, speed_down) = gate.speed(id);
    SocketTraffic {
        last_send_ms,
        last_recv_ms,
        bytes_up: observed.bytes_up,
        bytes_down: observed.bytes_down,
        speed_up,
        speed_down,
    }
}

/// The link totals since the gate was installed.
pub(crate) fn link_totals() -> LinkTotals {
    let observed = node_gate().totals();
    LinkTotals {
        packets_in: observed.packets_down,
        bytes_in: observed.bytes_down,
        packets_out: observed.packets_up,
        bytes_out: observed.bytes_up,
    }
}

/// The peer lists, white then gray, for every connector or clearnet only.
pub(crate) fn listed(dialer: &Dialer<MonotonicClock>, public_only: bool) -> Vec<ListedAddress> {
    let mut rows: Vec<(NetworkAddress, ListName, bool)> = {
        let shared = dialer.shared();
        shared
            .lists
            .snapshot()
            .into_iter()
            .filter(|(address, _)| {
                !public_only || Peerlist::connector_of(address) == Some(ConnectorId::Clearnet)
            })
            .map(|(address, list)| {
                let blocked = shared.lists.is_banned(&address);
                (address, list, blocked)
            })
            .collect()
    };
    rows.sort_by_key(|(_, list, _)| matches!(list, ListName::Gray));
    rows.into_iter()
        .map(|(address, list, blocked)| ListedAddress {
            address,
            white: matches!(list, ListName::White),
            blocked,
        })
        .collect()
}

/// The clearnet white and gray list sizes. White is counted against the
/// addresses the dialer holds, as the disclosure does.
pub(crate) fn clearnet_list_sizes(dialer: &Dialer<MonotonicClock>) -> (u64, u64) {
    let now = dialer.now();
    let (white, gray) = {
        let mut shared = dialer.shared();
        let mut kept = shared.kept_addresses(ConnectorId::Clearnet);
        let white = shared.lists.white_count(
            ConnectorId::Clearnet,
            now,
            &mut kept,
            &mut shekyl_relay::owner::SecureRelayRng,
        );
        let gray = shared.lists.gray_count(ConnectorId::Clearnet);
        (white, gray)
    };
    (count_width(white), count_width(gray))
}

/// The sockets per connector and direction, and the clearnet list sizes.
pub(crate) fn peer_counts(sockets: &Sockets, dialer: &Dialer<MonotonicClock>) -> PeerCounts {
    let (white, gray) = clearnet_list_sizes(dialer);
    PeerCounts {
        clearnet_in: sockets.socket_count(ConnectorId::Clearnet, Direction::Inbound),
        clearnet_out: sockets.socket_count(ConnectorId::Clearnet, Direction::Outbound),
        tor_in: sockets.socket_count(ConnectorId::Tor, Direction::Inbound),
        tor_out: sockets.socket_count(ConnectorId::Tor, Direction::Outbound),
        white,
        gray,
    }
}

/// Established sessions, outbound then inbound.
pub(crate) fn session_counts(board: &Board) -> (u64, u64) {
    (
        count_width(board.established_count(Direction::Outbound)),
        count_width(board.established_count(Direction::Inbound)),
    )
}
