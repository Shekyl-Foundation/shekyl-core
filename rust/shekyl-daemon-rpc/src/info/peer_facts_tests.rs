// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `has_peers` and the connection counts. Both are one read of the board:
//! handshaken sessions, per direction, and offline is a state with neither.

use std::sync::atomic::Ordering;

use super::super::{get_info, Disclosure, FactsFault, RpcFault, StatusConnections};
use super::{ours, synced_facts};
use crate::info_facts::{PeerFacts, SessionCounts};

// ── RK-D14: has_peers ──────────────────────────────────────────────────

/// `has_peers` is a handshaken session in either direction, and
/// nothing else moves it: not the socket counts, not the peerlists.
#[test]
fn has_peers_is_a_handshaken_session_and_nothing_else() {
    for (outbound, inbound, expected) in [
        (0, 0, false),
        (1, 0, true),
        (0, 1, true),
        (8, 12, true),
        (u64::MAX, u64::MAX, true),
    ] {
        let mut facts = synced_facts();
        facts.sessions = SessionCounts { outbound, inbound };
        assert_eq!(
            ours(&facts, Disclosure::FULL)["has_peers"],
            serde_json::json!(expected),
            "{outbound} out, {inbound} in"
        );
    }

    // Sockets open in both directions and a full peerlist, with no
    // session through its handshake: no peer.
    let mut dialing = synced_facts();
    dialing.sessions = SessionCounts::NONE;
    let reply = ours(&dialing, Disclosure::FULL);
    assert_eq!(reply["has_peers"], false);
    assert_eq!(reply["public_outgoing_socket_count"], 10);
    assert_eq!(reply["white_peerlist_size"], 500);

    // No socket counted, one handshaken session: a peer.
    let mut facts = synced_facts();
    let PeerFacts::Running(peers) = &mut facts.peers else {
        unreachable!("the fixture's P2P runs")
    };
    peers.public_incoming_sockets = 0;
    peers.public_outgoing_sockets = 0;
    facts.sessions = SessionCounts {
        outbound: 1,
        inbound: 0,
    };
    assert_eq!(ours(&facts, Disclosure::FULL)["has_peers"], true);
}

// ── RK-Q3: the connection counts ───────────────────────────────────────

/// **The two connection counts are the board's handshaken sessions,
/// per direction, written as they are read** (RK-Q3). Each direction
/// lands in its own member, including the cases the old arithmetic got
/// wrong.
///
/// Until 3.49 the incoming count was a clearnet total from one store
/// minus an outbound count from another, with no common lock, as an
/// unsigned subtraction. A total read a moment before a new outbound
/// session and an outbound count read after it gave `7 - 8`, which the
/// reply carried as 18446744073709551615 incoming connections. There is
/// no subtraction now, so the `(8, 7)` row cannot wrap: it is two
/// counts.
#[test]
fn the_connection_counts_are_the_boards_per_direction() {
    for (outbound, inbound) in [(8, 12), (0, 0), (5, 0), (0, 5), (8, 7), (u64::MAX, 3)] {
        let mut facts = synced_facts();
        facts.sessions = SessionCounts { outbound, inbound };
        let reply = ours(&facts, Disclosure::FULL);
        assert_eq!(
            reply["outgoing_connections_count"],
            serde_json::json!(outbound)
        );
        assert_eq!(
            reply["incoming_connections_count"],
            serde_json::json!(inbound)
        );
    }
}

/// **The invariant: in any reply that shows Status, `has_peers` is
/// exactly "the two connection counts are not both zero"** (RK-Q3 as
/// ruled 2026-10-12). One reply defines a connection once. The counts
/// are handshaken sessions, the same filter as `has_peers` (RK-Q4), so
/// the two cannot disagree: no `has_peers: false` beside a count, and
/// no `has_peers: true` beside two zeros.
///
/// It holds for an offline node too, where all three come from
/// configuration and none from the board. The counts are compared
/// without adding them, so two large counts cannot wrap the check.
///
/// The edit that turns this red is a count that includes a row
/// `has_peers` does not: a socket before its handshake, which an
/// outsider can open for almost nothing.
#[test]
fn has_peers_is_exactly_a_nonzero_connection_count_wherever_status_is_shown() {
    for offline in [false, true] {
        for (outbound, inbound) in [
            (0, 0),
            (1, 0),
            (0, 1),
            (8, 12),
            (u64::MAX, 0),
            (u64::MAX, u64::MAX),
        ] {
            let mut facts = synced_facts();
            facts.chain.offline = offline;
            if offline {
                facts.peers = PeerFacts::Offline;
            }
            facts.sessions = SessionCounts { outbound, inbound };
            let reply = get_info(&facts, Disclosure::FULL, 0).expect("a full caller");
            let status = reply.node.shown().expect("a full caller is shown Status");
            // Offline: no `has_peers` and no counts, both the state. Running:
            // `has_peers` is exactly a nonzero count.
            let expected = match status.connections {
                StatusConnections::Offline => None,
                StatusConnections::Running { outgoing, incoming } => {
                    Some(outgoing > 0 || incoming > 0)
                }
            };
            assert_eq!(
                reply.health.p2p.has_peers(),
                expected,
                "offline {offline}, {outbound} out, {inbound} in: {status:?}"
            );
            assert_eq!(
                matches!(status.connections, StatusConnections::Offline),
                offline,
                "Status's connections are the state offline exactly when Health's are"
            );
        }
    }
}

/// `has_peers` and the two counts are **one** read of the board, so a
/// full caller costs one board read, not two, and the three describe
/// the same snapshot.
#[test]
fn has_peers_and_the_connection_counts_are_one_board_read() {
    let facts = synced_facts();
    get_info(&facts, Disclosure::FULL, 0).expect("a full caller is answered");
    assert_eq!(facts.sessions_reads.load(Ordering::Relaxed), 1);
}

/// **An offline node shown its own Status carries no connection count,
/// and the board is not read** (Rick, 2026-10-14). The node was
/// configured to have no sessions, so the state is the answer: a zero
/// would read as a running node with none.
#[test]
fn an_offline_node_reports_no_connection_count_and_the_board_is_not_read() {
    let mut facts = synced_facts();
    facts.chain.offline = true;
    facts.peers = PeerFacts::Offline;
    facts.sessions_fault = Some(FactsFault::HubAbsent);
    let reply = ours(&facts, Disclosure::FULL);
    let members = reply.as_object().expect("a reply is an object");
    for key in [
        "outgoing_connections_count",
        "incoming_connections_count",
        "has_peers",
    ] {
        assert!(
            !members.contains_key(key),
            "an offline node carries no `{key}`"
        );
    }
    assert_eq!(reply["offline"], true);
    assert_eq!(reply["p2p"], "offline");
    assert_eq!(facts.sessions_reads.load(Ordering::Relaxed), 0);
}

/// **§3.1's defect, at its source.** A restricted caller's reply does
/// not carry the connection counts at all, and says `has_peers: true`,
/// because Health is told to every caller. A reader that asks "does
/// this node have peers" has a member that answers it. Until 3.47 it
/// had only two counts, which a restricted listener wrote as zero.
#[test]
fn a_restricted_reply_from_a_node_with_peers_says_it_has_peers() {
    let reply = ours(&synced_facts(), Disclosure::VIEW);
    assert_eq!(reply["has_peers"], true);
    let members = reply.as_object().expect("a reply is an object");
    assert!(!members.contains_key("outgoing_connections_count"));
    assert!(!members.contains_key("incoming_connections_count"));
    assert_eq!(reply["restricted"], true);

    // And the same member for the host's administrator.
    assert_eq!(ours(&synced_facts(), Disclosure::FULL)["has_peers"], true);
}

/// **An offline node says it is offline, and the board is not asked.**
/// A node started `--offline` binds no hub at all, so the read would
/// return the missing-hub fault and `get_info` would refuse on every
/// offline node. Offline is known from configuration, so the read is
/// not made: the count below is zero reads, with the fault armed to
/// show that nothing consulted it. Health carries `offline: true` and no
/// `has_peers`, for every caller (Rick, 2026-10-14).
///
/// The edits that turn this red: reading the board for an offline
/// node, or writing `has_peers: false` for it.
#[test]
fn an_offline_node_says_so_and_the_board_is_not_read() {
    for fault in [None, Some(FactsFault::HubAbsent)] {
        for disclosure in [Disclosure::VIEW, Disclosure::FULL] {
            let mut facts = synced_facts();
            facts.chain.offline = true;
            facts.peers = PeerFacts::Offline;
            facts.sessions_fault = fault;
            let reply = serde_json::to_value(
                get_info(&facts, disclosure, 0).expect("an offline node answers"),
            )
            .expect("the reply serializes");
            assert_eq!(reply["offline"], true);
            assert!(
                reply.get("has_peers").is_none(),
                "{disclosure:?}: an offline node carries no `has_peers`"
            );
            assert_eq!(
                facts.sessions_reads.load(Ordering::Relaxed),
                0,
                "{disclosure:?}, fault {fault:?}: the board is not read for an offline node"
            );
        }
    }
}

/// **A missing hub refuses; it does not answer `false`** (§4.2). For
/// every caller: Health is everyone's, so there is no caller the fault
/// is not for. Until 3.47 the reply carried zero counts here and status
/// OK.
///
/// The node here is online. That is the state in which a missing hub is
/// a fact nobody has; an offline node is the test above.
#[test]
fn a_missing_hub_refuses_every_caller() {
    let mut facts = synced_facts();
    assert!(!facts.chain.offline, "the fixture is an online node");
    facts.sessions_fault = Some(FactsFault::HubAbsent);
    for disclosure in [Disclosure::VIEW, Disclosure::FULL] {
        assert_eq!(
            get_info(&facts, disclosure, 0),
            Err(RpcFault::Facts(FactsFault::HubAbsent)),
            "{disclosure:?}"
        );
    }
}
