// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `peered` and the connection counts. Both are one read of the board:
//! handshaken sessions, per direction, and offline is a state with neither.

use std::sync::atomic::Ordering;

use super::super::{Disclosure, FactsFault, RpcFault};
use super::{ours, status, synced_facts, with_sockets};
use crate::info_facts::{PeerFacts, SessionCounts};
use shekyl_rpc_types::kinds::Count;
use shekyl_rpc_types::nullable::Nullable;

// ── RK-D14: peered ─────────────────────────────────────────────────────

/// `peered` is a handshaken session in either direction, and nothing else
/// moves it: not the socket counts, not the peer lists.
#[test]
fn peered_is_a_handshaken_session_and_nothing_else() {
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
            ours(&facts, Disclosure::FULL)["peered"],
            serde_json::json!(expected),
            "{outbound} out, {inbound} in"
        );
    }

    // Sockets open both ways and a full list, no session through its
    // handshake: no peer.
    let mut dialing = synced_facts();
    dialing.sessions = SessionCounts::NONE;
    let reply = ours(&dialing, Disclosure::FULL);
    assert_eq!(reply["peered"], false);
    assert_eq!(reply["connector"]["clearnet"]["outbound_count"], 10);
    assert_eq!(reply["connector"]["clearnet"]["peer_white_count"], 500);

    // No socket counted, one handshaken session: a peer.
    let mut facts = synced_facts();
    facts.peers = with_sockets(&facts.peers, 0, 0);
    facts.sessions = SessionCounts {
        outbound: 1,
        inbound: 0,
    };
    assert_eq!(ours(&facts, Disclosure::FULL)["peered"], true);
}

// ── RK-Q3: the connection counts ───────────────────────────────────────

/// **The two connection counts are the board's handshaken sessions, per
/// direction, written as read** (RK-Q3): no subtraction, so no wrap.
#[test]
fn the_connection_counts_are_the_boards_per_direction() {
    for (outbound, inbound) in [(8, 12), (0, 0), (5, 0), (0, 5), (8, 7), (u64::MAX, 3)] {
        let mut facts = synced_facts();
        facts.sessions = SessionCounts { outbound, inbound };
        let reply = ours(&facts, Disclosure::FULL);
        assert_eq!(reply["peer_outbound_count"], serde_json::json!(outbound));
        assert_eq!(reply["peer_inbound_count"], serde_json::json!(inbound));
    }
}

/// **In any reply that shows Status, `peered` is exactly "the two counts
/// are not both zero"** (RK-Q3, 2026-10-12), and an offline node has
/// neither: all three `null`. The edit that turns this red is a count that
/// includes a row `peered` does not.
#[test]
fn peered_is_exactly_a_nonzero_connection_count_wherever_status_is_shown() {
    for offline in [false, true] {
        for (outbound, inbound) in [(0, 0), (1, 0), (0, 1), (8, 12), (u64::MAX, u64::MAX)] {
            let mut facts = synced_facts();
            facts.chain.offline = offline;
            if offline {
                facts.peers = PeerFacts::Offline;
            }
            facts.sessions = SessionCounts { outbound, inbound };
            let reply = status(&facts, Disclosure::FULL, 0).expect("a full caller");
            let out = reply.peer_outbound_count.shown().expect("Status");
            let inb = reply.peer_inbound_count.shown().expect("Status");
            let expected = match (out, inb) {
                (Nullable(Some(Count(o))), Nullable(Some(Count(i)))) => Some(o > 0 || i > 0),
                (Nullable(None), Nullable(None)) => None,
                other => panic!("one count without the other: {other:?}"),
            };
            assert_eq!(reply.peered.0, expected, "offline {offline}");
            assert_eq!(expected.is_none(), offline);
        }
    }
}

/// `peered` and the counts are **one** board read.
#[test]
fn peered_and_the_connection_counts_are_one_board_read() {
    let facts = synced_facts();
    status(&facts, Disclosure::FULL, 0).expect("a full caller is answered");
    assert_eq!(facts.sessions_reads.load(Ordering::Relaxed), 1);
}

/// **§3.1's defect, at its source.** A view caller's reply carries no
/// connection count at all and says `peered: true`, because Health is
/// told to every caller.
#[test]
fn a_view_reply_from_a_node_with_peers_says_it_is_peered() {
    let reply = ours(&synced_facts(), Disclosure::VIEW);
    assert_eq!(reply["peered"], true);
    let members = reply.as_object().expect("a reply is an object");
    assert!(!members.contains_key("peer_outbound_count"));
    assert!(!members.contains_key("peer_inbound_count"));
}

/// **An offline node says it is offline, and the board is not asked**, for
/// every caller (Rick, 2026-10-14). The edits that turn this red: reading
/// the board for an offline node, or writing `peered: false` for it.
#[test]
fn an_offline_node_says_so_and_the_board_is_not_read() {
    for fault in [None, Some(FactsFault::Internal)] {
        for disclosure in [Disclosure::VIEW, Disclosure::FULL] {
            let mut facts = synced_facts();
            facts.chain.offline = true;
            facts.peers = PeerFacts::Offline;
            facts.sessions_fault = fault;
            let reply = ours(&facts, disclosure);
            assert_eq!(reply["offline"], true);
            assert!(reply["peered"].is_null(), "{disclosure:?}");
            assert_eq!(facts.sessions_reads.load(Ordering::Relaxed), 0);
        }
    }
}

/// **A board that cannot be read refuses every caller**; it does not answer
/// `false` (§4.2).
#[test]
fn an_unreadable_board_refuses_every_caller() {
    let mut facts = synced_facts();
    assert!(!facts.chain.offline, "the fixture is an online node");
    facts.sessions_fault = Some(FactsFault::Internal);
    for disclosure in [Disclosure::VIEW, Disclosure::FULL] {
        assert_eq!(
            status(&facts, disclosure, 0),
            Err(RpcFault::Facts(FactsFault::Internal)),
            "{disclosure:?}"
        );
    }
}
