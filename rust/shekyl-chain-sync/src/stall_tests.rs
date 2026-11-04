// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The stall surface (CS-5 F5) and the view it is published in (§7). A
//! stall is `Behind`, with nothing moving toward `H*`, because no
//! session's claim or frontier covers what is wanted.

#![cfg(test)]

use std::time::Instant;

use shekyl_chain_rules::HeaderView;
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockCount, BlockHash, ChainCount};

use crate::claim::PeerClaim;
use crate::model::{Event, Sync};
use crate::proof::drive;
use crate::relay_tests::with_two_headers;
use crate::scenarios::{request_for, NoDraw};
use crate::{Command, SessionMode, SyncState};

/// The one supplier of `H*`'s headers closes, and the session left claims
/// less. The node is `Behind`, nothing is asked of anyone, and further
/// events ask for nothing: `stalled()` holds. A session whose claim names
/// `H*` arrives, the stall clears, and the bodies are asked of it.
#[test]
fn the_last_supplier_closing_stalls_and_a_covering_claim_clears_it() {
    with_two_headers(|sync, view, (_, first), (_, second)| {
        let out = drive(sync, view, Event::Room { seats: 1 });
        let (who, asked) = request_for(&out).expect("the first body is wanted");
        assert_eq!((who, asked), (1, vec![*first.as_bytes()]));
        assert!(!sync.stalled(), "a span in flight is not a stall");

        claim(sync, view, 2, 1, 1, BlockHash::NULL);
        let out = drive(sync, view, Event::SessionClosed { session: 1 });
        assert!(
            matches!(sync.state(), SyncState::Behind { .. }),
            "{:?}",
            sync.state()
        );
        assert!(!requests(&out), "{out:?}");
        assert!(sync.stalled(), "nothing covers H* and nothing moves");

        let out = drive(sync, view, Event::Room { seats: 1 });
        assert!(!requests(&out), "a stall asked for something: {out:?}");
        assert!(sync.stalled());

        claim(sync, view, 3, 10, u128::MAX, second);
        assert!(!sync.stalled(), "a claim naming H* did not clear the stall");
        let out = drive(sync, view, Event::Room { seats: 1 });
        let asked_of_three = out
            .iter()
            .any(|command| matches!(command, Command::RequestBodies { session: 3, .. }))
            || sync.peers.get(&3).is_some_and(|peer| peer.span.is_some());
        assert!(
            asked_of_three,
            "the bodies were not asked of the new session: {out:?}"
        );
    });
}

/// A body with the entry is movement toward `H*`: the node is `Behind`
/// and not stalled while the entry's reply is awaited.
#[test]
fn an_arrival_with_the_entry_is_not_a_stall() {
    crate::scenarios::with_offer(|sync, _view, _tag, _hash, _raw| {
        assert!(
            matches!(sync.state(), SyncState::Behind { .. }),
            "{:?}",
            sync.state()
        );
        assert!(!sync.stalled(), "an awaited arrival was read as a stall");
    });
}

/// The view names what moves (§7): the target is `H*`'s count, the span
/// in flight is the first wanted block, and a session's rate is measured
/// once it has answered. When the last supplier closes, the view says
/// stalled and lists no request.
#[test]
fn the_view_shows_the_target_the_span_in_flight_and_the_stall() {
    with_two_headers(|sync, view, _, _| {
        let star = view.tip().expect("main answers").expect("a tip").height;
        let out = drive(sync, view, Event::Room { seats: 1 });
        assert!(request_for(&out).is_some(), "{out:?}");
        let seen = sync.view();
        assert!(matches!(seen.state, SyncState::Behind { .. }), "{seen:?}");
        assert!(!seen.stalled);
        assert_eq!(
            seen.target,
            ChainCount::with_tip(star + BlockCount::from_raw(2)).expect("a count")
        );
        let row = &seen.sessions[0];
        assert_eq!(row.session, 1);
        assert!(row.rate.is_some(), "the headers response was not measured");
        assert_eq!(row.body_requests.len(), 1, "{row:?}");
        let span = row.body_requests[0];
        assert_eq!(span.first, star + BlockCount::ONE);
        assert_eq!(span.count, BlockCount::ONE);
        assert!(span.deadline > span.sent);

        claim(sync, view, 2, 1, 1, BlockHash::NULL);
        drive(sync, view, Event::SessionClosed { session: 1 });
        let seen = sync.view();
        assert!(seen.stalled, "{seen:?}");
        assert_eq!(seen.sessions.len(), 1);
        assert_eq!(seen.sessions[0].mode, SessionMode::Idle);
        assert!(seen.sessions[0].header_request.is_none());
        assert!(seen.sessions[0].body_requests.is_empty());
        assert!(seen.sessions[0].rate.is_none());
    });
}

/// Open `session` and give it a claim of `count` blocks, `work` and `top`.
fn claim<'id, H>(
    sync: &mut Sync<u8, fn(shekyl_types::BlockHeight) -> shekyl_chain_rules::RuleSet>,
    view: &H,
    session: u8,
    count: u64,
    work: u128,
    top: BlockHash,
) where
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
{
    drive(
        sync,
        view,
        Event::SessionOpened {
            session,
            transit: std::time::Duration::from_secs(1),
        },
    );
    let mut out = Vec::new();
    sync.claim(
        session,
        PeerClaim {
            count: ChainCount::from_raw(count),
            work: CumulativeDifficulty::from_raw(work),
            top,
        },
        view,
        Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("the claim is a chain");
}

/// Whether `out` asks anyone for headers or bodies.
fn requests(out: &[Command<u8>]) -> bool {
    out.iter().any(|command| {
        matches!(
            command,
            Command::RequestHeaders { .. } | Command::RequestBodies { .. }
        )
    })
}
