// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owner's reply conversion and its serving queue. The owner end to
//! end is the loopback harness's (`shekyl-p2p-harness`,
//! `tests/chain_sync_loopback.rs`).

use shekyl_chain_ingest::service::{ArrivalTag, CannotFollow, Refusal, Reply};
use shekyl_chain_ingest::PopBeyondReorgCap;
use shekyl_chain_rules::{CenRow, InvalidBlock, Locus};
use shekyl_levin::{RequestBodies, RequestHeaders};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};

use super::{ServeRequest, Serving};
use crate::outcome::{of_refusal, of_reply};
use shekyl_chain_sync::{Outcome, SyncState};

/// A refused offer reaches the model as the outcome its refusal names. A
/// dry bucket is `Throttled`, never `NoRoom`: the model takes the seat back
/// and asks for the body (2026-11-02, a node `behind` with every offer
/// throttled, each frozen as `NoRoom`). A bound span takes no token since
/// the same day (`shekyl_chain_ingest::service::BoundArrival`), and the
/// owner forgets its sampled room after any `NoRoom`, so a seat report
/// follows every refusal that waits for one ([`super::Owner::offer`]).
#[test]
fn every_door_refusal_has_an_outcome() {
    let cases = [
        (Refusal::NoRoom, true, 10, Some(100), Outcome::NoRoom),
        (Refusal::Throttled, true, 10, Some(100), Outcome::Throttled),
        (Refusal::Throttled, false, 10, None, Outcome::Throttled),
        (
            Refusal::StoreUnreadable,
            true,
            10,
            Some(100),
            Outcome::StoreUnreadable,
        ),
        (
            Refusal::Oversize,
            true,
            101,
            Some(100),
            Outcome::Oversize { invalidate: true },
        ),
        (
            Refusal::Oversize,
            false,
            101,
            Some(100),
            Outcome::Oversize { invalidate: false },
        ),
        (Refusal::Oversize, true, 100, Some(100), Outcome::Again),
        (Refusal::Oversize, true, 101, None, Outcome::Again),
    ];
    for (refusal, solicited, bytes, max, expected) in cases {
        assert_eq!(
            of_refusal(refusal, solicited, bytes, max),
            expected,
            "{refusal:?} solicited={solicited} bytes={bytes} max={max:?}"
        );
    }
}

#[test]
fn every_entry_reply_has_an_outcome() {
    let verdict = InvalidBlock::new(CenRow::B2, Locus::Block);
    let hash = BlockHash::from_bytes([7; 32]);
    let cases = [
        (
            Reply::Connected {
                height: BlockHeight::ZERO,
                hash,
            },
            Outcome::Connected {
                height: BlockHeight::ZERO,
            },
        ),
        (Reply::Refused(verdict), Outcome::Refused { verdict }),
        (Reply::Unlinked { at: hash }, Outcome::Unlinked { at: hash }),
        (Reply::AlreadyHeld, Outcome::Noted),
        (
            Reply::Held {
                height: BlockHeight::ZERO,
            },
            Outcome::Noted,
        ),
        (
            Reply::PromotionRefused {
                at: BlockHeight::ZERO,
                hash,
                refused: verdict,
            },
            Outcome::PromotionRefused {
                verdict,
                block: hash,
            },
        ),
        (
            Reply::MissingBodies {
                hash,
                indices: vec![1, 3],
            },
            Outcome::MissingBodies {
                indices: vec![1, 3],
            },
        ),
        (Reply::Cancelled { by: ArrivalTag(4) }, Outcome::Again),
        (Reply::Stopped, Outcome::Again),
        (
            Reply::BeyondCap(PopBeyondReorgCap {
                depth: BlockCount::ONE,
                cap: BlockCount::ONE,
            }),
            Outcome::BeyondCap,
        ),
        (
            Reply::Switched {
                demoted: Vec::new(),
                promoted: Vec::new(),
            },
            Outcome::Noted,
        ),
        (
            Reply::Switched {
                demoted: vec![(BlockHeight::from_raw(7), BlockHash::from_bytes([8; 32]))],
                promoted: vec![
                    (BlockHeight::from_raw(7), BlockHash::from_bytes([9; 32])),
                    (BlockHeight::from_raw(8), hash),
                ],
            },
            Outcome::Connected {
                height: BlockHeight::from_raw(8),
            },
        ),
        (
            Reply::CannotFollow(CannotFollow::BelowFloor {
                tip: BlockHeight::ZERO,
                floor: BlockHeight::ZERO,
            }),
            Outcome::Noted,
        ),
    ];
    for (reply, expected) in cases {
        assert_eq!(
            of_reply(reply.clone(), true, Some(hash)),
            expected,
            "{reply:?}"
        );
    }
}

/// A connect carries the height the block took, whether the body was
/// requested or announced: the relay is the model's to decide.
#[test]
fn a_connect_carries_its_height_however_the_body_arrived() {
    let height = BlockHeight::from_raw(12);
    let connected = Reply::Connected {
        height,
        hash: BlockHash::from_bytes([3; 32]),
    };
    assert_eq!(
        of_reply(
            connected.clone(),
            false,
            Some(BlockHash::from_bytes([3; 32]))
        ),
        Outcome::Connected { height }
    );
    assert_eq!(
        of_reply(connected, true, None),
        Outcome::Connected { height }
    );
}

/// A switch is a connect only when this arrival is the new tip. The model
/// then relays it by the connect's rule. Any other tip, an empty promotion,
/// or an offer the owner no longer holds, is noted.
#[test]
fn a_switch_is_a_connect_only_when_the_arrival_is_the_new_tip() {
    let arrival = BlockHash::from_bytes([7; 32]);
    let height = BlockHeight::from_raw(8);
    let switched = |tip: BlockHash| Reply::Switched {
        demoted: vec![(BlockHeight::from_raw(7), BlockHash::from_bytes([8; 32]))],
        promoted: vec![
            (BlockHeight::from_raw(7), BlockHash::from_bytes([9; 32])),
            (height, tip),
        ],
    };
    assert_eq!(
        of_reply(switched(arrival), true, Some(arrival)),
        Outcome::Connected { height }
    );
    assert_eq!(
        of_reply(switched(arrival), false, Some(arrival)),
        Outcome::Connected { height }
    );
    assert_eq!(
        of_reply(
            switched(BlockHash::from_bytes([9; 32])),
            true,
            Some(arrival)
        ),
        Outcome::Noted
    );
    assert_eq!(of_reply(switched(arrival), true, None), Outcome::Noted);
    assert_eq!(
        of_reply(
            Reply::Switched {
                demoted: Vec::new(),
                promoted: Vec::new(),
            },
            true,
            Some(arrival),
        ),
        Outcome::Noted
    );
}

/// A session's queue holds at most one waiting request of each kind,
/// however many arrive while one is served: a later request replaces the
/// waiting one of its kind, in its place, and the other kind keeps its own.
#[test]
fn a_session_holds_one_waiting_request_of_each_kind() {
    let headers = |byte: u8| {
        ServeRequest::Headers(RequestHeaders {
            block_ids: vec![[byte; 32]],
        })
    };
    let mut serving = Serving {
        busy: true,
        ..Serving::default()
    };
    assert!(!serving.push(headers(0)));
    assert!(!serving.push(ServeRequest::Bodies(RequestBodies {
        hashes: vec![[9; 32]],
    })));
    for byte in 1..=64 {
        assert!(serving.push(headers(byte)), "request {byte} replaces");
    }
    assert_eq!(serving.queue.len(), 2);
    match &serving.queue[0] {
        ServeRequest::Headers(request) => assert_eq!(request.block_ids, vec![[64; 32]]),
        ServeRequest::Bodies(_) | ServeRequest::MissingTxs(_) => {
            panic!("the header request keeps its place")
        }
    }
    assert!(
        matches!(&serving.queue[1], ServeRequest::Bodies(request) if request.hashes == vec![[9; 32]])
    );
}

/// The node keeps its sender, so the owner's exit cannot close the watch.
/// The task publishes `NoView` instead, which is what facts and the
/// follower would have read from a closed watch. The same guard reports
/// how the task ended: the cause an exit set, or a panic when none did.
#[test]
fn an_owner_exit_publishes_no_view_and_reports_how_it_ended() {
    let (node, seen) = tokio::sync::watch::channel(SyncState::Synced);
    let (ended_tx, ended) = tokio::sync::watch::channel(None);
    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    let mut live = super::EndGuard {
        state: node.clone(),
        ended: ended_tx.clone(),
        stop: stop.clone(),
        how: super::Ended::Failed(super::PANICKED),
    };
    assert_eq!(*node.borrow(), SyncState::Synced);
    assert_eq!(*ended.borrow(), None, "a running owner has not ended");
    live.how = super::Ended::Failed(super::ROUTER_CLOSED);
    drop(live);
    assert_eq!(*node.borrow(), SyncState::NoView);
    assert_eq!(*seen.borrow(), SyncState::NoView);
    assert!(
        seen.has_changed().is_ok(),
        "the node's sender was dropped with the owner"
    );
    assert_eq!(
        *ended.borrow(),
        Some(super::Ended::Failed(super::ROUTER_CLOSED))
    );
    // An unwind runs the guard with no exit's cause set: a panic.
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = super::EndGuard {
            state: node.clone(),
            ended: ended_tx.clone(),
            stop: stop.clone(),
            how: super::Ended::Failed(super::PANICKED),
        };
        panic!("the owner's task");
    }));
    assert!(unwound.is_err());
    assert_eq!(*ended.borrow(), Some(super::Ended::Failed(super::PANICKED)));
    // A task cancelled after a stop was asked (the owner's runtime shut
    // down under it) ended by the stop, not by a failure.
    stop_tx.send_replace(true);
    drop(super::EndGuard {
        state: node.clone(),
        ended: ended_tx,
        stop,
        how: super::Ended::Failed(super::PANICKED),
    });
    assert_eq!(*ended.borrow(), Some(super::Ended::Stopped));
}
