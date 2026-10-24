// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owner's reply conversion and its serving queue. The owner end to
//! end is the loopback harness's (`shekyl-p2p-harness`,
//! `tests/chain_sync_loopback.rs`).

use shekyl_chain_ingest::service::{ArrivalTag, Reply};
use shekyl_chain_rules::{CenRow, InvalidBlock, Locus};
use shekyl_levin::{RequestBodies, RequestHeaders};
use shekyl_types::{BlockHash, BlockHeight};

use super::{outcome_of, ServeRequest, Serving};
use shekyl_chain_sync::Outcome;

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
                indices: vec![1, 3],
            },
            Outcome::MissingBodies {
                indices: vec![1, 3],
            },
        ),
        (Reply::Cancelled { by: ArrivalTag(4) }, Outcome::Again),
        (Reply::Stopped, Outcome::Again),
    ];
    for (reply, expected) in cases {
        assert_eq!(outcome_of(reply.clone(), true), Some(expected), "{reply:?}");
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
        outcome_of(connected.clone(), false),
        Some(Outcome::Connected { height })
    );
    assert_eq!(
        outcome_of(connected, true),
        Some(Outcome::Connected { height })
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
        ServeRequest::Bodies(_) => panic!("the header request keeps its place"),
    }
    assert!(
        matches!(&serving.queue[1], ServeRequest::Bodies(request) if request.hashes == vec![[9; 32]])
    );
}
