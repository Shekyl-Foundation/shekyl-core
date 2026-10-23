// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owner's reply conversion. The owner end to end is the loopback
//! harness's (`tests/loopback.rs`).

use shekyl_chain_ingest::service::{ArrivalTag, Reply};
use shekyl_chain_rules::{CenRow, InvalidBlock, Locus};
use shekyl_types::{BlockHash, BlockHeight};

use super::outcome_of;
use crate::Outcome;

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
            Outcome::Connected { relay: false },
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

/// An announced body's connect is a relay; a requested body's is not.
#[test]
fn an_announced_connect_is_relayed_and_a_requested_one_is_not() {
    let connected = Reply::Connected {
        height: BlockHeight::ZERO,
        hash: BlockHash::from_bytes([3; 32]),
    };
    assert_eq!(
        outcome_of(connected.clone(), false),
        Some(Outcome::Connected { relay: true })
    );
    assert_eq!(
        outcome_of(connected, true),
        Some(Outcome::Connected { relay: false })
    );
}
