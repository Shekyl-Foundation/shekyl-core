// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A response from `H*` that yields nothing, and children whose parent
//! main popped. Both were seen on the rehearsal fleet on 2026-11-02 as
//! one node asking the same peer for the same headers every millisecond:
//! the children sat in `T` under a parent main had popped, the parent
//! came back as a tip over them, nothing heavier was reachable, and every
//! answer was already held. Since 2026-11-03 the children leave `T` with
//! their anchor (`HeaderTree::drop_orphans`) and are served again above
//! the parent.

#![cfg(test)]

use std::time::Duration;

use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of, recorded, root};
use shekyl_chain_rules::harness::MockChain;
use shekyl_chain_rules::{AtHeight, HeaderView, RuleSet, Trust};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_levin::PortableMap;
use shekyl_types::{BlockHash, BlockHeight, ChainCount};
use shekyl_wire::PowBlob;

use crate::model::{Event, Sync};
use crate::proof::{drive, open_claim};
use crate::scenarios::{target_one, NoDraw};
use crate::{CloseCause, Command, PeerClaim, Spent};

type Model = Sync<u8, fn(BlockHeight) -> RuleSet>;

fn response(blobs: &[Vec<u8>], more: bool) -> Vec<u8> {
    stating(blobs, more, u128::MAX)
}

/// A response whose `tip_work` is `work`: the peer's statement of its
/// own chain, which replaces its claim (CS-Q2 step 1).
fn stating(blobs: &[Vec<u8>], more: bool, work: u128) -> Vec<u8> {
    shekyl_levin::ResponseHeaders {
        blobs: blobs.to_vec(),
        tip_work: work,
        more,
    }
    .store()
    .expect("the headers encode")
}

/// Three headers extending `main`'s tip, oldest first, with their hashes.
fn three_above(main: &MockChain) -> (Vec<Vec<u8>>, Vec<BlockHash>) {
    let mut block = candidate_on(main, Vec::new()).block;
    main.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        let mut when = match view.header_at(tip.height).expect("main answers") {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip is on main"),
        };
        let mut previous = tip.hash;
        let mut pows = Vec::new();
        let mut hashes = Vec::new();
        for _ in 0..3 {
            block.header.previous = previous;
            when += 120;
            block.header.timestamp = when;
            let pow = block.pow_blob();
            previous = PowBlob::read(&pow).expect("preimage").identity();
            hashes.push(previous);
            pows.push(pow);
        }
        (pows, hashes)
    })
}

fn headers_asked(out: &[Command<u8>], session: u8) -> Vec<Vec<[u8; 32]>> {
    out.iter()
        .filter_map(|command| match command {
            Command::RequestHeaders {
                session: who,
                request,
                ..
            } if *who == session => Some(request.block_ids.clone()),
            _ => None,
        })
        .collect()
}

/// Session 1 serves the three headers into `T` and leaves; `H*` is the
/// third. Session 2 is open with a claim above it and has been asked.
fn primed(main: &MockChain, pows: &[Vec<u8>]) -> Model {
    let mut sync: Model = Sync::new(Trust::UNPINNED, target_one);
    main.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        drive(&mut sync, &view, Event::Tip { tip });
        open_claim(&mut sync, &view, 1);
        drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 1,
                bytes: response(pows, false),
            },
        );
        drive(&mut sync, &view, Event::SessionClosed { session: 1 });
        open_claim(&mut sync, &view, 2);
    });
    sync
}

/// A peer whose answer from `H*` is headers `T` already holds, and no
/// more, stating the work of the chain it served, is not asked from `H*`
/// again: `T` did not change, so the same locator would get the same
/// page. The record is `HeadersSpent`. A new claim from that peer draws
/// it again.
#[test]
fn an_answer_already_held_spends_the_session_until_its_claim_changes() {
    let main = chain_of(8);
    let (pows, hashes) = three_above(&main);
    let mut sync = primed(&main, &pows);
    assert_eq!(sync.selected().hash, hashes[2]);
    let served = sync.selected().work.to_raw();
    main.with_view(|view| {
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 2,
                bytes: stating(&pows, false, served),
            },
        );
        assert!(
            out.iter().any(|command| matches!(
                command,
                Command::HeadersSpent {
                    session: 2,
                    cause: Spent::Exhausted,
                }
            )),
            "{out:?}"
        );
        assert!(
            headers_asked(&out, 2).is_empty(),
            "the same locator was sent again: {out:?}"
        );
        // Another event: the plan runs again and still does not draw it.
        let out = drive(
            &mut sync,
            &view,
            Event::SessionOpened {
                session: 3,
                transit: Duration::from_secs(1),
            },
        );
        assert!(headers_asked(&out, 2).is_empty(), "{out:?}");
        // The peer's claim moves: it is a source again.
        let mut out = Vec::new();
        sync.claim(
            2,
            PeerClaim {
                count: ChainCount::from_raw(3),
                work: CumulativeDifficulty::from_raw(u128::MAX - 1),
                top: BlockHash::NULL,
            },
            &view,
            std::time::Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the claim is a chain");
        assert_eq!(headers_asked(&out, 2).len(), 1, "{out:?}");
    });
}

/// A peer whose answer from `H*` is headers `T` already holds, and no
/// more, while stating more work than that chain has, is the liar: closed
/// at `ClaimUnmet`, not spent. The gate that spends an exhausted peer
/// first spent the liar too, and it kept its session (2026-11-02, the
/// loopback `the_liar_closes_at_claim_unmet`).
#[test]
fn an_answer_already_held_below_the_stated_work_closes_at_claim_unmet() {
    let main = chain_of(8);
    let (pows, hashes) = three_above(&main);
    let mut sync = primed(&main, &pows);
    assert_eq!(sync.selected().hash, hashes[2]);
    let served = sync.selected().work.to_raw();
    main.with_view(|view| {
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 2,
                bytes: stating(&pows, false, served + 1),
            },
        );
        assert!(
            out.iter().any(|command| matches!(
                command,
                Command::Close {
                    session: 2,
                    cause: CloseCause::ClaimUnmet,
                }
            )),
            "{out:?}"
        );
        assert!(
            !out.iter()
                .any(|command| matches!(command, Command::HeadersSpent { .. })),
            "{out:?}"
        );
    });
}

/// A peer that serves nothing above the locator, and no more, stating
/// more work than `H*` has, is the liar too: its tip is a locator hash,
/// none of which outweighs `H*`.
#[test]
fn an_empty_answer_below_the_stated_work_closes_at_claim_unmet() {
    let main = chain_of(8);
    let (pows, hashes) = three_above(&main);
    let mut sync = primed(&main, &pows);
    assert_eq!(sync.selected().hash, hashes[2]);
    let star = sync.selected().work.to_raw();
    main.with_view(|view| {
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 2,
                bytes: stating(&[], false, star + 1),
            },
        );
        assert!(
            out.iter().any(|command| matches!(
                command,
                Command::Close {
                    session: 2,
                    cause: CloseCause::ClaimUnmet,
                }
            )),
            "{out:?}"
        );
        // Stating exactly `H*`'s work, the same answer is exhaustion.
        open_claim(&mut sync, &view, 3);
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 3,
                bytes: stating(&[], false, star),
            },
        );
        assert!(
            out.iter().any(|command| matches!(
                command,
                Command::HeadersSpent {
                    session: 3,
                    cause: Spent::Exhausted,
                }
            )),
            "{out:?}"
        );
    });
}

/// A peer whose answer from `H*` is headers `T` already holds, with more
/// to come, is asked to continue from the last header it served, not
/// from `H*` again.
#[test]
fn an_answer_already_held_with_more_continues_from_its_last_header() {
    let main = chain_of(8);
    let (pows, hashes) = three_above(&main);
    let mut sync = primed(&main, &pows);
    main.with_view(|view| {
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 2,
                bytes: response(&pows[..2], true),
            },
        );
        assert_eq!(
            headers_asked(&out, 2),
            vec![vec![*hashes[1].as_bytes()]],
            "{out:?}"
        );
        assert!(
            !out.iter()
                .any(|command| matches!(command, Command::HeadersSpent { .. })),
            "{out:?}"
        );
    });
}

/// `T` holds `h+1` and `h+2` above a block `h` main has connected. Main
/// pops `h`: their anchor is off main, so the two leave `T` with it, and
/// `H*` is main's tip. A peer serves `h` again: it is the one header in
/// `T` and `H*`. The peer then serves `h+1` and `h+2` above it, and `H*`
/// is `h+2`.
///
/// Until 2026-11-03 the two stayed in `T` as an orphaned branch and `h`,
/// served again, adopted them. That held only while the page stopped at
/// `h`: a page that went on to `h+1` met a held header after a new one
/// and closed the session, every time
/// (`switch_orphan_tests`).
#[test]
fn children_of_a_popped_block_leave_t_and_are_served_again_above_it() {
    let main = chain_of(8);
    let (pows, hashes) = three_above(&main);
    let mut sync: Model = Sync::new(Trust::UNPINNED, target_one);
    main.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        drive(&mut sync, &view, Event::Tip { tip });
        open_claim(&mut sync, &view, 1);
        drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 1,
                bytes: response(&pows, false),
            },
        );
        drive(&mut sync, &view, Event::SessionClosed { session: 1 });
    });
    assert_eq!(sync.header_count(), 3);
    assert_eq!(sync.selected().hash, hashes[2]);

    // Main connects `h`: it leaves `T`, and its children's branch hangs
    // off main.
    let mut eighth = recorded(0);
    eighth.header = sync.header_record(hashes[0]).expect("h is in T");
    let longer = main.clone().push(eighth, root(9));
    longer.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        assert_eq!(tip.hash, hashes[0]);
        drive(&mut sync, &view, Event::Tip { tip });
    });
    assert_eq!(sync.header_count(), 2);
    assert!(!sync.contains_header(hashes[0]));
    assert_eq!(sync.selected().hash, hashes[2]);

    // Main pops `h`. The children's anchor is off main: they leave `T`,
    // and `H*` is the tip.
    main.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        drive(&mut sync, &view, Event::Tip { tip });
        assert_eq!(sync.selected().hash, tip.hash);
        assert_eq!(sync.header_count(), 0, "the orphaned branch left T");

        // A peer serves `h` from main's tip: the one header in `T`.
        open_claim(&mut sync, &view, 2);
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 2,
                bytes: response(&pows[..1], true),
            },
        );
        assert_eq!(sync.header_count(), 1);
        assert_eq!(sync.selected().hash, hashes[0], "{out:?}");
        assert_eq!(
            headers_asked(&out, 2),
            vec![vec![*hashes[0].as_bytes()]],
            "the peer is asked on from h: {out:?}"
        );

        // It serves `h+1` and `h+2` above `h`, which are new again.
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 2,
                bytes: response(&pows[1..], false),
            },
        );
        assert_eq!(sync.header_count(), 3);
        assert_eq!(sync.selected().hash, hashes[2], "{out:?}");
    });
}
