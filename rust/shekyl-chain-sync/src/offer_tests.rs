// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Offers: a seed the slots do not hold, a span that waits for the one
//! before it, and a claim that names the selected tip.

#![cfg(test)]

use std::time::{Duration, Instant};

use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::{AtHeight, HeaderView, RuleSet, Tip, Trust};
use shekyl_levin::PortableMap;
use shekyl_types::{BlockHash, BlockHeight, ChainCount};
use shekyl_wire::{Block, PowBlob};

use crate::model::{CachePlan, Event, Outcome, Proved, Sync};
use crate::proof::{drive, headers_of, open_claim, serialized};
use crate::scenarios::{answer, no_close, offer_tag, request_for, target_one, NoDraw};
use crate::{Command, PeerClaim};

/// A chain of eight, a session whose claim is open, and one block that
/// extends the tip. The block's nonce is the caller's.
fn with_extension<F>(f: F)
where
    F: for<'a, 'id> FnOnce(
        &mut Sync<u8, fn(BlockHeight) -> RuleSet>,
        &shekyl_chain_rules::harness::MockView<'a, 'id>,
        &mut Block,
        Tip,
        u64,
    ),
{
    let main = chain_of(8);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, target_one as fn(BlockHeight) -> RuleSet);
    main.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        drive(&mut sync, &view, Event::Tip { tip });
        open_claim(&mut sync, &view, 1);
        let timestamp = match view.header_at(tip.height).expect("main answers") {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip"),
        };
        block.header.previous = tip.hash;
        block.header.timestamp = timestamp + 120;
        f(&mut sync, &view, &mut block, tip, timestamp);
    });
}

/// A main seed the cache slots do not hold drops the run, keeps the
/// session, and does not issue the same proof again on the same event.
#[test]
fn a_main_seed_not_held_drops_the_run_and_keeps_the_session() {
    with_extension(|sync, view, block, _tip, _timestamp| {
        block.header.nonce = 0;
        let pow = block.pow_blob();
        let hash = PowBlob::read(&pow).expect("preimage").identity();
        let mut out = Vec::new();
        sync.handle(
            Event::Headers {
                session: 1,
                bytes: headers_of(pow),
            },
            view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("main answers");
        let job = out
            .iter()
            .find_map(|command| match command {
                Command::Prove {
                    job,
                    cache: CachePlan::Main(_),
                    ..
                } => Some(*job),
                _ => None,
            })
            .expect("a proof under a main seed");
        let mut out = Vec::new();
        sync.handle(
            Event::Proven {
                job,
                results: vec![Proved::NotHeld],
            },
            view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("main answers");
        no_close(&out);
        assert!(
            !out.iter()
                .any(|command| matches!(command, Command::Prove { .. })),
            "the same plan was issued again on the same event: {out:?}"
        );
        assert_eq!(sync.run_len(1), 0, "the run was dropped");
        assert!(!sync.contains_header(hash), "an unproven header joined T");
        assert!(sync.transit(1).is_some(), "the session is kept");
    });
}

/// A span is offered only once every arrival before it has connected. The
/// entry works each offer apart, so a span whose parent is still with the
/// entry would be unlinked and its bodies fetched again.
#[test]
fn a_span_is_offered_only_after_the_span_before_it_connects() {
    with_extension(|sync, view, block, _tip, timestamp| {
        block.header.nonce = 0;
        let first_raw = serialized(block);
        let first_pow = block.pow_blob();
        let first = PowBlob::read(&first_pow).expect("preimage").identity();
        block.header.previous = first;
        block.header.timestamp = timestamp + 240;
        let second_raw = serialized(block);
        let second_pow = block.pow_blob();
        let second = PowBlob::read(&second_pow).expect("preimage").identity();
        let out = drive(
            sync,
            view,
            Event::Headers {
                session: 1,
                bytes: shekyl_levin::ResponseHeaders {
                    blobs: vec![first_pow, second_pow],
                    tip_work: u128::MAX,
                    more: false,
                }
                .store()
                .expect("the headers encode"),
            },
        );
        assert!(sync.contains_header(second), "{out:?}");
        // One seat: the first body alone.
        let out = drive(sync, view, Event::Room { seats: 1 });
        let (who, asked) = request_for(&out).expect("the first body is wanted");
        assert_eq!(asked, vec![*first.as_bytes()]);
        let out = answer(sync, view, who, first_raw);
        let tag = offer_tag(&out);
        // A seat again before the first connects: the second body is
        // fetched, and held.
        let out = drive(sync, view, Event::Room { seats: 1 });
        let (who, asked) = request_for(&out).expect("the second body is wanted");
        assert_eq!(asked, vec![*second.as_bytes()]);
        let out = answer(sync, view, who, second_raw);
        assert!(
            !out.iter()
                .any(|command| matches!(command, Command::Offer { .. })),
            "the second span was offered over the first: {out:?}"
        );
        // The first connects; the next room offers the second.
        drive(
            sync,
            view,
            Event::Entry {
                tag,
                outcome: Outcome::Connected {
                    height: BlockHeight::from_raw(8),
                },
            },
        );
        let out = drive(sync, view, Event::Room { seats: 1 });
        let offered = out.iter().find_map(|command| match command {
            Command::Offer { arrivals } => Some(arrivals[0].header.hash()),
            _ => None,
        });
        assert_eq!(offered, Some(second), "{out:?}");
    });
}

/// A session whose claim names `H*`'s tip is a body source (CS-F8): it
/// never served a header, and it is not asked for one, since its work does
/// not exceed `H*`'s (CS-Q2 step 1). A claim naming a block this node does
/// not hold makes no source.
#[test]
fn a_claim_naming_the_selected_tip_makes_a_body_source_without_a_header_request() {
    with_extension(|sync, view, block, tip, _timestamp| {
        let pow = block.pow_blob();
        let hash = PowBlob::read(&pow).expect("preimage").identity();
        drive(
            sync,
            view,
            Event::Headers {
                session: 1,
                bytes: headers_of(pow),
            },
        );
        assert_eq!(sync.selected().hash, hash);
        // The supplier leaves before serving the body.
        drive(sync, view, Event::SessionClosed { session: 1 });
        drive(sync, view, Event::Room { seats: 1 });
        let work = sync.selected().work;
        let mut asked = None;
        for (session, top) in [(2u8, BlockHash::from_bytes([9; 32])), (3, hash)] {
            drive(
                sync,
                view,
                Event::SessionOpened {
                    session,
                    transit: Duration::from_secs(1),
                },
            );
            let mut out = Vec::new();
            sync.claim(
                session,
                PeerClaim {
                    count: ChainCount::from_raw(tip.height.to_raw() + 2),
                    work,
                    top,
                },
                view,
                Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .expect("a chain");
            assert!(
                !out.iter()
                    .any(|command| matches!(command, Command::RequestHeaders { .. })),
                "an equal-work session was asked for headers: {out:?}"
            );
            // The claim itself plans the bodies: an idle node has no
            // later event to do it.
            if let Some(request) = request_for(&out) {
                assert!(asked.is_none(), "{out:?}");
                asked = Some(request);
            }
        }
        let (who, asked) = asked.expect("the body is wanted on the claim");
        assert_eq!(who, 3, "the session naming the tip is the source");
        assert_eq!(asked, vec![*hash.as_bytes()]);
    });
}
