// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! An unsolicited announce proves beside a header run. It does not replace it.

use std::time::{Duration, Instant};

use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::{AtHeight, HeaderView, Trust};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_types::ChainCount;
use shekyl_wire::{BlockBody, PowBlob};

use crate::model::{Event, HashClass, Proved, Sync};
use crate::proof::{fixed, headers_of, prove_item, serialized};
use crate::{Command, PeerClaim};

struct NoDraw;

impl RelayRng for NoDraw {
    fn next_u64(&mut self) -> u64 {
        0
    }
}

/// A header run stays in place while an announce of a sibling block is proved.
#[test]
fn a_header_run_survives_an_announce() {
    let rules = fixed(1, 64);
    let main = chain_of(8);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("main answers");
        sync.handle(
            Event::SessionOpened {
                session: 1,
                transit: Duration::from_secs(1),
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("main answers");
        sync.claim(
            1,
            PeerClaim {
                count: ChainCount::from_raw(2),
                work: CumulativeDifficulty::from_raw(u128::MAX),
                top: shekyl_types::BlockHash::NULL,
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the claim is a chain");
        out.clear();
        let timestamp = match view.header_at(tip.height).expect("main answers") {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip is on main"),
        };
        block.header.previous = tip.hash;
        block.header.timestamp = timestamp + 120;
        block.header.nonce = 0;
        sync.handle(
            Event::Headers {
                session: 1,
                bytes: headers_of(block.pow_blob()),
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("main answers");
        assert_eq!(sync.run_len(1), 1);
        let (header_job, header_item) = out
            .iter()
            .find_map(|command| match command {
                Command::Prove {
                    job,
                    class: HashClass::HeaderPow,
                    items,
                    ..
                } => items.first().map(|item| (*job, item.clone())),
                _ => None,
            })
            .expect("the run asks for a header proof");
        let header_hash = PowBlob::read(&block.pow_blob())
            .expect("preimage")
            .identity();
        let mut sibling = block.clone();
        sibling.header.timestamp = timestamp + 240;
        let announce_hash = PowBlob::read(&sibling.pow_blob())
            .expect("preimage")
            .identity();
        out.clear();
        sync.handle(
            Event::Announce {
                session: 1,
                body: BlockBody {
                    block: serialized(&sibling),
                    txs: Vec::new(),
                    attestation_witness: Vec::new(),
                },
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("main answers");
        assert_eq!(sync.run_len(1), 1, "an announce replaced the header run");
        let (announce_job, announce_item) = out
            .iter()
            .find_map(|command| match command {
                Command::Prove {
                    job,
                    class: HashClass::Unsolicited,
                    items,
                    ..
                } => items.first().map(|item| (*job, item.clone())),
                _ => None,
            })
            .expect("the announce asks for its own proof");
        assert_ne!(header_job, announce_job);
        for (job, item) in [(header_job, header_item), (announce_job, announce_item)] {
            let formed = prove_item(&item).expect("target 1 accepts the header");
            out.clear();
            sync.handle(
                Event::Proven {
                    job,
                    results: vec![Proved::Formed(Box::new(formed))],
                },
                &view,
                Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .expect("main answers");
        }
        assert!(sync.contains_header(header_hash));
        assert!(sync.contains_header(announce_hash));
        assert_eq!(sync.run_len(1), 1);
    });
}

/// Block ids of each header request, in the order the commands were emitted.
type HeaderAsks = Vec<Vec<[u8; 32]>>;

fn header_requests(out: &[Command<u8>]) -> HeaderAsks {
    out.iter()
        .filter_map(|command| match command {
            Command::RequestHeaders {
                session: 1,
                request,
                ..
            } => Some(request.block_ids.clone()),
            _ => None,
        })
        .collect()
}

/// Announce a block whose parent is not the local tip, and return the
/// header requests from the claim through that announcement, then from a
/// second announcement. `heavier` is a claim that already beats `H*`;
/// otherwise the claim names this tip at its work.
fn unplaced_announcements(heavier: bool) -> (HeaderAsks, HeaderAsks) {
    let rules = fixed(1, 64);
    let main = chain_of(8);
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    let mut first = Vec::new();
    let mut second = Vec::new();
    main.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        let tip_work = match view.header_at(tip.height).expect("main answers") {
            AtHeight::Recorded(record) => record.cumulative_difficulty,
            AtHeight::AboveTip => panic!("the tip is on main"),
        };
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("main answers");
        sync.handle(
            Event::SessionOpened {
                session: 1,
                transit: Duration::from_secs(1),
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("main answers");
        sync.claim(
            1,
            PeerClaim {
                count: ChainCount::with_tip(tip.height).expect("a tip"),
                work: if heavier {
                    CumulativeDifficulty::from_raw(u128::MAX)
                } else {
                    tip_work
                },
                top: tip.hash,
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the claim is a chain");
        first = header_requests(&out);
        out.clear();
        let mut block = candidate_on(&main, Vec::new()).block;
        block.header.previous = shekyl_types::BlockHash::from_bytes([0xAB; 32]);
        let body = BlockBody {
            block: serialized(&block),
            txs: Vec::new(),
            attestation_witness: Vec::new(),
        };
        let announce = |sync: &mut Sync<u8, _>, out: &mut Vec<Command<u8>>| {
            sync.handle(
                Event::Announce {
                    session: 1,
                    body: body.clone(),
                },
                &view,
                Instant::now(),
                &mut NoDraw,
                out,
            )
            .expect("main answers");
        };
        announce(&mut sync, &mut out);
        first.extend(header_requests(&out));
        out.clear();
        announce(&mut sync, &mut out);
        second = header_requests(&out);
    });
    (first, second)
}

/// The supplier's claim still names our tip, so nothing else will ask it
/// for headers. The announcement is the only signal that its chain moved,
/// and one follow-up is enough until that request is answered.
#[test]
fn an_unplaced_announcement_from_an_equal_tip_asks_for_headers_once() {
    let (first, second) = unplaced_announcements(false);
    assert_eq!(
        first.len(),
        1,
        "no header request for an unknown parent: {first:?}"
    );
    assert!(
        second.is_empty(),
        "a second announcement asked again while the follow-up was out: {second:?}"
    );
}

/// A claim that already beats `H*` is plan's extending request. The
/// unplaced announcement must not add a second one.
#[test]
fn an_unplaced_announcement_from_a_heavier_claim_asks_once() {
    let (first, second) = unplaced_announcements(true);
    assert_eq!(
        first.len(),
        1,
        "a heavier claim and the announcement asked twice: {first:?}"
    );
    assert!(
        second.is_empty(),
        "a second announcement asked again: {second:?}"
    );
}
