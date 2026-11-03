// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A new `H*` withdraws the header request in flight: its locator is
//! stale. The peer still owes that request its answer, and sends it. The
//! answer is to a request this node made, so it is not the peer's fault;
//! it is discarded, and the next answer is judged against the request that
//! replaced it.

#![cfg(test)]

use std::time::{Duration, Instant};

use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::{AtHeight, HeaderRecord, HeaderView, Trust};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_levin::PortableMap;
use shekyl_types::{BlockHash, BlockHeight, ChainCount};
use shekyl_wire::{Block, PowBlob};

use crate::model::{CloseCause, Event, Sync};
use crate::proof::fixed;
use crate::scenarios::Prefix;
use crate::{Command, PeerClaim};

struct NoDraw;

impl RelayRng for NoDraw {
    fn next_u64(&mut self) -> u64 {
        0
    }
}

fn response(blobs: &[Vec<u8>], tip_work: u128, more: bool) -> Vec<u8> {
    shekyl_levin::ResponseHeaders {
        blobs: blobs.to_vec(),
        tip_work,
        more,
    }
    .store()
    .expect("the headers encode")
}

fn closes(out: &[Command<u8>]) -> Vec<&CloseCause> {
    out.iter()
        .filter_map(|command| match command {
            Command::Close { cause, .. } => Some(cause),
            _ => None,
        })
        .collect()
}

fn requests(out: &[Command<u8>]) -> Vec<u64> {
    out.iter()
        .filter_map(|command| match command {
            Command::RequestHeaders { session: 1, id, .. } => Some(*id),
            _ => None,
        })
        .collect()
}

/// Main is 8 blocks. Session 1 claims 14 and is asked for headers. Before
/// its answer arrives this node connects its own block `X1` (a miner's
/// case): `H*` moves, and the request is withdrawn. The answer is `X1..X6`
/// from main's block 7, well formed for the locator it was asked with.
///
/// It is discarded: no close, nothing judged. The request that replaced it
/// is answered with the same page, and that answer is judged: `X1` is
/// held, `X2..X6` are the run.
///
/// Before 2026-11-03 the withdrawn request was forgotten. Its answer
/// matched no request and closed the session at
/// `HeadersForm(ParentUnrequested)`, a fault charged to a peer that did
/// what it was asked. In the three-miner rehearsal (#1237) the node's own
/// blocks connected once a second, and every header request in flight
/// across one of them cost the session.
#[test]
fn an_answer_to_a_withdrawn_request_is_discarded_and_the_next_is_judged() {
    let rules = fixed(1, 64);
    let fixture = chain_of(8);
    let template = candidate_on(&fixture, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    let wall = shekyl_types::Timestamp::from_raw(u64::MAX / 4);
    sync.set_wall(wall);
    let base: Vec<HeaderRecord> = fixture.with_view(|view| {
        (0..8)
            .map(
                |height| match view.header_at(BlockHeight::from_raw(height)) {
                    Ok(AtHeight::Recorded(record)) => record,
                    _ => panic!("main has height {height}"),
                },
            )
            .collect()
    });
    let tip_record = base.last().expect("eight records").clone();
    let tip_work = tip_record.cumulative_difficulty.to_raw();
    let above = tip_work + 6;
    let mut block = template;
    let mut when = tip_record.header.timestamp;
    let mut previous = tip_record.hash;
    let mut x_blocks: Vec<Block> = Vec::new();
    let mut x_records = Vec::new();
    for index in 0..6u128 {
        block.header.previous = previous;
        when = when.saturating_add(120);
        block.header.timestamp = when;
        previous = PowBlob::read(&block.pow_blob())
            .expect("preimage")
            .identity();
        x_records.push(HeaderRecord {
            hash: previous,
            header: block.header.clone(),
            cumulative_difficulty: CumulativeDifficulty::from_raw(tip_work + 1 + index),
        });
        x_blocks.push(block.clone());
    }
    let x_pows: Vec<Vec<u8>> = x_blocks.iter().map(Block::pow_blob).collect();

    let drive = |sync: &mut Sync<u8, _>, view: &Prefix<'_>, event: Event<u8>| {
        let mut out = Vec::new();
        sync.handle(event, view, Instant::now(), &mut NoDraw, &mut out)
            .expect("the view answers");
        out
    };

    // Session 1 is above this node and is asked.
    let view = Prefix(&base);
    let tip = view.tip().expect("answers").expect("a tip");
    drive(&mut sync, &view, Event::Tip { tip });
    drive(&mut sync, &view, Event::Room { seats: 4 });
    let mut out = drive(
        &mut sync,
        &view,
        Event::SessionOpened {
            session: 1,
            transit: Duration::from_secs(1),
        },
    );
    sync.claim(
        1,
        PeerClaim {
            count: ChainCount::from_raw(14),
            work: CumulativeDifficulty::from_raw(above),
            top: BlockHash::NULL,
        },
        &view,
        Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("the claim is a chain");
    let first = requests(&out);
    assert_eq!(first.len(), 1, "session 1 is asked once: {out:?}");

    // This node's own `X1` connects before the answer: `H*` moves.
    let mut records = base.clone();
    records.push(x_records[0].clone());
    let view = Prefix(&records);
    let tip = view.tip().expect("answers").expect("a tip");
    let out = drive(&mut sync, &view, Event::Tip { tip });
    let mut later = requests(&out);
    assert!(closes(&out).is_empty(), "a new tip closes nothing: {out:?}");

    // The answer to the withdrawn request: discarded, not judged.
    let out = drive(
        &mut sync,
        &view,
        Event::Headers {
            session: 1,
            bytes: response(&x_pows, above, false),
        },
    );
    later.extend(requests(&out));
    assert!(
        closes(&out).is_empty(),
        "an answer this node asked for is not the peer's fault: {:?}",
        closes(&out)
    );
    assert_eq!(sync.run_len(1), 0, "a stale answer is not judged");
    assert!(
        !out.iter()
            .any(|command| matches!(command, Command::Prove { .. })),
        "a stale answer is not proven: {out:?}"
    );
    assert_eq!(
        later.len(),
        1,
        "the withdrawn request is replaced by one: {later:?}"
    );
    assert_ne!(later[0], first[0], "the replacement is a new request");

    // The answer to the replacement is judged: `X1` is held, `X2..X6` run.
    let out = drive(
        &mut sync,
        &view,
        Event::Headers {
            session: 1,
            bytes: response(&x_pows, above, false),
        },
    );
    assert!(
        closes(&out).is_empty(),
        "the page is well formed for the new locator: {:?}",
        closes(&out)
    );
    assert_eq!(sync.run_len(1), 5, "X2..X6 are the run");
    assert!(
        out.iter()
            .any(|command| matches!(command, Command::Prove { .. })),
        "the run is being proven: {out:?}"
    );
}
