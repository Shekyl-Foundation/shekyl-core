// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A chain switch demotes main blocks. A header in `T` anchored at one of
//! them is then an orphan: its parent is neither in `T` nor on main.
//! `T` hangs off main (CS-Q2), so the orphan leaves when main moves, and a
//! page that walks the demoted chain is judged as the new headers it is.

#![cfg(test)]

use std::time::{Duration, Instant};

use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::{form_header, AtHeight, HeaderRecord, HeaderView, Tip, Trust};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_levin::PortableMap;
use shekyl_types::{BlockHash, BlockHeight, ChainCount, Timestamp};
use shekyl_wire::{Block, BlockBody, BlockHeader, PowBlob};

use crate::model::{CloseCause, Event, HashClass, Proved, Sync};
use crate::proof::{fixed, serialized};
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

/// `count` blocks on `parent`, `step` seconds apart. Two chains with
/// different steps on one parent differ in every hash.
fn chain_on(
    template: &Block,
    parent: &HeaderRecord,
    count: usize,
    step: u64,
) -> (Vec<Block>, Vec<BlockHeader>, Vec<BlockHash>) {
    let mut block = template.clone();
    let mut when = parent.header.timestamp;
    let mut previous = parent.hash;
    let (mut blocks, mut headers, mut hashes) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..count {
        block.header.previous = previous;
        when = when.saturating_add(step);
        block.header.timestamp = when;
        previous = PowBlob::read(&block.pow_blob())
            .expect("preimage")
            .identity();
        hashes.push(previous);
        headers.push(block.header.clone());
        blocks.push(block.clone());
    }
    (blocks, headers, hashes)
}

fn closes(out: &[Command<u8>]) -> Vec<&CloseCause> {
    out.iter()
        .filter_map(|command| match command {
            Command::Close { cause, .. } => Some(cause),
            _ => None,
        })
        .collect()
}

/// Main is 8 blocks, then connects `X1..X3` (heights 8–10). Session 1
/// announces `X4`: its parent is main's tip, so it is judged and enters
/// `T` anchored at `X3`. Main then switches to `Y1..Y4` (heights 8–11),
/// demoting `X1..X3`. `X4`'s anchor is no longer on main: it is an orphan,
/// and it leaves `T` with the switch.
///
/// Session 2 is on the `X` chain and answers from main's block 7: the page
/// is `X1..X6`, whose six headers are all new to this node and whose tip
/// outweighs `Y4`. They are the run, and they are proven.
///
/// Before 2026-11-03 the orphan stayed. `X1..X3` were new (demoted, so not
/// on main, and never in `T`), `X4` was held, and a held header after a
/// new one is a form no peer can serve: the session closed at
/// `HeadersForm` and the next one got the same page. In the three-miner
/// rehearsal (#1237) a node that had switched once closed 47 sessions this
/// way and mined alone for the rest of the window.
#[test]
fn a_header_anchored_at_a_demoted_block_leaves_t_and_the_page_is_judged() {
    let rules = fixed(1, 64);
    let fixture = chain_of(8);
    let template = candidate_on(&fixture, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    let wall = Timestamp::from_raw(u64::MAX / 4);
    sync.set_wall(wall);
    let substrate = MockSubstrate {
        clock: wall,
        ..MockSubstrate::default()
    };
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
    let (x_blocks, x_headers, x_hashes) = chain_on(&template, &tip_record, 6, 120);
    let (_, y_headers, y_hashes) = chain_on(&template, &tip_record, 4, 121);
    assert_ne!(
        x_hashes[0], y_hashes[0],
        "the chains differ from their first block"
    );
    let x_pows: Vec<Vec<u8>> = x_blocks.iter().map(Block::pow_blob).collect();
    let record = |hash: BlockHash, header: &BlockHeader, work: u128| HeaderRecord {
        hash,
        header: header.clone(),
        cumulative_difficulty: CumulativeDifficulty::from_raw(work),
    };

    let drive = |sync: &mut Sync<u8, _>, view: &Prefix<'_>, event: Event<u8>| {
        let mut out = Vec::new();
        sync.handle(event, view, Instant::now(), &mut NoDraw, &mut out)
            .expect("the view answers");
        out
    };
    let open = |sync: &mut Sync<u8, _>, view: &Prefix<'_>, session: u8, count: u64, work: u128| {
        let mut out = drive(
            sync,
            view,
            Event::SessionOpened {
                session,
                transit: Duration::from_secs(1),
            },
        );
        sync.claim(
            session,
            PeerClaim {
                count: ChainCount::from_raw(count),
                work: CumulativeDifficulty::from_raw(work),
                top: BlockHash::NULL,
            },
            view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the claim is a chain");
        out
    };
    let prove_all = |sync: &mut Sync<u8, _>, view: &Prefix<'_>, mut out: Vec<Command<u8>>| {
        while let Some((job, items)) = out.iter().find_map(|command| match command {
            Command::Prove { job, items, .. } => Some((*job, items.clone())),
            _ => None,
        }) {
            let results = items
                .iter()
                .map(|item| {
                    let pow = PowBlob::read(&item.pow).expect("preimage");
                    let formed = form_header(
                        &pow,
                        &item.rule_set,
                        &substrate,
                        item.seed,
                        item.target,
                        item.attempt,
                    )
                    .expect("the mock answers")
                    .expect("the header forms");
                    Proved::Formed(Box::new(formed))
                })
                .collect();
            out = drive(sync, view, Event::Proven { job, results });
        }
    };

    // Main connects `X1..X3`; session 1 announces `X4`, which enters `T`.
    {
        let mut records = base.clone();
        for index in 0..3 {
            records.push(record(
                x_hashes[index],
                &x_headers[index],
                9 + index as u128,
            ));
        }
        let view = Prefix(&records);
        let tip = view.tip().expect("answers").expect("a tip");
        assert_eq!(tip.hash, x_hashes[2]);
        drive(&mut sync, &view, Event::Tip { tip });
        // The peer is at this node's tip: no header request, an announce.
        open(&mut sync, &view, 1, 11, 11);
        drive(&mut sync, &view, Event::Room { seats: 4 });
        let out = drive(
            &mut sync,
            &view,
            Event::Announce {
                session: 1,
                body: BlockBody {
                    block: serialized(&x_blocks[3]),
                    txs: Vec::new(),
                    attestation_witness: Vec::new(),
                },
            },
        );
        assert!(
            out.iter().any(|command| matches!(
                command,
                Command::Prove {
                    class: HashClass::Unsolicited,
                    ..
                }
            )),
            "the announce is proven: {out:?}"
        );
        prove_all(&mut sync, &view, out);
        assert!(
            sync.contains_header(x_hashes[3]),
            "X4 is in T, anchored at X3"
        );
    }

    // Main switches to `Y1..Y4`. `X1..X3` are demoted; `X4` is an orphan.
    let mut records = base.clone();
    for index in 0..4 {
        records.push(record(
            y_hashes[index],
            &y_headers[index],
            9 + index as u128,
        ));
    }
    let view = Prefix(&records);
    let tip = view.tip().expect("answers").expect("a tip");
    assert_eq!(
        tip,
        Tip {
            height: BlockHeight::from_raw(11),
            hash: y_hashes[3]
        }
    );
    drive(&mut sync, &view, Event::Tip { tip });
    assert!(
        !sync.contains_header(x_hashes[3]),
        "X4's anchor left main, so X4 left T"
    );

    // Session 2, on the `X` chain, answers from block 7: `X1..X6`.
    let out = open(&mut sync, &view, 2, 14, 14);
    assert!(
        out.iter()
            .any(|command| matches!(command, Command::RequestHeaders { session: 2, .. })),
        "session 2 is asked: {out:?}"
    );
    let out = drive(
        &mut sync,
        &view,
        Event::Headers {
            session: 2,
            bytes: response(&x_pows, 14, false),
        },
    );
    let closed = closes(&out);
    assert!(
        closed.is_empty(),
        "the demoted chain is new to this node and is judged: {closed:?}"
    );
    assert_eq!(sync.run_len(2), 6, "X1..X6 are the run");
    assert!(
        out.iter()
            .any(|command| matches!(command, Command::Prove { .. })),
        "the heavier run is being proven: {out:?}"
    );
}
