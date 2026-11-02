// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A block announced by two peers is proved once, and a proof that lands
//! after main has connected the block is dropped. Judging it again would
//! put a copy of a main block into `T`, under a view with no height, and
//! every later announcement would be judged above the copy.

#![cfg(test)]

use std::time::{Duration, Instant};

use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::{form_header, AtHeight, HeaderRecord, HeaderView, Trust};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_types::{BlockHash, BlockHeight, ChainCount, Timestamp};
use shekyl_wire::{BlockBody, PowBlob};

use crate::model::{Event, HashClass, Outcome, Proved, Sync};
use crate::proof::{fixed, serialized};
use crate::scenarios::Prefix;
use crate::{Command, PeerClaim};

struct NoDraw;

impl RelayRng for NoDraw {
    fn next_u64(&mut self) -> u64 {
        0
    }
}

fn unsolicited_job(out: &[Command<u8>]) -> Option<(crate::Job, crate::ProveItem)> {
    out.iter().find_map(|command| match command {
        Command::Prove {
            job,
            class: HashClass::Unsolicited,
            items,
            ..
        } => items.first().map(|item| (*job, item.clone())),
        _ => None,
    })
}

fn offered(out: &[Command<u8>]) -> Vec<(u64, BlockHash)> {
    out.iter()
        .flat_map(|command| match command {
            Command::Offer { arrivals } => arrivals
                .iter()
                .map(|arrival| (arrival.tag, arrival.header.hash()))
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}

/// Main is 8 blocks. Sessions 1 and 2 each announce `X` (height 8). The
/// first proof puts `X` in `T` and offers its body; the entry connects it
/// and main's tip becomes `X`. The second proof lands after that: `X` is
/// on main, so it is dropped and `T` does not hold it. Session 1 then
/// announces `Y` on `X`, which is judged above main's tip and offered.
///
/// Before 2026-11-02 the second proof was judged against a view of main at
/// height zero and inserted as a branch anchored at `X`'s parent; `Y` was
/// judged above that copy, `H*` stayed at main's tip, and nothing was
/// offered. In the three-miner rehearsal a node that heard each block
/// from two peers connected the first relayed block and no later one.
#[test]
fn a_second_proof_of_a_connected_block_is_dropped_and_the_next_block_enters() {
    let rules = fixed(1, 64);
    let fixture = chain_of(8);
    let mut block = candidate_on(&fixture, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    let wall = Timestamp::from_raw(u64::MAX / 4);
    sync.set_wall(wall);
    let substrate = MockSubstrate {
        clock: wall,
        ..MockSubstrate::default()
    };
    let mut records: Vec<HeaderRecord> = fixture.with_view(|view| {
        (0..8)
            .map(
                |height| match view.header_at(BlockHeight::from_raw(height)) {
                    Ok(AtHeight::Recorded(record)) => record,
                    _ => panic!("main has height {height}"),
                },
            )
            .collect()
    });
    let tip_record = records.last().expect("eight records").clone();
    let mut when = tip_record.header.timestamp;
    let mut previous = tip_record.hash;
    let mut blocks = Vec::new();
    let mut hashes: Vec<BlockHash> = Vec::new();
    for _ in 0..2 {
        block.header.previous = previous;
        when = when.saturating_add(120);
        block.header.timestamp = when;
        previous = PowBlob::read(&block.pow_blob())
            .expect("preimage")
            .identity();
        hashes.push(previous);
        blocks.push(block.clone());
    }
    let body_of = |index: usize| BlockBody {
        block: serialized(&blocks[index]),
        txs: Vec::new(),
        attestation_witness: Vec::new(),
    };
    let drive = |sync: &mut Sync<u8, _>, view: &Prefix<'_>, event: Event<u8>| {
        let mut out = Vec::new();
        sync.handle(event, view, Instant::now(), &mut NoDraw, &mut out)
            .expect("the view answers");
        out
    };
    let prove =
        |sync: &mut Sync<u8, _>, view: &Prefix<'_>, (job, item): (crate::Job, crate::ProveItem)| {
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
            drive(
                sync,
                view,
                Event::Proven {
                    job,
                    results: vec![Proved::Formed(Box::new(formed))],
                },
            )
        };

    let first_tag;
    let second_job;
    {
        let view = Prefix(&records);
        let tip = view.tip().expect("answers").expect("a tip");
        drive(&mut sync, &view, Event::Tip { tip });
        for session in [1u8, 2] {
            let mut out = drive(
                &mut sync,
                &view,
                Event::SessionOpened {
                    session,
                    transit: Duration::from_secs(1),
                },
            );
            sync.claim(
                session,
                PeerClaim {
                    count: ChainCount::from_raw(8),
                    work: tip_record.cumulative_difficulty,
                    top: tip.hash,
                },
                &view,
                Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .expect("the claim is a chain");
        }
        drive(&mut sync, &view, Event::Room { seats: 4 });

        // Both peers announce `X`.
        let out = drive(
            &mut sync,
            &view,
            Event::Announce {
                session: 1,
                body: body_of(0),
            },
        );
        let first_job = unsolicited_job(&out).expect("session 1's announce is proven");
        let out = drive(
            &mut sync,
            &view,
            Event::Announce {
                session: 2,
                body: body_of(0),
            },
        );
        second_job = unsolicited_job(&out).expect("session 2's announce is proven");

        // The first proof lands: `X` is in `T` and its body is offered.
        let out = prove(&mut sync, &view, first_job);
        assert!(sync.contains_header(hashes[0]), "X is in T: {out:?}");
        let offers = offered(&out);
        assert_eq!(offers.len(), 1, "X's body is offered: {out:?}");
        assert_eq!(offers[0].1, hashes[0]);
        first_tag = offers[0].0;
        drive(
            &mut sync,
            &view,
            Event::Entry {
                tag: first_tag,
                outcome: Outcome::Connected {
                    height: BlockHeight::from_raw(8),
                },
            },
        );
    }

    // Main connects `X`.
    records.push(HeaderRecord {
        hash: hashes[0],
        header: blocks[0].header.clone(),
        cumulative_difficulty: CumulativeDifficulty::from_raw(9),
    });
    let view = Prefix(&records);
    let tip = view.tip().expect("answers").expect("a tip");
    assert_eq!(tip.hash, hashes[0]);
    drive(&mut sync, &view, Event::Tip { tip });
    assert!(!sync.contains_header(hashes[0]), "X left T");

    // The second proof lands after the connect: `X` is main's, not `T`'s.
    let out = prove(&mut sync, &view, second_job);
    assert!(
        !sync.contains_header(hashes[0]),
        "a connected block was put back in T: {out:?}"
    );
    assert!(
        !out.iter()
            .any(|command| matches!(command, Command::Close { .. })),
        "the second proof closed a session: {out:?}"
    );

    // `Y` on `X` is announced, judged above main's tip, and offered.
    let out = drive(
        &mut sync,
        &view,
        Event::Announce {
            session: 1,
            body: body_of(1),
        },
    );
    let job = unsolicited_job(&out).expect("Y is proven: {out:?}");
    let out = prove(&mut sync, &view, job);
    assert_eq!(sync.selected().hash, hashes[1], "Y is H*: {out:?}");
    let offers = offered(&out);
    assert_eq!(
        offers.iter().map(|(_, hash)| *hash).collect::<Vec<_>>(),
        vec![hashes[1]],
        "Y's body is offered: {out:?}"
    );
}

/// A block already in `T` is not proved again when a second peer
/// announces it: the proof is one RandomX hash per announcing peer.
#[test]
fn an_announcement_of_a_block_already_in_t_is_not_proved_again() {
    let rules = fixed(1, 64);
    let fixture = chain_of(8);
    let mut block = candidate_on(&fixture, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    let wall = Timestamp::from_raw(u64::MAX / 4);
    sync.set_wall(wall);
    let substrate = MockSubstrate {
        clock: wall,
        ..MockSubstrate::default()
    };
    let records: Vec<HeaderRecord> = fixture.with_view(|view| {
        (0..8)
            .map(
                |height| match view.header_at(BlockHeight::from_raw(height)) {
                    Ok(AtHeight::Recorded(record)) => record,
                    _ => panic!("main has height {height}"),
                },
            )
            .collect()
    });
    let tip_record = records.last().expect("eight records").clone();
    block.header.previous = tip_record.hash;
    block.header.timestamp = tip_record.header.timestamp.saturating_add(120);
    let hash = PowBlob::read(&block.pow_blob())
        .expect("preimage")
        .identity();
    let body = BlockBody {
        block: serialized(&block),
        txs: Vec::new(),
        attestation_witness: Vec::new(),
    };
    let view = Prefix(&records);
    let tip = view.tip().expect("answers").expect("a tip");
    let mut out = Vec::new();
    let mut drive = |sync: &mut Sync<u8, _>, event: Event<u8>| {
        out.clear();
        sync.handle(event, &view, Instant::now(), &mut NoDraw, &mut out)
            .expect("the view answers");
        out.clone()
    };
    drive(&mut sync, Event::Tip { tip });
    for session in [1u8, 2] {
        drive(
            &mut sync,
            Event::SessionOpened {
                session,
                transit: Duration::from_secs(1),
            },
        );
        let mut claim_out = Vec::new();
        sync.claim(
            session,
            PeerClaim {
                count: ChainCount::from_raw(8),
                work: tip_record.cumulative_difficulty,
                top: tip.hash,
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut claim_out,
        )
        .expect("the claim is a chain");
    }
    let out = drive(
        &mut sync,
        Event::Announce {
            session: 1,
            body: body.clone(),
        },
    );
    let (job, item) = unsolicited_job(&out).expect("the first announce is proven");
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
    drive(
        &mut sync,
        Event::Proven {
            job,
            results: vec![Proved::Formed(Box::new(formed))],
        },
    );
    assert!(sync.contains_header(hash));
    let out = drive(&mut sync, Event::Announce { session: 2, body });
    assert!(
        unsolicited_job(&out).is_none(),
        "a block in T was proved again: {out:?}"
    );
    assert!(
        !out.iter()
            .any(|command| matches!(command, Command::Close { .. })),
        "{out:?}"
    );
}
