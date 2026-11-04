// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A header page that re-serves what the node holds. The peer answers from
//! the child of the first locator hash it holds (CS-Q2 step 2); the locator
//! is sparse below its dense prefix, so a page routinely starts with
//! headers already on main, then headers already in `T`, before anything
//! new. The new headers are judged above the last header held, wherever it
//! lives.

#![cfg(test)]

use std::time::{Duration, Instant};

use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::{form_header, AtHeight, HeaderRecord, HeaderView, Tip, Trust};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_levin::PortableMap;
use shekyl_types::{BlockHash, BlockHeight, ChainCount, Timestamp};
use shekyl_wire::PowBlob;

use crate::model::{CloseCause, Event, Proved, Sync};
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

/// Main is 8 blocks. Session 1 serves `Y1..Y20` (heights 8–27) into `T`.
/// Main then connects `Y1..Y5`, so `T` keeps `Y6..Y20` above main's tip
/// `Y5` at height 12. `H*` is `Y20`, whose locator's doubling heights are
/// 17, 15, 11, 3, 0: `Y4` at height 11 is the deepest point the peer
/// holds that is not in the dense prefix. Session 2 answers from `Y4`'s
/// child: `Y5` (on main), `Y6..Y20` (in `T`), then `Y21..Y23` (new).
///
/// The three new headers are judged above `Y20` in `T` and the run holds
/// them. Before 2026-11-02 the main-held `Y5` was treated as new, the
/// `T`-held stretch was skipped, and `Y21` was judged above `Y5`: CEN-A2
/// refused it, the session closed, the dialer redialled, and the same
/// page came back — the three-miner rehearsal's nodes never converged.
#[test]
fn a_page_that_reserves_main_and_t_is_judged_above_the_last_header_held() {
    let rules = fixed(1, 64);
    let fixture = chain_of(8);
    let mut block = candidate_on(&fixture, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNPINNED, move |_| rules);
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
    let mut pows = Vec::new();
    let mut headers = Vec::new();
    let mut hashes: Vec<BlockHash> = Vec::new();
    for _ in 0..23 {
        block.header.previous = previous;
        when = when.saturating_add(120);
        block.header.timestamp = when;
        let pow = block.pow_blob();
        previous = PowBlob::read(&pow).expect("preimage").identity();
        hashes.push(previous);
        headers.push(block.header.clone());
        pows.push(pow);
    }
    let drive = |sync: &mut Sync<u8, _>, view: &Prefix<'_>, event: Event<u8>| {
        let mut out = Vec::new();
        sync.handle(event, view, Instant::now(), &mut NoDraw, &mut out)
            .expect("the view answers");
        out
    };
    let claim_more = |sync: &mut Sync<u8, _>, view: &Prefix<'_>, session: u8| {
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
                count: ChainCount::from_raw(200),
                work: CumulativeDifficulty::from_raw(u128::MAX),
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

    // Session 1's 20 headers, proven into `T`.
    {
        let view = Prefix(&records);
        let tip = view.tip().expect("answers").expect("a tip");
        drive(&mut sync, &view, Event::Tip { tip });
        claim_more(&mut sync, &view, 1);
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 1,
                bytes: response(&pows[..20], 1, false),
            },
        );
        prove_all(&mut sync, &view, out);
        assert!(sync.contains_header(hashes[19]), "Y20 is in T");
    }

    // Main connects `Y1..Y5`: they leave `T`; `Y6..Y20` stay above `Y5`.
    for index in 0..5 {
        records.push(HeaderRecord {
            hash: hashes[index],
            header: headers[index].clone(),
            cumulative_difficulty: CumulativeDifficulty::from_raw(9 + index as u128),
        });
    }
    let view = Prefix(&records);
    let tip = view.tip().expect("answers").expect("a tip");
    assert_eq!(
        tip,
        Tip {
            height: BlockHeight::from_raw(12),
            hash: hashes[4]
        }
    );
    drive(&mut sync, &view, Event::Tip { tip });
    assert!(!sync.contains_header(hashes[4]), "Y5 left T");
    assert!(sync.contains_header(hashes[5]), "Y6 stays in T");

    // Session 2 is drawn and answers from `Y4`'s child.
    let out = claim_more(&mut sync, &view, 2);
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
            bytes: response(&pows[4..23], u128::MAX, false),
        },
    );
    let closes: Vec<&CloseCause> = out
        .iter()
        .filter_map(|command| match command {
            Command::Close { cause, .. } => Some(cause),
            _ => None,
        })
        .collect();
    assert!(
        closes.is_empty(),
        "the page is judged above Y20: {closes:?}"
    );
    assert_eq!(sync.run_len(2), 3, "Y21..Y23 are the run");
    assert!(
        out.iter()
            .any(|command| matches!(command, Command::Prove { .. })),
        "the three new headers are being proven: {out:?}"
    );
}
