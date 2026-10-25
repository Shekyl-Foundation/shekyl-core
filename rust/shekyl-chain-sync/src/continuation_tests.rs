// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A run that starts from a header in `T`, continued before its proofs
//! land. The continuation's headers are judged against the run's own base
//! in `T`, not against main.

#![cfg(test)]

use std::time::{Duration, Instant};

use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::{form_header, AtHeight, HeaderView, Trust};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_levin::PortableMap;
use shekyl_types::{BlockHash, ChainCount, Timestamp};
use shekyl_wire::PowBlob;

use crate::model::{Event, Proved, Sync};
use crate::proof::fixed;
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

/// Session 1 serves 100 headers into `T`, then claims no more. Session 2,
/// claiming more, is drawn: it serves 10 headers from `T`'s tip, and its
/// continuation, 10 more, arrives while the first 10 are still being
/// proven. The continuation is cheap-checked against the run's base in
/// `T` (the median-time window reaches below the run, into `T`), so the
/// run keeps all 20 headers and no session closes. Judged against main,
/// those heights are above main's tip, and the run was dropped.
#[test]
fn a_run_from_t_keeps_a_continuation_that_arrives_before_its_proofs() {
    let rules = fixed(1, 64);
    let main = chain_of(8);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    let wall = Timestamp::from_raw(u64::MAX / 4);
    sync.set_wall(wall);
    let substrate = MockSubstrate {
        clock: wall,
        ..MockSubstrate::default()
    };
    main.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        let drive = |sync: &mut Sync<u8, _>, event: Event<u8>| {
            let mut out = Vec::new();
            sync.handle(event, &view, Instant::now(), &mut NoDraw, &mut out)
                .expect("the view answers");
            out
        };
        let mut when = match view.header_at(tip.height).expect("main answers") {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip is on main"),
        };
        let mut previous = tip.hash;
        let mut pows = Vec::new();
        let mut hashes: Vec<BlockHash> = Vec::new();
        for _ in 0..120 {
            block.header.previous = previous;
            when = when.saturating_add(120);
            block.header.timestamp = when;
            let pow = block.pow_blob();
            previous = PowBlob::read(&pow).expect("preimage").identity();
            hashes.push(previous);
            pows.push(pow);
        }
        let claim_more = |sync: &mut Sync<u8, _>, session: u8| {
            let mut out = drive(
                sync,
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
                &view,
                Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .expect("the claim is a chain");
            out
        };
        let prove_all = |sync: &mut Sync<u8, _>, mut out: Vec<Command<u8>>| {
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
                out = drive(sync, Event::Proven { job, results });
            }
        };

        drive(&mut sync, Event::Tip { tip });
        claim_more(&mut sync, 1);
        // Session 1's 100 headers, proven into `T`. Its stated tip work is
        // below them, so it is no source afterwards.
        let out = drive(
            &mut sync,
            Event::Headers {
                session: 1,
                bytes: response(&pows[..100], 1, false),
            },
        );
        prove_all(&mut sync, out);
        assert!(
            sync.contains_header(hashes[99]),
            "session 1's headers are in T"
        );

        // Session 2 is drawn and serves 10 headers from `T`'s tip.
        let out = claim_more(&mut sync, 2);
        assert!(
            out.iter()
                .any(|command| matches!(command, Command::RequestHeaders { session: 2, .. })),
            "session 2 is asked: {out:?}"
        );
        let out = drive(
            &mut sync,
            Event::Headers {
                session: 2,
                bytes: response(&pows[100..110], u128::MAX, true),
            },
        );
        assert!(
            out.iter()
                .any(|command| matches!(command, Command::Prove { .. })),
            "the 10 headers are being proven: {out:?}"
        );
        assert!(
            out.iter()
                .any(|command| matches!(command, Command::RequestHeaders { session: 2, .. })),
            "the continuation is asked for: {out:?}"
        );
        assert_eq!(sync.run_len(2), 10);

        // The continuation, before the first proofs land.
        let out = drive(
            &mut sync,
            Event::Headers {
                session: 2,
                bytes: response(&pows[110..120], u128::MAX, false),
            },
        );
        assert!(
            !out.iter()
                .any(|command| matches!(command, Command::Close { .. })),
            "{out:?}"
        );
        assert_eq!(
            sync.run_len(2),
            20,
            "the continuation was judged against main and the run dropped"
        );
    });
}
