// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Past-cap windows, the evidence draw, and a body that does not bind.

use std::time::{Duration, Instant};

use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::{AtHeight, HeaderRecord, HeaderView, RuleSet, Trust};
use shekyl_difficulty::{CumulativeDifficulty, MTP_WINDOW_USIZE, N_USIZE};
use shekyl_draw_rng::SplitMix64;
use shekyl_levin::{PortableMap, ResponseBodies, ResponseHeaders};
use shekyl_types::{BlockHeight, ChainCount};
use shekyl_wire::{Block, BlockBody, PowBlob, TxBody};

use super::{
    answer, cap, closes, formed_on, open_and_claim, proves, Along, NoDraw, UnitWork, Words,
};
use crate::model::{CloseCause, Event, HashClass, Sync};
use crate::{Command, PeerClaim};

/// While the latch is set, a past-cap offer plans no evidence hash.
#[test]
fn the_latch_plans_no_evidence_hash() {
    let rules = cap(1);
    let main = chain_of(8);
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        sync.handle(
            Event::Latch { set: true },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        open_and_claim(&mut sync, &view, 1, u128::MAX);
        let prefix = prefix_of(&main, 0);
        let along = Along {
            prefix: &prefix,
            extra: &[],
            fork: 0,
        };
        let mut block = candidate_on(&main, Vec::new()).block;
        let parent = prefix[0].hash;
        let timestamp = prefix[0].header.timestamp;
        formed_on(&along, &rules, &mut block, parent, timestamp + 120);
        let out = answer(&mut sync, &view, 1, block.pow_blob(), u128::MAX, true);
        assert!(!proves(&out).contains(&HashClass::Evidence));
        assert!(sync.evidence_session().is_none());
    });
}

fn prefix_of(main: &shekyl_chain_rules::harness::MockChain, fork: u64) -> Vec<HeaderRecord> {
    main.with_view(|view| {
        (0..=fork)
            .map(
                |h| match view.header_at(BlockHeight::from_raw(h)).unwrap() {
                    AtHeight::Recorded(record) => record,
                    AtHeight::AboveTip => panic!("height {h} is on main"),
                },
            )
            .collect()
    })
}

/// A past-cap run keeps the branch-view window, not every header it saw.
#[test]
fn a_past_cap_run_holds_only_its_window() {
    let rules = cap(1);
    let main = chain_of(400);
    let window = N_USIZE.max(MTP_WINDOW_USIZE).saturating_add(8);
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|raw| {
        let view = UnitWork(raw);
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        open_and_claim(&mut sync, &view, 1, u128::MAX);
        let prefix = prefix_of(&main, 0);
        let mut block = candidate_on(&main, Vec::new()).block;
        let mut parent = prefix[0].hash;
        let mut timestamp = prefix[0].header.timestamp;
        let steps = u64::try_from(window).unwrap() + 20;
        let mut peak = 0usize;
        for step in 0..steps {
            let extra = sync.run_records(1);
            let along = Along {
                prefix: &prefix,
                extra: &extra,
                fork: 0,
            };
            timestamp += 120;
            formed_on(&along, &rules, &mut block, parent, timestamp);
            parent = PowBlob::read(&block.pow_blob())
                .expect("preimage")
                .identity();
            let _ = answer(
                &mut sync,
                &view,
                1,
                block.pow_blob(),
                u128::MAX,
                step + 1 < steps,
            );
            peak = peak.max(sync.run_len(1));
        }
        let sent = usize::try_from(steps).unwrap();
        assert!(
            peak <= window,
            "the run held {peak} headers; the window is {window}"
        );
        assert!(
            peak + 8 < sent,
            "the run kept every header it was sent ({peak} of {sent})"
        );
    });
}

/// The evidence draw over two waiting candidates is uniform.
#[test]
fn the_evidence_draw_is_uniform_over_the_waiting_candidates() {
    let rules = cap(1);
    let main = chain_of(4);
    let prefix = prefix_of(&main, 0);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut blobs = Vec::new();
    let mut parent = prefix[0].hash;
    let mut timestamp = prefix[0].header.timestamp;
    let mut scratch = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|raw| {
        let view = UnitWork(raw);
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        scratch
            .handle(
                Event::Tip { tip },
                &view,
                Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .unwrap();
        open_and_claim(&mut scratch, &view, 1, u128::MAX);
        for step in 0..4 {
            let extra = scratch.run_records(1);
            let along = Along {
                prefix: &prefix,
                extra: &extra,
                fork: 0,
            };
            timestamp += 120;
            formed_on(&along, &rules, &mut block, parent, timestamp);
            let pow = block.pow_blob();
            parent = PowBlob::read(&pow).expect("preimage").identity();
            blobs.push(pow.clone());
            let out = answer(&mut scratch, &view, 1, pow, u128::MAX, step < 3);
            assert!(
                closes(&out).is_empty(),
                "header {} closed: {out:?}",
                blobs.len()
            );
        }
        assert!(scratch.run_len(1) > 0, "the candidate run did not form");
    });
    let mut hits = [0u32; 2];
    let trials = 80u64;
    for seed in 0..trials {
        let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
        let mut rng = SplitMix64::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        main.with_view(|raw| {
            let view = UnitWork(raw);
            let tip = view.tip().unwrap().unwrap();
            let mut out = Vec::new();
            sync.handle(
                Event::Tip { tip },
                &view,
                Instant::now(),
                &mut rng,
                &mut out,
            )
            .unwrap();
            for session in [1u8, 2] {
                sync.handle(
                    Event::SessionOpened {
                        session,
                        transit: Duration::from_secs(1),
                    },
                    &view,
                    Instant::now(),
                    &mut rng,
                    &mut out,
                )
                .unwrap();
            }
            sync.claim(
                1,
                PeerClaim {
                    count: ChainCount::from_raw(2),
                    work: CumulativeDifficulty::from_raw(u128::MAX),
                },
                &view,
                Instant::now(),
                &mut rng,
                &mut out,
            )
            .unwrap();
            for (index, pow) in blobs.iter().enumerate() {
                let bytes = ResponseHeaders {
                    blobs: vec![pow.clone()],
                    tip_work: u128::MAX,
                    more: index + 1 < blobs.len(),
                }
                .store()
                .unwrap();
                sync.handle(
                    Event::Headers { session: 1, bytes },
                    &view,
                    Instant::now(),
                    &mut rng,
                    &mut out,
                )
                .unwrap();
            }
            // The first run has ended, so the next request is session 2's.
            // `claim` does not draw; the room event draws over both runs.
            out.clear();
            sync.claim(
                2,
                PeerClaim {
                    count: ChainCount::from_raw(2),
                    work: CumulativeDifficulty::from_raw(u128::MAX),
                },
                &view,
                Instant::now(),
                &mut rng,
                &mut out,
            )
            .unwrap();
            let asked = out.iter().find_map(|command| match command {
                Command::RequestHeaders { session, .. } => Some(*session),
                _ => None,
            });
            assert_eq!(asked, Some(2), "the second request went to {asked:?}");
            for (index, pow) in blobs.iter().enumerate() {
                let bytes = ResponseHeaders {
                    blobs: vec![pow.clone()],
                    tip_work: u128::MAX,
                    more: index + 1 < blobs.len(),
                }
                .store()
                .unwrap();
                sync.handle(
                    Event::Headers { session: 2, bytes },
                    &view,
                    Instant::now(),
                    &mut rng,
                    &mut out,
                )
                .unwrap();
            }
            assert!(
                sync.run_len(1) > 0 && sync.run_len(2) > 0,
                "candidates {} {}",
                sync.run_len(1),
                sync.run_len(2)
            );
            out.clear();
            sync.handle(
                Event::Room { seats: 0 },
                &view,
                Instant::now(),
                &mut rng,
                &mut out,
            )
            .unwrap();
            let drawn = out.iter().find_map(|command| match command {
                Command::Prove {
                    class: HashClass::Evidence,
                    ..
                } => sync.evidence_session(),
                _ => None,
            });
            match drawn {
                Some(1) => hits[0] += 1,
                Some(2) => hits[1] += 1,
                other => panic!("the draw picked {other:?}"),
            }
        });
    }
    let expected = f64::from(u32::try_from(trials).unwrap()) / 2.0;
    let chi: f64 = hits
        .iter()
        .map(|hit| {
            let d = f64::from(*hit) - expected;
            d * d / expected
        })
        .sum();
    assert!(
        chi < 10.83,
        "chi-squared {chi} over {hits:?} is not a uniform draw"
    );
}

/// An unavailable block does not close. A body that fails the binding
/// closes the supplier and leaves the header in `T`.
#[test]
fn a_bind_failure_closes_and_an_unavailable_block_does_not() {
    let rules = cap(64);
    let main = chain_of(21);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        open_and_claim(&mut sync, &view, 1, u128::MAX);
        let timestamp = match view.header_at(tip.height).unwrap() {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip"),
        };
        let branch = sync.branch_of(&view, tip.hash).unwrap();
        formed_on(&branch, &rules, &mut block, tip.hash, timestamp + 120);
        let raw = {
            let mut bytes = Vec::new();
            block.write(&mut bytes).unwrap();
            bytes
        };
        let hash = Block::from_bytes(&raw).unwrap().hash();
        let _ = answer(&mut sync, &view, 1, block.pow_blob(), u128::MAX, false);
        let before = sync.header_count();
        out.clear();
        sync.handle(
            Event::Room { seats: 4 },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        let request = out
            .iter()
            .find_map(|command| match command {
                Command::RequestBodies { request, .. } => Some(request.hashes.clone()),
                _ => None,
            })
            .expect("a body is wanted along H*");
        let missed = ResponseBodies {
            bodies: Vec::new(),
            deferred: Vec::new(),
            missed_ids: request.clone(),
        }
        .store()
        .unwrap();
        out.clear();
        sync.handle(
            Event::Bodies {
                session: 1,
                bytes: missed,
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        assert!(
            closes(&out).is_empty(),
            "an unavailable block closed the session: {out:?}"
        );
        assert_eq!(sync.header_count(), before);
        // The block is wanted again, from the same session once no other
        // session covers it. A body whose transactions are not the header's
        // closes that session and leaves the header in `T`.
        assert!(
            out.iter()
                .any(|command| matches!(command, Command::RequestBodies { .. })),
            "the unavailable block was not wanted again: {out:?}"
        );
        let body = BlockBody {
            block: raw,
            txs: vec![TxBody::Full(vec![1, 2, 3])],
            attestation_witness: Vec::new(),
        };
        let bad = ResponseBodies {
            bodies: vec![body],
            deferred: Vec::new(),
            missed_ids: Vec::new(),
        }
        .store()
        .unwrap();
        out.clear();
        sync.handle(
            Event::Bodies {
                session: 1,
                bytes: bad,
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        assert!(
            closes(&out)
                .iter()
                .any(|cause| matches!(cause, CloseCause::Bind(_))),
            "a mismatched body did not close: {out:?}"
        );
        assert!(sync.contains_header(hash));
        assert_eq!(sync.header_count(), before);
    });
}

/// Two honest sessions extend one frontier with one header request.
#[test]
fn one_header_request_extends_the_frontier() {
    let mut sync = Sync::new(Trust::UNANCHORED, |_: BlockHeight| RuleSet::GENESIS);
    let main = chain_of(4);
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        open_and_claim(&mut sync, &view, 1, u128::MAX);
        open_and_claim(&mut sync, &view, 2, u128::MAX);
        out.clear();
        sync.handle(
            Event::Deadline {
                session: 9,
                request: 0,
            },
            &view,
            Instant::now(),
            &mut Words(vec![0]),
            &mut out,
        )
        .unwrap();
        let requests = out
            .iter()
            .filter(|command| matches!(command, Command::RequestHeaders { .. }))
            .count();
        assert!(
            requests <= 1,
            "two header requests extended one frontier: {out:?}"
        );
    });
}
