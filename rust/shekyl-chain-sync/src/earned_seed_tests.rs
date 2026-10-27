// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A seed is earned once (CS-Q2 step 3; Rick, 2026-10-24). When the seed
//! header and the lag after it are proven on the run's branch, the cache
//! may be built, and every later header under that seed is proven in one
//! job, spread across the budget's permits and answered in item order.

#![cfg(test)]

use std::time::Instant;

use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::{form_header, seed_height, AtHeight, HeaderView, Trust};
use shekyl_draw_rng::RelayRng;
use shekyl_levin::PortableMap;
use shekyl_types::{BlockHeight, Timestamp};
use shekyl_wire::PowBlob;

use crate::model::{CachePlan, Event, Proved, Sync};
use crate::proof::{fixed, open_claim};
use crate::Command;

struct NoDraw;

impl RelayRng for NoDraw {
    fn next_u64(&mut self) -> u64 {
        0
    }
}

/// 2,300 headers above a tip at height 7 cross into the first branch seed,
/// block 2048: the headers from 2113 on name it. The first job proves the
/// headers under main's seed. Once those land, the seed header and the lag
/// after it are proven, and one job proves every header under the branch
/// seed. Red edit: earn a seed per header, one job each.
#[test]
fn every_header_under_an_earned_seed_is_proven_in_one_job() {
    const COUNT: usize = 2_300;
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
        drive(&mut sync, Event::Tip { tip });
        open_claim(&mut sync, &view, 1);
        let mut when = match view.header_at(tip.height).expect("main answers") {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip is on main"),
        };
        let mut previous = tip.hash;
        let mut pows = Vec::with_capacity(COUNT);
        for _ in 0..COUNT {
            block.header.previous = previous;
            when = when.saturating_add(120);
            block.header.timestamp = when;
            let pow = block.pow_blob();
            previous = PowBlob::read(&pow).expect("preimage").identity();
            pows.push(pow);
        }
        let bytes = shekyl_levin::ResponseHeaders {
            blobs: pows,
            tip_work: u128::MAX,
            more: false,
        }
        .store()
        .expect("the headers encode");
        let mut out = drive(&mut sync, Event::Headers { session: 1, bytes });
        let mut branch_jobs = Vec::new();
        while let Some((job, cache, items)) = out.iter().find_map(|command| match command {
            Command::Prove {
                job, cache, items, ..
            } => Some((*job, *cache, items.clone())),
            _ => None,
        }) {
            if matches!(cache, CachePlan::Branch(_)) {
                branch_jobs.push(items.len());
            }
            let results = items
                .iter()
                .map(|item| {
                    let pow = PowBlob::read(&item.pow).expect("preimage");
                    Proved::Formed(Box::new(
                        form_header(
                            &pow,
                            &item.rule_set,
                            &substrate,
                            item.seed,
                            item.target,
                            item.attempt,
                        )
                        .expect("the mock answers")
                        .expect("the header forms"),
                    ))
                })
                .collect();
            out = drive(&mut sync, Event::Proven { job, results });
        }
        // Heights 8 ..= 2307; the branch seed names 2113 onward.
        let first_named = (8..8 + COUNT as u64)
            .find(|height| {
                seed_height(BlockHeight::from_raw(*height)) == Some(BlockHeight::from_raw(2048))
            })
            .expect("the run crosses the seed");
        let under_branch = usize::try_from(8 + COUNT as u64 - first_named).expect("a count");
        assert_eq!(
            branch_jobs,
            vec![under_branch],
            "the headers under the branch seed were not proven in one job"
        );
    });
}
