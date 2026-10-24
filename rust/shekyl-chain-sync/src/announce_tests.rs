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
