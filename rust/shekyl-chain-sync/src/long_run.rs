// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The floor-device job: every captured corpus, then 50,000 headers at
//! fixed target 1. `cargo test --lib` does not build it. The rate floor
//! is not derived here; the job's first run on the floor device is the
//! measurement, and it is recorded after that run.

use std::io::BufReader;
use std::num::NonZeroU128;
use std::path::PathBuf;
use std::time::Instant;

use shekyl_chain_ingest::{CorpusReader, IngestEvent, Source};
use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::{
    AtHeight, FakechainSchedule, HeaderRecord, HeaderView, RuleSet, SettlementEpochBlocks, Tip,
    Trust,
};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_levin::PortableMap;
use shekyl_types::{BlockCount, BlockHeight, Timestamp};
use shekyl_wire::PowBlob;

use crate::model::{Event, Proved, Sync};
use crate::proof::{fixed, open_claim, prove_item};
use crate::Command;

const CORPORA: [&str; 6] = [
    "spend-1in-2out",
    "spend-depth3",
    "median-full",
    "limit-full",
    "emission-claim",
    "bond-post",
];

struct NoDraw;

impl RelayRng for NoDraw {
    fn next_u64(&mut self) -> u64 {
        0
    }
}

struct One {
    record: HeaderRecord,
}

impl HeaderView<'static> for One {
    type Fault = core::convert::Infallible;

    fn tip(&self) -> Result<Option<Tip>, Self::Fault> {
        Ok(Some(Tip {
            height: BlockHeight::ZERO,
            hash: self.record.hash,
        }))
    }

    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, Self::Fault> {
        if height.is_zero() {
            Ok(AtHeight::Recorded(self.record.clone()))
        } else {
            Ok(AtHeight::AboveTip)
        }
    }
}

fn corpus_rules() -> RuleSet {
    let epoch = SettlementEpochBlocks::new(10_000).expect("the corpus epoch");
    let schedule =
        FakechainSchedule::new(epoch, BlockCount::from_raw(720)).expect("the corpus cap");
    RuleSet::fakechain(NonZeroU128::new(1), schedule)
}

fn load(name: &str) -> Vec<shekyl_chain_rules::Candidate> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../shekyl-chain-ingest/tests/vectors")
        .join(name)
        .join("corpus.e2");
    let file = std::fs::File::open(&path).unwrap_or_else(|err| panic!("{name}: {err}"));
    let mut reader =
        CorpusReader::open(BufReader::new(file)).unwrap_or_else(|err| panic!("{name}: {err}"));
    let mut out = Vec::new();
    while let Some(sequenced) =
        Source::next(&mut reader).unwrap_or_else(|err| panic!("{name}: {err}"))
    {
        if let IngestEvent::Extend(candidate) = sequenced.event {
            out.push(*candidate);
        }
    }
    out
}

#[test]
fn long_real_hashes_on_captured_corpora_and_fifty_thousand_headers() {
    let started = Instant::now();
    for name in CORPORA {
        let n = run_corpus(name);
        eprintln!("{name}: {n} headers in {:?}", started.elapsed());
    }
    run_synthetic(50_000);
    eprintln!(
        "captured corpora and 50,000 headers: {:?}",
        started.elapsed()
    );
}

fn run_corpus(name: &str) -> usize {
    let candidates = load(name);
    assert!(!candidates.is_empty(), "{name} is empty");
    let genesis = One {
        record: HeaderRecord {
            hash: candidates[0].block.hash(),
            header: candidates[0].block.header.clone(),
            cumulative_difficulty: CumulativeDifficulty::from_raw(1),
        },
    };
    let rules = corpus_rules();
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    let tip = genesis.tip().expect("genesis").expect("a tip");
    let mut out = Vec::new();
    sync.handle(
        Event::Tip { tip },
        &genesis,
        Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("genesis answers");
    open_claim(&mut sync, &genesis, 1);
    let wall = candidates
        .iter()
        .map(|candidate| candidate.block.header.timestamp)
        .max()
        .expect("a header");
    sync.set_wall(Timestamp::from_raw(wall));
    let pows: Vec<Vec<u8>> = candidates[1..]
        .iter()
        .map(|candidate| candidate.block.pow_blob())
        .collect();
    feed(&mut sync, &genesis, &pows);
    let last = candidates.last().expect("non-empty").block.hash();
    assert!(sync.contains_header(last), "{name}: the tip did not enter");
    pows.len()
}

fn run_synthetic(count: usize) {
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
        open_claim(&mut sync, &view, 1);
        let timestamp = match view.header_at(tip.height).expect("main answers") {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip"),
        };
        let mut previous = tip.hash;
        let mut when = timestamp;
        let mut pows = Vec::with_capacity(count);
        for _ in 0..count {
            block.header.previous = previous;
            when = when.saturating_add(120);
            block.header.timestamp = when;
            block.header.nonce = 0;
            let pow = block.pow_blob();
            previous = PowBlob::read(&pow).expect("preimage").identity();
            pows.push(pow);
        }
        feed(&mut sync, &view, &pows);
        let tip = PowBlob::read(pows.last().expect("non-empty"))
            .expect("preimage")
            .identity();
        assert!(sync.contains_header(tip), "the synthetic tip did not enter");
    });
}

fn feed<'id, H, R>(sync: &mut Sync<u8, R>, main: &H, pows: &[Vec<u8>])
where
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
    R: Fn(BlockHeight) -> RuleSet,
{
    let mut start = 0;
    while start < pows.len() {
        let end = (start + 64).min(pows.len());
        let more = end < pows.len();
        let bytes = shekyl_levin::ResponseHeaders {
            blobs: pows[start..end].to_vec(),
            tip_work: u128::MAX,
            more,
        }
        .store()
        .expect("the headers encode");
        let mut out = Vec::new();
        sync.handle(
            Event::Headers { session: 1, bytes },
            main,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the view answers");
        settle(sync, main, &mut out);
        start = end;
    }
}

fn settle<'id, H, R>(sync: &mut Sync<u8, R>, main: &H, out: &mut Vec<Command<u8>>)
where
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
    R: Fn(BlockHeight) -> RuleSet,
{
    for _ in 0..64 {
        let Some((job, items)) = out.iter().find_map(|command| match command {
            Command::Prove { job, items, .. } => Some((*job, items.clone())),
            _ => None,
        }) else {
            return;
        };
        let mut results = Vec::new();
        for item in items {
            match prove_item(&item) {
                Ok(formed) => results.push(Proved::Formed(Box::new(formed))),
                Err(refused) => {
                    results.push(Proved::Refused(refused));
                    break;
                }
            }
        }
        out.clear();
        sync.handle(
            Event::Proven { job, results },
            main,
            Instant::now(),
            &mut NoDraw,
            out,
        )
        .expect("the view answers");
    }
    assert!(
        out.iter()
            .all(|command| !matches!(command, Command::Prove { .. })),
        "proofs remained after the settle loop"
    );
}
