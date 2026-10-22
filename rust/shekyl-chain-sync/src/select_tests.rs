// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Selection, the locator's reads, and the reorg cap.

use std::cell::Cell;
use std::time::{Duration, Instant};

use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::harness::{expected_seed, expected_target, MockChain, MockSubstrate};
use shekyl_chain_rules::{
    form_header, judge_header, AtHeight, FakechainSchedule, FormAttempt, FormedHeader,
    HeaderRecord, HeaderView, RuleSet, SettlementEpochBlocks, Tip, Trust,
};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_levin::HEADERS_RESPONSE_BYTES;
use shekyl_types::{
    AttestationRoot, BlockCount, BlockHash, BlockHeight, ChainCount, CurveTreeRoot,
};
use shekyl_wire::{BlockHeader, PowBlob};

use crate::model::{Event, Job, Proved, Sync, HEADERS_RATE_FLOOR};
use crate::{Command, PeerClaim};

fn issued(_: BlockHeight) -> RuleSet {
    RuleSet::GENESIS
}

fn cap(blocks: u64) -> RuleSet {
    let epoch = SettlementEpochBlocks::new(512).expect("512");
    let schedule =
        FakechainSchedule::new(epoch, BlockCount::from_raw(blocks)).expect("cap inside the epoch");
    RuleSet::fakechain(None, schedule)
}

fn wide(_: BlockHeight) -> RuleSet {
    cap(64)
}

fn tight(_: BlockHeight) -> RuleSet {
    cap(1)
}

struct NoDraw;

impl RelayRng for NoDraw {
    fn next_u64(&mut self) -> u64 {
        0
    }
}

struct Words(Vec<u64>);

impl RelayRng for Words {
    fn next_u64(&mut self) -> u64 {
        self.0.remove(0)
    }
}

fn header_record(hash: BlockHash, work: CumulativeDifficulty, previous: BlockHash) -> HeaderRecord {
    HeaderRecord {
        hash,
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1,
            previous,
            nonce: 0,
            curve_tree_root: CurveTreeRoot::from_bytes([0; 32]),
            attestation_root: AttestationRoot::from_bytes([0; 32]),
        },
        cumulative_difficulty: work,
    }
}

/// `len` blocks. Hashes are the height, except `anchors`, which a judged
/// header's parent has to match. `reads` counts `header_at`.
struct Counted {
    len: u64,
    tip_work: CumulativeDifficulty,
    reads: Cell<u64>,
    anchors: Vec<(BlockHeight, BlockHash)>,
}

impl Counted {
    fn hash_of(height: BlockHeight) -> BlockHash {
        let mut raw = [0u8; 32];
        raw[0..8].copy_from_slice(&height.to_raw().to_le_bytes());
        BlockHash::from_bytes(raw)
    }

    fn tip_height(&self) -> BlockHeight {
        BlockHeight::from_raw(self.len - 1)
    }
}

impl HeaderView<'static> for Counted {
    type Fault = core::convert::Infallible;

    fn tip(&self) -> Result<Option<Tip>, Self::Fault> {
        Ok(Some(Tip {
            height: self.tip_height(),
            hash: Self::hash_of(self.tip_height()),
        }))
    }

    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, Self::Fault> {
        self.reads.set(self.reads.get() + 1);
        if height.to_raw() >= self.len {
            return Ok(AtHeight::AboveTip);
        }
        let hash = self
            .anchors
            .iter()
            .find(|(at, _)| *at == height)
            .map(|(_, hash)| *hash)
            .unwrap_or_else(|| Self::hash_of(height));
        let previous = height
            .checked_sub_count(BlockCount::ONE)
            .map(Self::hash_of)
            .unwrap_or(BlockHash::NULL);
        let work = if height == self.tip_height() {
            self.tip_work
        } else {
            CumulativeDifficulty::from_raw(u128::from(height.to_raw()) + 1)
        };
        Ok(AtHeight::Recorded(header_record(hash, work, previous)))
    }
}

struct Extension {
    formed: FormedHeader,
    chain: MockChain,
    work: CumulativeDifficulty,
    parent: BlockHash,
    fork: BlockHeight,
    hash: BlockHash,
}

fn extension(len: u64) -> Extension {
    let chain = chain_of(len);
    let candidate = candidate_on(&chain, Vec::new());
    let pow = PowBlob::read(&candidate.block.pow_blob()).expect("preimage");
    let formed = form_header(
        &pow,
        &RuleSet::GENESIS,
        &MockSubstrate::default(),
        expected_seed(&chain),
        expected_target(&chain, &RuleSet::GENESIS),
        FormAttempt::FIRST,
    )
    .expect("the mock answers")
    .expect("the header forms");
    let judged = chain.with_view(|view| {
        match judge_header(&formed, &view, &RuleSet::GENESIS, &Trust::UNANCHORED).expect("view") {
            Ok(judged) => judged,
            Err(refused) => panic!("judge refused: {refused:?}"),
        }
    });
    Extension {
        fork: judged
            .connecting()
            .checked_sub_count(BlockCount::ONE)
            .expect("above genesis"),
        work: judged.cumulative_difficulty(),
        parent: judged.previous(),
        hash: judged.hash(),
        formed,
        chain,
    }
}

fn prove<R: Fn(BlockHeight) -> RuleSet>(sync: &mut Sync<u8, R>, built: Extension) {
    let mut out = Vec::new();
    built.chain.with_view(|view| {
        sync.handle(
            Event::Proven {
                job: Job::from_raw(0),
                results: vec![Proved::Formed(Box::new(built.formed))],
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the fork view answers");
    });
}

fn observe_tall<R: Fn(BlockHeight) -> RuleSet>(
    sync: &mut Sync<u8, R>,
    height: u64,
    work: CumulativeDifficulty,
) {
    let view = Counted {
        len: height + 1,
        tip_work: work,
        reads: Cell::new(0),
        anchors: Vec::new(),
    };
    let mut out = Vec::new();
    sync.handle(
        Event::Tip {
            tip: Tip {
                height: BlockHeight::from_raw(height),
                hash: Counted::hash_of(BlockHeight::from_raw(height)),
            },
        },
        &view,
        Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("the chain answers");
}

#[test]
fn a_heavier_tip_within_the_cap_displaces() {
    let built = extension(19);
    let header = built.hash;
    let work = built.work;
    let mut sync = Sync::new(Trust::UNANCHORED, wide);
    observe_tall(
        &mut sync,
        built.fork.to_raw() + 2,
        CumulativeDifficulty::from_raw(1),
    );
    prove(&mut sync, built);
    assert_eq!(sync.selected().hash, header);
    assert_eq!(sync.selected().work, work);
}

#[test]
fn an_equal_work_tip_does_not_displace() {
    let built = extension(19);
    let height = built.fork.to_raw() + 2;
    let local = Counted::hash_of(BlockHeight::from_raw(height));
    let work = built.work;
    let mut sync = Sync::new(Trust::UNANCHORED, wide);
    observe_tall(&mut sync, height, work);
    prove(&mut sync, built);
    assert_eq!(sync.selected().hash, local);
    assert_eq!(sync.selected().work, work);
}

#[test]
fn a_heavier_tip_past_the_cap_does_not_displace() {
    let built = extension(19);
    let height = built.fork.to_raw() + 2;
    let local = Counted::hash_of(BlockHeight::from_raw(height));
    assert!(height - built.fork.to_raw() > 1);
    let mut sync = Sync::new(Trust::UNANCHORED, tight);
    observe_tall(&mut sync, height, CumulativeDifficulty::from_raw(1));
    prove(&mut sync, built);
    assert_eq!(sync.selected().hash, local);
}

#[test]
fn the_locator_reads_logarithmically() {
    let view = Counted {
        len: 1_024,
        tip_work: CumulativeDifficulty::from_raw(1),
        reads: Cell::new(0),
        anchors: Vec::new(),
    };
    let mut sync = Sync::new(Trust::UNANCHORED, issued);
    let mut out = Vec::new();
    sync.handle(
        Event::SessionOpened {
            session: 1,
            transit: Duration::from_secs(30),
        },
        &view,
        Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .unwrap();
    view.reads.set(0);
    sync.claim(
        1,
        PeerClaim {
            count: ChainCount::from_raw(2),
            work: CumulativeDifficulty::from_raw(u128::MAX),
        },
        &view,
        Instant::now(),
        &mut Words(vec![0]),
        &mut out,
    )
    .unwrap();
    let reads = view.reads.get();
    assert!(reads < 40, "locator reads {reads} of 1024");
    assert!(reads > 10, "the dense prefix is ten headers");
}

#[test]
fn selection_reads_one_header_per_candidate_tip() {
    let first = extension(19);
    let second = extension(10);
    let anchors = vec![(first.fork, first.parent), (second.fork, second.parent)];
    let mut sync = Sync::new(Trust::UNANCHORED, issued);
    prove(&mut sync, first);
    prove(&mut sync, second);
    let view = Counted {
        len: 1_024,
        tip_work: CumulativeDifficulty::from_raw(1),
        reads: Cell::new(0),
        anchors,
    };
    let mut out = Vec::new();
    sync.handle(
        Event::Tip {
            tip: Tip {
                height: view.tip_height(),
                hash: Counted::hash_of(view.tip_height()),
            },
        },
        &view,
        Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .unwrap();
    // The local tip, then one read for each heavier candidate.
    assert_eq!(view.reads.get(), 3, "a walk of main would read 1024");
}

#[test]
fn a_header_deadline_is_transit_plus_the_response_bound() {
    let view = Counted {
        len: 1,
        tip_work: CumulativeDifficulty::from_raw(1),
        reads: Cell::new(0),
        anchors: Vec::new(),
    };
    let mut sync = Sync::new(Trust::UNANCHORED, issued);
    let mut out = Vec::new();
    let now = Instant::now();
    sync.handle(
        Event::SessionOpened {
            session: 1,
            transit: Duration::from_secs(30),
        },
        &view,
        now,
        &mut NoDraw,
        &mut out,
    )
    .unwrap();
    sync.claim(
        1,
        PeerClaim {
            count: ChainCount::from_raw(2),
            work: CumulativeDifficulty::from_raw(10),
        },
        &view,
        now,
        &mut Words(vec![0]),
        &mut out,
    )
    .unwrap();
    let deadline = out.iter().find_map(|command| match command {
        Command::RequestHeaders { deadline, .. } => Some(*deadline),
        _ => None,
    });
    let secs = 30 + HEADERS_RESPONSE_BYTES / HEADERS_RATE_FLOOR;
    assert_eq!(deadline, Some(now + Duration::from_secs(secs)));
}

/// Lands with the run layer (§4.8). A `judge_header` refusal closes the
/// supplier as `HeaderRefused`. A `Stale` is not the peer's: the run is
/// planned again with the attempt the fault names. A `Proven` whose job
/// matches no run is discarded.
#[test]
#[ignore = "run layer §4.8: HeaderRefused closes the supplier; Stale re-plans with the fault's attempt"]
fn a_judge_refusal_closes_and_a_stale_replans() {}
