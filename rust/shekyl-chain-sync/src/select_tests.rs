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
    form_header, judge_header, seed_height, target_claim, AtHeight, FakechainSchedule, FormAttempt,
    FormedHeader, HeaderRecord, HeaderView, RuleSet, SettlementEpochBlocks, Tip, Trust,
};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_levin::{PortableMap, ResponseHeaders, HEADERS_RESPONSE_BYTES};
use shekyl_types::{
    AttestationRoot, BlockCount, BlockHash, BlockHeight, ChainCount, CurveTreeRoot,
};
use shekyl_wire::{BlockHeader, PowBlob};

use crate::model::{Event, Proved, Sync, HEADERS_RATE_FLOOR};
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
    pow: Vec<u8>,
    chain: MockChain,
    work: CumulativeDifficulty,
    parent: BlockHash,
    fork: BlockHeight,
    hash: BlockHash,
}

fn extension(len: u64) -> Extension {
    let chain = chain_of(len);
    let candidate = candidate_on(&chain, Vec::new());
    let raw = candidate.block.pow_blob();
    let pow = PowBlob::read(&raw).expect("preimage");
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
        pow: raw,
        chain,
    }
}

fn prove<R: Fn(BlockHeight) -> RuleSet>(sync: &mut Sync<u8, R>, built: Extension) {
    built.chain.with_view(|view| {
        let mut out = Vec::new();
        if sync.transit(9).is_none() {
            sync.handle(
                Event::SessionOpened {
                    session: 9,
                    transit: Duration::from_secs(1),
                },
                &view,
                Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .expect("the fork view answers");
        }
        sync.claim(
            9,
            PeerClaim {
                count: ChainCount::from_raw(2),
                work: CumulativeDifficulty::from_raw(u128::MAX),
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the claim is a chain");
        let bytes = ResponseHeaders {
            blobs: vec![built.pow],
            tip_work: built.work.to_raw(),
            more: false,
        }
        .store()
        .expect("the response encodes");
        out.clear();
        sync.handle(
            Event::Headers { session: 9, bytes },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("the fork view answers");
        let Some(job) = out.iter().find_map(|command| match command {
            Command::Prove { job, .. } => Some(*job),
            _ => None,
        }) else {
            return;
        };
        sync.handle(
            Event::Proven {
                job,
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
    let second = extension(15);
    let anchors = vec![(first.fork, first.parent), (second.fork, second.parent)];
    let mut sync = Sync::new(Trust::UNANCHORED, issued);
    observe_tall(
        &mut sync,
        first.fork.to_raw() + 2,
        CumulativeDifficulty::from_raw(1),
    );
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
        Event::SessionClosed { session: 9 },
        &view,
        Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .unwrap();
    view.reads.set(0);
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
    // The local tip, one read for each header that might have connected,
    // and one anchor read for each heavier candidate. Not the chain.
    assert!(
        view.reads.get() < 30,
        "a walk of main would read 1024, got {}",
        view.reads.get()
    );
    assert!(view.reads.get() > 2);
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

fn fixed_rules() -> RuleSet {
    let epoch = SettlementEpochBlocks::new(512).expect("512");
    let schedule =
        FakechainSchedule::new(epoch, BlockCount::from_raw(64)).expect("cap inside the epoch");
    RuleSet::fakechain(core::num::NonZeroU128::new(1_000), schedule)
}

/// The next header on `view`, whose tip is `parent`. The seed and the
/// target are claimed from that view, which is the view `adopt` judges.
fn formed_on<'id, H>(
    view: &H,
    rules: &RuleSet,
    block: &mut shekyl_wire::Block,
    parent: BlockHash,
    timestamp: u64,
) -> FormedHeader
where
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
{
    block.header.previous = parent;
    block.header.timestamp = timestamp;
    let tip = view.tip().expect("the view answers").expect("a tip");
    let connecting = tip.height + BlockCount::ONE;
    let seed = match seed_height(connecting) {
        None => BlockHash::NULL,
        Some(height) => match view.header_at(height).expect("the view answers") {
            AtHeight::Recorded(record) => record.hash,
            AtHeight::AboveTip => panic!("the seed height is on the branch"),
        },
    };
    let target = target_claim(view, connecting, rules)
        .expect("the view answers")
        .expect("the window has a target");
    let pow = PowBlob::read(&block.pow_blob()).expect("preimage");
    form_header(
        &pow,
        rules,
        &MockSubstrate::default(),
        seed,
        target,
        FormAttempt::FIRST,
    )
    .expect("the mock answers")
    .expect("the header forms")
}

fn adopt_formed<'id, R, H>(
    sync: &mut Sync<u8, R>,
    main: &H,
    pow: Vec<u8>,
    tip_work: u128,
    more: bool,
) where
    R: Fn(BlockHeight) -> RuleSet,
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
{
    let mut out = Vec::new();
    if sync.transit(9).is_none() {
        sync.handle(
            Event::SessionOpened {
                session: 9,
                transit: Duration::from_secs(1),
            },
            main,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("main answers");
    }
    sync.claim(
        9,
        PeerClaim {
            count: ChainCount::from_raw(2),
            work: CumulativeDifficulty::from_raw(u128::MAX),
        },
        main,
        Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("the claim is a chain");
    let bytes = ResponseHeaders {
        blobs: vec![pow],
        tip_work,
        more,
    }
    .store()
    .expect("the response encodes");
    out.clear();
    sync.handle(
        Event::Headers { session: 9, bytes },
        main,
        Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("main answers");
    for _ in 0..8 {
        let Some((job, items)) = out.iter().find_map(|command| match command {
            Command::Prove { job, items, .. } => Some((*job, items.clone())),
            _ => None,
        }) else {
            break;
        };
        let mut results = Vec::new();
        for item in items {
            let pow = PowBlob::read(&item.pow).expect("preimage");
            let formed = form_header(
                &pow,
                &item.rule_set,
                &MockSubstrate::default(),
                item.seed,
                item.target,
                item.attempt,
            )
            .expect("the mock answers")
            .expect("the header forms");
            results.push(Proved::Formed(Box::new(formed)));
        }
        out.clear();
        sync.handle(
            Event::Proven { job, results },
            main,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("main answers");
    }
}

/// Main stays at height 100. Three thousand headers extend it, across a
/// difficulty window and a seed point, and a second branch forks off that
/// run at height 2,000. `handle` is given the fixed main view every time.
#[test]
fn a_header_run_above_a_fixed_main_chain_joins_the_tree() {
    const RUN: u64 = 3_000;
    const FORK_AT: u64 = 2_000;
    let rules = cap(64);
    let main = chain_of(101);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    let mut hashes = Vec::with_capacity(usize::try_from(RUN).expect("the run fits"));
    main.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        assert_eq!(tip.height.to_raw(), 100);
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("main answers");
        let mut parent = tip.hash;
        let mut timestamp = match view.header_at(tip.height).expect("main answers") {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip is on main"),
        };
        for _job in 0..RUN {
            timestamp += 120;
            let formed = {
                let branch = sync
                    .branch_of(&view, parent)
                    .expect("the parent is the branch tip");
                formed_on(&branch, &rules, &mut block, parent, timestamp)
            };
            parent = formed.hash();
            hashes.push(parent);
            adopt_formed(&mut sync, &view, block.pow_blob(), u128::MAX, false);
        }
        assert_eq!(
            sync.header_count(),
            usize::try_from(RUN).expect("the run fits")
        );
        assert_eq!(sync.selected().hash, parent);
        let tip_height = 100 + RUN;
        assert!(
            tip_height > shekyl_difficulty::N,
            "the run has to cross an LWMA window"
        );
        assert!(
            tip_height
                > shekyl_difficulty::SEEDHASH_EPOCH_BLOCKS + shekyl_difficulty::SEEDHASH_EPOCH_LAG,
            "the run has to cross a seed point"
        );

        let side_parent = hashes[usize::try_from(FORK_AT - 101).expect("the fork fits")];
        let side_ts = {
            let branch = sync.branch_of(&view, parent).expect("the long tip is in T");
            match branch
                .header_at(BlockHeight::from_raw(FORK_AT))
                .expect("the branch answers")
            {
                AtHeight::Recorded(record) => record.header.timestamp,
                AtHeight::AboveTip => panic!("height 2000 is on the run"),
            }
        };
        let side = {
            let branch = sync
                .branch_of(&view, side_parent)
                .expect("the fork is in T");
            // The run already has the header at this parent and timestamp.
            // A different nonce is a different block on the same parent.
            block.header.nonce = 1;
            formed_on(&branch, &rules, &mut block, side_parent, side_ts + 120)
        };
        let side_hash = side.hash();
        adopt_formed(&mut sync, &view, block.pow_blob(), 1, false);
        // Height 2,000 is not a hash the sparse locator of the tip names,
        // so this response is not an answer to the request. `T` is unchanged.
        assert!(!sync.contains_header(side_hash));
        assert_eq!(sync.selected().hash, parent);
    });
}

/// Adopting `n` headers, reselecting after each, loads each node
/// O(log n) times. A walk from the tip down to the fork would load
/// `n(n + 1) / 2` nodes and miss the bound.
#[test]
fn adopting_ten_thousand_headers_does_not_walk_the_branch() {
    const N: u64 = 10_000;
    let rules = fixed_rules();
    let main = chain_of(101);
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
        sync.reset_visits();
        let mut parent = tip.hash;
        let mut timestamp = match view.header_at(tip.height).expect("main answers") {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip is on main"),
        };
        for _job in 0..N {
            timestamp += 120;
            let formed = {
                let branch = sync
                    .branch_of(&view, parent)
                    .expect("the parent is the branch tip");
                formed_on(&branch, &rules, &mut block, parent, timestamp)
            };
            parent = formed.hash();
            adopt_formed(&mut sync, &view, block.pow_blob(), u128::MAX, false);
        }
        let visits = sync.tree_visits();
        let linear = N * (N + 1) / 2;
        let steps = u64::from(N.ilog2()) + 1;
        // A linear walk of the branch is `linear` node loads. This bound is
        // a constant times n log n, and it sits under that walk.
        let bound = N.saturating_mul(256).saturating_mul(steps);
        assert!(linear > bound, "the bound does not exclude a linear walk");
        assert!(
            visits < bound,
            "node visits {visits}; bound {bound}; a linear walk is {linear}"
        );
        assert_eq!(
            sync.header_count(),
            usize::try_from(N).expect("the run fits")
        );
        assert_eq!(sync.selected().hash, parent);
    });
}

/// A header whose parent is below the tip, on a hash the locator names,
/// is judged on that branch. When the branch outweighs the tip and the
/// fork is inside the cap, it enters `T` and becomes `H*`.
#[test]
fn a_fork_below_the_tip_enters_when_it_is_heavier() {
    let rules = cap(64);
    let main = chain_of(21);
    let fork = chain_of(11);
    let mut block = candidate_on(&fork, Vec::new()).block;
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
        let fork_hash =
            fork.with_view(|fork_view| fork_view.tip().expect("fork answers").expect("a tip").hash);
        let on_main = match view
            .header_at(BlockHeight::from_raw(10))
            .expect("main answers")
        {
            AtHeight::Recorded(record) => record.hash,
            AtHeight::AboveTip => panic!("height 10 is on main"),
        };
        assert_eq!(fork_hash, on_main);
        let mut parent = fork_hash;
        let mut timestamp = fork.with_view(|fork_view| {
            match fork_view
                .header_at(BlockHeight::from_raw(10))
                .expect("fork answers")
            {
                AtHeight::Recorded(record) => record.header.timestamp,
                AtHeight::AboveTip => panic!("the fork tip"),
            }
        });
        let mut last = parent;
        for step in 0..15u64 {
            timestamp += 120;
            let formed = if sync.contains_header(parent) || parent == tip.hash {
                let branch = sync.branch_of(&view, parent).expect("the parent is known");
                formed_on(&branch, &rules, &mut block, parent, timestamp)
            } else {
                fork.with_view(|fork_view| {
                    formed_on(&fork_view, &rules, &mut block, parent, timestamp)
                })
            };
            last = formed.hash();
            adopt_formed(&mut sync, &view, block.pow_blob(), u128::MAX, step + 1 < 15);
            parent = last;
        }
        assert!(sync.contains_header(last), "count {}", sync.header_count());
        assert_eq!(sync.selected().hash, last);
        assert!(sync.header_count() >= 15);
    });
}

#[test]
fn a_header_judged_against_the_wrong_view_is_recorded() {
    let rules = cap(64);
    let main = chain_of(101);
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
        let timestamp = match view.header_at(tip.height).expect("main answers") {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip is on main"),
        };
        let formed = {
            let branch = sync.branch_of(&view, tip.hash).expect("the local tip");
            formed_on(
                &branch,
                &rules,
                &mut block,
                BlockHash::from_bytes([0xab; 32]),
                timestamp + 120,
            )
        };
        assert_ne!(formed.hash(), tip.hash);
        adopt_formed(&mut sync, &view, block.pow_blob(), u128::MAX, false);
        assert_eq!(sync.header_count(), 0);
        assert_eq!(sync.selected().hash, tip.hash);
    });
}
