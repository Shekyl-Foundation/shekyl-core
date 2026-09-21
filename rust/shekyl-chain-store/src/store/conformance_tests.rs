// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The mock is reconciled against the real view (E6 slice 2 F11).
//!
//! Every rule in `shekyl-chain-rules` is unit-tested against
//! `harness::MockChain`, whose fidelity to the store's `BatchView` was —
//! until this file — **assumed**. That is the shape of W12, CEN-I12 and
//! SOK-10: a double whose behaviour is its author's belief about the real
//! thing, where a wrong belief passes the test and fails production. The
//! distinction that makes the principle operational is not substitution but
//! **unvalidated** substitution, so this file validates it: the same chain
//! is built twice — connected into a real store through `connect`, and
//! pushed into a `MockChain` from the same blocks and facts — and every
//! candidate shape the landed rules can judge is run through both stages
//! over **both** views, asserting identical verdicts and identical coverage.
//!
//! G1 forbids the rules crate from depending on the store, so the test
//! lives here and reaches the mock through the rules crate's `harness`
//! feature (its only consumer). The dependency direction picked the
//! location.
//!
//! # What a disagreement here means
//!
//! Not "a rule is wrong" — the rules are the same code over both views. A
//! disagreement means the two `ChainView` implementations answer the same
//! question differently: the tip, a block at a height, a root at a height
//! (SCW-19's keying is exactly where a mock could drift), the absence arm.
//! Every rule that reads the view would then have been tested against an
//! answer the store does not give.
//!
//! # What this does not cover, and where it is covered
//!
//! The chain is short (the store fixtures' `root_after` bytes are
//! `0xc0 + h`, so heights above 63 cannot be built with them), which
//! exercises the MTP window, its genesis padding, the seed at block 0 and
//! the DAA's genesis-constant range — not a full LWMA-1 window past `N`.
//! The E2 replay is the instrument for that: it runs the real store past
//! `N` against the C++'s verdicts, which is the comparison this file's
//! short chain cannot make.

use shekyl_chain_rules::harness::{fixture, MockChain, MockSubstrate};
use shekyl_chain_rules::{
    form, validate, AtHeight, Candidate, CenRow, ChainView, Corrupt, Fault, FormAttempt, Locus,
    RecordedBlock, RuleSet, Stale, Substrate, Trust, Verdict,
};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, PowHash, Timestamp};

use super::connect_fixtures::{candidate, facts, judge, FixtureSubstrate};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;

/// One judgement, projected to what both views must agree on. The two
/// views' fault types differ (`StoreError` vs `Infallible`), so a view fault
/// is compared by presence only; the crate's own arms and the verdict are
/// compared by value.
///
/// A refusal is carried as its `(rule, locus)`, read off the `Verdict`'s
/// error by field: this crate does not name the verdict type, and the
/// conversion-ban gate (clause 2) holds that for every file under it, tests
/// included — an exemption for `_tests.rs` would outlive its reason. The
/// projection loses nothing the comparison needs.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Valid {
        coverage: Vec<CenRow>,
    },
    Refused {
        rule: CenRow,
        locus: Locus,
    },
    Stale(Stale),
    Corrupt(Corrupt),
    ViewFault,
    /// The stateless stage refused; the view was never consulted.
    FormRefused {
        rule: CenRow,
        locus: Locus,
    },
}

impl Outcome {
    fn of<V: core::fmt::Debug>(result: Result<Verdict<Vec<CenRow>>, Fault<V>>) -> Self {
        match result {
            Ok(Ok(coverage)) => Self::Valid { coverage },
            Ok(Err(refused)) => Self::Refused {
                rule: refused.rule,
                locus: refused.locus,
            },
            Err(Fault::Stale(stale)) => Self::Stale(stale),
            Err(Fault::Corrupt(corrupt)) => Self::Corrupt(corrupt),
            Err(Fault::View(_)) => Self::ViewFault,
        }
    }
}

/// The environment both runs share: the store fixtures' clock and longhash,
/// or a variant a shape needs.
#[derive(Clone, Copy)]
struct Env {
    clock: Timestamp,
    longhash: fn(&[u8], &BlockHash) -> Result<PowHash, core::convert::Infallible>,
}

impl Substrate for Env {
    type Fault = core::convert::Infallible;

    fn local_clock(&self) -> Result<Timestamp, Self::Fault> {
        Ok(self.clock)
    }

    fn longhash(&self, pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, Self::Fault> {
        (self.longhash)(pow_blob, seed)
    }
}

impl Env {
    const FIXTURE: Self = Self {
        clock: FixtureSubstrate::CLOCK,
        longhash: Self::zeros,
    };

    #[allow(clippy::unnecessary_wraps)] // the fn pointer's shape
    fn zeros(_: &[u8], _: &BlockHash) -> Result<PowHash, core::convert::Infallible> {
        Ok(PowHash::from_bytes([0; 32]))
    }

    #[allow(clippy::unnecessary_wraps)] // the fn pointer's shape
    fn top_byte_set(_: &[u8], _: &BlockHash) -> Result<PowHash, core::convert::Infallible> {
        let mut bytes = [0u8; 32];
        bytes[31] = 0xff;
        Ok(PowHash::from_bytes(bytes))
    }
}

/// The seed CEN-D3 expects for the next block on a chain of `len` blocks
/// whose block 0 is `genesis` — the honest driver's claim, computed from
/// the inputs, not read from either view.
fn seed_for(len: u64, genesis: BlockHash) -> BlockHash {
    let Some(seed_height) = shekyl_chain_rules::seed_height(BlockHeight::from_raw(len)) else {
        return BlockHash::NULL;
    };
    assert!(seed_height.is_zero(), "short chains seed from block 0");
    genesis
}

/// Both stages over one view.
fn run<'id, V: ChainView<'id>>(
    view: &V,
    candidate: Candidate,
    env: &Env,
    seed: BlockHash,
) -> Outcome
where
    V::Fault: core::fmt::Debug,
{
    let formed = match form(candidate, &RuleSet::GENESIS, env, seed, FormAttempt::FIRST) {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => {
            return Outcome::FormRefused {
                rule: refused.rule,
                locus: refused.locus,
            }
        }
        Err(never) => match never {},
    };
    Outcome::of(
        validate(formed, view, &RuleSet::GENESIS, &Trust::UNANCHORED)
            .map(|verdict| verdict.map(|valid| valid.coverage().iter().collect::<Vec<_>>())),
    )
}

/// A chain of `len` coinbase-only blocks, connected into a real store AND
/// mirrored into a `MockChain` from the same inputs: the blocks the store
/// fixtures build, the `root_after` the connect facts carry (the mock keys
/// roots the way SCW-19 does, so a keying drift shows here), and the
/// cumulative work the validator derived for each block (read back off the
/// verdict the store connected — the record both views must then agree on).
fn twin_chains(len: u64) -> (ChainStore, std::path::PathBuf, MockChain, Vec<Candidate>) {
    let path = tmp(&format!("conformance-{len}"));
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let mut mock = MockChain::default();
    let mut previous = BlockHash::NULL;
    let mut blocks = Vec::new();
    for h in 0..len {
        let cand = candidate(h, previous, Vec::new());
        previous = cand.block.hash();
        blocks.push(cand.clone());
        let work: Result<_, TestErr> = store.write(|batch| {
            let view = batch.chain_view();
            let valid = judge(&view, cand.clone())?;
            let work = valid.block().cumulative_difficulty();
            batch.connect(valid, facts(h, 0), RuleSet::GENESIS)?;
            Ok(work)
        });
        let work = work.expect("connects");
        mock = mock.push(
            RecordedBlock {
                hash: cand.block.hash(),
                header: cand.block.header.clone(),
                cumulative_difficulty: work,
            },
            facts(h, 0).root_after.value,
        );
    }
    (store, path, mock, blocks)
}

/// Judge `candidate` over the real store's `BatchView` and over the mock;
/// return both outcomes.
fn both(
    store: &ChainStore,
    mock: &MockChain,
    candidate: Candidate,
    env: &Env,
    seed: BlockHash,
) -> (Outcome, Outcome) {
    let real: Result<Outcome, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(run(&view, candidate.clone(), env, seed))
    });
    let real = real.expect("the write closure only reads");
    let mocked = mock.with_view(|view| run(&view, candidate, env, seed));
    (real, mocked)
}

/// The shapes every landed view-bound rule can refuse or pass, each built
/// on a chain of `len` blocks. Names are the row each shape exercises.
fn shapes(len: u64, blocks: &[Candidate]) -> Vec<(&'static str, Candidate, Env)> {
    let tip = blocks
        .last()
        .map(|b| b.block.hash())
        .unwrap_or(BlockHash::NULL);
    let well_formed = candidate(len, tip, Vec::new());
    let mut out = vec![("well-formed", well_formed.clone(), Env::FIXTURE)];

    // A2: previous is not the tip.
    let mut orphan = well_formed.clone();
    orphan.block.header.previous = BlockHash::from_bytes([0xee; 32]);
    out.push(("A2 previous≠tip", orphan, Env::FIXTURE));

    // B5: header root is not the state at the connecting height.
    let mut wrong_root = well_formed.clone();
    wrong_root.block.header.curve_tree_root = CurveTreeRoot::from_bytes([0xdd; 32]);
    out.push(("B5 wrong root", wrong_root, Env::FIXTURE));

    // C1: timestamp past clock + FTL (exempt at genesis — both must agree).
    let mut future = well_formed.clone();
    future.block.header.timestamp = FixtureSubstrate::CLOCK.to_raw() + 541;
    out.push(("C1 above FTL", future, Env::FIXTURE));

    // C2 / C3: timestamp at the padded median (exempt at genesis).
    let mut at_median = well_formed.clone();
    at_median.block.header.timestamp = 0;
    out.push(("C2 at/below median", at_median, Env::FIXTURE));

    // D1: a longhash above the target.
    out.push((
        "D1 pow above target",
        well_formed.clone(),
        Env {
            longhash: Env::top_byte_set,
            ..Env::FIXTURE
        },
    ));

    // B1: stateless refusal — the view is never consulted; both agree
    // trivially, and the fixture pins that neither view is asked.
    let mut bad_major = well_formed;
    bad_major.block.header.major_version = 9;
    out.push(("B1 major version", bad_major, Env::FIXTURE));
    out
}

#[test]
fn every_landed_rule_judges_identically_over_batch_view_and_the_mock() {
    // Genesis admission (no window, null seed), a one-block chain (block 0
    // pads the MTP window; the seed is block 0), and twelve blocks (a full
    // MTP window; C3 pads nothing).
    for len in [0u64, 1, 12] {
        let (store, path, mock, blocks) = twin_chains(len);
        let genesis = blocks
            .first()
            .map(|b| b.block.hash())
            .unwrap_or(BlockHash::NULL);
        let seed = seed_for(len, genesis);
        let mut checked = 0;
        for (name, cand, env) in shapes(len, &blocks) {
            let (real, mocked) = both(&store, &mock, cand, &env, seed);
            // `Valid` carries the row list, so a drift in *which* rows ran
            // fails here even when the verdict matches.
            assert_eq!(
                real, mocked,
                "{name} at len {len}: BatchView vs MockChain disagree"
            );
            if name == "well-formed" {
                // Otherwise the agreement above is over a chain neither
                // view could judge — a vacuous comparison (rule 47).
                assert!(matches!(real, Outcome::Valid { .. }), "len {len}: {real:?}");
            }
            checked += 1;
        }
        assert_eq!(checked, 7, "every shape ran at len {len}");
        drop(store);
        cleanup(&path);
    }
}

#[test]
fn a_drifted_mock_is_caught_by_the_comparison() {
    // Negative control (rule 47): the comparison must be able to go red.
    // A mock whose root keying is off by one — the SCW-19 drift the file
    // exists to catch — disagrees with the real view on the well-formed
    // candidate: the store passes it, the drifted mock refuses it on B5.
    let (store, path, mock, blocks) = twin_chains(3);
    let mut drifted = MockChain::default();
    for (h, b) in blocks.iter().enumerate() {
        let h = h as u64;
        let work = mock.with_view(|view| match view.block_at(BlockHeight::from_raw(h)) {
            Ok(AtHeight::Recorded(r)) => r.cumulative_difficulty,
            Ok(AtHeight::AboveTip) => unreachable!("built above"),
            Err(never) => match never {},
        });
        // The root the connect of h − 1 wrote, pushed as h's `root_after`:
        // one height late.
        let late_root = facts(h.saturating_sub(1), 0).root_after.value;
        drifted = drifted.push(
            RecordedBlock {
                hash: b.block.hash(),
                header: b.block.header.clone(),
                cumulative_difficulty: work,
            },
            late_root,
        );
    }
    let cand = candidate(3, blocks[2].block.hash(), Vec::new());
    let seed = seed_for(3, blocks[0].block.hash());
    let (real, mocked) = both(&store, &drifted, cand, &Env::FIXTURE, seed);
    assert!(matches!(real, Outcome::Valid { .. }), "{real:?}");
    assert_eq!(
        mocked,
        Outcome::Refused {
            rule: CenRow::B5,
            locus: Locus::Block,
        }
    );
    assert_ne!(real, mocked, "the comparison goes red on a drifted mock");
    drop(store);
    cleanup(&path);
}

#[test]
fn a_stale_seed_is_stale_over_both_views() {
    let (store, path, mock, _) = twin_chains(3);
    let wrong = BlockHash::from_bytes([0xbb; 32]);
    let cand = candidate(3, mock.tip().expect("blocks").hash, Vec::new());
    let (real, mocked) = both(&store, &mock, cand, &Env::FIXTURE, wrong);
    assert_eq!(real, mocked);
    assert!(
        matches!(real, Outcome::Stale(Stale::Seed { .. })),
        "{real:?}"
    );
    drop(store);
    cleanup(&path);
}

/// What the rules read off a recorded block, as one comparable value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockRead {
    hash: BlockHash,
    timestamp: u64,
    work: u128,
}

impl BlockRead {
    fn of(at: AtHeight<RecordedBlock>) -> Option<Self> {
        match at {
            AtHeight::Recorded(b) => Some(Self {
                hash: b.hash,
                timestamp: b.header.timestamp,
                work: b.cumulative_difficulty.to_raw(),
            }),
            AtHeight::AboveTip => None,
        }
    }
}

#[test]
fn the_mock_view_and_the_batch_view_answer_the_same_reads() {
    // The reads the rules make, compared directly, so a disagreement above
    // has a named cause below.
    let (store, path, mock, blocks) = twin_chains(5);
    let real: Result<Vec<Option<BlockRead>>, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let mut out = Vec::new();
        for h in 0..7u64 {
            out.push(BlockRead::of(view.block_at(BlockHeight::from_raw(h))?));
        }
        Ok(out)
    });
    let real = real.expect("reads");
    let mocked: Vec<Option<BlockRead>> = mock.with_view(|view| {
        (0..7u64)
            .map(|h| match view.block_at(BlockHeight::from_raw(h)) {
                Ok(at) => BlockRead::of(at),
                Err(never) => match never {},
            })
            .collect()
    });
    assert_eq!(real, mocked);
    assert_eq!(real.iter().filter(|r| r.is_some()).count(), 5);
    assert_eq!(real[0].map(|r| r.hash), Some(blocks[0].block.hash()));

    // Roots: SCW-19 keying — `root_at(h)` is the state AT h, written by the
    // connect of h − 1; `root_at(tip + 1)` is recorded, `tip + 2` is not.
    let real_roots: Result<Vec<Option<CurveTreeRoot>>, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let mut out = Vec::new();
        for h in 0..8u64 {
            out.push(match view.root_at(BlockHeight::from_raw(h))? {
                AtHeight::Recorded(r) => Some(r),
                AtHeight::AboveTip => None,
            });
        }
        Ok(out)
    });
    let mocked_roots: Vec<Option<CurveTreeRoot>> = mock.with_view(|view| {
        (0..8u64)
            .map(|h| match view.root_at(BlockHeight::from_raw(h)) {
                Ok(AtHeight::Recorded(r)) => Some(r),
                Ok(AtHeight::AboveTip) => None,
                Err(never) => match never {},
            })
            .collect()
    });
    assert_eq!(real_roots.expect("roots"), mocked_roots);
    assert_eq!(mocked_roots[0], Some(CurveTreeRoot::EMPTY));
    assert!(mocked_roots[5].is_some() && mocked_roots[6].is_none());

    let real_tip: Result<_, TestErr> = store.write(|batch| Ok(batch.chain_view().tip()?));
    assert_eq!(real_tip.expect("tip"), mock.tip());
    drop(store);
    cleanup(&path);
}

#[test]
fn the_harness_fixtures_are_the_same_shape_the_store_fixtures_build() {
    // Belt on the belt: the rules crate's own fixture chain and this file's
    // store-fixture chain are two builders; a candidate from either is
    // judged the same over the mock. Guards against the harness's
    // `candidate_on` and the store's `candidate` drifting into different
    // header conventions that would make the comparison above vacuous.
    let (store, path, mock, blocks) = twin_chains(2);
    let from_store = candidate(2, blocks[1].block.hash(), Vec::new());
    let from_harness = fixture::candidate_on(&mock, Vec::new());
    assert_eq!(
        from_store.block.header.previous,
        from_harness.block.header.previous
    );
    assert_eq!(
        from_store.block.header.curve_tree_root,
        from_harness.block.header.curve_tree_root
    );
    // The two builders differ in ONE convention — the timestamp era (the
    // harness's `MockSubstrate::CLOCK`, the store fixtures' `1_000_000`), so
    // the harness candidate is judged under the harness clock: under the
    // store clock both views refuse it on C1, an agreement that would prove
    // nothing about the view. Header identity and root keying agree, which
    // is what makes the comparison above non-vacuous.
    let harness_clock = Env {
        clock: MockSubstrate::CLOCK,
        ..Env::FIXTURE
    };
    let seed = seed_for(2, blocks[0].block.hash());
    let (real, mocked) = both(&store, &mock, from_harness, &harness_clock, seed);
    assert_eq!(real, mocked);
    assert!(matches!(real, Outcome::Valid { .. }), "{real:?}");
    drop(store);
    cleanup(&path);
}
