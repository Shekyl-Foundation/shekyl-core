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
//! The chain is short (three coinbase-only blocks: nothing has matured, so
//! every root is the empty tree), which exercises the MTP window, its
//! genesis padding, the seed at block 0 and the DAA's genesis-constant
//! range — not a full LWMA-1 window past `N`, and not a grown tree.
//! The E2 replay is the instrument for that: it runs the real store past
//! `N` against the C++'s verdicts, which is the comparison this file's
//! short chain cannot make.

use shekyl_chain_rules::harness::{fixture, MockChain, MockSubstrate};
use shekyl_chain_rules::{
    form, validate, AtHeight, Candidate, CenRow, ChainView, Corrupt, Fault, FormAttempt,
    HeaderRecord, HeaderView, Locus, RecordedBlock, RecordedWeights, RuleSet, Stale, Substrate,
    Trust, TxSlot, Verdict,
};
use shekyl_types::{
    ArchivalLength, BlockCount, BlockHash, BlockHeight, CurveTreeRoot, PowHash, Timestamp, TxHash,
};
use shekyl_wire::{Ct, Transaction};

use super::connect_fixtures::{
    batch_root_going_into, candidate, candidate_over, endow_genesis, grown_over, judge, priced,
    root_going_into, FixtureSubstrate, FIRST_SPEND_HEIGHT,
};
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
/// fixtures build, the `root_after` the verdict derived (the mock keys
/// roots the way SCW-19 does, so a keying drift shows here), the leaf count
/// the store recorded under that root (CEN-I13's `depth_at` operand), and
/// the cumulative work the validator derived for each block (read back off
/// the verdict the store connected and the store it connected into — the
/// record both views must then agree on).
fn twin_chains(len: u64) -> (ChainStore, std::path::PathBuf, MockChain, Vec<Candidate>) {
    let path = tmp(&format!("conformance-{len}"));
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let mut mock = MockChain::default();
    let mut previous = BlockHash::NULL;
    let mut blocks = Vec::new();
    for h in 0..len {
        // Priced against the store's view (the coinbase F18 owes, from
        // height 1) before it is judged, so the candidate the mock records
        // and the block the store connected are one object.
        let derived: Result<_, TestErr> = store.write(|batch| {
            let view = batch.chain_view();
            // Carrying the root the store recorded going into `h` (CEN-B5;
            // the tree grows once the unlock window has elapsed).
            let root = batch_root_going_into(&view, h)?;
            let mut cand = candidate_over(root, h, previous, Vec::new());
            if h == 0 {
                // Genesis stands as built (CEN-F11); endowed so its
                // coinbase is one the spend shapes below can spend.
                endow_genesis(&mut cand);
            }
            let cand = priced(&view, cand)?;
            let valid = judge(&view, cand.clone())?;
            let derived = (
                cand,
                valid.block().cumulative_difficulty(),
                valid.block().root_after(),
                *valid.block().weights(),
                valid.block().emission().coins_generated,
            );
            batch.connect(valid, RuleSet::GENESIS)?;
            // The leaf count the store recorded going into `h + 1` — the
            // tree after this block's drain, keyed as `root_after` is
            // (SCW-19) — read back off the store, not re-derived: CEN-I13
            // reads `depth_at(ref_height)` off it, and a twin told the root
            // but not the count would hold an empty tree under every
            // recorded root and refuse at I13 what the store admits.
            let AtHeight::Recorded(leaf_count_after) = batch
                .chain_view()
                .leaf_count_at(BlockHeight::from_raw(h + 1))?
            else {
                unreachable!("the block at {h} just connected");
            };
            Ok((derived, leaf_count_after))
        });
        let ((cand, work, root_after, weights, coins_generated), leaf_count_after) =
            derived.expect("connects");
        previous = cand.block.hash();
        blocks.push(cand.clone());
        mock = mock
            .push_tree_weighing(
                RecordedBlock {
                    header: HeaderRecord {
                        hash: cand.block.hash(),
                        header: cand.block.header.clone(),
                        cumulative_difficulty: work,
                    },
                    // What the store records for this chain: the verdict's
                    // accumulator (G12; slice 7 commit 5), and a tx count
                    // that stays zero because no fixture block lists a
                    // transaction.
                    coins_generated,
                    cumulative_tx_count: 0,
                    cumulative_archival_len: ArchivalLength::ZERO,
                },
                root_after,
                leaf_count_after,
                // The two weights the store recorded for `h` — the
                // verdict's (G6b; `weights_window` is held to the store's
                // below).
                RecordedWeights {
                    weight: weights.weight,
                    long_term_weight: weights.long_term_weight,
                },
            )
            // The store records the miner transaction under its identity
            // like a listed one; the mock is told, so `has_transaction` can
            // be held to the store's.
            .with_transaction(cand.block.miner_transaction.hash());
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
fn shapes(
    len: u64,
    blocks: &[Candidate],
    store: &ChainStore,
    mock: &MockChain,
) -> Vec<(&'static str, Candidate, Env)> {
    let tip = blocks
        .last()
        .map(|b| b.block.hash())
        .unwrap_or(BlockHash::NULL);
    // The root a header at `len` must carry is the store's going into
    // `len` (CEN-B5); the mock is held to the same root by the comparison.
    let root = root_going_into(store, len);
    // Priced over the **mock** (CEN-F18's coinbase): the store's view then
    // judges a coinbase the mock priced, so the reads F17/F18 depend on —
    // the accumulator, the burned fold, the leaf count, the medians — are
    // reconciled by this comparison too, not only by the reads below.
    let well_formed = fixture::repriced(mock, candidate_over(root, len, tip, Vec::new()));
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
    let mut bad_major = well_formed.clone();
    bad_major.block.header.major_version = 9;
    out.push(("B1 major version", bad_major, Env::FIXTURE));

    // I10–I12 (slice 6 commit 5), once the chain is old enough to list a
    // spend: a real spend of genesis's coinbase, built over the chain both
    // views hold — the reference found by `height_of` on both views,
    // measured by I11, its root read by I12 — passes on both; the same
    // spend re-anchored to a block no chain holds is refused by I10 on
    // both. `height_of` is the read this file exists to reconcile here,
    // not the rows' operation on a chain (the ingest's driver holds that).
    if len >= FIRST_SPEND_HEIGHT {
        let mut grown = grown_over(blocks.iter().map(|b| (&b.block, b.transactions.as_slice())));
        assert_eq!(
            grown.height(),
            BlockHeight::from_raw(len),
            "one record per connected block"
        );
        let the_spend = grown.spend(0);
        let listing = |body: Transaction| {
            let mut with_body = well_formed.clone();
            with_body.block.transaction_hashes = vec![body.hash()];
            with_body.transactions = vec![body];
            with_body
        };
        let mut unrecorded = the_spend.clone();
        match &mut unrecorded.ct {
            Ct::Fcmp {
                reference_block, ..
            } => *reference_block = fixture::UNRECORDED_REFERENCE,
            Ct::Null(_) => panic!("a spend's ct is Fcmp"),
        }
        out.push(("I10–I12 anchored spend", listing(the_spend), Env::FIXTURE));
        out.push((
            "I10 unrecorded reference",
            listing(unrecorded),
            Env::FIXTURE,
        ));
    }
    out
}

#[test]
fn every_landed_rule_judges_identically_over_batch_view_and_the_mock() {
    // Genesis admission (no window, null seed), a one-block chain (block 0
    // pads the MTP window; the seed is block 0), twelve blocks (a full MTP
    // window; C3 pads nothing), and the first chain that may list a spend
    // (the spend shapes run; the tree has grown, so B5 and I12 read a
    // non-empty root on both views).
    for len in [0u64, 1, 12, FIRST_SPEND_HEIGHT] {
        let (store, path, mock, blocks) = twin_chains(len);
        let genesis = blocks
            .first()
            .map(|b| b.block.hash())
            .unwrap_or(BlockHash::NULL);
        let seed = seed_for(len, genesis);
        let mut checked = 0;
        for (name, cand, env) in shapes(len, &blocks, &store, &mock) {
            let (real, mocked) = both(&store, &mock, cand, &env, seed);
            // `Valid` carries the row list, so a drift in *which* rows ran
            // fails here even when the verdict matches.
            assert_eq!(
                real, mocked,
                "{name} at len {len}: BatchView vs MockChain disagree"
            );
            if name == "well-formed" || name == "I10–I12 anchored spend" {
                // Otherwise the agreement above is over a chain neither
                // view could judge — a vacuous comparison (rule 47).
                assert!(
                    matches!(real, Outcome::Valid { .. }),
                    "{name} at len {len}: {real:?}"
                );
            }
            if name == "I10 unrecorded reference" {
                assert_eq!(
                    real,
                    Outcome::Refused {
                        rule: CenRow::I10,
                        locus: Locus::Tx {
                            slot: TxSlot::Listed(0),
                        },
                    }
                );
            }
            checked += 1;
        }
        // Seven shapes on every chain; the two spend shapes once a spend
        // can be listed.
        let expected = if len >= FIRST_SPEND_HEIGHT { 7 + 2 } else { 7 };
        assert_eq!(checked, expected, "every shape ran at len {len}");
        drop(store);
        cleanup(&path);
    }
}

#[test]
fn a_drifted_mock_is_caught_by_the_comparison() {
    // Negative control (rule 47): the comparison must be able to go red.
    // A mock whose roots are not the store's — here a root that claims the
    // tree grew where the store's derivation says nothing matured, the
    // shape a SCW-19 keying drift takes once roots differ per height —
    // disagrees with the real view on the well-formed candidate: the store
    // passes it, the drifted mock refuses it on B5.
    let (store, path, mock, blocks) = twin_chains(3);
    let mut drifted = MockChain::default();
    for (h, b) in blocks.iter().enumerate() {
        let h = h as u64;
        let (work, coins_generated) =
            mock.with_view(|view| match view.block_at(BlockHeight::from_raw(h)) {
                Ok(AtHeight::Recorded(r)) => (r.header.cumulative_difficulty, r.coins_generated),
                Ok(AtHeight::AboveTip) => unreachable!("built above"),
                Err(never) => match never {},
            });
        // A root the store never recorded, pushed as h's `root_after`.
        let late_root = CurveTreeRoot::from_bytes([0xd0 + u8::try_from(h).expect("small"); 32]);
        drifted = drifted.push(
            RecordedBlock {
                header: HeaderRecord {
                    hash: b.block.hash(),
                    header: b.block.header.clone(),
                    cumulative_difficulty: work,
                },
                coins_generated,
                cumulative_tx_count: 0,
                cumulative_archival_len: ArchivalLength::ZERO,
            },
            late_root,
        );
    }
    // Priced over the faithful mock (F18): the store must pass it, and the
    // drifted mock refuses it on B5 before the reward chain runs.
    let cand = fixture::repriced(&mock, candidate(3, blocks[2].block.hash(), Vec::new()));
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

/// What the header rules read off a recorded block through
/// `HeaderView::header_at`, as one comparable value (DRS-E5 `E5-13`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeaderRead {
    hash: BlockHash,
    timestamp: u64,
    work: u128,
}

impl HeaderRead {
    fn of(at: AtHeight<HeaderRecord>) -> Option<Self> {
        match at {
            AtHeight::Recorded(h) => Some(Self {
                hash: h.hash,
                timestamp: h.header.timestamp,
                work: h.cumulative_difficulty.to_raw(),
            }),
            AtHeight::AboveTip => None,
        }
    }
}

/// What the executed-chain rules read off a recorded block through
/// `ChainView::block_at` beyond its header: the facts only a connected
/// block has. Carries the header too, so the partition can be checked as
/// a projection (`block_at(h).header == header_at(h)`) on each view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockRead {
    header: HeaderRead,
    coins_generated: u64,
    cumulative_tx_count: u64,
    cumulative_archival_len: u64,
}

impl BlockRead {
    fn of(at: AtHeight<RecordedBlock>) -> Option<Self> {
        match at {
            AtHeight::Recorded(b) => Some(Self {
                header: HeaderRead::of(AtHeight::Recorded(b.header))?,
                coins_generated: b.coins_generated.to_raw(),
                cumulative_tx_count: b.cumulative_tx_count,
                cumulative_archival_len: b.cumulative_archival_len.to_raw(),
            }),
            AtHeight::AboveTip => None,
        }
    }
}

/// The two per-height reads (`E5-13`): the header read beside the block read.
type HeightReads = Vec<(Option<HeaderRead>, Option<BlockRead>)>;

/// Both reads at every probed height, off one view.
fn reads<'id, V: ChainView<'id>>(view: &V) -> Result<HeightReads, V::Fault> {
    let mut out = Vec::new();
    for h in 0..7u64 {
        let h = BlockHeight::from_raw(h);
        out.push((
            HeaderRead::of(view.header_at(h)?),
            BlockRead::of(view.block_at(h)?),
        ));
    }
    Ok(out)
}

#[test]
fn the_mock_view_and_the_batch_view_answer_the_same_reads() {
    // The reads the rules make, compared directly, so a disagreement above
    // has a named cause below. Two reads per height since `E5-13`: the
    // header read the cheap-tier rules make, and the block read the
    // executed-chain rules make. Each view must agree with the other on
    // both, and with itself that the header read is the block read's
    // projection — a view whose `header_at` answered from a different
    // record than its `block_at` would pass the first check and fail the
    // second.
    let (store, path, mock, blocks) = twin_chains(5);
    let real: Result<HeightReads, TestErr> = store.write(|batch| Ok(reads(&batch.chain_view())?));
    let real = real.expect("reads");
    let mocked = mock.with_view(|view| match reads(&view) {
        Ok(reads) => reads,
        Err(never) => match never {},
    });
    assert_eq!(real, mocked);
    for (header, block) in &real {
        assert_eq!(
            *header,
            block.map(|b| b.header),
            "header_at is block_at's projection"
        );
    }
    assert_eq!(real.iter().filter(|(h, _)| h.is_some()).count(), 5);
    assert_eq!(real[0].0.map(|r| r.hash), Some(blocks[0].block.hash()));

    // By hash (CEN-I10): every recorded identity answers its height on both
    // views, and a hash no chain holds answers `None` on both — the mock's
    // `height_of` is held to the store's here, not assumed (slice 6
    // commit 5).
    let asked: Vec<BlockHash> = blocks
        .iter()
        .map(|b| b.block.hash())
        .chain(core::iter::once(fixture::UNRECORDED_REFERENCE))
        .collect();
    let real_heights: Result<Vec<Option<BlockHeight>>, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let mut out = Vec::new();
        for hash in &asked {
            out.push(view.height_of(hash)?);
        }
        Ok(out)
    });
    let real_heights = real_heights.expect("reads");
    let mocked_heights: Vec<Option<BlockHeight>> = mock.with_view(|view| {
        asked
            .iter()
            .map(|hash| match view.height_of(hash) {
                Ok(at) => at,
                Err(never) => match never {},
            })
            .collect()
    });
    assert_eq!(real_heights, mocked_heights);
    let expected_heights: Vec<Option<BlockHeight>> = (0..5u64)
        .map(|h| Some(BlockHeight::from_raw(h)))
        .chain(core::iter::once(None))
        .collect();
    assert_eq!(real_heights, expected_heights, "five recorded, one unknown");

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

    // The weights window (CEN-G6 / G6b, slice 7 commit 3): every `end` from
    // the empty chain through one past the recordable, at four widths — the
    // window that is shorter than the chain, one that is exactly it, one
    // wider (clamped to what exists), and zero — held to the store's, and
    // the shape held to the contract: `end ≤ tip + 1` is `Recorded` with
    // exactly `min(at_most, end)` rows in height order, `end > tip + 1` is
    // `AboveTip`. Five blocks are recorded, so `end = 5` is the candidate's
    // connecting height and `end = 6` asks about a block the chain lacks.
    let asks: Vec<(u64, u64)> = (0..=6u64)
        .flat_map(|end| [0u64, 1, 3, 5, 100].into_iter().map(move |n| (end, n)))
        .collect();
    let real_windows: Result<Vec<AtHeight<Vec<RecordedWeights>>>, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let mut out = Vec::new();
        for (end, n) in &asks {
            out.push(view.weights_window(BlockHeight::from_raw(*end), BlockCount::from_raw(*n))?);
        }
        Ok(out)
    });
    let real_windows = real_windows.expect("reads");
    let mocked_windows: Vec<AtHeight<Vec<RecordedWeights>>> = mock.with_view(|view| {
        asks.iter()
            .map(|(end, n)| {
                match view.weights_window(BlockHeight::from_raw(*end), BlockCount::from_raw(*n)) {
                    Ok(at) => at,
                    Err(never) => match never {},
                }
            })
            .collect()
    });
    assert_eq!(real_windows, mocked_windows);
    for ((end, n), window) in asks.iter().zip(&real_windows) {
        match window {
            AtHeight::Recorded(rows) => {
                assert!(*end <= 5, "end {end} is past tip + 1 and was Recorded");
                let span = (*end).min(*n);
                assert_eq!(rows.len() as u64, span, "end {end}, at_most {n}");
                for (i, row) in rows.iter().enumerate() {
                    let h = end - span + i as u64;
                    // The verdict's (G6b): the coinbase-only block's wire
                    // weight, and that weight clamped under the zone — the
                    // median every height of a light chain reads.
                    let block = &blocks[usize::try_from(h).expect("small")].block;
                    assert_eq!(
                        row.weight.to_raw(),
                        u64::try_from(block.miner_transaction.weight()).expect("fits"),
                        "height {h}"
                    );
                    assert_eq!(
                        row.long_term_weight.to_raw(),
                        shekyl_economics::long_term_weight(
                            shekyl_economics::FULL_REWARD_ZONE,
                            row.weight.to_raw()
                        ),
                        "height {h}"
                    );
                }
            }
            AtHeight::AboveTip => assert_eq!(*end, 6, "only end = tip + 2 is AboveTip"),
        }
    }

    // Transaction membership (CEN-G1, slice 7 commit 3): every recorded
    // miner transaction answers `true` on both views, an identity no chain
    // holds answers `false` on both.
    let asked_txs: Vec<TxHash> = blocks
        .iter()
        .map(|b| b.block.miner_transaction.hash())
        .chain(core::iter::once(TxHash::from_bytes([0xee; 32])))
        .collect();
    let real_present: Result<Vec<bool>, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let mut out = Vec::new();
        for hash in &asked_txs {
            out.push(view.has_transaction(hash)?);
        }
        Ok(out)
    });
    let real_present = real_present.expect("reads");
    let mocked_present: Vec<bool> = mock.with_view(|view| {
        asked_txs
            .iter()
            .map(|hash| match view.has_transaction(hash) {
                Ok(present) => present,
                Err(never) => match never {},
            })
            .collect()
    });
    assert_eq!(real_present, mocked_present);
    assert_eq!(real_present, vec![true, true, true, true, true, false]);

    // The archival reads (DRS-E4 commit 2): a chain that posted no bond has
    // no archival state, and both views say so in the same shape — `None`,
    // empty, `PassCount::ZERO` — which is the only archival answer the mock
    // gives (§5.2: no `Mock*` archival state; a chain with a bond is
    // witnessed against the real store alone). What is held here is that
    // the store's empty state and the mock's empty state are the *same*
    // empties, so a rule tested over the mock reads the absences the store
    // reads.
    //
    // Read this block's greenness for what it is: agreement about absence,
    // not coverage of the reads. Until E4 commit 4 writes a row, absence is
    // the only thing the two views have to agree on, and every read's
    // *present* arm is witnessed by `archival_read_tests` against the store
    // alone. When the writer lands, the chain here gains a bond and this
    // comparison starts holding the present arms too — its strength grows
    // with the writer, and nothing here should be read as having it yet.
    let real_archival: Result<ArchivalReads, TestErr> =
        store.write(|batch| Ok(ArchivalReads::of(&batch.chain_view())?));
    let mocked_archival = mock.with_view(|view| match ArchivalReads::of(&view) {
        Ok(reads) => reads,
        Err(never) => match never {},
    });
    assert_eq!(real_archival.expect("reads"), mocked_archival);
    assert_eq!(mocked_archival, ArchivalReads::EMPTY);
    drop(store);
    cleanup(&path);
}

/// Every archival read, asked once, at one persona / shard / epoch / height
/// — the projection both views are compared on.
#[derive(Debug, PartialEq, Eq)]
struct ArchivalReads {
    bond: Option<shekyl_types::archival::BondRecord>,
    slashes: Vec<shekyl_types::archival::SlashLogEntry>,
    last_served: Option<shekyl_types::SettlementEpoch>,
    served: Vec<shekyl_types::archival::ServedShard>,
    passes: shekyl_types::archival::PassCount,
    r_market: Option<shekyl_types::archival::RMarket>,
    sigma_work: Option<shekyl_types::archival::SigmaWorkMilli>,
    budget: Option<shekyl_units::AtomicUnits>,
    watermark: Option<shekyl_types::SettlementEpoch>,
    records: Vec<(
        shekyl_types::PCanonicalId,
        shekyl_types::archival::BondRecord,
    )>,
    slash_applied: bool,
    accruing: Option<shekyl_units::AtomicUnits>,
}

impl ArchivalReads {
    /// What a chain with no bonds answers.
    const EMPTY: Self = Self {
        bond: None,
        slashes: Vec::new(),
        last_served: None,
        served: Vec::new(),
        passes: shekyl_types::archival::PassCount::ZERO,
        r_market: None,
        sigma_work: None,
        budget: None,
        watermark: None,
        records: Vec::new(),
        slash_applied: false,
        accruing: None,
    };

    fn of<'id, V: ChainView<'id>>(view: &V) -> Result<Self, V::Fault> {
        let persona = shekyl_types::PCanonicalId::from_bytes([0x5a; 32]);
        let shard = shekyl_types::ShardId::from_raw(7);
        let epoch = shekyl_types::SettlementEpoch::from_raw(3);
        Ok(Self {
            bond: view.bond_record(&persona)?,
            // No boundary has run on either side: the floor is `NONE`.
            slashes: view.slash_log_after(
                &persona,
                BlockHeight::ZERO,
                shekyl_chain_rules::SlashLogFloor::NONE,
            )?,
            last_served: view.last_served_epoch(&persona, shard)?,
            served: view.served_shards(&persona)?,
            passes: view.pass_count(&persona, shard, epoch)?,
            r_market: view.r_market(shard, epoch)?,
            sigma_work: view.sigma_work(epoch)?,
            budget: view.budget(epoch)?,
            watermark: view.last_settled_slash_epoch()?,
            records: view.bond_records()?,
            slash_applied: view.slash_applied(&persona, shard, epoch)?,
            accruing: view.budget_accruing(epoch)?,
        })
    }
}

#[test]
fn the_harness_fixtures_are_the_same_shape_the_store_fixtures_build() {
    // Belt on the belt: the rules crate's own fixture chain and this file's
    // store-fixture chain are two builders; a candidate from either is
    // judged the same over the mock. Guards against the harness's
    // `candidate_on` and the store's `candidate` drifting into different
    // header conventions that would make the comparison above vacuous.
    let (store, path, mock, blocks) = twin_chains(2);
    let from_store = fixture::repriced(&mock, candidate(2, blocks[1].block.hash(), Vec::new()));
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
