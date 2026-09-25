// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The mutation family against the pipeline (`DRS_E2_REPLAY_DRIVER.md`
//! §3.10). One run per mutation; the assertion's branch is chosen by the
//! expected row's **census status**, so a ported row turns a pinned gap red.

use std::num::{NonZeroU128, NonZeroUsize};
use std::sync::Arc;

use shekyl_chain_rules::harness::{Faulted, MockSubstrate};
use shekyl_chain_rules::{seed_height, Candidate, CenRow, Locus, RowStatus, TxSlot};
use shekyl_difficulty::{check_hash, Difficulty, FTL_SECONDS};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, PowHash, Timestamp};
use shekyl_wire::{Block, Transaction};

use crate::metrics::Metrics;
use crate::mutation::{
    first_nonce, Environment, ExpectedPlace, Mutated, Mutation, MutationFault, Pow, Unmutable,
    UNHELD_ROOT,
};
use crate::pipeline::{run, PipelineConfig, PipelineFault, RunReport};
use crate::schedule::ChainRules;
use crate::source::{IngestEvent, Source};
use crate::test_support::{
    block_with_nonce, chain_listing, chain_listing_with, cleanup, h, key_image, open_store,
    root_at, spend, tmp, trace_of, Family, Scripted, FIRST_SPEND_HEIGHT,
};

const GENESIS_RULES: ChainRules = ChainRules::Regtest {
    fixed_difficulty: None,
};

/// D1's target for the mined chain: half of all hashes pass.
const MINED_DIFFICULTY: u128 = 2;

/// Nonces the fixture will try. At difficulty 2 a hash meets the target
/// about half the time, so a valid block is a few tries; the wrong-seed
/// nonce (pass one seed, fail the other) is about one in four.
const NONCE_BUDGET: u32 = 1 << 16;

/// A seed the chain does not hold. Distinct from the null hash (genesis's
/// seed) and from any block id the fixture mines.
const WRONG_SEED: [u8; 32] = [0xbb; 32];

fn mined_rules() -> ChainRules {
    ChainRules::Regtest {
        fixed_difficulty: Some(NonZeroU128::new(MINED_DIFFICULTY).expect("non-zero")),
    }
}

/// A seed-sensitive mock longhash: `keccak256(blob ‖ seed)`. Deterministic,
/// fails the target about half the time at difficulty 2, and — unlike
/// `always_satisfies` — distinguishes seeds, which is what D1-under-a-wrong-
/// seed needs.
fn seeded_keccak(blob: &[u8], seed: &BlockHash) -> PowHash {
    let mut preimage = blob.to_vec();
    preimage.extend_from_slice(seed.as_bytes());
    PowHash::from_bytes(shekyl_crypto_hash::keccak256(&preimage))
}

/// [`seeded_keccak`] in the shape `MockSubstrate::longhash` takes — the
/// `Result` is the fn pointer's, as `always_satisfies` says of its own.
#[allow(clippy::unnecessary_wraps)]
fn seeded_keccak_substrate(blob: &[u8], seed: &BlockHash) -> Result<PowHash, Faulted> {
    Ok(seeded_keccak(blob, seed))
}

/// The seed CEN-D3 names for `height`, read from blocks already built.
/// `hash_at` is the block id at a height the schedule selects; that height
/// is below `height`, or absent at genesis.
fn seed_for(height: u64, hash_at: impl Fn(u64) -> BlockHash) -> BlockHash {
    match seed_height(h(height)) {
        None => BlockHash::NULL,
        Some(at) => hash_at(at.to_raw()),
    }
}

/// The first nonce in [`NONCE_BUDGET`] whose longhash under `seed` meets
/// [`MINED_DIFFICULTY`].
fn nonce_meeting_target(
    seed: &BlockHash,
    height: u64,
    previous: BlockHash,
    txs: &[Transaction],
) -> u32 {
    let difficulty = Difficulty::from_raw(MINED_DIFFICULTY);
    first_nonce(NONCE_BUDGET, |nonce| {
        let block = block_with_nonce(height, previous, txs, nonce);
        check_hash(seeded_keccak(&block.pow_blob(), seed).as_bytes(), difficulty)
    })
    .unwrap_or_else(|| {
        panic!(
            "no nonce in 0..{NONCE_BUDGET} satisfies difficulty {MINED_DIFFICULTY} under the true seed"
        )
    })
}

/// A chain of `n` blocks mined against [`seeded_keccak`] at
/// [`MINED_DIFFICULTY`]: every block's longhash under the true seed
/// satisfies the target. The seed is [`seed_height`]'s, the same function
/// the pipeline claims with.
fn mined_chain(n: u64) -> Vec<(Block, Vec<Transaction>)> {
    // The same listing as `test_support::chain`: a spend from the first
    // admissible height, nothing below.
    let listed: Vec<Vec<Transaction>> = (0..n)
        .map(|hh| {
            if hh < FIRST_SPEND_HEIGHT {
                Vec::new()
            } else {
                vec![spend(key_image(Family::Main, hh))]
            }
        })
        .collect();
    let mut recorded: Vec<BlockHash> = Vec::with_capacity(listed.len());
    chain_listing_with(listed, |height, previous, txs| {
        let seed = seed_for(height, |at| {
            recorded[usize::try_from(at).expect("seed height fits an index")]
        });
        let nonce = nonce_meeting_target(&seed, height, previous, txs);
        let block = block_with_nonce(height, previous, txs, nonce);
        recorded.push(block.hash());
        block
    })
}

fn candidate(b: &Block, txs: &[Transaction]) -> Candidate {
    Candidate::new(b.clone(), txs.to_vec())
}

fn scripted(chain: &[(Block, Vec<Transaction>)]) -> Scripted {
    Scripted::new(
        chain
            .iter()
            .map(|(b, txs)| IngestEvent::Extend(Box::new(candidate(b, txs))))
            .collect(),
    )
}

/// How one mutated run ended.
enum Outcome {
    Report(Box<RunReport>),
    Fault(PipelineFault<MutationFault<std::convert::Infallible>, Faulted>),
}

/// Replay `chain` with `mutation` applied at `at`, under `rules` and the
/// given substrate.
async fn judge(
    name: &str,
    chain: &[(Block, Vec<Transaction>)],
    at: u64,
    mutation: Mutation,
    rules: ChainRules,
    substrate: MockSubstrate,
    pow: Option<Pow<'_>>,
) -> Outcome {
    let path = tmp(&format!("mutation-{name}"));
    let env = Environment {
        clock: substrate.clock,
        pow,
    };
    let mut source = Mutated::new(scripted(chain), h(at), mutation, env);
    let trace = Arc::new(trace_of(chain, false));
    let out = run(
        &mut source,
        Arc::new(substrate),
        Arc::new(Metrics::new()),
        rules,
        open_store(&path),
        trace,
        PipelineConfig {
            window: NonZeroUsize::new(4).expect("non-zero"),
            hashers: NonZeroUsize::new(2).expect("non-zero"),
        },
    )
    .await;
    cleanup(&path);
    match out {
        Ok(report) => Outcome::Report(Box::new(report)),
        Err(fault) => Outcome::Fault(fault),
    }
}

/// The assertion §3.10 states: on an `Implemented` row the run refuses
/// exactly that row at `at` after connecting everything below it; on a
/// `Pending` row the family pins today's shape, per mutation.
fn assert_lands(mutation: Mutation, at: u64, outcome: &Outcome) {
    let expected = mutation.expected();
    match expected.status() {
        RowStatus::Implemented => {
            let report = match outcome {
                Outcome::Report(report) => report,
                Outcome::Fault(fault) => {
                    panic!("{mutation}: the run faulted instead of refusing: {fault}")
                }
            };
            let (height, verdict) = report
                .refused
                .unwrap_or_else(|| panic!("{mutation}: the mutated block was not refused"));
            assert_eq!(height, h(at), "{mutation}: refused at the wrong height");
            assert_eq!(
                verdict.rule,
                expected,
                "{mutation}: refused on {} — a rule other than the one the mutation \
                 violates fired, which is a finding on its own",
                verdict.rule.as_str()
            );
            assert_place(mutation, verdict.locus);
            assert_eq!(
                report.connected.len(),
                usize::try_from(at).expect("small"),
                "{mutation}: everything below the mutation connected"
            );
        }
        RowStatus::Pending => assert_pinned_gap(mutation, at, outcome),
        other => panic!("{mutation}: no family member expects a {other:?} row"),
    }
}

/// The place [`Mutation::expected_place`] names. [`ExpectedPlace::Unnamed`]
/// fails here on purpose: a port must name the locus, not inherit `Block`.
fn assert_place(mutation: Mutation, locus: Locus) {
    match mutation.expected_place() {
        ExpectedPlace::Block => assert_eq!(locus, Locus::Block, "{mutation}: place"),
        ExpectedPlace::Miner => assert_eq!(
            locus,
            Locus::Tx {
                slot: TxSlot::Miner
            },
            "{mutation}: §3.10 names the miner transaction"
        ),
        ExpectedPlace::Input => assert!(
            matches!(locus, Locus::Input { .. }),
            "{mutation}: §3.10 names an input, got {locus}"
        ),
        ExpectedPlace::Listed => assert!(
            matches!(
                locus,
                Locus::Tx {
                    slot: TxSlot::Listed(_)
                }
            ),
            "{mutation}: §3.10 names a listed transaction, got {locus}"
        ),
        ExpectedPlace::Unnamed => panic!(
            "{mutation}: {} is Implemented and expected_place is still Unnamed. \
             Name the locus on the mutation when the row is ported.",
            mutation.expected().as_str()
        ),
    }
}

/// §3.10's last column: what Rust does today with a violation whose row is
/// not ported. The match is exhaustive over [`Mutation`], so a new variant
/// names its pin at compile time. When a row flips to `Implemented`,
/// `assert_lands` takes the other branch and this arm is never reached again.
fn assert_pinned_gap(mutation: Mutation, at: u64, outcome: &Outcome) {
    match mutation {
        Mutation::WrongReward | Mutation::ReorderedBodies => {
            let report = match outcome {
                Outcome::Report(report) => report,
                Outcome::Fault(fault) => panic!(
                    "{mutation}: the run faulted; {} is Pending and connects today: {fault}",
                    mutation.expected().as_str()
                ),
            };
            assert_eq!(
                report.refused,
                None,
                "{mutation}: {} is Pending, so the block connects today; a refusal here means \
                 the row landed — flip the census, not this test",
                mutation.expected().as_str()
            );
            assert_eq!(
                report.connected.len(),
                usize::try_from(at + 1).expect("small"),
                "{mutation}: the mutated block connected"
            );
        }
        // `DoubleSpend` pinned the SI-1 halt while I7 was Pending (C2-R8's
        // taxonomy — a belt firing is the validator's hole — observed, not
        // accepted); E6 slice 6 commit 4 ported I7 and the pin was deleted
        // with the hole. It refuses at its input now, like the six.
        Mutation::HeaderVersion
        | Mutation::Orphan
        | Mutation::WrongRoot
        | Mutation::FutureTimestamp
        | Mutation::StaleTimestamp
        | Mutation::PowUnderWrongSeed
        | Mutation::DoubleSpend
        | Mutation::UnknownReference
        | Mutation::ReferenceTooRecent => panic!(
            "{mutation}: the census says {} is pending, and the family has no pin for a row \
             that was Implemented at the pin",
            mutation.expected().as_str()
        ),
    }
}

// ---------------------------------------------------------------------------
// The family, one run each
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_family_lands_on_its_named_rows() {
    // Every mutation runs; a mutation missing here is a compile error via
    // the exhaustive match in `setup`, and `Mutation::ALL` is the order.
    for mutation in Mutation::ALL {
        let outcome = setup_and_judge(mutation).await;
        assert_lands(mutation, AT, &outcome);
    }
}

/// Where a mutation lands: the block after the first spend block, so the
/// blocks below it hold a spend to reuse and a median to fall under. The
/// mutated block is the tip. (Block 2 until slice 6 commit 5: CEN-I11 put
/// the first admissible spend at `FIRST_SPEND_HEIGHT`, and `DoubleSpend`
/// needs one beneath it.)
///
/// A pending row connects, and a successor built on the pre-mutation hash
/// orphans on CEN-A2, so the pin would read a gap as a refusal. An
/// implemented row stops the run at the refusal, so a successor would not
/// be judged either. One length covers both.
const AT: u64 = FIRST_SPEND_HEIGHT + 1;
const CHAIN_LEN: u64 = AT + 1;

async fn setup_and_judge(mutation: Mutation) -> Outcome {
    let n = CHAIN_LEN;
    match mutation {
        Mutation::PowUnderWrongSeed => {
            let chain = mined_chain(n);
            let substrate = MockSubstrate {
                clock: MockSubstrate::CLOCK,
                longhash: seeded_keccak_substrate,
            };
            let pow = Pow {
                longhash: &seeded_keccak,
                difficulty: Difficulty::from_raw(MINED_DIFFICULTY),
                true_seed: seed_for(AT, |at| {
                    chain[usize::try_from(at).expect("seed height fits an index")]
                        .0
                        .hash()
                }),
                wrong_seed: BlockHash::from_bytes(WRONG_SEED),
                nonce_budget: NONCE_BUDGET,
            };
            judge(
                "pow-wrong-seed",
                &chain,
                AT,
                mutation,
                mined_rules(),
                substrate,
                Some(pow),
            )
            .await
        }
        Mutation::ReorderedBodies => {
            // `chain(n)`'s listing, except that block `AT` lists two bodies
            // so there is something to swap.
            let listed: Vec<Vec<Transaction>> = (0..n)
                .map(|hh| {
                    if hh < FIRST_SPEND_HEIGHT {
                        Vec::new()
                    } else if hh == AT {
                        vec![
                            spend(key_image(Family::Main, hh)),
                            spend(key_image(Family::Fork, hh)),
                        ]
                    } else {
                        vec![spend(key_image(Family::Main, hh))]
                    }
                })
                .collect();
            assert_eq!(listed.len() as u64, n, "the reordered block is the tip");
            let chain = chain_listing(listed);
            judge(
                "reordered-bodies",
                &chain,
                AT,
                mutation,
                GENESIS_RULES,
                MockSubstrate::default(),
                None,
            )
            .await
        }
        Mutation::HeaderVersion
        | Mutation::Orphan
        | Mutation::WrongRoot
        | Mutation::FutureTimestamp
        | Mutation::StaleTimestamp
        | Mutation::WrongReward
        | Mutation::DoubleSpend
        | Mutation::UnknownReference
        | Mutation::ReferenceTooRecent => {
            let chain = crate::test_support::chain(n);
            judge(
                &format!("{mutation:?}").to_lowercase(),
                &chain,
                AT,
                mutation,
                GENESIS_RULES,
                MockSubstrate::default(),
                None,
            )
            .await
        }
    }
}

/// The mined chain itself replays clean under the seeded hasher — so a D1
/// refusal in the family is the mutation's, not the fixture's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mined_chain_replays_clean_under_the_seeded_hasher() {
    let path = tmp("mutation-mined-clean");
    // The family's own length, so the clean replay covers the spend blocks
    // the mutations are staged over.
    let chain = mined_chain(CHAIN_LEN);
    let mut source = scripted(&chain);
    let report = run(
        &mut source,
        Arc::new(MockSubstrate {
            clock: MockSubstrate::CLOCK,
            longhash: seeded_keccak_substrate,
        }),
        Arc::new(Metrics::new()),
        mined_rules(),
        open_store(&path),
        Arc::new(trace_of(&chain, false)),
        PipelineConfig::default(),
    )
    .await
    .expect("a mined chain is a valid chain");
    assert_eq!(report.refused, None);
    assert_eq!(
        report.connected.len(),
        usize::try_from(CHAIN_LEN).expect("small")
    );
    assert!(
        report.exercised.contains("CEN-D1"),
        "D1 was judged, not skipped"
    );
    cleanup(&path);
}

// ---------------------------------------------------------------------------
// The wrapper's own contract
// ---------------------------------------------------------------------------

fn env() -> Environment<'static> {
    Environment {
        clock: MockSubstrate::CLOCK,
        pow: None,
    }
}

fn drain<S: Source>(source: &mut S) -> Result<usize, S::Fault> {
    let mut n = 0;
    while source.next()?.is_some() {
        n += 1;
    }
    Ok(n)
}

#[test]
fn the_wrapper_keeps_numbering_and_heights_and_mutates_exactly_one_block() {
    let chain = crate::test_support::chain(3);
    let mut source = Mutated::new(scripted(&chain), h(1), Mutation::Orphan, env());
    assert_eq!(source.first_height(), h(0));
    let mut seen = Vec::new();
    while let Some(ev) = source.next().expect("no fault") {
        seen.push(ev);
    }
    assert_eq!(seen.len(), 3);
    for (i, ev) in seen.iter().enumerate() {
        assert_eq!(ev.seq.to_raw(), i as u64, "numbering is the inner source's");
    }
    let block_at = |i: usize| match &seen[i].event {
        IngestEvent::Extend(c) => c.block.clone(),
        IngestEvent::Rewind { .. } => panic!("Extend-only"),
    };
    assert_eq!(block_at(0), chain[0].0, "below: untouched");
    assert_eq!(block_at(2), chain[2].0, "above: untouched");
    assert_ne!(block_at(1).header.previous, chain[1].0.header.previous);
    assert_eq!(
        block_at(1).header.timestamp,
        chain[1].0.header.timestamp,
        "one violation"
    );
}

#[test]
fn a_rewind_from_the_inner_source_is_a_wrapper_fault() {
    let chain = crate::test_support::chain(2);
    let events = vec![
        IngestEvent::Extend(Box::new(candidate(&chain[0].0, &chain[0].1))),
        IngestEvent::Rewind { to: h(0) },
    ];
    let mut source = Mutated::new(Scripted::new(events), h(0), Mutation::WrongRoot, env());
    source.next().expect("block 0 mutated");
    match source.next() {
        Err(MutationFault::Rewind { to }) => assert_eq!(to, h(0)),
        other => panic!("{other:?}"),
    }
    match source.next() {
        Err(MutationFault::Stopped) => {}
        other => panic!("a fault is not retryable: {other:?}"),
    }
}

#[test]
fn a_mutation_height_the_chain_never_reaches_is_a_fault_not_a_clean_replay() {
    let chain = crate::test_support::chain(2);
    let mut source = Mutated::new(scripted(&chain), h(5), Mutation::Orphan, env());
    match drain(&mut source) {
        Err(MutationFault::NeverReached { at, next }) => {
            assert_eq!((at, next), (h(5), Some(h(2))));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_candidate_that_cannot_carry_the_mutation_names_why() {
    // The first spend block of `chain(FIRST_SPEND_HEIGHT + 1)` lists one
    // body: nothing to reorder.
    let first_spend = FIRST_SPEND_HEIGHT;
    let chain = crate::test_support::chain(first_spend + 1);
    let mut source = Mutated::new(
        scripted(&chain),
        h(first_spend),
        Mutation::ReorderedBodies,
        env(),
    );
    for below in 0..first_spend {
        source
            .next()
            .unwrap_or_else(|e| panic!("block {below} passes through: {e:?}"));
    }
    match source.next() {
        Err(MutationFault::Unmutable {
            mutation: Mutation::ReorderedBodies,
            at,
            cause: Unmutable::TooFewBodies { listed: 1 },
        }) => assert_eq!(at, h(first_spend)),
        other => panic!("{other:?}"),
    }
    // Genesis has nothing spent before it: no double spend to stage.
    let mut source = Mutated::new(scripted(&chain), h(0), Mutation::DoubleSpend, env());
    match source.next() {
        Err(MutationFault::Unmutable {
            cause: Unmutable::NothingSpentBefore,
            ..
        }) => {}
        other => panic!("{other:?}"),
    }
    // PoW without the leg.
    let mut source = Mutated::new(scripted(&chain), h(0), Mutation::PowUnderWrongSeed, env());
    match source.next() {
        Err(MutationFault::Unmutable {
            cause: Unmutable::NoPowEnvironment,
            ..
        }) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn every_mutation_names_a_row_and_the_pending_ones_are_the_two_the_plan_lists() {
    let pending: Vec<CenRow> = Mutation::ALL
        .iter()
        .map(|m| m.expected())
        .filter(|row| row.status() == RowStatus::Pending)
        .collect();
    // §3.10's table at the pin. When an E6 slice ports one of these, this
    // line and the family's pinned-gap arm both go red together — the plan's
    // table is then updated with the row, not the test loosened. (Slice 4
    // re-keyed WrongReward F13 → F18, Q8: F13 landed as a definition, and
    // the predicate a wrong amount trips is F18, blocked on G6. Slice 6
    // commit 4 ported I7: `DoubleSpend` now refuses at its input, and the
    // family's landing arm below holds it.)
    assert_eq!(pending, vec![CenRow::F18, CenRow::G2]);
    for m in Mutation::ALL {
        assert!(
            m.to_string().contains(m.expected().as_str()),
            "{m}: Display names the row"
        );
    }
    let places: Vec<(Mutation, ExpectedPlace)> = Mutation::ALL
        .into_iter()
        .map(|m| (m, m.expected_place()))
        .collect();
    assert_eq!(
        places,
        vec![
            (Mutation::HeaderVersion, ExpectedPlace::Block),
            (Mutation::Orphan, ExpectedPlace::Block),
            (Mutation::WrongRoot, ExpectedPlace::Block),
            (Mutation::FutureTimestamp, ExpectedPlace::Block),
            (Mutation::StaleTimestamp, ExpectedPlace::Block),
            (Mutation::PowUnderWrongSeed, ExpectedPlace::Block),
            (Mutation::WrongReward, ExpectedPlace::Miner),
            (Mutation::ReorderedBodies, ExpectedPlace::Unnamed),
            (Mutation::DoubleSpend, ExpectedPlace::Input),
            // Slice 6 commit 5: the reference rows name the transaction.
            (Mutation::UnknownReference, ExpectedPlace::Listed),
            (Mutation::ReferenceTooRecent, ExpectedPlace::Listed),
        ]
    );
}

#[test]
fn a_timestamp_mutation_at_genesis_cannot_provoke_its_row() {
    let chain = crate::test_support::chain(1);
    for mutation in [Mutation::FutureTimestamp, Mutation::StaleTimestamp] {
        let mut source = Mutated::new(scripted(&chain), h(0), mutation, env());
        match source.next() {
            Err(MutationFault::Unmutable {
                cause: Unmutable::GenesisExempt(which),
                at,
                ..
            }) => {
                assert_eq!(which, mutation);
                assert_eq!(at, h(0));
            }
            other => panic!("{mutation}: {other:?}"),
        }
        match source.next() {
            Err(MutationFault::Stopped) => {}
            other => panic!("{mutation}: a fault is not retryable: {other:?}"),
        }
    }
}

#[test]
fn a_clock_with_no_representable_future_does_not_pretend_to_be_past_the_ftl() {
    let chain = crate::test_support::chain(2);
    // `clock + FTL + 1` is `u64::MAX + 1`. The saturating predicate would
    // still accept `u64::MAX`, so emitting it would not be CEN-C1.
    let env = Environment {
        clock: Timestamp::from_raw(u64::MAX - FTL_SECONDS),
        pow: None,
    };
    let mut source = Mutated::new(scripted(&chain), h(1), Mutation::FutureTimestamp, env);
    source.next().expect("block 0 is not the mutation");
    match source.next() {
        Err(MutationFault::Unmutable {
            cause: Unmutable::NoRepresentableFuture,
            at,
            ..
        }) => assert_eq!(at, h(1)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_amount_at_the_top_of_the_range_cannot_move_by_one() {
    let chain = crate::test_support::chain(1);
    let mut candidate = candidate(&chain[0].0, &chain[0].1);
    candidate.block.miner_transaction.prefix.outputs[0].amount = u64::MAX;
    let err = Mutation::WrongReward
        .apply(candidate, &env(), &[], h(0))
        .expect_err("u64::MAX + 1 does not fit");
    assert_eq!(err, Unmutable::RewardSaturated);
}

#[test]
fn the_unheld_root_is_not_a_fixture_root() {
    let chain = crate::test_support::chain(CHAIN_LEN);
    let mut source = Mutated::new(scripted(&chain), h(AT), Mutation::WrongRoot, env());
    for _ in 0..AT {
        source.next().expect("blocks below the mutation");
    }
    let ev = source.next().expect("the mutated block").expect("yielded");
    let IngestEvent::Extend(candidate) = ev.event else {
        panic!("Extend-only");
    };
    let root = candidate.block.header.curve_tree_root;
    assert_eq!(root.as_bytes(), &UNHELD_ROOT);
    assert_ne!(root, CurveTreeRoot::EMPTY);
    assert_ne!(root, root_at(AT));
}

#[test]
fn the_last_representable_height_is_yielded_and_another_event_is_a_fault() {
    let chain = crate::test_support::chain(1);
    let block = IngestEvent::Extend(Box::new(candidate(&chain[0].0, &chain[0].1)));
    let ceiling = BlockHeight::from_raw(u64::MAX);
    let mut source = Mutated::new(
        Scripted::from(ceiling, vec![block.clone(), block]),
        ceiling,
        Mutation::Orphan,
        env(),
    );
    let yielded = source
        .next()
        .expect("the block at u64::MAX is a real event")
        .expect("yielded");
    let IngestEvent::Extend(carried) = yielded.event else {
        panic!("Extend-only");
    };
    assert_ne!(
        carried.block.header.previous, chain[0].0.header.previous,
        "the mutation landed on the last height"
    );
    match source.next() {
        Err(MutationFault::HeightExhausted { after }) => assert_eq!(after, ceiling),
        other => panic!("{other:?}"),
    }
    match source.next() {
        Err(MutationFault::Stopped) => {}
        other => panic!("a fault is not retryable: {other:?}"),
    }

    // The same height, with the source ending there, is a clean close.
    let block = IngestEvent::Extend(Box::new(candidate(&chain[0].0, &chain[0].1)));
    let mut source = Mutated::new(
        Scripted::from(ceiling, vec![block]),
        ceiling,
        Mutation::Orphan,
        env(),
    );
    assert!(source.next().expect("yielded").is_some());
    assert!(source.next().expect("clean end").is_none());
}
